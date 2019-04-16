/*
 * Copyright 2019 Theobroma Systems Design und Consulting GmbH
 * Copyright 2019 Cherry GmbH
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <secureboard/secureboard.h>

#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

void secureboard_usb_control_request_callback(void *data,
                                              unsigned len,
                                              secureboard_usb_encap_control_request_result_t status,
                                              intptr_t _ctx)
{
    secureboard_usb_control_request_callback_context_t *ctx = (secureboard_usb_control_request_callback_context_t*)_ctx;
    ctx->length = len;
    ctx->status = status;
}

static inline unsigned _secureboard_msg_len(secureboard_msg_t *msg)
{
    return (msg->hdr[0] | (((unsigned)msg->hdr[1]) << 8)) & 0x7fff;
}

static int _secureboard_usb_encap_handle_control_message(secureboard_connection_t *sb, unsigned data_len)
{
    secureboard_usb_encap_control_request_t *cr = sb->pending_ctrl_request;
    sb->pending_ctrl_request = NULL;

    if (sb->rd_msg.hdr[1] & 0x80) { // stall bit set;
        if (cr->cb)
            cr->cb(NULL, 0, SECUREBOARD_USB_ENCAP_REQUEST_STALL, cr->ctx);
        goto done;
    }

    unsigned rd_len = _secureboard_msg_len(&sb->rd_msg);
    if (rd_len > cr->length)
        rd_len = cr->length;

    memcpy(cr->data, sb->rd_msg.data, rd_len);
    if (cr->cb)
        cr->cb(cr->data, rd_len, SECUREBOARD_USB_ENCAP_REQUEST_COMPLETE, cr->ctx);

done:
    free(cr);
    return 0;
}

static int _secureboard_usb_encap_handle_EPn_message(
    secureboard_connection_t *sb,
    unsigned data_len,
    uint8_t ep)
{
    secureboard_usb_encap_rx_object_t *ro;
    TAILQ_FOREACH(ro, &sb->rx_head, tailq) {
        if (ro->ep == ep) {
            TAILQ_REMOVE(&sb->rx_head, ro, tailq);
            secureboard_printf(sb, "Received EP%d message.\n", ep);
            secureboard_usb_encap_ep_complete_action_t action;
            action = SECUREBOARD_USB_ENCAP_EP_COMPLETE_DISPOSE_REQUEST;

            if (ro->cb){
                if (sb->rd_msg.hdr[1] & 0x80) { // stall bit set;
                    action = ro->cb(NULL, 0, ep, SECUREBOARD_USB_ENCAP_REQUEST_STALL, ro->ctx);
                }
                else {
                    memcpy(ro->data, sb->rd_msg.data, data_len);
                    action = ro->cb(ro->data, data_len, ep,
                                    SECUREBOARD_USB_ENCAP_REQUEST_COMPLETE, ro->ctx);
                }
            }
            switch (action) {
                case SECUREBOARD_USB_ENCAP_EP_COMPLETE_DISPOSE_REQUEST:
                    free(ro);
                    break;
                case SECUREBOARD_USB_ENCAP_EP_COMPLETE_RESUBMIT_REQUEST:
                    TAILQ_INSERT_TAIL(&sb->rx_head, ro, tailq);
                    break;
            }
            return SECUREBOARD_SUCCESS;
        }
    }

    secureboard_printf(sb, "Dropped EP%d message.\n", ep);
    return SECUREBOARD_SUCCESS;
}

static int _secureboard_usb_encap_handle_msg(secureboard_connection_t *sb, unsigned data_len)
{
    uint8_t ep = sb->rd_msg.hdr[2];

    if ((ep & 0x7f) == 0) {
        // drop since no controll transfer is ongoing
        if (!sb->pending_ctrl_request) {
            secureboard_printf(sb, "Dropped spurious EP0 message.\n");
            return SECUREBOARD_SUCCESS;
        }

        return _secureboard_usb_encap_handle_control_message(sb, data_len);
    }
    else {
        if ((ep & SECUREBOARD_USB_ENCAP_IN) == SECUREBOARD_USB_ENCAP_IN) {
            return _secureboard_usb_encap_handle_EPn_message(sb, data_len, ep & 0x7f);
        }
        else {
            secureboard_printf(sb, "Dropped spurious EP%d message. Since direction was OUT\n", ep & 0x7f);
            return SECUREBOARD_SUCCESS;
        }
    }
}


static int _secureboard_setup_msg_hdr(secureboard_connection_t *sb,
                                      secureboard_msg_t *msg,
                                      unsigned len,
                                      secureboard_usb_encap_dir_t dir,
                                      unsigned ep)
{
    if (len > SECUREBOARD_MSG_MAX_LEN - SECUREBOARD_MSG_HDR_LEN) {
        secureboard_printf(sb, "Transmit message too long\n");
        return SECUREBOARD_ERR_ENCAP_TXOV;
    }

    if (ep & 0x80) {
        secureboard_printf(sb, "Cannot transmit message with IN direction\n");
        return SECUREBOARD_ERR_ENCAP_EP;
    }

    msg->hdr[0] = len & 0xff;
    msg->hdr[1] = (len >> 8) & 0xff;
    msg->hdr[2] = ep | dir;

    return SECUREBOARD_SUCCESS;
}

static secureboard_wr_tqe_t *_secureboard_create_setup(secureboard_connection_t *sb,
                                                       uint8_t bmRequestType,
                                                       uint8_t bRequest,
                                                       uint16_t wValue,
                                                       uint16_t wIndex,
                                                       uint16_t wLength)
{
    secureboard_wr_tqe_t *tqe = malloc(SECUREBOARD_MSG_HDR_LEN + 8 + offsetof(secureboard_wr_tqe_t, msg));
    if (!tqe) {
        secureboard_printf(sb, "Failed allocating message buffer\n");
        return NULL;
    }

    _secureboard_setup_msg_hdr(sb, &tqe->msg, 8, SECUREBOARD_USB_ENCAP_OUT, SECUREBOARD_USB_ENCAP_SETUP_EP);
    tqe->msg.data[0] = bmRequestType;
    tqe->msg.data[1] = bRequest;
    tqe->msg.data[2] = wValue & 0xff;
    tqe->msg.data[3] = (wValue >> 8) & 0xff;
    tqe->msg.data[4] = wIndex & 0xff;
    tqe->msg.data[5] = (wIndex >> 8) & 0xff;
    tqe->msg.data[6] = wLength & 0xff;
    tqe->msg.data[7] = (wLength >> 8) & 0xff;

    tqe->wr_pos = 0;
    tqe->wr_len = SECUREBOARD_MSG_HDR_LEN + 8;

    return tqe;
}

static secureboard_wr_tqe_t *_secureboard_create_epdata(secureboard_connection_t *sb,
                                                        void *data,
                                                        unsigned data_len,
                                                        uint8_t ep)
{
    secureboard_wr_tqe_t *tqe = malloc(SECUREBOARD_MSG_HDR_LEN + data_len + offsetof(secureboard_wr_tqe_t, msg));
    if (!tqe) {
        secureboard_printf(sb, "Failed allocating message buffer\n");
        return NULL;
    }

    _secureboard_setup_msg_hdr(sb, &tqe->msg, data_len, SECUREBOARD_USB_ENCAP_OUT, ep);
    memcpy(tqe->msg.data, data, data_len);

    tqe->wr_pos = 0;
    tqe->wr_len = SECUREBOARD_MSG_HDR_LEN + data_len;

    return tqe;
}

int secureboard_usb_encap_control_request(secureboard_connection_t *sb,
                                          uint8_t bmRequestType,
                                          uint8_t bRequest,
                                          uint16_t wValue,
                                          uint16_t wIndex,
                                          uint16_t wLength,
                                          void *data,
                                          unsigned timeout_sec,
                                          secureboard_usb_encap_control_request_cb cb,
                                          intptr_t ctx)
{
    int res;

    if (wLength > SECUREBOARD_MSG_DATA_LEN) {
        secureboard_printf(sb, "Control Request exceeds maximum message size\n");
        return ((bmRequestType & SECUREBOARD_REQTYPE_DEVICE_TO_HOST) == SECUREBOARD_REQTYPE_DEVICE_TO_HOST) ?
                SECUREBOARD_ERR_ENCAP_RXOV : SECUREBOARD_ERR_ENCAP_TXOV;
    }

    if (sb->pending_ctrl_request) {
        secureboard_printf(sb, "Control transfer pending\n");
        return SECUREBOARD_ERR_ENCAP_BUSY;
    }

    secureboard_usb_encap_control_request_t *ctrl_request = malloc(sizeof(secureboard_usb_encap_control_request_t));
    if (!ctrl_request) {
        secureboard_printf(sb, "Out of memory\n");
        return SECUREBOARD_ERR_NO_MEMORY;
    }

    secureboard_wr_tqe_t *setup_msg = _secureboard_create_setup(sb, bmRequestType, bRequest, wValue, wIndex, wLength);
    if (!setup_msg) {
        free(ctrl_request);
        secureboard_printf(sb, "Out of memory\n");
        return SECUREBOARD_ERR_NO_MEMORY;
    }


    secureboard_wr_tqe_t *data_out_msg = NULL;
    if ((wLength > 0) && ((bmRequestType & SECUREBOARD_REQTYPE_DEVICE_TO_HOST) == SECUREBOARD_REQTYPE_HOST_TO_DEVICE)) {
        data_out_msg = _secureboard_create_epdata(sb, data, wLength, 0);
        if (!data_out_msg) {
            free(setup_msg);
            free(ctrl_request);
            secureboard_printf(sb, "Out of memory\n");
            return SECUREBOARD_ERR_NO_MEMORY;
        }
    }

    TAILQ_INSERT_TAIL(&sb->tx_head, setup_msg, tailq);
    if (data_out_msg) {
        TAILQ_INSERT_TAIL(&sb->tx_head, data_out_msg, tailq);
    }

    ctrl_request->dir = (secureboard_usb_encap_dir_t)(bmRequestType & 0x80);
    // For HOST_DO_DEV we do not expect a response
    ctrl_request->length = data_out_msg ? 0 : wLength;
    ctrl_request->data = data;
    ctrl_request->cb = cb;
    ctrl_request->ctx = ctx;

    sb->pending_ctrl_request = ctrl_request;

    res = SECUREBOARD_SUCCESS;

    if (timeout_sec) {
        res = secureboard_usb_encap_control_request_wait_complete(sb, timeout_sec);
        if (sb->pending_ctrl_request) {
            secureboard_usb_encap_control_request_cancel(sb);
        }
    }

    return res;
}

int secureboard_usb_encap_control_request_wait_complete(
    secureboard_connection_t *sb,
    unsigned timeout_sec)
{
    int res;
    res = secureboard_arm_timer(sb, timeout_sec, 0);
    if (res != SECUREBOARD_SUCCESS)
        return res;

    // Assume write in the first place
    secureboard_connnection_io_wants_t wants = SECUREBOARD_CONNNECTION_IO_WANTS_WRITE;

    struct pollfd pollfds[2] = {
        [0] = {
            .fd = sb->socket,
            .events = 0,
            .revents = 0,
        },
        [1] = {
            .fd = sb->timer_fd,
            .events = 0,
            .revents = 0,
        }
    };

    while (1) {
        res = secureboard_usb_encap_do_io(sb, &wants);
        if (res != SECUREBOARD_SUCCESS) {
            secureboard_disarm_timer(sb);
            return res;
        }

        if (!sb->pending_ctrl_request) {
            secureboard_disarm_timer(sb);
            return SECUREBOARD_SUCCESS;
        }

        // there is nothing to wait for but the request is still
        // incomplete
        if (!wants) {
            return SECUREBOARD_ERR_INTERNAL;
        }

        pollfds[0].events = 0;
        if (wants & SECUREBOARD_CONNNECTION_IO_WANTS_READ) {
                pollfds[0].events |= POLLIN;
        }
        if (wants & SECUREBOARD_CONNNECTION_IO_WANTS_WRITE) {
                pollfds[0].events |= POLLOUT;
        }

        res = poll(pollfds, 2, 1000);
        if (res < 0) {
            secureboard_disarm_timer(sb);
            if (errno == EINTR)
                return SECUREBOARD_ERR_SIGNAL;
            return SECUREBOARD_ERR_IO;
        }

        if (pollfds[1].revents & POLLIN) {
            secureboard_disarm_timer(sb);
            return SECUREBOARD_ERR_TIMEOUT;
        }
    }
}

void secureboard_usb_encap_control_request_cancel(secureboard_connection_t *sb)
{
    secureboard_usb_encap_control_request_t *cr = sb->pending_ctrl_request;
    sb->pending_ctrl_request = NULL;
    if (cr) {
        if (cr->cb)
            cr->cb(NULL, 0, SECUREBOARD_USB_ENCAP_REQUEST_CANCEL, cr->ctx);
        free(cr);
    }
}

int secureboard_usb_encap_submit_rx_request(
    secureboard_connection_t *sb,
    uint8_t ep,
    void *data,
    unsigned length,
    secureboard_usb_encap_rx_ep_request_cb cb,
    intptr_t ctx,
    secureboard_usb_encap_rx_object_t **request_object)
{
    if (length > SECUREBOARD_MSG_MAX_LEN - SECUREBOARD_MSG_HDR_LEN) {
        secureboard_printf(sb, "Transmit message too long.\n");
        return SECUREBOARD_ERR_ENCAP_RXOV;
    }

    if (ep & 0x80) {
        secureboard_printf(sb, "Cannot transmit message with IN direction.\n");
        return SECUREBOARD_ERR_ENCAP_EP;
    }

    if ((ep & 0x7F) == 0) {
        secureboard_printf(sb, "Cannot transmit message on EP0 directly.\n");
        return SECUREBOARD_ERR_ENCAP_EP;
    }

    secureboard_usb_encap_rx_object_t *_request_object;
    _request_object = malloc(sizeof(secureboard_usb_encap_rx_object_t));

    if (!_request_object) {
        secureboard_printf(sb, "Out of memory\n");
        return SECUREBOARD_ERR_NO_MEMORY;
    }

    _request_object->data = data;
    _request_object->length = length;
    _request_object->ep = ep;
    _request_object->cb = cb;
    _request_object->ctx = ctx;

    TAILQ_INSERT_TAIL(&sb->rx_head, _request_object, tailq);

    if (request_object) {
        *request_object = _request_object;
    }

    return SECUREBOARD_SUCCESS;
}

void secureboard_usb_encap_rx_ep_request_cancel(secureboard_connection_t *sb,
                                                secureboard_usb_encap_rx_object_t *request_object)
{
    TAILQ_REMOVE(&sb->rx_head, request_object, tailq);

    if (request_object->cb)
        request_object->cb(NULL, 0, request_object->ep,
                           SECUREBOARD_USB_ENCAP_REQUEST_CANCEL, request_object->ctx);
    free(request_object);
}

bool secureboard_usb_encap_tx_pending(secureboard_connection_t *sb)
{
    if (!TAILQ_EMPTY(&sb->tx_head))
        return true;
    return false;
}

bool secureboard_usb_encap_rx_pending(secureboard_connection_t *sb)
{
    if (!TAILQ_EMPTY(&sb->rx_head))
        return true;
    if (sb->pending_ctrl_request)
        return true;
    return false;
}

int secureboard_usb_encap_do_read(secureboard_connection_t *sb,
                                  secureboard_connnection_io_wants_t *wants)
{
    unsigned rd_len;
    unsigned data_len = 0;
    int res;

    while (secureboard_usb_encap_rx_pending(sb)) {
        if (sb->rd_pos < SECUREBOARD_MSG_HDR_LEN) {
            rd_len = SECUREBOARD_MSG_HDR_LEN - sb->rd_pos;
        }
        else {
            data_len = (sb->rd_msg.hdr[0] | (((unsigned)sb->rd_msg.hdr[1]) << 8)) & 0x7fff;

            if (data_len > sizeof(sb->rd_msg.data)) {
                secureboard_printf(sb, "Received message too long\n");
                return SECUREBOARD_ERR_ENCAP_RXOV;
            }

            rd_len = data_len + SECUREBOARD_MSG_HDR_LEN - sb->rd_pos;
        }

        res = SSL_read(sb->con, &sb->rd_msg.raw[sb->rd_pos], rd_len);
        if (res <= 0) {
            switch (SSL_get_error(sb->con, res)) {
                case SSL_ERROR_WANT_READ:
                    *wants = SECUREBOARD_CONNNECTION_IO_WANTS_READ;
                    return SECUREBOARD_SUCCESS;

                case SSL_ERROR_WANT_WRITE:
                    *wants = SECUREBOARD_CONNNECTION_IO_WANTS_WRITE;
                    return SECUREBOARD_SUCCESS;

                case SSL_ERROR_ZERO_RETURN:
                    return SECUREBOARD_ERR_CLOSED;

                default:
                    secureboard_print_errors(sb);
                    return SECUREBOARD_ERR_SSL;
            }
        }
        else {
            sb->rd_pos += res;

            // check if message is complete
            if (sb->rd_pos >= SECUREBOARD_MSG_HDR_LEN) {
                data_len = (sb->rd_msg.hdr[0] | (((unsigned)sb->rd_msg.hdr[1]) << 8)) & 0x7fff;

                if (data_len > sizeof(sb->rd_msg.data)) {
                    secureboard_printf(sb, "Received message too long\n");
                    return SECUREBOARD_ERR_ENCAP_RXOV;
                }
            }

            if (sb->rd_pos == data_len + SECUREBOARD_MSG_HDR_LEN) {
                res = _secureboard_usb_encap_handle_msg(sb, data_len);
                if (res) {
                    secureboard_printf(sb, "secureboard_usb_encap_handle_msg failed\n");
                    return res;
                }
                sb->rd_pos = 0;
            }
        }
    };

    *wants = SECUREBOARD_CONNNECTION_IO_WANTS_NOTHING;
    return SECUREBOARD_SUCCESS;
}

int secureboard_usb_encap_do_write(secureboard_connection_t *sb,
                                   secureboard_connnection_io_wants_t *wants)
{
    int res;

    while (secureboard_usb_encap_tx_pending(sb)) {
        secureboard_wr_tqe_t *tqe = TAILQ_FIRST(&sb->tx_head);
        if (!tqe)
            break;

        res = SSL_write(sb->con, &tqe->msg.raw[tqe->wr_pos], tqe->wr_len - tqe->wr_pos);
        if (res < 0) {
            switch (SSL_get_error(sb->con, res)) {
                case SSL_ERROR_WANT_READ:
                    *wants = SECUREBOARD_CONNNECTION_IO_WANTS_READ;
                    break;

                case SSL_ERROR_WANT_WRITE:
                    *wants = SECUREBOARD_CONNNECTION_IO_WANTS_WRITE;
                    break;

                case SSL_ERROR_ZERO_RETURN:
                    return SECUREBOARD_ERR_CLOSED;

                default:
                    secureboard_print_errors(sb);
                    return SECUREBOARD_ERR_SSL;
            }
        }
        else {
            tqe->wr_pos += res;
            if (tqe->wr_pos == tqe->wr_len) {
                TAILQ_REMOVE(&sb->tx_head, tqe, tailq);
            }
            free(tqe);
        }
    }

    *wants = SECUREBOARD_CONNNECTION_IO_WANTS_NOTHING;
    return SECUREBOARD_SUCCESS;
}

int secureboard_usb_encap_do_io(
    secureboard_connection_t *sb,
    secureboard_connnection_io_wants_t *wants)
{
    secureboard_connnection_io_wants_t wants_rd, wants_wr;
    int res;

    res = secureboard_usb_encap_do_read(sb, &wants_rd);
    if (res != SECUREBOARD_SUCCESS)
        return res;

    res = secureboard_usb_encap_do_write(sb, &wants_wr);
    if (res != SECUREBOARD_SUCCESS)
        return res;

    *wants = (wants_rd | wants_wr);

    return SECUREBOARD_SUCCESS;
}

void secureboard_usb_encap_cancel_all(secureboard_connection_t *sb)
{
    secureboard_usb_encap_control_request_cancel(sb);

    secureboard_wr_tqe_t *tqe;
    while ((tqe = TAILQ_FIRST(&sb->tx_head))) {
        TAILQ_REMOVE(&sb->tx_head, tqe, tailq);
        free(tqe);
    }

    secureboard_usb_encap_rx_object_t *ro;
    while ((ro = TAILQ_FIRST(&sb->rx_head))) {
        secureboard_usb_encap_rx_ep_request_cancel(sb, ro);
    }
}
