#ifndef LIB_INTERNAL_SECUREBOARD_H
#define LIB_INTERNAL_SECUREBOARD_H

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

#ifndef ALLOW_LIB_SECUREBOARD_INTERNAL
#error This header is for internal use only
#endif

#define SECUREBOARD_MSG_MAX_LEN 640
#define SECUREBOARD_MSG_HDR_LEN 3
#define SECUREBOARD_MSG_DATA_LEN (SECUREBOARD_MSG_MAX_LEN - SECUREBOARD_MSG_HDR_LEN)

#define SECUREBOARD_USB_ENCAP_SETUP_EP 0x7f

#include <sys/queue.h>

typedef enum secureboard_usb_encap_dir_tag {
    SECUREBOARD_USB_ENCAP_OUT = 0x00,
    SECUREBOARD_USB_ENCAP_IN  = 0x80,
} secureboard_usb_encap_dir_t;

typedef struct secureboard_usb_encap_rx_object_tag {
    TAILQ_ENTRY(secureboard_usb_encap_rx_object_tag) tailq;
    void *data;
    unsigned length;
    uint8_t ep;
    secureboard_usb_encap_rx_ep_request_cb cb;
    intptr_t ctx;
} secureboard_usb_encap_rx_object_t;

typedef struct secureboard_usb_encap_control_request_tag {
    secureboard_usb_encap_dir_t dir;
    unsigned length;
    void *data;
    secureboard_usb_encap_control_request_cb cb;
    intptr_t ctx;
} secureboard_usb_encap_control_request_t;

typedef union secureboard_msg_tag {
    struct {
        uint8_t hdr[SECUREBOARD_MSG_HDR_LEN];
        uint8_t data[SECUREBOARD_MSG_MAX_LEN - SECUREBOARD_MSG_HDR_LEN];
    } __attribute__((packed));
    uint8_t raw[0];
} secureboard_msg_t;

typedef struct secureboard_wr_tqe_tag {
    TAILQ_ENTRY(secureboard_wr_tqe_tag) tailq;
    unsigned wr_pos;
    unsigned wr_len;
    secureboard_msg_t msg;
} secureboard_wr_tqe_t;

typedef struct secureboard_connection_tag {
    secureboard_connection_args_t args;
    int socket;
    int timer_fd;

    BIO *bio;
    SSL_CTX *ctx;
    SSL *con;

    BIO *bio_err;

    unsigned rd_pos;
    secureboard_msg_t rd_msg;

    TAILQ_HEAD(, secureboard_wr_tqe_tag) tx_head;
    TAILQ_HEAD(, secureboard_usb_encap_rx_object_tag) rx_head;
    secureboard_usb_encap_control_request_t *pending_ctrl_request;
} secureboard_connection_t;

void secureboard_print_errors(secureboard_connection_t *sb);
void secureboard_printf(secureboard_connection_t *sb, const char *format, ...);
int secureboard_arm_timer(secureboard_connection_t *sb, unsigned seconds, unsigned ms);
int secureboard_disarm_timer(secureboard_connection_t *sb);

#endif
