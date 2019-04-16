#ifndef SECUREBOARD_USB_ENCAP_H
#define SECUREBOARD_USB_ENCAP_H

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

/**
 * \file
 *
 * \brief Secure board USB encapsulation layer.
 */

#include <secureboard/connection.h>

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * \brief Result of a completed encapsulated request.
     */
    typedef enum {

        /**
         * \brief Request completed without errors.
         *
         * \param sb libsecureboard connection context
         *
         * \return Errorcode defined in error.h.
         */
        SECUREBOARD_USB_ENCAP_REQUEST_COMPLETE,

        /**
         * \brief SECURE BOARD 1.0 stalled the request.
         *
         * In most cases this means: *not supported by the firmware*.
         */
        SECUREBOARD_USB_ENCAP_REQUEST_STALL,

        /**
         * \brief REquest canceled by the application.
         *
         * \param sb libsecureboard connection context
         *
         * \return Errorcode defined in error.h.
         */
        SECUREBOARD_USB_ENCAP_REQUEST_CANCEL,
    } secureboard_usb_encap_control_request_result_t;

    // Note: if the status of the request is cancel than action has no
    // effect, resubmission of canceled requests is not supported.
    /**
     * \brief Action to take after completing the request.
     */
    typedef enum {
        /**
         * \brief Free resources.
         */
        SECUREBOARD_USB_ENCAP_EP_COMPLETE_DISPOSE_REQUEST,

        /**
         * \brief Resubmit (repeat) the request with the same
         * parameters as the current request.
         *
         * Resubmit is not possible for canceled requests. On cancel
         * the action is always
         * SECUREBOARD_USB_ENCAP_EP_COMPLETE_DISPOSE_REQUEST.
         */
        SECUREBOARD_USB_ENCAP_EP_COMPLETE_RESUBMIT_REQUEST,
    } secureboard_usb_encap_ep_complete_action_t;

    /**
     * \brief Receive handle for an RX request.
     */
    typedef struct secureboard_usb_encap_rx_object_tag secureboard_usb_encap_rx_object_t;

    /**
     * \brief Callback when completing a control request.
     *
     * \param data address of the received data if applicable.
     * \param len length of the received data applicable.
     * \param status result of the control request.
     * \param application context
     */
    typedef void
    (*secureboard_usb_encap_control_request_cb)(void *data,
                                                unsigned len,
                                                secureboard_usb_encap_control_request_result_t status,
                                                intptr_t ctx);

    /**
     * \brief Callback when completing a receive (IN) request.
     *
     * \param data address of the received data if applicable.
     * \param len length of the received data applicable.
     * \param ep on which the data was received
     * \param status result of the control request.
     * \param application context
     *
     * The function must return
     * SECUREBOARD_USB_ENCAP_EP_COMPLETE_DISPOSE_REQUEST if status
     * indicates SECUREBOARD_USB_ENCAP_REQUEST_CANCEL.
     *
     * \return Dispose action.
     */
    typedef secureboard_usb_encap_ep_complete_action_t
    (*secureboard_usb_encap_rx_ep_request_cb)(void *data,
                                              unsigned len,
                                              uint8_t ep,
                                              secureboard_usb_encap_control_request_result_t status,
                                              intptr_t ctx);

    /**
     * \brief Start a control request.
     *
     * If timeout_sec is Zero, the call never blocks. If timeout_sec
     * is not Zero the function blocks.
     *
     * \param sb libsecureboard connection context.
     * \param bmRequestType USB request type
     * \param bRequest USB request.
     * \param wValue depends on bRequest and bmRequestType.
     * \param wIndex depends on bRequest and bmRequestType.
     * \param wLength length of data for OUT requests. Maximum
     *        length of data to be received for IN requests.
     * \param data data location to read/write depending on the direction
     * \param timeout_sec timeout of the request.
     * \param cb completion callback.
     * \param ctx application context.
     *
     * \return Errorcode defined in error.h.
     */
    int secureboard_usb_encap_control_request(secureboard_connection_t *sb,
                                              uint8_t bmRequestType,
                                              uint8_t bRequest,
                                              uint16_t wValue,
                                              uint16_t wIndex,
                                              uint16_t wLength,
                                              void *data,
                                              unsigned timeout_sec,
                                              secureboard_usb_encap_control_request_cb cb,
                                              intptr_t ctx);

    /**
     * \brief Waits up to timeout_sec seconds for the current control request to be completed.
     *
     * \param sb libsecureboard connection context
     * \param timeout_sec timeout of the request.
     *
     * \return Errorcode defined in error.h.
     */
    int secureboard_usb_encap_control_request_wait_complete(secureboard_connection_t *sb, unsigned timeout_sec);

    /**
     * \brief Submit a receive request.
     *
     * Once data matching the request is received, the library calls
     * the callback and disposes the structures depending on the
     * return code of the callback.
     *
     * \param sb libsecureboard connection context
     * \param ep on which to listen.
     * \param data buffer for received data.
     * \param length of the data.
     * \param cb completion callback.
     * \param ctx application context.
     * \param[out] request_object handle. May be NULL.
     *
     * \return Errorcode defined in error.h.
     */
    int secureboard_usb_encap_submit_rx_request(secureboard_connection_t *sb,
                                                uint8_t ep,
                                                void *data,
                                                unsigned length,
                                                secureboard_usb_encap_rx_ep_request_cb cb,
                                                intptr_t ctx,
                                                secureboard_usb_encap_rx_object_t **request_object);

    /**
     * \brief Check it rx requests are pending.
     *
     * \param sb libsecureboard connection context
     *
     * \return true if rx is pending, false if not.
     */
    bool secureboard_usb_encap_rx_pending(secureboard_connection_t *sb);

    /**
     * \brief Check it tx requests are pending.
     *
     * \param sb libsecureboard connection context
     *
     * \return true if tx is pending, false if not.
     */
    bool secureboard_usb_encap_tx_pending(secureboard_connection_t *sb);

    /**
     * \brief Process as many rx items as possible.
     *
     * \param sb libsecureboard connection context
     * \param[out] wants indicates which IO states make it necessary
     *             calling the function again.
     *
     * \return Errorcode defined in error.h.
     */
    int secureboard_usb_encap_do_read(secureboard_connection_t *sb,
                                      secureboard_connnection_io_wants_t *wants);

    /**
     * \brief Process as many tx items as possible.
     *
     * \param sb libsecureboard connection context
     * \param[out] wants indicates which IO states make it necessary
     *             calling the function again.
     *
     * \return Errorcode defined in error.h.
     */
    int secureboard_usb_encap_do_write(secureboard_connection_t *sb,
                                       secureboard_connnection_io_wants_t *wants);

    /**
     * \brief Process as many rx and tx items as possible.
     *
     * \param sb libsecureboard connection context
     * \param[out] wants indicates which IO states make it necessary
     *             calling the function again.
     *
     * \return Errorcode defined in error.h.
     */
    int secureboard_usb_encap_do_io(secureboard_connection_t *sb,
                                    secureboard_connnection_io_wants_t *wants);

    /**
     * \brief Cancel the ongoing control request.
     *
     * If the request is canceled the callback is called and
     * SECUREBOARD_USB_ENCAP_REQUEST_CANCEL is indicated.
     *
     * \param sb libsecureboard connection context
     *
     * \return Errorcode defined in error.h.
     */
    void secureboard_usb_encap_control_request_cancel(secureboard_connection_t *sb);

    /**
     * \brief Cancel the ongoing rx request.
     *
     * If the request is canceled the callback is called and
     * SECUREBOARD_USB_ENCAP_REQUEST_CANCEL is indicated.
     *
     * \param sb libsecureboard connection context
     * \param request_object to cancel.
     *
     * \return Errorcode defined in error.h.
     */
    void secureboard_usb_encap_rx_ep_request_cancel(secureboard_connection_t *sb,
                                                    secureboard_usb_encap_rx_object_t *request_object);

    /**
     * \brief Cancel the ongoing requesta.
     *
     * For each canceled request´the callback is called and
     * SECUREBOARD_USB_ENCAP_REQUEST_CANCEL is indicated.
     *
     * \param sb libsecureboard connection context
     *
     * \return Errorcode defined in error.h.
     */
    void secureboard_usb_encap_cancel_all(secureboard_connection_t *sb);


#ifdef __cplusplus
}
#endif


#endif
