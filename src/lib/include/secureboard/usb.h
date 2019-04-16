#ifndef SECUREBOARD_USB_H
#define SECUREBOARD_USB_H

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
 * \brief USB Encapsulation Wrapper functions
 */

#include <secureboard/connection.h>

#ifdef __cplusplus
extern "C" {
#endif
    #ifndef SECUREBOARD_CONTROL_REQUEST_TIMEOUT
    /**
     * \brief Default timeout for wrapped control requests.
     */
    #define SECUREBOARD_CONTROL_REQUEST_TIMEOUT 5
    #endif

    /**
     * \brief USB Device Descriptor returned by SECURE BOARDs 1.0
     */
    typedef struct {
        /**
         * \brief Overall length of the descriptor
         */
        uint8_t  bLength;
        /**
         * \brief Descriptor Type. Always 1 for device descriptors
         */
        uint8_t  bDescriptorType;
        /**
         * \brief USB version
         */
        uint16_t bcdUSB;
        /**
         * \brief USB Device Class
         */
        uint8_t  bDeviceClass;
        /**
         * \brief USB Device Sub Class
         */
        uint8_t  bDeviceSubClass;
        /**
         * \brief USB Device Protocol
         */
        uint8_t  bDeviceProtocol;
        /**
         * \brief EP0 Packet size (can be ignored)
         */
        uint8_t  bMaxPacketSize0;
        /**
         * \brief USB VID
         */
        uint16_t idVendor;
        /**
         * \brief USB PID
         */
        uint16_t idProduct;
        /**
         * \brief Device Version
         */
        uint16_t bcdDevice;
        /**
         * \brief Manufacturer string index
         */
        uint8_t  iManufacturer;
        /**
         * \brief Product string Index
         */
        uint8_t  iProduct;
        /**
         * \brief Serialnumber string index
         */
        uint8_t  iSerialNumber;
        /**
         * \brief Number of configurations (multiple configuration are not yet implemented).
         */
        uint8_t  bNumConfigurations;
    } __attribute__((packed)) secureboard_usb_device_descriptor_t;

    /**
     * \brief Version information returned by the device.
     */
    typedef struct {
        /**
         * \brief Major Revision
         */
        uint8_t maj_rev;
        /**
         * \brief Major Version
         */
        uint8_t maj;
        /**
         * \brief Minor Version
         */
        uint8_t min;
        /**
         * \brief Patch Number
         */
        uint8_t nr;
    } __attribute__((packed)) secureboard_fw_version_t;

    /**
     * \brief Relevant USB specific constants for SECURE BOARDs 1.0
     */
    enum {
        SECUREBOARD_REQTYPE_HOST_TO_DEVICE = 0x00,
        SECUREBOARD_REQTYPE_DEVICE_TO_HOST = 0x80,

        SECUREBOARD_REQTYPE_STANDARD       = 0x00,
        SECUREBOARD_REQTYPE_CLASS          = 0x20,
        SECUREBOARD_REQTYPE_VENDOR         = 0x40,

        SECUREBOARD_REQTYPE_DEVICE         = 0x00,
        SECUREBOARD_REQTYPE_INTERFACE      = 0x01,
        SECUREBOARD_REQTYPE_ENDPOINT       = 0x02,
        SECUREBOARD_REQTYPE_OTHER          = 0x03,

        SECUREBOARD_STD_REQ_GET_STATUS         = 0x00, // not supported by Secure Board
        SECUREBOARD_STD_REQ_CLEAR_FEATURE      = 0x01, // not supported by Secure Board
        SECUREBOARD_STD_REQ_SET_FEATURE        = 0x03, // not supported by Secure Board
        SECUREBOARD_STD_REQ_SET_ADDRESS        = 0x05, // not supported by Secure Board
        SECUREBOARD_STD_REQ_GET_DESCRIPTOR     = 0x06,
        SECUREBOARD_STD_REQ_SET_DESCRIPTOR     = 0x07, // not supported by Secure Board
        SECUREBOARD_STD_REQ_GET_CONFIGURATION  = 0x08, // not supported by Secure Board
        SECUREBOARD_STD_REQ_SET_CONFIGURATION  = 0x09, // not supported by Secure Board

        SECUREBOARD_VEN_DEV_REQ_GET_FW_VERSION    = 0x00,
        SECUREBOARD_VEN_INT_REQ_SET_RUNNING       = 0x00,
        SECUREBOARD_VEN_INT_REQ_SET_USER_CERT     = 0x01,
        SECUREBOARD_VEN_INT_REQ_SET_USER_PRIV_KEY = 0x02,
        SECUREBOARD_VEN_INT_REQ_SET_USER_ROOT_CA  = 0x03,
        SECUREBOARD_CLS_INT_REQ_SET_REPORT        = 0x09, // HID set report
    };

    /**
     * \brief Callback context used by secureboard_usb wrapper functions.
     */
    typedef struct {
        /**
         * \brief Result of the USB encapsulation request.
         */
        secureboard_usb_encap_control_request_result_t status;
        /**
         * \brief Length of the received data, or 0 if not applicable.
         */
        unsigned length;
    } secureboard_usb_control_request_callback_context_t;

    /**
     * \brief Callback function used by secure board wrapper functions.
     *
     * \param data address of where the payload data is stored to.
     * \param len stored the length of the payload data if applicable.
     * \param status stores the result of the USB encapsulation request.
     * \param ctx is the application context of the request.
     */
    void secureboard_usb_control_request_callback(void *data,
                                                  unsigned len,
                                                  secureboard_usb_encap_control_request_result_t status,
                                                  intptr_t ctx);

    /**
     * \brief Converts the result of an USB encapsulation request into
     *        a single return code, usefull by the application.
     *
     * \param res is the result of the corresponding secureboard_usb_encap_control_request.
     * \param ctx is the context of the request
     *
     * \return negative on error, and length of the result on success.
     */
    static inline int secureboard_usb_status_to_result(int res, secureboard_usb_control_request_callback_context_t *ctx)
    {
        if (res != SECUREBOARD_SUCCESS)
            return res;

        switch (ctx->status) {
            case SECUREBOARD_USB_ENCAP_REQUEST_COMPLETE:
                return ctx->length;
            case SECUREBOARD_USB_ENCAP_REQUEST_STALL:
                return SECUREBOARD_ERR_ENCAP_STALL;
            case SECUREBOARD_USB_ENCAP_REQUEST_CANCEL:
                return SECUREBOARD_ERR_ENCAP_CANCEL;
            default:
                return SECUREBOARD_ERR_INTERNAL;
        }
    }

    /**
     * \brief Retreive the Device Descriptor
     *
     * \param sb secure board connection used
     * \param[out] device_descriptor application memory for the result
     *
     * \return negative on error, and length of the result on success.
     */
    static inline int secureboard_usb_get_device_descriptor(secureboard_connection_t *sb,
                                                            secureboard_usb_device_descriptor_t *device_descriptor)
    {
        secureboard_usb_control_request_callback_context_t ctx;
        int res = secureboard_usb_encap_control_request(sb,
                                                        SECUREBOARD_REQTYPE_DEVICE_TO_HOST |
                                                        SECUREBOARD_REQTYPE_STANDARD |
                                                        SECUREBOARD_REQTYPE_DEVICE,
                                                        SECUREBOARD_STD_REQ_GET_DESCRIPTOR,
                                                        0x0100, // DEVICE_DESCRIPTOR | Index 0
                                                        0x0000,
                                                        sizeof(*device_descriptor),
                                                        device_descriptor,
                                                        SECUREBOARD_CONTROL_REQUEST_TIMEOUT,
                                                        secureboard_usb_control_request_callback,
                                                        (intptr_t)&ctx);
        return secureboard_usb_status_to_result(res, &ctx);
    }

    /**
     * \brief Retreive the Configuration Descriptor
     *
     * \param sb secure board connection used
     * \param[out] configuration_descriptor application memory for the result
     * \param configuration_descriptor_len size of the application allocated memory
     *
     * \return negative on error, and length of the result on success.
     */
    static inline int secureboard_usb_get_configuration_descriptor(secureboard_connection_t *sb,
                                                                   uint8_t *configuration_descriptor,
                                                                   unsigned configuration_descriptor_len)
    {
        secureboard_usb_control_request_callback_context_t ctx;
        int res = secureboard_usb_encap_control_request(sb,
                                                        SECUREBOARD_REQTYPE_DEVICE_TO_HOST |
                                                        SECUREBOARD_REQTYPE_STANDARD |
                                                        SECUREBOARD_REQTYPE_DEVICE,
                                                        SECUREBOARD_STD_REQ_GET_DESCRIPTOR,
                                                        0x0200, // CONFIGURATION_DESCRIPTOR | Index 0
                                                        0x0000,
                                                        configuration_descriptor_len,
                                                        configuration_descriptor,
                                                        SECUREBOARD_CONTROL_REQUEST_TIMEOUT,
                                                        secureboard_usb_control_request_callback,
                                                        (intptr_t)&ctx);
        return secureboard_usb_status_to_result(res, &ctx);
    }

    /**
     * \brief Retreive the firmaware version of the SECURE BOARD 1.0
     *
     * \param sb secure board connection used
     * \param[out] fw_version application memory for the result
     *
     * \return negative on error, and length of the result on success.
     */
    static inline int secureboard_usb_get_fw_version(secureboard_connection_t *sb,
                                                     secureboard_fw_version_t *fw_version)
    {
        secureboard_usb_control_request_callback_context_t ctx;
        int res = secureboard_usb_encap_control_request(sb,
                                                        SECUREBOARD_REQTYPE_DEVICE_TO_HOST |
                                                        SECUREBOARD_REQTYPE_VENDOR |
                                                        SECUREBOARD_REQTYPE_DEVICE,
                                                        SECUREBOARD_VEN_DEV_REQ_GET_FW_VERSION,
                                                        0x0000,
                                                        0x0000,
                                                        sizeof(*fw_version),
                                                        fw_version,
                                                        SECUREBOARD_CONTROL_REQUEST_TIMEOUT,
                                                        secureboard_usb_control_request_callback,
                                                        (intptr_t)&ctx);
        return secureboard_usb_status_to_result(res, &ctx);
    }

    /**
     * \brief Set the running mode of SECURE BOARDs 1.0
     *
     * When the device is in running mode it begins to send reports on
     * its virtual endpoints. Reports are generated when the keyboard
     * state changes. (See USB HID 1.1) All reports are formatted
     * exactly as in normal mode.
     *
     * If a SECURE BOARD switches to running, it also enforces to send
     * a single report to report its current state. This obsoletes the
     * RET_REPORT request.
     *
     * \param sb secure board connection used.
     * \param interface is the target interface.
     * \param running new state.
     * \param[out] device_descriptor application memory for the result
     *
     * \return negative on error, and length of the result on success.
     */
    static inline int secureboard_usb_set_running(secureboard_connection_t *sb,
                                                  unsigned interface,
                                                  bool running)
    {
        secureboard_usb_control_request_callback_context_t ctx;
        int res = secureboard_usb_encap_control_request(sb,
                                                        SECUREBOARD_REQTYPE_HOST_TO_DEVICE |
                                                        SECUREBOARD_REQTYPE_VENDOR |
                                                        SECUREBOARD_REQTYPE_INTERFACE,
                                                        SECUREBOARD_VEN_INT_REQ_SET_RUNNING,
                                                        running ? 1 : 0,
                                                        interface,
                                                        0,
                                                        NULL,
                                                        SECUREBOARD_CONTROL_REQUEST_TIMEOUT,
                                                        secureboard_usb_control_request_callback,
                                                        (intptr_t)&ctx);
        return secureboard_usb_status_to_result(res, &ctx);
    }

    /**
     * \brief Set the current led state (CAPS, NUM)
     *
     * \param sb secure board connection used
     * \param interface is the target interface.
     * \param led is the new led state.
     *
     * \return negative on error, and length of the result on success.
     */
    static inline int secureboard_usb_set_led_report(secureboard_connection_t *sb,
                                                     unsigned interface,
                                                     uint8_t led)
    {
        secureboard_usb_control_request_callback_context_t ctx;
        int res = secureboard_usb_encap_control_request(sb,
                                                        SECUREBOARD_REQTYPE_HOST_TO_DEVICE |
                                                        SECUREBOARD_REQTYPE_CLASS |
                                                        SECUREBOARD_REQTYPE_INTERFACE,
                                                        SECUREBOARD_CLS_INT_REQ_SET_REPORT,
                                                        0,
                                                        interface,
                                                        sizeof(led),
                                                        &led,
                                                        SECUREBOARD_CONTROL_REQUEST_TIMEOUT,
                                                        secureboard_usb_control_request_callback,
                                                        (intptr_t)&ctx);
        return secureboard_usb_status_to_result(res, &ctx);
    }

    /**
     * \brief Initialize the device user certificate of a SECURE BOARD 1.0
     *
     * The device certificate needs to be DER encoded, with a public
     * key SECURE BOARDS can handle. The supported signature format is
     * ECDSA with SHA256, over the Curve prime256v1 (NIST P-256).
     *
     * \param sb secure board connection used.
     * \param interface is the target interface.
     * \param running new state.
     * \param[out] device_descriptor application memory for the result
     *
     * \return negative on error, and length of the result on success.
     */
    static inline int secureboard_usb_set_user_root_ca(secureboard_connection_t *sb,
                                                       unsigned interface,
                                                       void *cert,
                                                       int len)
    {
        secureboard_usb_control_request_callback_context_t ctx;
        int res = secureboard_usb_encap_control_request(sb,
                                                        SECUREBOARD_REQTYPE_HOST_TO_DEVICE |
                                                        SECUREBOARD_REQTYPE_VENDOR |
                                                        SECUREBOARD_REQTYPE_INTERFACE,
                                                        SECUREBOARD_VEN_INT_REQ_SET_USER_ROOT_CA,
                                                        0,
                                                        interface,
                                                        len,
                                                        cert,
                                                        SECUREBOARD_CONTROL_REQUEST_TIMEOUT,
                                                        secureboard_usb_control_request_callback,
                                                        (intptr_t)&ctx);
        return secureboard_usb_status_to_result(res, &ctx);
    }

    /**
     * \brief Initialize the device user certificate of a SECURE BOARD 1.0
     *
     * The device certificate needs to be DER encoded, with a public
     * key SECURE BOARDS can handle. The supported signature format is
     * ECDSA with SHA256, over the Curve prime256v1 (NIST P-256).
     *
     * \param sb secure board connection used.
     * \param interface is the target interface.
     * \param running new state.
     * \param[out] device_descriptor application memory for the result
     *
     * \return negative on error, and length of the result on success.
     */
    static inline int secureboard_usb_set_user_cert(secureboard_connection_t *sb,
                                                    unsigned interface,
                                                    void *cert,
                                                    int len)
    {
        secureboard_usb_control_request_callback_context_t ctx;
        int res = secureboard_usb_encap_control_request(sb,
                                                        SECUREBOARD_REQTYPE_HOST_TO_DEVICE |
                                                        SECUREBOARD_REQTYPE_VENDOR |
                                                        SECUREBOARD_REQTYPE_INTERFACE,
                                                        SECUREBOARD_VEN_INT_REQ_SET_USER_CERT,
                                                        0,
                                                        interface,
                                                        len,
                                                        cert,
                                                        SECUREBOARD_CONTROL_REQUEST_TIMEOUT,
                                                        secureboard_usb_control_request_callback,
                                                        (intptr_t)&ctx);
        return secureboard_usb_status_to_result(res, &ctx);
    }

    /**
     * \brief Initialize the device user private key of a SECURE BOARD 1.0
     *
     * The privte key is a bignum (big endian) used to sign handshake
     * data along with the user certificate. It therefor must be over
     * the Curve prime256v1 (NIST P-256).
     *
     * \param sb secure board connection used.
     * \param interface is the target interface.
     * \param running new state.
     * \param[out] device_descriptor application memory for the result
     *
     * \return negative on error, and length of the result on success.
     */
    static inline int secureboard_usb_set_user_private_key(secureboard_connection_t *sb,
                                                           unsigned interface,
                                                           void *user_priv_key,
                                                           int len)
    {
        secureboard_usb_control_request_callback_context_t ctx;
        int res = secureboard_usb_encap_control_request(sb,
                                                        SECUREBOARD_REQTYPE_HOST_TO_DEVICE |
                                                        SECUREBOARD_REQTYPE_VENDOR |
                                                        SECUREBOARD_REQTYPE_INTERFACE,
                                                        SECUREBOARD_VEN_INT_REQ_SET_USER_PRIV_KEY,
                                                        0,
                                                        interface,
                                                        len,
                                                        user_priv_key,
                                                        SECUREBOARD_CONTROL_REQUEST_TIMEOUT,
                                                        secureboard_usb_control_request_callback,
                                                        (intptr_t)&ctx);
        return secureboard_usb_status_to_result(res, &ctx);
    }
#ifdef __cplusplus
}
#endif

#endif
