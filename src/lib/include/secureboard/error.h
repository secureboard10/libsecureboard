#ifndef LIB_SECUREBOARD_ERROR_H
#define LIB_SECUREBOARD_ERROR_H

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
 * \brief Error definitions
 */

#ifdef __cplusplus
extern "C" {
#endif

    enum {
        SECUREBOARD_SUCCESS             =  0,       ///< Success
        SECUREBOARD_ERR_TIMEOUT         = -1,       ///< Operation timed out
        SECUREBOARD_ERR_INTR            = -2,       ///< Operation interrupted by an signal
        SECUREBOARD_ERR_HOSTSERV        = -3,       ///< Invalid hostserv string (host:service)
        SECUREBOARD_ERR_DNS_LOOKUP      = -4,       ///< Invalid hostserv string (host:service)
        SECUREBOARD_ERR_CONNECT         = -5,       ///< Unable to connect to relay daemon
        SECUREBOARD_ERR_NO_MEMORY       = -6,       ///< Out of memory
        SECUREBOARD_ERR_INTERNAL        = -7,       ///< Some internal error condition detected
        SECUREBOARD_ERR_SIGNAL          = -8,       ///< Signal received during blocking call
        SECUREBOARD_ERR_IO              = -9,       ///< IO Error
        SECUREBOARD_ERR_CLOSED          = -10,      ///< Server closed connection
        SECUREBOARD_ERR_CLOSE_TIMEOUT   = -11,      ///< Server did not close within its given timeout

        SECUREBOARD_ERR_ENCAP_STALL     = -100,     ///< USB Enacapsulation received a stall
        SECUREBOARD_ERR_ENCAP_BUSY      = -101,     ///< USB Enacapsulation Busy
        SECUREBOARD_ERR_ENCAP_RXOV      = -102,     ///< USB RX Overflow
        SECUREBOARD_ERR_ENCAP_TXOV      = -103,     ///< USB TX Overflow
        SECUREBOARD_ERR_ENCAP_DIRECTION = -104,     ///< Invalid EP direction given
        SECUREBOARD_ERR_ENCAP_EP        = -105,     ///< Invalid EP given
        SECUREBOARD_ERR_ENCAP_CANCEL    = -106,     ///< USB Control Request canceled

        SECUREBOARD_ERR_SSL             = -1000,    ///< SSL Operation Failed
    };

#ifdef __cplusplus
}
#endif

#endif
