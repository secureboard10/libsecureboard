#ifndef LIB_SECUREBOARD_H
#define LIB_SECUREBOARD_H

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
 * \mainpage libsecureboard API documentation
 *
 * \section INTRO Introduction
 *
 * libsecureboard wraps around openssl to connect to a Cherry SECURE
 * BOARD 1.0 devices. The link between Linux sockets and USB is built
 * by a separate tool called relay daemon. The relay daemon has to be
 * started on the host that is physically connected to the SECURE
 * BOARD 1.0.
 *
 * libsecure board on the other hand can run on any host that is able
 * to connect to the relay daemon using TCP sockets.
 *
 * \section PHILOSOPHY API Philosophy
 *
 * The API is built to mimic USB devices. This eases future extensions
 * and moving device specific functions out of libsecureboard and into
 * more specific application code.
 *
 * A good point to start is by looking at the example \ref
 * demo/secureboard.c.
 *
 * \subsection BLOCKS libsecureboard building blocks
 *
 * Currently libsecureboard consists three major parts.
 *
 * 1. secureboard_library:
 *
 *    These functions provide support library identification and
 *    version management.
 *
 * 2. secureboard_con:
 *
 *    These functions are uses for connection managmenet.
 *
 * 3. secureboard_usb_encap:
 *
 *    These function provide encapsulation support for device protocol
 *    messages, like control request.
 *
 *    Note: USB reset is 'virtually' executed after completing the
 *    handshake.
 *
 * \subsection IO libsecureboard IO
 *
 * libsecureboard uses non-blocking io. Most calls never block. If
 * they need to a timeout parameter is used, and the library blocks
 * using poll(2). Timeouts are implemented using timerfd_create(2).
 *
 * Non-blocking calls return information when to function should be
 * called again. This can be either if data is available for read or
 * data can be written to the under-laying file descriptors.
 *
 * To avoid busy loops the application SHOULD only call the
 * corresponding IO function if on of the returned condition is met.
 *
 * \subsection THREAD libsecureboard Thread safety
 *
 * The library is *NOT* thread safe.
 *
 * \section PROTOCOL Low Level Protocol Description
 *
 * \todo Add Protocol description.
 */

/**
 * \file
 *
 * \brief Application include concentrator and general functions.
 */

#include <openssl/ssl.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * \brief Opaque libsecureboard context
 */
typedef struct secureboard_connection_tag secureboard_connection_t;

#include <secureboard/connection.h>
#include <secureboard/error.h>
#include <secureboard/usb_encap.h>
#include <secureboard/usb.h>

#ifdef ALLOW_LIB_SECUREBOARD_INTERNAL
#include "../../internal/secureboard.h"
#endif

/**
 * \brief Constant storing the library version.
*/
extern const uint8_t secureboard_library_version[4];

/**
 * \brief Returns the library version as string.
 *
 * \return Library version string
 */
const char *secureboard_library_version_string();

/**
 * \brief Print License to stdout
 *
 * \return Library version string
 */
void secureboard_library_show_license(void);

#endif
