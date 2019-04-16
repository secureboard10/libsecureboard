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

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sb-relayd.h"
#include "inet-socket.h"

static socket_handle_t inet_socket_create(config_setting_t *config,
                                          const char *device_serial)
{
    int fd = -1;

    const char *bind_addr;
    if (config_setting_lookup_string(config, "bind", &bind_addr) == CONFIG_FALSE) {
        fprintf(stderr,
                "sb-relayd: inet-socket failed to retrieve config item bind for SECUREBOARD1.0 with serial %s\n",
                device_serial);
        errno = EINVAL;
        return SOCKET_HANDLE_INVALID;
    }
    int port;
    if (config_setting_lookup_int(config, "port", &port) == CONFIG_FALSE) {
        fprintf(stderr,
                "sb-relayd: inet-socket failed to retrieve config item port for SECUREBOARD1.0 with serial %s\n",
                device_serial);
        errno = EINVAL;
        return SOCKET_HANDLE_INVALID;
    }

    if ((port > 65535) || (port <= 0)) {
        fprintf(stderr,
                "sb-relayd: inet-socket invalid port number %d for SECUREBOARD1.0 with serial %s\n",
                port,
                device_serial);
        errno = EINVAL;
        return SOCKET_HANDLE_INVALID;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(bind_addr);
    addr.sin_port = htons(port);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return SOCKET_HANDLE_INVALID;

    if (bind(fd, (const struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(fd);
        return SOCKET_HANDLE_INVALID;
    }

    if (listen(fd, 1) < 0) {
        close(fd);
        return SOCKET_HANDLE_INVALID;
    }

    return (socket_handle_t)fd;
}

static int inet_socket_accept(socket_handle_t s)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    socklen_t len = sizeof(addr);

    int fd = accept4((int)s, &addr, &len, 0);
    fprintf(stdout,
            "sb-relayd: accepted connection from %s\n", inet_ntoa(addr.sin_addr));
    return fd;
}

static void inet_socket_destroy(socket_handle_t s)
{
    close((int)s);
}

const socket_func_t inet_socket_functions = {
    .create = inet_socket_create,
    .accept = inet_socket_accept,
    .destroy = inet_socket_destroy,
};


