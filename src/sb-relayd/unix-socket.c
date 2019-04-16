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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "sb-relayd.h"
#include "unix-socket.h"

static socket_handle_t unix_socket_create(config_setting_t *config,
                                          const char *device_serial)
{
    int fd = -1;

    const char *socket_name;
    if (config_setting_lookup_string(config, "file", &socket_name) == CONFIG_FALSE) {
        fprintf(stderr,
                "sb-relayd: unix-socket failed to retrieve config item file for SECUREBOARD1.0 with serial %s\n",
                device_serial);
        errno = EINVAL;
        return SOCKET_HANDLE_INVALID;
    }

    socket_name = config_replace_patterns(socket_name);
    if (!socket_name){
        errno = EINVAL;
        return SOCKET_HANDLE_INVALID;
    }

    struct sockaddr_un name;
    memset(&name, 0, sizeof(struct sockaddr_un));
    name.sun_family = AF_UNIX;
    // use abstract namespace
    strncpy(name.sun_path + 1, socket_name, sizeof(name.sun_path) - 2);
    free((void*)socket_name);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return SOCKET_HANDLE_INVALID;

    if (bind(fd, (const struct sockaddr *) &name,
             strlen(name.sun_path + 1) + 3) < 0) {
        close(fd);
        return SOCKET_HANDLE_INVALID;
    }

    if (listen(fd, 1) < 0) {
        close(fd);
        return SOCKET_HANDLE_INVALID;
    }

    return (socket_handle_t)fd;
}

static int unix_socket_accept(socket_handle_t s)
{
    struct sockaddr_un name;
    memset(&name, 0, sizeof(struct sockaddr_un));
    name.sun_family = AF_UNIX;
    socklen_t len = sizeof(name);

    int fd = accept4((int)s, &name, &len, 0);
    return fd;
}

static void unix_socket_destroy(socket_handle_t s)
{
    close((int)s);
}

const socket_func_t unix_socket_functions = {
    .create = unix_socket_create,
    .accept = unix_socket_accept,
    .destroy = unix_socket_destroy,
};


