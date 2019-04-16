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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include <libconfig.h>
#include <hidapi.h>

#include "udev.h"
#include "threads.h"
#include "sb-relayd.h"
#include "unix-socket.h"
#include "inet-socket.h"

#define SOCKET_NAME "/tmp/sb-socket"
#define DEFAULT_CONFIG_FILE "/etc/sb-relayd.conf"

static config_t *config = NULL;
static const char *serial = NULL;
static const char *config_file = NULL;

// global variables
static const char *device_node;
static const char *device_serial;
static config_t *config;
static atomic_bool terminate = ATOMIC_VAR_INIT(false);
static atomic_bool connected = ATOMIC_VAR_INIT(false);
static const socket_func_t *socket_func = NULL;
static socket_handle_t socket_handle = SOCKET_HANDLE_INVALID;
static pthread_t socket_to_device_thread;
static bool socket_to_device_thread_running = false;
//static pthread_t *device_to_socket_thread = NULL;
static hid_device *hid_dev = NULL;

__asm__(        ".section .rodata                        ;"
                "_license_start: .incbin \"" LICENSE "\" ;"
                "_license_end:                           ;");

extern char _license_start;
extern char _license_end;

static const socket_def_t socket_defs[] = {
#ifdef UNIX_SOCKET_H
    { .config_type = "unix",
      .functions = &unix_socket_functions,
    },
#endif
#ifdef INET_SOCKET_H
    { .config_type = "inet",
      .functions = &inet_socket_functions,
    },
#endif
    { .config_type = NULL,
      .functions = NULL,
    },
};

static void show_license(void)
{
    fwrite(&_license_start, &_license_end - &_license_start, 1, stdout);
}

static void usage(FILE *out, const char *cmd)
{
    char *_c = strdupa(cmd);
    _c = basename(_c);
    fprintf(out,
            "SYNOPSYS: %s [-c <config-file>] [-s <serial>]\n"
            "\t-c <config-file>        sb-relayd config file (default: %s)\n"
            "\t-s <serial>             SECUREBOARD1.0 serial to use (default: first device found)\n"
            "\t-l                      Print License information\n"
            "\t\n",
            _c, DEFAULT_CONFIG_FILE);
}

static int parse_options(int argc, char **argv)
{
    int c;

    while ((c = getopt(argc, argv, "c:s:hl")) != -1) {
        switch (c) {
        case 's':
            if (serial) {
                usage(stderr, argv[0]);
                fprintf(stderr, "error: -s option is given twice!");
                return -1;
            }
            serial = optarg;
            break;

        case 'c':
            if (config_file) {
                usage(stderr, argv[0]);
                fprintf(stderr, "error: -c option is given twice!");
                return -1;
            }
            config_file = optarg;
            break;

        case 'l':
            show_license();
            exit(0);

        case 'h':
            usage(stdout, argv[0]);
            return -2;

        default:
            usage(stderr, argv[0]);
            return -1;
        }
    }
    if (!config_file)
        config_file = DEFAULT_CONFIG_FILE;

    return 0;
}

static int load_config(void)
{
    config = malloc(sizeof(*config));
    config_init(config);
    if (config_read_file(config, config_file) == CONFIG_FALSE) {
        const char *cfile = config_error_file(config);
        if (cfile) {
            fprintf(stderr,
                    "sb-relayd: failed to read: %s %s:%d\n",
                    config_error_text(config),
                    cfile,
                    config_error_line(config));
        }
        else {
            fprintf(stderr,
                    "sb-relayd: failed to read '%s': %s\n",
                    config_file,
                    config_error_text(config));
        }
        return -1;
    }

    const char *version = NULL;
    if (config_lookup_string(config, "version", &version) == CONFIG_FALSE) {
        fprintf(stderr,
                "sb-relayd: version entry is missing or not a string in '%s'\n",
                config_file);
        return -1;
    }
    if (strcmp(version, "1.0")) {
        fprintf(stderr,
                "sb-relayd: invalid config version '%s'\n",
                version);
        return -1;
    }
    return 0;
}

static void exit_handler(int status, void *arg)
{
    if (socket_func && (socket_handle != SOCKET_HANDLE_INVALID)) {
        socket_func->destroy(socket_handle);
        socket_func = NULL;
        socket_handle = SOCKET_HANDLE_INVALID;
    }

    if (config) {
        config_destroy(config);
        free(config);
        config = NULL;
    }

    if (device_node) {
        free((void*)device_node);
        device_node = NULL;
    }

    if (device_serial) {
        free((void*)device_serial);
        device_serial = NULL;
    }

    if (hid_dev) {
        hid_close(hid_dev);
        hid_dev = NULL;
    }

    hid_exit();

    if (status) {
        fprintf(stderr, "sb-relayd: terminated with status %d\n", status);
    }
}

static void signal_handler(int signal)
{
    fprintf(stderr, "sb-relayd: signal cought %d\n", signal);

    // do not terminate on SIGPIPE
    if (signal != SIGPIPE) {
        atomic_store(&terminate, true);
    }

    if (socket_to_device_thread_running)
        pthread_cancel(socket_to_device_thread);
}

static void install_signal_handler(int signal, void (*handler)(int))
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sa.sa_flags = 0;
    (void)sigaction(signal, &sa, NULL);
}

static char *replace_substring(const char *in, const char *old, const char *rep)
{
    int sub_len = strlen(old);
    int rep_len = strlen(rep);

    const char *i = in;
    int cnt = 0;
    while ((i = strstr(i, old))) {
        cnt++;
        i += sub_len;
    }

    char *out = malloc(strlen(in) + (rep_len - sub_len) * cnt + 1);

    char *o = out;
    i = in;
    while (cnt) {
        const char *p;
        p = strstr(i, old);
        if (!p) {
            free(out);
            return NULL;
        }

        memcpy(o, i, p - i);
        o += p - i;
        i = p + sub_len;

        memcpy(o, rep, rep_len);
        o += rep_len;

        cnt--;
    }

    *o = '\0';
    return out;
}

char *config_replace_patterns(const char *in)
{
    if (!device_serial)
        return NULL;

    return replace_substring(in, "${serial}", device_serial);
}

int main(int argc, char **argv)
{
    int res;

    hid_init();

    // install exit handler
    on_exit(exit_handler, NULL);

    // install signal handler
    install_signal_handler(SIGINT, signal_handler);
    install_signal_handler(SIGQUIT, signal_handler);
    install_signal_handler(SIGTERM, signal_handler);
    install_signal_handler(SIGPIPE, signal_handler);

    res = parse_options(argc, argv);
    if (res) {
        if (res == -2) {
            return 0;
        }
        return 1;
    }

    res = load_config();
    if (res | !config) {
        return 1;
    }

    res = udev_get_secureboard_hid_path(serial,
                                        &device_node,
                                        &device_serial);
    if (res) {
        fprintf(stderr, "sb-relayd: failed to find SECUREBOARD1.0\n");
        return 1;
    }

    fprintf(stdout,
           "sb-relayd: found SECUREBOARD1.0 serial: %s, path: %s\n",
           device_serial, device_node);

    char config_path[64];
    memset(config_path, 0, sizeof(config_path));
    snprintf(config_path, sizeof(config_path) - 1, "secureboard/serial-%s", device_serial);

    config_setting_t *sb_config = NULL;
    sb_config = config_lookup(config, config_path);
    if (!sb_config) {
        fprintf(stderr,
                "sb-relayd: no configuration %s found, trying secureboard/default\n",
                config_path);

        sb_config = config_lookup(config, "secureboard/default");
    }

    if (!sb_config) {
        fprintf(stderr,
                "sb-relayd: failed to retrieve config for SECUREBOARD1.0 with serial %s\n",
                device_serial);
        return 1;
    }

    config_setting_t *sb_socket_config = config_setting_get_member(sb_config, "socket");
    if (!sb_socket_config) {
        fprintf(stderr,
                "sb-relayd: socket entry is missing for SECUREBOARD1.0 with serial %s\n",
                device_serial);
        return 1;
    }

    const char *socket_type;
    if (config_setting_lookup_string(sb_socket_config, "type", &socket_type) == CONFIG_FALSE) {
        fprintf(stderr,
                "sb-relayd: failed to retrieve socket type for SECUREBOARD1.0 with serial %s\n",
                device_serial);
        return 1;
    }

    const socket_def_t *socket_def = socket_defs;
    while (socket_def->config_type) {
        if (strcmp(socket_def->config_type, socket_type) == 0) {
            break;
        }
        socket_def++;
    }

    if (!socket_def->config_type) {
        fprintf(stderr,
                "sb-relayd: socket type: %s is not supported\n",
                socket_type);
        return 1;
    }

    socket_func = socket_def->functions;
    socket_handle = socket_func->create(sb_socket_config, device_serial);

    if (socket_handle == SOCKET_HANDLE_INVALID) {
        fprintf(stderr,
                "sb-relayd: failed to create socket: %s\n",
                strerror(errno));
        return 1;
    }

    while (!atomic_load(&terminate)) {
        int fd = socket_func->accept(socket_handle);
        if (fd < 0) {
            if (errno == EINTR) {
                continue;
            }

            fprintf(stderr,
                    "sb-relayd: failed to accept connection: %s",
                    strerror(errno));
            goto cleanup;
        }

        atomic_store(&connected, true);

        fprintf(stdout,
                "sb-relayd: remote host connected\n");

        hid_dev = hid_open_path(device_node);
        if (!hid_dev) {
            fprintf(stderr,
                    "sb-relayd: failed to connect to SECUREBOARD1.0: device_node %s; error: %s %p\n", device_node, strerror(errno), hid_dev);
            atomic_store(&terminate, true);
            goto cleanup;
        }

        int err;
        if ((err = start_socket_to_device_thread(&socket_to_device_thread,
                                                 fd,
                                                 hid_dev,
                                                 &connected,
                                                 &terminate))) {
            fprintf(stderr,
                    "sb-relayd: failed to create_thread: %s\n",
                    strerror(err));
            goto cleanup;
        }
        socket_to_device_thread_running = true;

  cleanup:
        if (socket_to_device_thread_running) {
            pthread_join(socket_to_device_thread, NULL);
            socket_to_device_thread_running = false;
        }

        if (hid_dev) {
            hid_close(hid_dev);
            hid_dev = NULL;
        }

        if (fd >= 0) {
            printf("closing\n");
            close(fd);
        }
    }

    socket_func->destroy(socket_handle);
    socket_handle = SOCKET_HANDLE_INVALID;

    return res;
}
