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
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#include <hidapi.h>

#include "sb-relayd.h"
#include "threads.h"

int start_device_to_socket_thread(pthread_t *thread,
                                  int fd,
                                  hid_device *hid_dev,
                                  pthread_t socket_to_device_thread);

static const uint8_t cancel_record[7] = {
    // 0xFE == control record, 0x0303 Protocol, 2 Bytes
    0xfe, 0x03, 0x03, 0x00, 0x02,
    // Len = 0, Command = 0 (cancel)
    0x00, 0x00,
};

typedef struct {
    int fd;
    hid_device *hid_dev;
} socket_to_device_thread_args_t;

typedef struct {
    int fd;
    hid_device *hid_dev;
    pthread_t socket_to_device_thread;
} device_to_socket_thread_args_t;

static int hid_transmit_record(hid_device *hid_dev, const uint8_t *record)
{
    const unsigned len = 5 + ((((unsigned)record[3]) << 8) | record[4]);
    uint8_t b[65];
    unsigned pos;
    b[0] = 0;
    for (pos = 0; pos < len; pos += 64) {
        unsigned remain = len - pos;
        if (remain > 64)
            remain = 64;

        // copy data and pad
        memcpy(&b[1], record + pos, remain);
        memset(&b[1 + remain], 0xff, 64 - remain);

        // Failed to communicate with device -> terminate
        if (hid_write(hid_dev, b, sizeof(b)) < 0) {
            fprintf(stderr, "sb-relayd: failed to communicate with device.\n");
            return -1;
        }
    }
    return 0;
}

static void socket_to_device_thread_cancel_connection(void *a)
{
    socket_to_device_thread_args_t *args = a;
    hid_transmit_record(args->hid_dev, cancel_record);
}

static void socket_to_device_join_device_to_socket_thread(void *a)
{
    pthread_cancel(*(pthread_t*)a);
    pthread_join(*(pthread_t*)a, NULL);
}

static void *socket_to_device_thread(void *a)
{
    socket_to_device_thread_args_t *args = a;
    int oldstate;

    pthread_cleanup_push(socket_to_device_thread_cancel_connection, a);

    if (pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &oldstate)) {
        fprintf(stderr, "sb-relayd: pthread_setcanceltype failed\n");
        goto done1;
    }

    if (hid_transmit_record(args->hid_dev, cancel_record)) {
        goto done1;
    }

    static pthread_t device_to_socket_thread;
    if (start_device_to_socket_thread(&device_to_socket_thread, args->fd, args->hid_dev, pthread_self())) {
        goto done1;
    }
    pthread_cleanup_push(socket_to_device_join_device_to_socket_thread, &device_to_socket_thread);

    while (1) {
        if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate)) {
            fprintf(stderr,
                    "sb-relayd: pthread_setcancelstate failed\n");
            goto done2;
        }

        unsigned pos = 0;
        unsigned bytes_remain = 5;
        uint8_t record[1024];
        while (bytes_remain != 0) {
            int res = read(args->fd, record + pos, bytes_remain);
            if (res < 0) {
                if (errno == EINTR)
                    continue;

                fprintf(stderr, "sb-relayd: failed to read from socket\n");
                goto done2;
            }
            else if (res == 0) {
                // connection closed
                fprintf(stdout,
			"sb-relayd: remote connection closed\n");
                goto done2;
            }

            bytes_remain -= res;
            pos += res;

            if (pos == 5) {
                unsigned len = (((unsigned)record[3]) << 8) | record[4];
                bytes_remain += len;
                if (bytes_remain > (sizeof(record) - pos)) {
                    fprintf(stderr,
                            "sb-relayd: rx overflow from socket\n");
                    goto done2;
                }
            }
        }

        if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate)) {
            fprintf(stderr,
                    "sb-relayd: pthread_setcancelstate failed\n");
            goto done2;
        }

        if (hid_transmit_record(args->hid_dev, record)) {
            goto done2;
        }
    }

done2:
    pthread_cleanup_pop(1);
done1:
    pthread_cleanup_pop(1);
    return NULL;
}

static void device_to_socket_thread_cleanup(void *a)
{
    device_to_socket_thread_args_t *args = a;
    pthread_cancel(args->socket_to_device_thread);
}

static void *device_to_socket_thread(void *a)
{
    device_to_socket_thread_args_t *args = a;
    int oldstate;
    pthread_cleanup_push(device_to_socket_thread_cleanup, a);

    if (pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &oldstate)) {
        fprintf(stderr, "sb-relayd: pthread_setcanceltype failed\n");
        goto done;
    }

    if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate)) {
        fprintf(stderr,
                "sb-relayd: pthread_setcancelstate failed\n");
        goto done;
    }

    while (1) {
        unsigned pos = 0;
        unsigned bytes_remain = 5;
        uint8_t record[1024];
        uint8_t report[64];

        while (pos < bytes_remain) {
            int res = hid_read(args->hid_dev, report, sizeof(report));
            if (res < 0) {
                if (errno == EINTR)
                    continue;

                fprintf(stderr, "sb-relayd: failed to read from socket\n");
                goto done;
            }
            else if (res == 0) {
                fprintf(stderr, "sb-relayd: hid_read timed out\n");
                goto done;
            }

            // compute the total record length when reading the first packet
            if (pos == 0) {
                unsigned len = (((unsigned)report[3]) << 8) | report[4];
                bytes_remain += len;
            }

            if (bytes_remain > (sizeof(record) - pos)) {
                fprintf(stderr,
                        "sb-relayd: rx_overflow from device\n");
                goto done;
            }

            unsigned bytes_to_copy = bytes_remain;
            if (bytes_to_copy > (sizeof(report))) {
                bytes_to_copy = sizeof(report);
            }

            memcpy(&record[pos], &report[0], bytes_to_copy);
            pos += bytes_to_copy;
            bytes_remain -= bytes_to_copy;
        }

        unsigned len = pos;
        for (pos = 0; pos < len;) {
            int wr = write(args->fd, &record[pos], len - pos);
            if (wr < 0) {
                if (errno == EINTR)
                    continue;
                fprintf(stderr,
                        "sb-relayd: transmit to remote host failed\n");
                goto done;
            }
            if (wr == 0) {
                // connection closed
                fprintf(stdout,
			"sb-relayd: remote connection closed\n");
                goto done;
            }
            pos += wr;
        }
    }

done:
    pthread_cleanup_pop(1);
    return NULL;
}

int start_device_to_socket_thread(pthread_t *thread,
                                  int fd,
                                  hid_device *hid_dev,
                                  pthread_t socket_to_device_thread)
{
    static device_to_socket_thread_args_t args;

    args.fd = fd;
    args.hid_dev = hid_dev;
    args.socket_to_device_thread = socket_to_device_thread;
    return pthread_create(thread, NULL, device_to_socket_thread, &args);
}

int start_socket_to_device_thread(pthread_t *thread,
                                  int fd,
                                  hid_device *hid_dev,
                                  atomic_bool *connected,
                                  atomic_bool*terminate)
{
    int res;
    static socket_to_device_thread_args_t args;

    args.fd = fd;
    args.hid_dev = hid_dev;
    res = pthread_create(thread, NULL, socket_to_device_thread, &args);
    if (res) {
        return -1;
    }

    return 0;
}
