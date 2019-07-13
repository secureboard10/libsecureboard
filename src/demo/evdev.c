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

#if USE_EVDEV == 1

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <libevdev/libevdev.h>
#include <libevdev/libevdev-uinput.h>

#include "evdev.h"

// see linux source /drivers/hid/usbhid/usbkbd.c
static const unsigned char usb_kbd_keycode[256] = {
    0,  0,  0,  0, 30, 48, 46, 32, 18, 33, 34, 35, 23, 36, 37, 38,
    50, 49, 24, 25, 16, 19, 31, 20, 22, 47, 17, 45, 21, 44,  2,  3,
    4,  5,  6,  7,  8,  9, 10, 11, 28,  1, 14, 15, 57, 12, 13, 26,
    27, 43, 43, 39, 40, 41, 51, 52, 53, 58, 59, 60, 61, 62, 63, 64,
    65, 66, 67, 68, 87, 88, 99, 70,119,110,102,104,111,107,109,106,
    105,108,103, 69, 98, 55, 74, 78, 96, 79, 80, 81, 75, 76, 77, 71,
    72, 73, 82, 83, 86,127,116,117,183,184,185,186,187,188,189,190,
    191,192,193,194,134,138,130,132,128,129,131,137,133,135,136,113,
    115,114,  0,  0,  0,121,  0, 89, 93,124, 92, 94, 95,  0,  0,  0,
    122,123, 90, 91, 85,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    29, 42, 56,125, 97, 54,100,126,164,166,165,163,161,115,114,113,
    150,158,159,128,136,177,178,176,142,152,173,140
};

typedef uint8_t keys_down_t[15];  // +1 to zero terminate

struct evdev_t
{
    struct libevdev *d;
    struct libevdev_uinput *ui;
    int fd;
    keys_down_t keys_down;
    uint8_t led_state;
};

struct evdev_t *evdev_init()
{
    struct evdev_t *dev = NULL;

    dev = calloc(1, sizeof(struct evdev_t));
    if (!dev)
        goto error_malloc;
    dev->fd = -1;

    dev->d = libevdev_new();
    if (!dev->d)
        goto error_evdev_new;

    libevdev_set_name(dev->d, "Cherry SECUREBOARD1.0 in Secure Keyboard Mode");
    libevdev_enable_event_type(dev->d, EV_KEY);

    for (int i = 0; i < 128; i++) {
        if (usb_kbd_keycode[i])
            libevdev_enable_event_code(dev->d, EV_KEY, usb_kbd_keycode[i], NULL);
    }
    for (int i = 0xe0; i < 0xe8; i++) {
        if (usb_kbd_keycode[i])
            libevdev_enable_event_code(dev->d, EV_KEY, usb_kbd_keycode[i], NULL);
    }

    libevdev_enable_event_code(dev->d, EV_LED, LED_CAPSL, NULL);
    libevdev_enable_event_code(dev->d, EV_LED, LED_NUML, NULL);

    if (libevdev_uinput_create_from_device(dev->d,
                                           LIBEVDEV_UINPUT_OPEN_MANAGED,
                                           &dev->ui)) {
        goto error_uidev;
    }

    dev->fd = libevdev_uinput_get_fd(dev->ui);
    libevdev_set_fd(dev->d, dev->fd);

    return dev;

error_uidev:
    libevdev_free(dev->d);

error_evdev_new:
    free(dev);

error_malloc:
    printf("%s\n", strerror(errno));
    return NULL;
}

int evdev_get_fd(struct evdev_t *dev)
{
    return dev->fd;
}

static void _expand_report(keys_down_t *k, const uint8_t *report, unsigned len)
{
    int i, p;
    assert(len == 8);
    memset(k, 0, sizeof(*k));
    p = 0;
    for (i = 0; i < 8; i++) {
        if (report[0] & (1 << i)) {
            (*k)[p] = 0xE0 + i;
            p++;
        }
    }
    for (i = 0; i < 6; i++) {
        if (report[2 + i]) {
            (*k)[p] = report[2 + i];
            p++;
        }
    }
}

static int _is_key_in_expended_report(const keys_down_t *k, uint8_t key)
{
    const uint8_t *p;
    for (p = &(*k)[0]; *p; p++) {
        if (*p == key)
            return 1;
    }
    return 0;
}

void evdev_input_report(struct evdev_t *dev, const uint8_t *report, unsigned len)
{
    assert(len == 8);
    uint8_t *p;
    uint8_t syn_report = 0;
    keys_down_t expanded_report;
    _expand_report(&expanded_report, report, len);

    // Check for key release events
    for (p = &dev->keys_down[0]; *p; p++) {
        if (!_is_key_in_expended_report((const keys_down_t*)&expanded_report, *p)) {
            libevdev_uinput_write_event(dev->ui,
                                        EV_KEY,
                                        usb_kbd_keycode[*p],
                                        0);
            syn_report = 1;
            if (EVDEV_VERBOSE)
                printf("key up %d %d\n", *p, dev->fd);
        }
    }
    // Check for key down events
    for (p = &expanded_report[0]; *p; p++) {
        if (!_is_key_in_expended_report((const keys_down_t*)&dev->keys_down, *p)) {
            libevdev_uinput_write_event(dev->ui,
                                        EV_KEY,
                                        usb_kbd_keycode[*p],
                                        1);
            syn_report = 1;
            if (EVDEV_VERBOSE)
                printf("key down %d\n", *p);
        }
    }

    if (syn_report) {
            libevdev_uinput_write_event(dev->ui,
                                        EV_SYN,
                                        SYN_REPORT,
                                        0);
    }

    fsync(dev->fd);

    memcpy(&dev->keys_down, expanded_report, sizeof(dev->keys_down));
}

int evdev_read_event(struct evdev_t *dev, secureboard_connection_t *sb)
{
    struct input_event ev;
    int rd;
    uint8_t mask = 0;
    uint8_t current_led_state = dev->led_state;

    rd = read(dev->fd, &ev, sizeof(struct input_event));
    if (rd != sizeof(ev))
        return -1;

    switch (ev.type) {
        case EV_LED:
            switch (ev.code) {
                case LED_NUML:
                    mask = (1 << 0);
                    break;
                case LED_CAPSL:
                    mask = (2 << 0);
                    break;
            }

            if (ev.value) {
                dev->led_state |= mask;
            }
            else {
                dev->led_state &= ~mask;
            }

            if (dev->led_state != current_led_state) {
                if (EVDEV_VERBOSE)
                    printf("new LED state: %x\n", dev->led_state);
                return secureboard_usb_set_led_report(sb,
                                                      0,
                                                      dev->led_state);
            }
    }

    return 0;
}

void evdev_destroy(struct evdev_t *dev)
{
    libevdev_uinput_destroy(dev->ui);
    libevdev_free(dev->d);
    free(dev);
}

#endif
