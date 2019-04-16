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
#include <string.h>
#include <libudev.h>

#include "udev.h"

static int _check_attr(struct udev_device *dev, const char *attr, const char *value)
{
    const char *v = udev_device_get_sysattr_value(dev, attr);
    if (!v)
        return 0;
    if (strcmp(v, value))
        return 0;
    return 1;
}

int udev_get_secureboard_hid_path(const char *serial,
                                  const char **device_node,
                                  const char **device_serial)
{
    int ret = -1;
    struct udev *udev = udev_new();
    if (!udev)
        goto error_udev_init;

    struct udev_enumerate *udev_enum = udev_enumerate_new(udev);
    if (!udev)
        goto error_udev_enumerate_new;

    if (udev_enumerate_add_match_subsystem(udev_enum, "hidraw") < 0)
        goto error_udev_enumerate_not_found;

    if (udev_enumerate_scan_devices(udev_enum) < 0)
        goto error_udev_enumerate_not_found;

    struct udev_list_entry *e, *devices = udev_enumerate_get_list_entry(udev_enum);
    if (!devices)
        goto error_udev_enumerate_not_found;

    udev_list_entry_foreach(e, devices) {
        const char *path = udev_list_entry_get_name(e);

        struct udev_device *dev =
                udev_device_new_from_syspath(udev, path);
        if (!dev)
            continue;

        struct udev_device *dev_interface =
                udev_device_get_parent_with_subsystem_devtype(dev, "usb", "usb_interface");
        if (!dev_interface) {
            udev_device_unref(dev);
            continue;
        }

        struct udev_device *dev_device =
                udev_device_get_parent_with_subsystem_devtype(dev_interface, "usb", "usb_device");
        if (!dev_device) {
            udev_device_unref(dev);
            continue;
        }

        if (!_check_attr(dev_interface, "interface", "SKM") ||
            !_check_attr(dev_device, "idVendor", "046a") ||
            !_check_attr(dev_device, "idProduct", "01a2") ||
            (serial && !_check_attr(dev_device, "serial", serial))) {
            udev_device_unref(dev);
            continue;
        }

        *device_node = strdup(udev_device_get_devnode(dev));
        *device_serial = udev_device_get_sysattr_value(dev_device, "serial");
        if (*device_serial) {
            *device_serial = strdup(*device_serial);
            ret = 0;
        }
        udev_device_unref(dev);
        break;
    }

error_udev_enumerate_not_found:
    udev_enumerate_unref(udev_enum);
error_udev_enumerate_new:
    udev_unref(udev);
error_udev_init:
    return ret;
}
