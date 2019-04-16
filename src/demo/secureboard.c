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
 * \example
 *
 * \brief Example for libsecureboard
 *
 * This example connects to a SECURE BOARD 1.0 and prints all reports
 * onto the console.
 */

#include <secureboard/secureboard.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <poll.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include "evdev.h"

// The demo does not parse the descriptors, we just define the values
// as is.
#define SECUREBOARD_HID_INTERFACE  0
#define SECUREBOARD_HID_BOOT_EP    1
#define SECUREBOARD_HID_MEDIA_EP   2

#define SECUREBOARD_VID            0x046a
#define SECUREBOARD_PID            0x01a2

#define COMMAND_CHARS_NUMOF        1023
#define COMMAND_ARGS_NUMOF         16

static volatile bool terminate = false;  // Changed by signal handler
static const char *user_root_ca = NULL;
static const char *user_cert = NULL;
EVP_PKEY *user_priv_key = NULL;
X509 *client_cert = NULL;
EVP_PKEY *client_key = NULL;
static bool verbose = 0;
static const char *ca_dir;
#if USE_EVDEV == 1
#define EVDEV_IN_POLL_IDX 3
struct evdev_t *evdev = NULL;
#endif

static const struct option long_opts[] =
{
    { "verbose", no_argument, 0, 'v' },
    { "license", no_argument, 0, 0, },
    { "ca-dir", required_argument, 0, 0 },
    { "sni", required_argument, 0, 0 },
    { "client-cert", required_argument, 0, 0 },
    { "client-key", required_argument, 0, 0 },
    { "user-root-ca", required_argument, 0, 0 },
    { "user-cert", required_argument, 0, 0 },
    { "user-priv-key", required_argument, 0, 0 },
#if USE_EVDEV == 1
    { "evdev", no_argument, 0, 0 },
#endif
    { 0, 0, 0, 0 }
};

void usage(const char *cmd)
{
    char *_cmd = basename(strdupa(cmd));
    printf("SYNOPSIS: %s <options>\n"
           "\n"
           "\tConnection Management\n"
           "\t\t-c <host>:<port>     (opt)   Host and Port of the relay-daemon\n"
           "\t\t-u <unix-socket>     (opt)   Unix Socket path (use @ as first character for abstract namespace)\n"
           "\t\t                     Note: either -c or -u must be given\n"
           "\t\t--ca-dir <ca-dir>    (req)   Directory to CA used to verify certificates\n"
           "\t\t-s <sessionfile>     (opt)   Sessionfile uses to store PSK key\n"
           "\t\t--sni <servername>   (opt)   Use <servername> as server name indication in ClientHello message\n"
           "\t\t--client-cert <cert> (opt)   Use <cert> as client certificate if requested (PEM encoded)\n"
           "\t\t                             If used --client_key must also be present\n"
           "\t\t--client-key <key>   (opt)   Use <key> as client key if requested (PEM encoded)\n"
           "\t\t                             If used --client_cert must also be present\n"
#if USE_EVDEV == 1
           "\t\t--evdev              (opt)   Send Reports to evdev\n"
#endif
           "\n"
           "\tDevice Personalization **ENSURE CORRECT ENCODINGS**\n"
           "\t\t--user-cert          (opt)   Update User Certificate and terminate (DER encoded)\n"
           "\t\t--user-priv-key      (opt)   Update User User Private Key (must match User Certificate) (PEM encoded)\n"
           "\t\t--user-root-ca       (opt)   Update User Root Certificate Authority (PEM encoded)\n"
           "\n"
           "\tOther Options\n"
           "\t\t--verbose, -v        (opt)   Be verbose\n"
           "\t\t--license            (opt)   Show License\n"
           "\n",
           _cmd);
    exit(1);
}

X509 *load_x509_cert_pem(const char *name)
{
    FILE *f = fopen(name, "rb");
    if (f == NULL)
        return NULL;

    X509 *cert = PEM_read_X509(f, NULL, NULL, NULL);

    fclose(f);

    return cert;
}

EVP_PKEY *load_keypair_pem(const char *name)
{
    EVP_PKEY *pkey = NULL;

    FILE *f = fopen(name, "r");
    if (f == NULL)
        return NULL;

    if (PEM_read_PrivateKey(f, &pkey, NULL, NULL) == NULL) {
        fclose(f);
        return NULL;
    }
    fclose(f);

    return pkey;
}

void parse_arguments(secureboard_connection_args_t *args, int argc, char **argv)
{
    int c;
    int oi;
    secureboard_con_default_args(args);
    while ((c = getopt_long(argc, argv, "c:u:s:v",
                            long_opts, &oi)) != EOF) {
        switch (c) {
            case 0:
                if (strcmp(long_opts[oi].name, "ca-dir") == 0) {
                    if (ca_dir)
                        usage(argv[0]);
                    ca_dir = optarg;
                }
                else if (strcmp(long_opts[oi].name, "sni") == 0) {
                    if (args->servername)
                        usage(argv[0]);
                    args->servername = optarg;
                }
                else if (strcmp(long_opts[oi].name, "user-root-ca") == 0) {
                    if (user_root_ca)
                        usage(argv[0]);
                    user_root_ca = optarg;
                    terminate = true;
                }
                else if (strcmp(long_opts[oi].name, "user-cert") == 0) {
                    if (user_cert)
                        usage(argv[0]);
                    user_cert = optarg;
                    terminate = true;
                }
                else if (strcmp(long_opts[oi].name, "user-priv-key") == 0) {
                    if (user_priv_key)
                        usage(argv[0]);
                    user_priv_key = load_keypair_pem(optarg);
                    if (!user_priv_key) {
                        fprintf(stderr, "Failed to load key '%s': %s\n", optarg, strerror(errno));
                        usage(argv[0]);
                    }
                    terminate = true;
                }
                else if (strcmp(long_opts[oi].name, "client-cert") == 0) {
                    if (client_cert)
                        usage(argv[0]);
                    client_cert = load_x509_cert_pem(optarg);
                    if (!client_cert) {
                        printf("Failed to load client certificate '%s': %s\n", optarg, strerror(errno));
                        usage(argv[0]);
                    }
                }
                else if (strcmp(long_opts[oi].name, "client-key") == 0) {
                    if (client_key)
                        usage(argv[0]);
                    client_key = load_keypair_pem(optarg);
                    if (!client_key) {
                        printf("Failed to load client key '%s': %s\n", optarg, strerror(errno));
                        usage(argv[0]);
                    }
                }
#if USE_EVDEV == 1
                else if (strcmp(long_opts[oi].name, "evdev") == 0) {
                    evdev = evdev_init();
                    if (!evdev) {
                        printf("Failed to create evdev device\n");
                        usage(argv[0]);
                    }
                }
#endif
                else if (strcmp(long_opts[oi].name, "license") == 0) {
                    secureboard_library_show_license();
                }
                else {
                    usage(argv[0]);
                }
                break;

            case 'v':
                if (args->bio_err)
                    usage(argv[0]);
                args->bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);
                if (!args->bio_err)
                    printf("WARNING: Failed to open error out BIO\n");
                verbose = true;
                break;

            case 'u':
                args->family = AF_UNIX;
            case 'c':
                if (args->hostserv)
                    usage(argv[0]);
                args->hostserv = optarg;
                break;

            case 's':
                if (args->session_file)
                    usage(argv[0]);
                args->session_file = optarg;
                break;

            default:
                usage(argv[0]);
        }
    }

    if ((client_key == NULL && client_cert != NULL) ||
        (client_key != NULL && client_cert == NULL))
        usage(argv[0]);

    if (!args->hostserv)
        usage(argv[0]);
}

secureboard_usb_encap_ep_complete_action_t
secureboard_ep_boot_rx(void *data,
                       unsigned len,
                       uint8_t ep,
                       secureboard_usb_encap_control_request_result_t status,
                       intptr_t ctx)
{
    switch (status) {
        case SECUREBOARD_USB_ENCAP_REQUEST_COMPLETE:
            switch (ep) {
                case SECUREBOARD_HID_BOOT_EP:
                    if (len != 8) {
                        fprintf(stderr, "Invalid Packet on EP%d\n", ep);
                    }
                    else {
#if USE_EVDEV == 1
                        if (evdev) {
                            evdev_input_report(evdev, data, len);
                            break;
                        }
#endif
                        printf("New Report: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                               ((uint8_t*)data)[0], ((uint8_t*)data)[1],
                               ((uint8_t*)data)[2], ((uint8_t*)data)[3],
                               ((uint8_t*)data)[4], ((uint8_t*)data)[5],
                               ((uint8_t*)data)[6], ((uint8_t*)data)[7]);
                    }
                    break;
                default:
                    fprintf(stderr, "Dropping Packet on EP%d\n", ep);
                    break;
            }
            return SECUREBOARD_USB_ENCAP_EP_COMPLETE_RESUBMIT_REQUEST;
        case SECUREBOARD_USB_ENCAP_REQUEST_STALL:
            fprintf(stderr, "Dropping STALL on EP%d\n", ep);
            return SECUREBOARD_USB_ENCAP_EP_COMPLETE_RESUBMIT_REQUEST;
        case SECUREBOARD_USB_ENCAP_REQUEST_CANCEL:
            return SECUREBOARD_USB_ENCAP_EP_COMPLETE_DISPOSE_REQUEST;
    }
    abort();
}

static int do_command(secureboard_connection_t *sb, secureboard_connnection_io_wants_t *wants,
                      int argc, const char **argv)
{
    int result = SECUREBOARD_SUCCESS;
    if (argc < 1) {
        fprintf(stderr, "invalid command\n");
        return result;
    }
    else if (strcasecmp(argv[0], "k") == 0) {
        bool request_server_update = false;
        switch (argc) {
            case 1:
                break;
            case 2:
                if (strcasecmp(argv[1], "1") == 0) {
                    request_server_update = true;
                    break;
                }
                else if (strcasecmp(argv[1], "0") == 0) {
                    break;
                }

                // fall through for synopsis.
            default:
                fprintf(stderr, "SYNPOSIS: k [0|1]\n");
                request_server_update = true;
                return result;
        }
        return secureboard_con_keyupdate(sb, request_server_update, wants);
    }
    else {
        fprintf(stderr, "invalid command: %s\n", argv[0]);
        return result;
    }
}

static int stdin_handler(secureboard_connection_t *sb, secureboard_connnection_io_wants_t *wants)
{
    static unsigned cmd_buffer_pos = 0;
    static char cmd_buffer[COMMAND_CHARS_NUMOF+1];

    int rd = 0;
    rd = read(fileno(stdin), cmd_buffer + cmd_buffer_pos, 1);

    if (rd != 1) {
        return rd;
    }
    else {
        bool cmd_complete = false;
        if (cmd_buffer[cmd_buffer_pos] == '\n') {
            cmd_complete = true;
        }
        else {
            cmd_buffer_pos++;
            if (cmd_buffer_pos == sizeof(cmd_buffer) - 1) {
                cmd_complete = true;
            }
        }

        if (cmd_complete) {
            cmd_buffer[cmd_buffer_pos] = 0;
            cmd_buffer_pos = '\0';

            const char **cmdv = alloca(sizeof(char*) * COMMAND_ARGS_NUMOF);
            unsigned cmdc = 0;

            cmdv[cmdc] = strtok(cmd_buffer, " \t");
            while (cmdv[cmdc]) {
                cmdc++;
                if (cmdc == COMMAND_ARGS_NUMOF) {
                    fprintf(stderr, "command argument limit reached\n");
                    return 1;
                }
                cmdc[cmdv] = strtok(NULL,  " \t");
            }
            if (cmdc) {
                do_command(sb, wants, cmdc, cmdv);
            }
        }
        return 1;
    }
}

void signal_handler(int signal)
{
    if (verbose)
        printf("Signal %d caught. terminating\n", signal);
    terminate = true;
}

void *load_file(const char *name, size_t *len)
{
    void *b;
    struct stat sbuf;

    if (stat(name, &sbuf))
        return NULL;

    *len = sbuf.st_size;

    FILE *f = fopen(name, "rb");
    if (f == NULL)
        return NULL;

    b = malloc(sbuf.st_size);
    if (b == NULL)
        return NULL;

    if (fread(b, *len, 1, f) != 1) {
        free(b);
        fclose(f);
        return NULL;
    }

    fclose(f);
    return b;
}

void *load_pubkey_from_x509(const char *name, size_t *len)
{
    void *res = NULL;

    X509 *cert = load_x509_cert_pem(name);

    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey == NULL)
        return NULL;

    EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(pkey);
    if (eckey == NULL)
        return NULL;

    *len = EC_KEY_key2buf(eckey,
                          POINT_CONVERSION_UNCOMPRESSED,
                          (unsigned char**)&res, NULL);

    if (*len != 65) {
        fprintf(stderr, "Failed to extract public key from x509 certificate\n");
        EVP_PKEY_free(pkey);
        return NULL;
    }

    X509_free(cert);
    return res;
}

int load_fingerprint_from_x509(const char *name, unsigned char *md, unsigned int *len)
{
    X509 *cert = load_x509_cert_pem(name);
    const EVP_MD *fdig = EVP_sha256();

    if (!cert || !fdig)
        return 0;

    unsigned int res = X509_digest(cert, fdig, md, len);

    X509_free(cert);

    return (res != 1) ? -1 : 0;
}

int update_user_root_ca(secureboard_connection_t *sb, const char *name)
{
    int result;

    unsigned int fingerprint_len;
    unsigned char fingerprint[EVP_MAX_MD_SIZE];

    if (load_fingerprint_from_x509(name, fingerprint, &fingerprint_len)) {
        fprintf(stderr, "Failed to update User Root Certificate\n");
        return -1;
    }

    result = secureboard_usb_set_user_root_ca(sb, SECUREBOARD_HID_INTERFACE,
                                              fingerprint, fingerprint_len);

    if (result < 0) {
        fprintf(stderr, "Failed to update User Root Certificate\n");
        return result;
    }

    if (verbose)
        printf("User Root Certificate Authority updated\n");

    return result;
}

int update_user_certificate(secureboard_connection_t *sb, const char *name)
{
    int result;
    size_t cert_len;
    void *cert = load_file(name, &cert_len);
    if (!cert) {
        perror("Failed to load certificate");
        return -1;
    }

    result = secureboard_usb_set_user_cert(sb, SECUREBOARD_HID_INTERFACE,
                                           cert, cert_len);
    free(cert);

    if (result < 0) {
        fprintf(stderr, "Failed to update User Certificate %d\n", result);
        return result;
    }

    if (verbose)
        printf("User Certificate updated\n");

    return result;
}

void *load_priv_key(EVP_PKEY *user_keypair, size_t *len)
{
    EC_KEY *eckey;
    void *res = NULL;

    eckey = EVP_PKEY_get1_EC_KEY(user_keypair);
    if (eckey == NULL) {
        fprintf(stderr, "Failed to get EC Key\n");
        return NULL;
    }

    *len = EC_KEY_priv2buf(eckey, (unsigned char**)&res);
    if (*len == 0) {
        fprintf(stderr, "Failed to extract private data\n");
        return NULL;
    }

    return res;
}

int update_user_private_key(secureboard_connection_t *sb, EVP_PKEY *user_keypair)
{
    int result;
    size_t user_pkey_len;

    void *user_pkey = load_priv_key(user_keypair, &user_pkey_len);
    if (user_pkey == NULL) {
        return -1;
    }

    result = secureboard_usb_set_user_private_key(sb, SECUREBOARD_HID_INTERFACE,
                                                  user_pkey, user_pkey_len);
    if (result) {
        fprintf(stderr, "Failed to update User Private Key\n");
    }
    free(user_pkey);

    if (verbose)
        printf("User Private Key updated\n");

    return result;
}

int pre_handshake_cb(secureboard_connection_t *sb, SSL *ssl)
{
    if ((client_cert) && (client_key)) {
        if (SSL_use_certificate(ssl, client_cert) != 1) {
            printf("Failed to set client certificate\n");
            return SECUREBOARD_ERR_SSL;
        }

        if (SSL_use_PrivateKey(ssl, client_key) != 1) {
            printf("Failed to set client key\n");
            return SECUREBOARD_ERR_SSL;
        }

        if (SSL_check_private_key(ssl) != 1) {
            printf("Certificate and private key do not match");
            return SECUREBOARD_ERR_SSL;
        }
    }

    return SECUREBOARD_SUCCESS;
}

int main(int argc, char **argv)
{
    int result;
    secureboard_connection_args_t sb_args;
    secureboard_connection_t *sb;
    secureboard_usb_device_descriptor_t device_descriptor;
    uint8_t configuration_descriptor[400];
    unsigned configuration_descriptor_len;
    secureboard_fw_version_t fw_version;

    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGHUP, signal_handler);

    printf("libsecureboard version %s\n", secureboard_library_version_string());

    if (fcntl(fileno(stdin), F_SETFL, fcntl(fileno(stdin), F_GETFL) | O_NONBLOCK) < 0) {
        perror("Failed to set non-blocking io on stdin");
        goto error_exit;
    }

    parse_arguments(&sb_args, argc, argv);

    sb_args.pre_handshake_cb = pre_handshake_cb;

    // try to load session
    if (sb_args.session_file) {
        BIO *stmp;
        if ((stmp = BIO_new_file(sb_args.session_file, "r"))) {
            sb_args.session = PEM_read_bio_SSL_SESSION(stmp, NULL, 0, NULL);
            BIO_free(stmp);
        }
    }

    sb = secureboard_con_init(&sb_args);
    if (!sb) {
        fprintf(stderr, "Failed to init connection.\n");
        goto error;
    }

    if (SSL_CTX_load_verify_locations(secureboard_con_get_ssl_ctx(sb), NULL, ca_dir) != 1) {
        printf("Failed to load verify locations");
        goto error_free;
    }

    result = secureboard_con_connect(sb, 15);
    if (result != SECUREBOARD_SUCCESS) {
        fprintf(stderr, "Failed to connect to SECUREBOARD (%d).\n", result);
        goto error_free;
    }

    result = secureboard_usb_get_device_descriptor(sb, &device_descriptor);
    if (result < 0) {
        fprintf(stderr, "Failed to retrieve SECUREBOARD USB Device Descriptor (%d).\n", result);
        goto error_shutdown;
    }

    if (sb_args.bio_err) {
        printf("Connected to device %04x:%04x\n",
               le16toh(device_descriptor.idVendor),
               le16toh(device_descriptor.idProduct));
    }

    if ((le16toh(device_descriptor.idVendor) != SECUREBOARD_VID) ||
        (le16toh(device_descriptor.idProduct) != SECUREBOARD_PID)) {
        fprintf(stderr, "Unsupported VID:PID");
        goto error_shutdown;
    }

    result = secureboard_usb_get_configuration_descriptor(sb,
                                                          configuration_descriptor,
                                                          sizeof(configuration_descriptor));
    if (result < 0) {
        fprintf(stderr, "Failed to retrieve SECUREBOARD USB Configuration Descriptor (%d).\n", result);
        goto error_shutdown;
    }

    configuration_descriptor_len = result;
    if (sb_args.bio_err) {
        printf("Configuration Descriptor has length %d\n", configuration_descriptor_len);
    }

    result = secureboard_usb_get_fw_version(sb, &fw_version);
    if (result < 0) {
        fprintf(stderr, "Failed to retrieve SECUREBOARD FW Version. (%d).\n", result);
        goto error_shutdown;
    }

    if (sb_args.bio_err) {
        printf("FW_version %d.%d.%d.%d\n",
               fw_version.maj_rev, fw_version.maj, fw_version.min, fw_version.nr);
    }

    if (user_cert) {
        result = update_user_certificate(sb, user_cert);
        if (result < 0)
            goto error_shutdown;
    }

    if (user_priv_key) {
        printf("Updating User Private Key\n");
        result = update_user_private_key(sb, user_priv_key);
        if (result < 0)
            goto error_shutdown;
    }

    if (user_root_ca) {
        result = update_user_root_ca(sb, user_root_ca);
        if (result < 0)
            goto error_shutdown;
    }

    struct pollfd pollfds[] = {
        [0] = {
            .fd = 0,
            .events = POLLIN,
            .revents = 0,
        },
        [1] = {
            .fd = 0,
            .events = POLLOUT,
            .revents = 0,
        },
        [2] = {
            .fd = fileno(stdin),
            .events = POLLIN | POLLPRI,
            .revents = 0,
        },
#if USE_EVDEV == 1
        [EVDEV_IN_POLL_IDX] = {
            .fd = evdev ? evdev_get_fd(evdev) : -1,
            .events = evdev ? (POLLIN | POLLPRI) : 0,
            .revents = 0,
        },
#endif
    };

    if (!terminate) {
        // Turn off NUM/CAPS Led
        result = secureboard_usb_set_led_report(sb, SECUREBOARD_HID_INTERFACE, 0);
        if (result < 0) {
            fprintf(stderr, "Failed to to set led report (%d).\n", result);
            goto error_shutdown;
        }

        result = secureboard_usb_set_running(sb, SECUREBOARD_HID_INTERFACE, true);
        if (result < 0) {
            fprintf(stderr, "Failed to bring device into running mode (%d) (Likely you did not personalize your device (see --user-cert, --user-priv-key).\n", result);
            goto error_shutdown;
        }

        result = secureboard_con_get_fds(sb,
                                         &pollfds[0].fd,
                                         &pollfds[1].fd);
        if (result < 0) {
            fprintf(stderr, "Failed to get file IO fds (%d).\n", result);
            goto error_shutdown;
        }

        uint8_t key_report0[8];
        result = secureboard_usb_encap_submit_rx_request(sb, SECUREBOARD_HID_BOOT_EP,
                                                         key_report0, sizeof(key_report0),
                                                         secureboard_ep_boot_rx,
                                                         0,
                                                         NULL);
        if (result < 0) {
            fprintf(stderr, "Failed to submit EP1 request (%d).\n", result);
            goto error_shutdown;
        }
    }

    secureboard_connnection_io_wants_t io_wants = SECUREBOARD_CONNNECTION_IO_WANTS_NOTHING;
    secureboard_connnection_io_wants_t std_wants = SECUREBOARD_CONNNECTION_IO_WANTS_NOTHING;

    while (!terminate) {
        result = poll(pollfds,
                      (sizeof(pollfds) / sizeof(pollfds[0])) - (evdev ? 0 : 1),
                      1000);
        if (result < 0) {
            if (errno == EINTR)
                continue;
            perror("poll failed");
            goto error_shutdown;
        }

        if ((pollfds[0].revents | pollfds[1].revents) & POLLHUP) {
            printf("remote host closed connections\n");
            goto error_shutdown;
        }

        if ((pollfds[0].revents | pollfds[1].revents) & (POLLERR | POLLNVAL)) {
            printf("connection error\n");
            goto error_shutdown;
        }

#if USE_EVDEV == 1
        if ((pollfds[EVDEV_IN_POLL_IDX].revents) & (POLLERR | POLLNVAL)) {
            printf("evdev error error\n");
            goto error_shutdown;
        }
#endif

        // timeout
        if (result == 0) {
            continue;
        }

        if ((pollfds[0].revents & POLLIN) ||
            (pollfds[1].revents & POLLOUT)) {

            result = secureboard_usb_encap_do_io(sb, &io_wants);
            if (result < 0) {
                fprintf(stderr, "Failed to submit EP1 request (%d).\n", result);
                goto error_shutdown;
            }

        }

        if (pollfds[2].revents & POLLIN) {
            result = stdin_handler(sb, &std_wants);
            if (result == 0) {
                terminate = true;
            }
            else if (result < 0) {
                perror("stdin handler failed");
                goto error_shutdown;
            }
        }

#if USE_EVDEV == 1
        if (pollfds[EVDEV_IN_POLL_IDX].revents & POLLIN) {
            if (evdev_read_event(evdev, sb)) {
                perror("evdev handler failed");
                goto error_shutdown;
            }
        }
#endif

        secureboard_connnection_io_wants_t wants = (io_wants | std_wants);
        pollfds[0].events = (wants & SECUREBOARD_CONNNECTION_IO_WANTS_READ) ? POLLIN : 0;
        pollfds[1].events = (wants & SECUREBOARD_CONNNECTION_IO_WANTS_WRITE) ? POLLOUT : 0;
    }

#if USE_EVDEV == 1
    if (evdev)
        evdev_destroy(evdev);
    evdev = NULL;
#endif

    result = secureboard_con_disconnect(sb, 10);
    if (result < 0) {
        fprintf(stderr, "Failed to disconnect from SECUREBOARD (%d).\n", result);
        goto error_free;
    }

    result = secureboard_con_free(sb, 1);
    if (result < 0) {
        fprintf(stderr, "Failed to free connection (%d).\n", result);
        goto error;
    }

    if (sb_args.bio_err) {
        BIO_free(sb_args.bio_err);
    }
    return 0;

error_shutdown:
    secureboard_con_disconnect(sb, 10);

error_free:
    secureboard_con_free(sb, 1);

error:
    if (sb_args.bio_err) {
        BIO_free(sb_args.bio_err);
    }

error_exit:
#if USE_EVDEV == 1
    if (evdev)
        evdev_destroy(evdev);
    evdev = NULL;
#endif

    if (client_key)
        EVP_PKEY_free(client_key);

    if (user_priv_key)
        EVP_PKEY_free(user_priv_key);

    return 1;
}
