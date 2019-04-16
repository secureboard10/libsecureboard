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

#include <secureboard/secureboard.h>

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/timerfd.h>
#include <sys/socket.h>
#include <sys/un.h>

// There is no way to attach a context to openssl callbacks, hence a
// global is required
static const secureboard_connection_args_t *_sb_args;

void secureboard_print_errors(secureboard_connection_t *sb)
{
    if (sb->bio_err)
        ERR_print_errors(sb->bio_err);
}

void secureboard_printf(secureboard_connection_t *sb, const char *format, ...)
{
    if (sb->bio_err) {
        va_list args;
        va_start(args, format);
        BIO_vprintf(sb->bio_err, format, args);
        va_end(args);
    }
}

void secureboard_con_default_args(secureboard_connection_args_t *args)
{
    memset(args, 0, sizeof(*args));
    args->family = AF_INET;
}

static int _secureboard_verify_cb(int ok, X509_STORE_CTX *ctx)
{
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);

    if (_sb_args->bio_err) {
        X509_print(_sb_args->bio_err, cert);
    }

    return ok;
}

static int _secureboard_default_psk_use_session_cb(SSL *ssl, const EVP_MD *md,
                                            const unsigned char **id,
                                            size_t *idlen,
                                            SSL_SESSION **sess)
{
    BIO *stmp;
    SSL_SESSION *session;
    if (_sb_args->session_file && (stmp = BIO_new_file(_sb_args->session_file, "r"))) {
        session = PEM_read_bio_SSL_SESSION(stmp, NULL, 0, NULL);
        BIO_free(stmp);
        if (session && SSL_SESSION_has_ticket(session)) {
            SSL_SESSION_get0_ticket(session, id, idlen);
            *sess = session;
            return 1;
        }
    }
    return 1;
}

static int _secureboard_default_new_session_cb(SSL *s, SSL_SESSION *sess)
{
    int res = 1;
    if (_sb_args->session_file) {
        BIO *stmp = BIO_new_file(_sb_args->session_file, "w");
        if (stmp) {
            PEM_write_bio_SSL_SESSION(stmp, sess);
            BIO_free(stmp);
        }
        else {
            res = 0;
        }
    }

    SSL_SESSION_free(sess);
    return res;
}

static int _secureboard_servername_cb(SSL *s, int *ad, void *arg)
{
    return SSL_TLSEXT_ERR_OK;
}

secureboard_connection_t *secureboard_con_init(secureboard_connection_args_t *args)
{
    secureboard_connection_t *sb = calloc(1, sizeof(secureboard_connection_t));
    if (!sb) {
        secureboard_printf(sb, "Failed to allocate secure board memory\n");
        goto error;
    }

    memcpy(&sb->args, args, sizeof(*_sb_args));
    _sb_args = &sb->args;
    sb->socket = -1;
    sb->bio_err = args->bio_err;
    TAILQ_INIT(&sb->tx_head);
    TAILQ_INIT(&sb->rx_head);

    sb->timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (sb->timer_fd < 0) {
        secureboard_printf(sb, "Failed to create timer\n");
        goto error_free_sb;
    }

    sb->ctx = SSL_CTX_new(TLS_client_method());
    if (!sb->ctx) {
        secureboard_print_errors(sb);
        goto error_close_timer;
    }

    SSL_CTX_set_options(sb->ctx, SSL_OP_ALLOW_NO_DHE_KEX);
    SSL_CTX_clear_mode(sb->ctx, SSL_MODE_AUTO_RETRY);

    SSL_CONF_CTX *cctx = SSL_CONF_CTX_new();
    if (!cctx) {
        secureboard_print_errors(sb);
        goto error_free_ctx;
    }

    SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_CLIENT | SSL_CONF_FLAG_CMDLINE);

    SSL_CONF_CTX_set_ssl_ctx(cctx, sb->ctx);

    if (SSL_CONF_cmd(cctx, "-curves", "prime256v1") != 2) {
        secureboard_print_errors(sb);
        goto error_free_conf_ctx;
    }

    if (!SSL_CTX_set_tlsext_micro_fragment(sb->ctx, TLSEXT_micro_fragment_enabled) ||
        !SSL_CTX_set_min_proto_version(sb->ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set_max_proto_version(sb->ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set_ciphersuites(sb->ctx, "TLS_CHACHA20_POLY1305_SHA256")/*  || */
        /* !SSL_CTX_load_verify_locations(sb->ctx, sb->args.ca, NULL) */) {
        fprintf(stderr, "DCCCCC\n");
        secureboard_print_errors(sb);
        goto error_free_conf_ctx;
    }

    SSL_CTX_set_session_cache_mode(sb->ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_LOOKUP |
                                   SSL_SESS_CACHE_NO_INTERNAL_STORE);
    if (args->new_session_cb)
        SSL_CTX_sess_set_new_cb(sb->ctx, sb->args.new_session_cb);
    else
        SSL_CTX_sess_set_new_cb(sb->ctx, _secureboard_default_new_session_cb);

    SSL_CONF_CTX_free(cctx);
    return sb;

error_free_conf_ctx:
    SSL_CONF_CTX_free(cctx);
error_free_ctx:
    SSL_CTX_free(sb->ctx);
error_close_timer:
    close(sb->timer_fd);
error_free_sb:
    free(sb);
error:
    secureboard_printf(sb, "%s: Failed", __FUNCTION__);

    return NULL;
}

int secureboard_con_free(secureboard_connection_t *sb, unsigned timeout_sec)
{
    if (sb->con) {
        secureboard_usb_encap_cancel_all(sb);
        secureboard_con_disconnect(sb, timeout_sec);
    }
    SSL_CTX_free(sb->ctx);
    close(sb->timer_fd);
    free(sb);
    return SECUREBOARD_SUCCESS;
}

SSL_CTX *secureboard_con_get_ssl_ctx(secureboard_connection_t *sb)
{
    return sb->ctx;
}

int secureboard_con_connect(secureboard_connection_t *sb, unsigned timeout_sec)
{
    int res = 0;
    char *host = NULL;
    char *service = NULL;
    BIO_ADDRINFO *addr_info;
    const BIO_ADDRINFO *ai;

    if (BIO_sock_init() != 1) {
        res = SECUREBOARD_ERR_SSL;
        secureboard_print_errors(sb);
        goto error;
    }

    if (sb->args.family == AF_INET) {
        if (!BIO_parse_hostserv(sb->args.hostserv, &host, &service,
                                BIO_PARSE_PRIO_HOST)) {
            res = SECUREBOARD_ERR_HOSTSERV;
            secureboard_print_errors(sb);
            goto error;
        }

        if (!BIO_lookup_ex(host, service, BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM, 0,
                           &addr_info)) {
            res = SECUREBOARD_ERR_DNS_LOOKUP;
            secureboard_print_errors(sb);
            goto error;
        }

        for (ai = addr_info; ai != NULL; ai = BIO_ADDRINFO_next(ai)) {
            sb->socket = BIO_socket(BIO_ADDRINFO_family(ai), BIO_ADDRINFO_socktype(ai),
                                    BIO_ADDRINFO_protocol(ai), 0);

            if (sb->socket < 0) {
                // try next address
                continue;
            }
            else {
                if (!BIO_connect(sb->socket, BIO_ADDRINFO_address(ai), BIO_SOCK_NODELAY)) {
                    BIO_closesocket(sb->socket);
                    sb->socket = -1;
                    continue;
                }
                break;
            }
        }
    }
    else if (sb->args.family == AF_UNIX) {
        struct sockaddr_un name;
        memset(&name, 0, sizeof(struct sockaddr_un));
        name.sun_family = AF_UNIX;

        strncpy(name.sun_path, sb->args.hostserv, sizeof(name.sun_path) - 1);

        socklen_t len = sizeof(name);
        if (name.sun_path[0] == '@') {
            name.sun_path[0] = '\0';
            len = strlen(name.sun_path + 1) + 3;
        }

        sb->socket = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sb->socket < 0) {
            res = SECUREBOARD_ERR_CONNECT;
            goto error;
        }

        if (connect(sb->socket, (struct sockaddr*)&name, len) < 0) {
            res = SECUREBOARD_ERR_CONNECT;
            goto error_close_socket;
        }
    }

    if (sb->socket < 0) {
        res = SECUREBOARD_ERR_CONNECT;
        secureboard_printf(sb, "Failed to connect to relay daemon\n");
        goto error;
    }

    // Set blocking IO
    if (!BIO_socket_nbio(sb->socket, 1)) {
        res = SECUREBOARD_ERR_SSL;
        secureboard_print_errors(sb);
        goto error_close_socket;
    }

    sb->bio = BIO_new_socket(sb->socket, BIO_CLOSE);
    if (!sb->bio) {
        res = SECUREBOARD_ERR_SSL;
        secureboard_print_errors(sb);
        goto error_close_socket;
    }

    if (!sb->con) {
        sb->con = SSL_new(sb->ctx);
        if (!sb->con) {
            res = SECUREBOARD_ERR_SSL;
            secureboard_print_errors(sb);
            goto error_free_bio;
        }
    }


    SSL_set_verify(sb->con, SSL_VERIFY_PEER, _secureboard_verify_cb);

    if (sb->args.session) {
        if (sb->args.psk_use_session_cb)
            SSL_set_psk_use_session_callback(sb->con, sb->args.psk_use_session_cb);
        else
            SSL_set_psk_use_session_callback(sb->con, _secureboard_default_psk_use_session_cb);
    }

    SSL_set_bio(sb->con, sb->bio, sb->bio);
    SSL_set_connect_state(sb->con);

    if (sb->args.servername) {
        SSL_CTX_set_tlsext_servername_callback(sb->ctx, _secureboard_servername_cb);
        SSL_CTX_set_tlsext_servername_arg(sb->ctx, sb);

        if (SSL_set_tlsext_host_name(sb->con, sb->args.servername) != 1) {
            res = SECUREBOARD_ERR_SSL;
            secureboard_print_errors(sb);
            goto error_free_bio;
        }
    }

    if (sb->args.pre_handshake_cb) {
        res = sb->args.pre_handshake_cb(sb, sb->con);
        if (res != SECUREBOARD_SUCCESS) {
            secureboard_print_errors(sb);
            goto error_free_bio;
        }
    }

    if ((res = secureboard_arm_timer(sb, timeout_sec, 0)) < 0)
        goto error_free_ssl;

    struct pollfd pollfds[2] = {
        [0] = {
            .fd = sb->socket,
            .events = 0,
            .revents = 0,
        },
        [1] = {
            .fd = sb->timer_fd,
            .events = POLLIN,
            .revents = 0,
        }
    };

    while ((res = SSL_do_handshake(sb->con)) < 0) {
        if (res == 0) {
            secureboard_print_errors(sb);
            res = SECUREBOARD_ERR_SSL;
            goto error_free_ssl;
        }

        switch (SSL_get_error(sb->con, res)) {
            case SSL_ERROR_WANT_READ:
                pollfds[0].events = POLLIN;
                break;
            case SSL_ERROR_WANT_WRITE:
                pollfds[0].events = POLLOUT;
                break;
            case SSL_ERROR_SYSCALL:
            default:
                secureboard_print_errors(sb);
                res = SECUREBOARD_ERR_SSL;
                goto error_free_ssl;
        }

        res = poll(pollfds, 2, 1000);

        if (res < 0) {
            if (errno == EINTR)
                res = SECUREBOARD_ERR_SIGNAL;
            res = SECUREBOARD_ERR_IO;
            goto error_shutdown;
        }

        if (pollfds[0].revents & POLLHUP) {
            res = SECUREBOARD_ERR_CLOSED;
            goto error_shutdown;
        }

        if (pollfds[0].revents & (POLLERR | POLLNVAL)) {
            res = SECUREBOARD_ERR_IO;
            goto error_shutdown;
        }

        if (pollfds[1].revents & POLLIN) {
            res = SECUREBOARD_ERR_CLOSE_TIMEOUT;
            goto error_shutdown;
        }

        pollfds[0].revents = 0;
        pollfds[1].revents = 0;
    }

    return SECUREBOARD_SUCCESS;

error_shutdown:
    SSL_shutdown(sb->con);

error_free_ssl:
    SSL_free(sb->con);
    sb->con = NULL;

error_free_bio:
    sb->bio = NULL;

error_close_socket:
    BIO_closesocket(sb->socket);
    sb->socket = -1;

error:
    secureboard_print_errors(sb);
    secureboard_printf(sb, "%s: Failed\n", __FUNCTION__);
    return res;
}

static int _secureboard_con_flush(secureboard_connection_t *sb, bool rd, bool wr)
{
    int res;
    struct pollfd pollfds[2] = {
        [0] = {
            .fd = sb->socket,
            .events = 0,
            .revents = 0,
        },
        [1] = {
            .fd = sb->timer_fd,
            .events = POLLIN,
            .revents = 0,
        }
    };

    while ((wr && secureboard_usb_encap_tx_pending(sb)) ||
           (rd && secureboard_usb_encap_rx_pending(sb))) {
        secureboard_connnection_io_wants_t wants;

        switch (SSL_get_shutdown(sb->con)) {
            case 0:
                res = secureboard_usb_encap_do_io(sb, &wants);
                break;
            case SSL_SENT_SHUTDOWN:
                res = secureboard_usb_encap_do_read(sb, &wants);
                break;
            case SSL_RECEIVED_SHUTDOWN:
                res = secureboard_usb_encap_do_write(sb, &wants);
                break;
            case SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN:
                return SECUREBOARD_ERR_CLOSED;
        }

        pollfds[0].events = POLLIN | POLLOUT;
        res = poll(pollfds, 2, 1000);

        if (res < 0) {
            if (errno == EINTR)
                return SECUREBOARD_ERR_SIGNAL;
            return SECUREBOARD_ERR_IO;
        }

        if (pollfds[0].revents & POLLHUP) {
            return SECUREBOARD_ERR_CLOSED;
        }

        if (pollfds[0].revents & (POLLERR | POLLNVAL)) {
            return SECUREBOARD_ERR_IO;
        }

        if (pollfds[1].revents & POLLIN) {
            return SECUREBOARD_ERR_CLOSE_TIMEOUT;
        }
    }

    return SECUREBOARD_SUCCESS;
}

static int _secureboard_shutdown(secureboard_connection_t *sb)
{
    int res;
    struct pollfd pollfds[2] = {
        [0] = {
            .fd = sb->socket,
            .events = 0,
            .revents = 0,
        },
        [1] = {
            .fd = sb->timer_fd,
            .events = POLLIN,
            .revents = 0,
        }
    };

    while ((res = SSL_shutdown(sb->con)) < 0) {
        switch (SSL_get_error(sb->con, res)) {

            case SSL_ERROR_WANT_READ:
                pollfds[0].events = POLLIN;
                break;

            case SSL_ERROR_WANT_WRITE:
                pollfds[0].events = POLLOUT;
                break;

            case SSL_ERROR_SYSCALL:
            default:
                secureboard_print_errors(sb);
                return SECUREBOARD_ERR_SSL;
        }

        res = poll(pollfds, 2, 1000);

        if (res < 0) {
            if (errno == EINTR)
                return SECUREBOARD_ERR_SIGNAL;
            return SECUREBOARD_ERR_IO;
        }

        if (pollfds[0].revents & POLLHUP) {
            return SECUREBOARD_ERR_CLOSED;
        }

        if (pollfds[0].revents & (POLLERR | POLLNVAL)) {
            return SECUREBOARD_ERR_IO;
        }

        if (pollfds[1].revents & POLLIN) {
            return SECUREBOARD_ERR_CLOSE_TIMEOUT;
        }
    }

    return SECUREBOARD_SUCCESS;
}


int secureboard_con_disconnect(secureboard_connection_t *sb, unsigned timeout_sec)
{
    int res;

    res = secureboard_arm_timer(sb, timeout_sec, 0);
    if (res < 0) {
      return res;
    }

    // flush tx queue and ensure that our side has been shut down
    while (!(SSL_get_shutdown(sb->con) & SSL_SENT_SHUTDOWN)) {
        res = _secureboard_con_flush(sb, false, true);
        if (res == SECUREBOARD_ERR_CLOSED) {
            goto done;
        }

        if (res != SECUREBOARD_SUCCESS) {
            goto done;
        }

        res = _secureboard_shutdown(sb);
        if (res != SECUREBOARD_SUCCESS) {
            goto done;
        }
    }

    while (!(SSL_get_shutdown(sb->con) & SSL_RECEIVED_SHUTDOWN)) {
        res = _secureboard_con_flush(sb, true, false);
        if (res == SECUREBOARD_ERR_CLOSED) {
            res = SECUREBOARD_SUCCESS;
            goto done;
        }

        if (res != SECUREBOARD_SUCCESS) {
            goto done;
        }

        res = _secureboard_shutdown(sb);
        if (res != SECUREBOARD_SUCCESS) {
            goto done;
        }
    }

    res = SECUREBOARD_SUCCESS;

done:
    secureboard_disarm_timer(sb);
    secureboard_usb_encap_cancel_all(sb);

    SSL_free(sb->con);
    sb->con = NULL;
    sb->bio = NULL;
    BIO_closesocket(sb->socket);
    sb->socket = -1;

    return res;
}

int secureboard_con_get_fds(secureboard_connection_t *sb, int *rd_fd, int *wr_fd)
{
    if (!sb || !rd_fd || !wr_fd)
        return -1;

    *rd_fd = sb->socket;
    *wr_fd = sb->socket;

    return 0;
}

int secureboard_arm_timer(secureboard_connection_t *sb, unsigned seconds, unsigned nanoseconds)
{
    struct itimerspec timerValue;

    bzero(&timerValue, sizeof(timerValue));
    timerValue.it_value.tv_sec = seconds;
    timerValue.it_value.tv_nsec = nanoseconds;
    timerValue.it_interval.tv_sec = 0;
    timerValue.it_interval.tv_nsec = 0;

    if (timerfd_settime(sb->timer_fd, 0, &timerValue, NULL) < 0)
        return SECUREBOARD_ERR_INTERNAL;

    return SECUREBOARD_SUCCESS;
}

int secureboard_disarm_timer(secureboard_connection_t *sb)
{
    int res;

    res = secureboard_arm_timer(sb, 0, 0);
    if (res != SECUREBOARD_SUCCESS)
        return res;

    // flush received events
    struct pollfd pollfds[1] = {
        [0] = {
            .fd = sb->timer_fd,
            .events = POLLIN,
            .revents = 0,
        }
    };

    while ((res = poll(pollfds, 1, 0)) > 0) {
        uint64_t _; // just a
        read(sb->timer_fd, &_, 8);
        pollfds[0].revents = 0;
    };

    return (res == 0) ? SECUREBOARD_SUCCESS : SECUREBOARD_ERR_INTERNAL;
}

int secureboard_con_keyupdate(secureboard_connection_t *sb,
                              bool request_srv_update,
                              secureboard_connnection_io_wants_t *wants)
{
    int result;
    result = SSL_key_update(sb->con,
                            request_srv_update ? SSL_KEY_UPDATE_REQUESTED : SSL_KEY_UPDATE_NOT_REQUESTED);
    if (result != 1) {
        return SECUREBOARD_ERR_SSL;
    }

    result = SSL_do_handshake(sb->con);
    if (result == 0) {
        secureboard_print_errors(sb);
        return SECUREBOARD_ERR_SSL;
    }

    if (result < 0) {
        switch (SSL_get_error(sb->con, result)) {
            case SSL_ERROR_WANT_READ:
                *wants = SECUREBOARD_CONNNECTION_IO_WANTS_READ;
                return SECUREBOARD_SUCCESS;
            case SSL_ERROR_WANT_WRITE:
                *wants = SECUREBOARD_CONNNECTION_IO_WANTS_WRITE;
            case SSL_ERROR_SYSCALL:
            default:
                secureboard_print_errors(sb);
                return SECUREBOARD_ERR_SSL;
        }
    }

    return SECUREBOARD_SUCCESS;
}
