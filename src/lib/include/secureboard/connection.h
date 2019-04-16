#ifndef LIB_SECUREBOARD_CONNECTION_H
#define LIB_SECUREBOARD_CONNECTION_H

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
 * \brief Secure board connection management
 */

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * \brief Connection arguments.
     *
     * Since the is no nice way to put a context onto openssl
     * callbacks, this structure must be implemented as a
     * singelton. It is stored in a global variable within the
     * library.
     */
    typedef struct secureboard_connection_args_tag {
        /**
         * \brief Service to connect to. Format host:port
         */
        const char *hostserv;
        /**
         * \brief Address Family (AF_INET, AF_UNIX)
         */
        int family;
        /**
         * \brief server name to be included in the client hello
         */
        const char *servername;
        /**
         * \brief Root CA used to validate the SECURE Board certificate
         */
        BIO *bio_err;
        /**
         * \brief session file name where sessions are stored to.
         *
         * If not NULL libsecureboard stores the new session into this
         * file if a new ticket is sent by SECURE BOARDs 1.0. This is
         * normally the case just before the device gracefully closes
         * its side.
         *
         * To reconnect SECURE BOARDs 1.0 use the session management
         * procedure defined in TLS1.3.
         */
        const char *session_file; // if session file to use for default session management
        /**
         * \brief Session to use for reconnecting.
         *
         * If not NULL libsecureboard provides a session to
         * resume. Using the default mechanism is regarded INSECURE
         * since the session secrets are stored in plaintext.
         */
        SSL_SESSION *session;

        int (*pre_handshake_cb)(secureboard_connection_t *sb, SSL *ssl);

        /**
         * \brief Override the internal session management by the
         *        application (new session part).
         *
         * It is recommended to use sessions since it significantly
         * expedites handshake by avoiding asymmetric operations.
         *
         * It is *NOT* recommended to use the built in session
         * management since session secrets are stored in plaintext on
         * the local drive.
         *
         * There for it is recommended to use new_session_cb in order
         * to tailor session management to the application
         * requirements.
         */
        int (*new_session_cb)(struct ssl_st *ssl, SSL_SESSION *sess);
        /**
         * \brief Override the internal session management by the
         *        application (load/use session part).
         *
         * It is recommended to use sessions since it significantly
         * expedites handshake by avoiding asymmetric operations.
         *
         * It is *NOT* recommended to use the built in session
         * management since session secrets are stored in plaintext on
         * the local drive.
         *
         * There for it is recommended to use new_session_cb in order
         * to tailor session management to the application
         * requirements.
         */
        SSL_psk_use_session_cb_func psk_use_session_cb;


    } secureboard_connection_args_t;

    /**
     * \brief Application information indicating when to call the IO functions again.
     */
    typedef enum {
        /**
         * \brief Not need to call again, there is nothing scheduled.
         */
        SECUREBOARD_CONNNECTION_IO_WANTS_NOTHING = 0,
        /**
         * \brief Call again when there is data available to read.
         */
        SECUREBOARD_CONNNECTION_IO_WANTS_READ    = (1 << 0),
        /**
         * \brief Call again when there is data available to write.
         */
        SECUREBOARD_CONNNECTION_IO_WANTS_WRITE   = (1 << 1),
    } secureboard_connnection_io_wants_t;

    /**
     * \brief Setup argument structure with default values.
     *
     * \param[out] args argument structure to setup.
     */
    void secureboard_con_default_args(secureboard_connection_args_t *args);

    /**
     * \brief Create a new connection context.
     *
     * \param[out] args context arguments.
     *
     * \return libsecureboard connection context
     */
    secureboard_connection_t *secureboard_con_init(secureboard_connection_args_t *args);

    /**
     * \brief Get the SSL context
     *
     * \param sb libsecureboard connection context
     *
     * \return SSL Context
     */
    SSL_CTX *secureboard_con_get_ssl_ctx(secureboard_connection_t *sb);

    /**
     * \brief Connect to a secure board and execute the handshake.
     *
     * This function blocks for at most timeout_sec seconds.
     *
     * \param sb libsecureboard connection context
     * \param timeout_sec seconds for timeout. 15 seconds are
     *        recommend to execute a full handshake.
     *
     * \return Errorcode defined in error.h.
     */
    int secureboard_con_connect(secureboard_connection_t *sb, unsigned timeout_sec);

    /**
     * \brief Retrieve the file descriptors in use for the under-laying Linux sockets.
     *
     * \param sb libsecureboard connection context
     * \param[out] rd_fd file descriptor used for read operations
     * \param[out] wr_fd file descriptor used for write operations
     *
     * \return Errorcode defined in error.h.
     */
    int secureboard_con_get_fds(secureboard_connection_t *sb, int *rd_fd, int *wr_fd);

    /**
     * \brief Disconnect a connection and free structures.
     *
     * This flushes all operations and cancels those that are not
     * completed after shutdown. It also tries a graceful disconnect
     * leaving a new session for reconnect.
     *
     * Calling disconnect might block.
     *
     * \param sb libsecureboard connection context
     * \param timeout_sec seconds for timeout. 5 seconds should be
     *        more than enough for most applications.
     *
     * \return Errorcode defined in error.h.
     */
    int secureboard_con_disconnect(secureboard_connection_t *sb, unsigned timeout_sec);

    /**
     * \brief Free the libsecureboard context and free structures.
     *
     * If the connection is still active the call might block because
     * secureboard_con_disconnect is called.
     *
     * \param sb libsecureboard connection context
     * \param timeout_sec seconds for timeout. 5 seconds should be
     *        more than enough for most applications.
     *
     * \return Errorcode defined in error.h.
     */
    int secureboard_con_free(secureboard_connection_t *sb, unsigned timeout_sec);

    /**
     * \brief Execute a key update as defined in TLS13.
     *
     * \param sb libsecureboard connection context
     * \param request_srv_update request that the server also updates its key
     * \param[out] wants indicates which IO states make it necessary
     *             calling io functions again. Call secureboard_usb_encap_do_io.
     *
     * \return Errorcode defined in error.h.
     */
    int secureboard_con_keyupdate(secureboard_connection_t *sb,
                                  bool request_srv_update,
                                  secureboard_connnection_io_wants_t *wants);

#ifdef __cplusplus
}
#endif

#endif
