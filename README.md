# General Notes

SECUREBOARD1.0 implement only a subset of requirements for TLS13 server.

The most notable restrictions are:

* The only cipher suite supported is TLS_CHACHA20_POLY1305_SHA256.

* The only supported signature algorithm is ECDSA_SHA256 over the
  prime256v1.

* All handshake messages (except Certificate) are restricted to 475
  bytes.

* Client Certificates within the Certificate message are restricted to
  475 bytes (for each certificate separately).

* Clients must support and offer the proprietary extension
  micro-fragmentation (This repository provides an openssl
  implementation).

# Build

This repository contains an *openssl* as submodule call

   ```
   git submodule update --init --recursive
   git submodule sync
   ```

after clone/checkout.

The simplest way to build the project is to call

   ```
   ./release.sh
   ```

to produce binaries in `.build`. See the script it self for details.

# Certificate Trust Chain

* The trust chain is defined as follows:

  Cherry Secure Board CA -> Theobroma Systems Production Certificate -> SECUREBOARD Device Certificate

* The certificates (public part) are maintained and published at

  https://github.com/secureboard10/secureboard-ca.

  After downloading/updating your local copy. Prepare it for use with openssl:

    ```
    c_rehash <path-to-ca>
    ```

  Also verify the fingerprint of `SecureboardRootCA.pem`:

   ```
   $ openssl x509 -noout -fingerprint -sha256 -inform pem -in SecureboardRootCA.pem
     SHA256 Fingerprint=2E:1E:CB:35:76:EF:D4:AF:77:0C:91:0B:C3:48:00:9B: \
                        F7:BF:E2:1C:DB:EC:41:08:8D:6B:28:94:13:6C:38:BE

   $ openssl x509 -noout -fingerprint -sha1 -inform pem -in SecureboardRootCA.pem
     SHA1 Fingerprint=88:A0:59:94:FD:E8:EE:D0:C9:24:EA:A0:F1:F5:01:24:64:E2:B9:D1
   ```

* This trust chain can only be used to verify that the device genuineness, and for device personalizing.

* To allow to operate in *Secure Keyboard Mode* a *User Certificate*
  and *User Key* **must** be loaded into the device.

  Thus step must be executed in a *Secure Environment* (e.g.: offline PC).

# Relay Daemon (sb-relayd)

*sb-relayd* is a service the relays TLS1.3 records between secure
boards and libsecureboard. It has to be started after the SECUREBOARD
1.0 is connected. Systemd and udev rules are provided in this
repository.

The following files need to be installed at the proper locations to
work with systemd/udev:

   ```
   /sbin/sb-relayd
   /etc/sb-relayd.conf
   /etc/udev/rules.d/95-secureboard.rules
   /lib/systemd/system/sb-relayd@.service
   ```

After installing the files and reload the rules:

   ```
   sudo systemctl daemon-reload
   sudo udevadm control --reload-rules
   sudo udevadm trigger
   ```

and after reconnecting a SECUREBOARD 1.0 the a service should show
up:

   ```
   # sudo systemctl | grep SECUREBOARD
   sb-relayd@00000002JS0405948N5LI0OTHA.service   loaded active running   "SECUREBOARD 1.0 Relay Daemon 00000002JS0405948N5LI0OTHA"
   ```

With its abstract namespace socket:

   ```
   $ netstat -lnp | grep SECUREBOARD
   unix  2  [ ACC ]  STREAM   LISTENING   42128  -   @SECUREBOARD1.0-00000002JS0405948N5LI0OTHA
   ```

Once the relay daemon is running, the secure keyboard mode can be
activated with (see <path-to>/sb-tool -h for further options):

   ```
   sudo <path-to>/sb-tool --ca-dir <path-to-ca> -u @SECUREBOARD1.0-<device-serial>
   ```

or, to enable SKM Linux OS binding, by:

   ```
   sudo <path-to>/sb-tool --ca-dir <path-to-ca> -u @SECUREBOARD1.0-<device-serial> --evdev
   ```

*Note: The SECUREBOARD 1.0 needs to be personalized for the commands*
*above to work. See Below*

# Certificate Creation (Device Personalization)

## User Device Certificates

Restrictions:

1) User Certificate must be an X509 Version 3 Certificate

2) The size of the DER encoded certificate must no exeed 572 bytes.

Example to cCreate a Root CA (Keep subject short to to fit into the 572 limit):

   ```
   export CADIR=<path-to-your-ca>
   export KEYDIR=<path-to-a-secure-storage>
   export CONFIGFILE=<path-to-openssl.cnf>
   export USER_DEVICE_ROOT_CA=device_root_ca

   cd $CADIR
   openssl req -days 3650 -config $CONFIGFILE -sha256 -new -x509 \
      -newkey ec:<(openssl ecparam -name prime256v1)             \
      -subj "/C=AT/O=User Company/CN=SB Root"                    \
      -keyout $KEYDIR/$USER_DEVICE_ROOT_CA-key.pem -out $USER_DEVICE_ROOT_CA.pem
   c_rehash $CADIR
   ```

If you have multiple SECUREBOARD 1.0 you can reuse the Root CA for multiple devices.

Example; Create and sign a Device Certificate (Keep subject short to to fit into the 572 limit):

   ```
   export TMPDIR=/tmp
   export USER_DEVICE=device01
   cd $TMPDIR
   openssl req -config $CONFIGFILE -sha256 -new                  \
       -newkey ec:<(openssl ecparam -name prime256v1)            \
       -subj "/C=AT/O=User Company/CN=$USER_DEVICE"              \
       -keyout $USER_DEVICE-key.pem -out $USER_DEVICE-csr.pem
   openssl x509 -sha256 -days 3650 -req -in $USER_DEVICE-csr.pem \
       -CA $CADIR/$USER_DEVICE_ROOT_CA.pem                       \
       -CAkey $KEYDIR/$USER_DEVICE_ROOT_CA-key.pem               \
       -extfile $(dirname $CONFIGFILE)/production.ext            \
       -CAcreateserial -out $USER_DEVICE.der --outform DER

   # certificate signing request is no longer required
   rm $TMPDIR/$USER_DEVICE-csr.pem
   ```

If you have more than one SECUREBOARD 1.0 it is highly recommended to
create a unique certificate for each device you own.

## Uploading

After creating the Certificates they have to be uploaded to the Device:

   ```
   # Assuming sb-relayd is running in default configuration
   sb-tool                                                 \
       -u @SECUREBOARD1.0-<device-serial>                  \
       --ca-dir <path-to-secureboard-ca>                   \
       --user-cert $TMPDIR/$USER_DEVICE.der                \
       --user-priv-key $TMPDIR/$USER_DEVICE-key.pem

   # Certificate and key are no longer required
   rm $TMPDIR/$USER_DEVICE.der $TMPDIR/$USER_DEVICE-key.pem
   ```

## Client Certificate

Restrictions:

1) The size of the DER encoded certificate must no exceed 475
   bytes. This applies to each certificate in the chain (including the
   root certificate).

   If you use the root CA also for client certificates (which is
   possible), the 475 byte restriction also applies to the root CA.

Once a root CA is initialized with a fingerprint the device requests a
client certificate when connecting not using a PSK session. The client
*must* send the complete certificate chain and starting with the
client certificate (use a --ca-dir with a directory containing all
certificates in the chain). The secure board verifies the signature of
each certificate sent in the chain.

A connection is accepted if:

1) The signature of each item in the chain can be verified with the
   public key of the following item in the chain (see TLS13
   Certificate).

2) The fingerprint (sha256 of the DER encoded certificate) of the last
   item in the chain matches the fingerprint of the root CA. This
   certificate may or may not be self signed.

3) The client can proof that it posses the private key of the client
   certificate by generating a valid signature of the handshake
   traffic (see TLS13 CertificateVerify).

Notes on client certificates:

The devices memory and computation power is restricted. The following
limitations apply:

1) The DER encoded size of each certificate in the chain must not
   exceed 475 bytes. Especially when using Verision 3 certificated
   this can oppose a limitation.  Secure board accepts Version 3
   certificates, but does *NOT ENCFORCE* them.

   To print the size of the DER encoded certificate the following CLI
   can be used:

   ```
   openssl x509 -in <certificate> -out - -outform DER | wc -c
   ```

2) Signature Verification takes about 2 seconds per signature. This
   can significantly increase handshake time when using longer chains.

   When reconnecting using PSK sessions (-s), no certificates are sent
   and verified at all. Use them to speed up handshake significantly.

### Example of creating a client certificate chain

1) Generate the root CA (Especially when using longer subjects, verify
   the certificate length). Use the same commands as for the Device
   Certificate root CA. You may even use the Device Certificate Root
   CA to sign you client certificates.

2) Generate one or more Client Certificates signed by the root ca:

   ```
   export CLIENT_NAME=bob
   cd $CADIR
   openssl req -config $CONFIGFILE -sha256 -new                       \
       -newkey ec:<(openssl ecparam -name prime256v1)                 \
       -subj "/C=AT/O=User Company/CN=$CLIENT_NAME"                   \
       -keyout $KEYDIR/$CLIENT_NAME-key.pem -out $CLIENT_NAME-csr.pem
   openssl x509 -sha256 -days 365 -req                                \
       -in $CLIENT_NAME-csr.pem -CA $CADIR/$USER_DEVICE_ROOT_CA.pem   \
       -CAkey $KEYDIR/$USER_DEVICE_ROOT_CA-key.pem                    \
       -extfile $(dirname $CONFIGFILE)/device.ext                     \
       -CAcreateserial -out $CADIR/$CLIENT_NAME.pem
   rm $CLIENT_NAME-csr.pem
   c_rehash $CADIR		     
   ```

## Upload the Client Root CA into the SECUREBOARD 1.0

   ```
   # Note, that since the CA has already been provisioned into the
   # SECUREBOARD 1.0 # the --ca-dir option changed.   
   sb-tool                                \
       -u @SECUREBOARD1.0-<device-serial> \
       --ca-dir $CADIR                    \
       --user-root-ca $CADIR/$USER_DEVICE_ROOT_CA.pem
   ```

# TODOs

* Extend sb-relayd to support non abstract AF_UNIT sockets
