#! /bin/bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

OPENSSL_SRC=$DIR/external/openssl
OPENSSL_PREFIX=$DIR/external/.build/openssl

configure_openssl() {
    cd $OPENSSL_SRC ; ./config no-shared --prefix=$OPENSSL_PREFIX
}

build_openssl() {
    make -C $OPENSSL_SRC -j $(nproc)
}

install_openssl() {
    make install_sw
}

configure_openssl
build_openssl
install_openssl
