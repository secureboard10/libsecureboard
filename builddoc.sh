#! /bin/bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source $DIR/scv.sh
source $DIR/VERSION
VERSION=$PROJECT_NUMBER

DOXGEN_DOC_OUTPUT_DIRECTORY=$DIR/doc

while getopts "ho:" arg; do
    case $arg in
	h)
	    echo "usage: builddoc.sh -o <output>"
	    exit 1
	    ;;
	o)
	    mkdir -p $OPTARG
	    DOXGEN_DOC_OUTPUT_DIRECTORY=$(cd $OPTARG; pwd)
	    ;;
    esac
done

export DOXGEN_DOC_OUTPUT_DIRECTORY

build_doc() {
    cd $DIR/src && doxygen doc/doxygen.config
}

archive_doc() {
    cd $DIR/.build && tar --transform "s/^doc/libsecureboard-doc-$VERSION/" -czvf libsecureboard-doc-$VERSION$HASH.tar.gz doc
}

if [ ! which doxygen ]; then
    echo "doxygen binary not in path. Pleasy install doxygen." 1>&2
    exit 1
fi

build_doc
archive_doc
