#! /bin/bash

set -ex

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
source $DIR/scv.sh
source $DIR/VERSION
VERSION=$PROJECT_NUMBER

OUTPUT_DIRECTORY=$DIR/.build
BUILDDOC=0

while getopts "ho:d" arg; do
    case $arg in
	h)
	    echo "usage: $(basename $0) -o <output> -d"
	    exit 1
	    ;;
	o)
	    mkdir -p $OPTARG
	    OUTPUT_DIRECTORY=$(cd $OPTARG; pwd)
	    ;;
	d)
	    BUILDDOC=1
	    ;;
    esac
done

$DIR/bootstrap.sh
if [ $BUILDDOC == 1 ]; then
    $DIR/builddoc.sh -o $OUTPUT_DIRECTORY/doc
fi
mkdir -p $OUTPUT_DIRECTORY
cd $OUTPUT_DIRECTORY && cmake $DIR -DCMAKE_INSTALL_PREFIX=
make -C $OUTPUT_DIRECTORY
make -C $OUTPUT_DIRECTORY DESTDIR=$OUTPUT_DIRECTORY/libsecureboard install
cd $OUTPUT_DIRECTORY && tar --transform "s/^libsecureboard/libsecureboard-$VERSION/" -czvf libsecureboard-$VERSION$HASH.tar.gz libsecureboard
