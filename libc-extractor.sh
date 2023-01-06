#!/bin/sh

# ./libc-extractor.sh 20.04
# check arguments
if [ $# -ne 1 ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 20.04"
    exit 1
fi

# we extract the libc from docker image
docker pull ubuntu:$1

# extract the libc
docker run --rm -v $(pwd):/mnt \
    -u $(id -u):$(id -g) \
    -it ubuntu:$1 bash -c "cp /lib/x86_64-linux-gnu/libc*.so /mnt"
