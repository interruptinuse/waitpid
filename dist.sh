#!/usr/bin/env bash

set -ex

export TZ=UTC
export TAR_OPTIONS="--owner=user:1000 --group=user:1000 --numeric-owner"
export GZIP="--rsyncable --no-name -9"

autoreconf -fvi
./configure --host=i686-w64-mingw32 CXXFLAGS="-g0"

make clean
make
i686-w64-mingw32-strip --strip-all waitpid.exe

make waitpid.1.html
make dist
