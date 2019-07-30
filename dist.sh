#!/usr/bin/env bash

set -ex

export TZ=UTC

autoreconf -fvi
./configure --host=i686-w64-mingw32 CXXFLAGS="-g0"

make
i686-w64-mingw32-strip --strip-debug waitpid.exe

make waitpid.1.html
TAR_OPTIONS="--owner=user:1000 --group=user:1000 --numeric-owner" GZIP="--rsyncable --no-name -9" make dist
