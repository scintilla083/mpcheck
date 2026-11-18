#!/bin/sh
# Part of the mpscand daemon (GPLv2+, see mpscand/LICENSE) - derived from
# taviso/loadlibrary.
#
# Build the mpscand daemon inside a taviso/loadlibrary checkout.
#
# Usage: ./build.sh /path/to/loadlibrary
#
# The daemon links against loadlibrary's peloader/intercept, so it has to be
# built from within that checkout. This copies mpscand.c in, makes sure the
# loadlibrary libraries are built, and compiles+links mpscand next to mpclient.
set -eu

LL="${1:?usage: build.sh /path/to/loadlibrary}"
SRC="$(cd "$(dirname "$0")" && pwd)/mpscand.c"

if [ ! -f "$LL/mpclient.c" ]; then
    echo "error: $LL does not look like a loadlibrary checkout" >&2
    exit 1
fi
if [ ! -d "$LL/engine" ]; then
    echo "warning: $LL/engine is missing - add mpengine.dll + VDMs before scanning" >&2
fi

cp "$SRC" "$LL/mpscand.c"
cd "$LL"

# Build peloader + intercept (no-op if already built).
make >/dev/null

CFLAGS="-O3 -march=native -ggdb3 -m32 -std=gnu99 -fshort-wchar -Wno-multichar -Iinclude -mstackrealign"
CPPFLAGS="-DNDEBUG -D_GNU_SOURCE -I. -Iintercept -Ipeloader"
LDLIBS="intercept/libdisasm.a -Wl,--whole-archive,peloader/libpeloader.a,--no-whole-archive"
LDFLAGS="$CFLAGS -m32 -lm -Wl,--dynamic-list=exports.lst"

# shellcheck disable=SC2086
cc $CFLAGS $CPPFLAGS -c mpscand.c -o mpscand.o
# shellcheck disable=SC2086
cc $CFLAGS mpscand.o intercept/hook.o -o mpscand $LDLIBS $LDFLAGS

echo "built $LL/mpscand"
