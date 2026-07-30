#!/usr/bin/env bash
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
object="$work/device_fpga.o"

gcc -c "$root/leechcore/device_fpga.c" \
    -I"$root/leechcore" -I"$root/includes" \
    -D LINUX -D _GNU_SOURCE \
    -O1 -fPIC -Wall -Wno-multichar -Wno-unused-variable \
    $(pkg-config libusb-1.0 --cflags) \
    -o "$object"

if nm -u "$object" |
    grep -q 'DeviceFPGA_Session_TlpFrameStep'; then
    echo "unexpected external Linux framing call" >&2
    exit 1
fi
echo "PASS: Linux framing transition is inline"
