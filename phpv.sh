#!/usr/bin/env bash
#
# Run a PHP interpreter out of an extracted image rootfs, using that rootfs's
# own dynamic loader. No chroot, no root, no Docker daemon required.
#
# Works for both libc flavours the official images ship:
#   glibc (php:8.4.26-cli)            -> ld-linux-x86-64.so.2, supports --library-path
#   musl  (php:8.4.26-fpm-alpine3.23) -> ld-musl-x86_64.so.1, needs LD_LIBRARY_PATH
#                                        (musl's loader ignores --library-path)
#
#   ./phpv.sh 8.4.26 -v
#   ./phpv.sh 8.4.26-fpm-alpine3.23 -d memory_limit=64M -S 127.0.0.1:8426 -t www
#
# The runtime name is whatever fetch-php.sh created under runtimes/.
# Override the runtimes location with PHP_LAB_RUNTIMES.
#
set -euo pipefail

RUNTIME="${1:?usage: phpv.sh <runtime> [php args...]}"; shift
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIMES="${PHP_LAB_RUNTIMES:-$HERE/runtimes}"
R="$RUNTIMES/php-$RUNTIME/rootfs"
PHP="$R/usr/local/bin/php"

if [ ! -x "$PHP" ]; then
  echo "phpv: no runtime at $R" >&2
  echo "      run: ./fetch-php.sh <version> [variant]" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64)  ARCH=x86_64 ;;
  aarch64) ARCH=aarch64 ;;
  *) echo "phpv: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

# musl first: alpine images ship no ld-linux, and their loader takes no
# --library-path flag.
if [ -e "$R/lib/ld-musl-$ARCH.so.1" ]; then
  exec env LD_LIBRARY_PATH="$R/usr/local/lib:$R/lib:$R/usr/lib" \
       "$R/lib/ld-musl-$ARCH.so.1" "$PHP" "$@"
fi

case "$ARCH" in
  x86_64)  LOADER="lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
           LIBDIRS="usr/local/lib usr/lib/x86_64-linux-gnu lib/x86_64-linux-gnu" ;;
  aarch64) LOADER="lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"
           LIBDIRS="usr/local/lib usr/lib/aarch64-linux-gnu lib/aarch64-linux-gnu" ;;
esac

if [ ! -x "$R/$LOADER" ]; then
  echo "phpv: no dynamic loader at $R/$LOADER" >&2
  exit 1
fi

LIBPATH=""
for d in $LIBDIRS; do LIBPATH="$LIBPATH:$R/$d"; done

exec "$R/$LOADER" --library-path "${LIBPATH#:}" "$PHP" "$@"
