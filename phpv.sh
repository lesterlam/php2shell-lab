#!/usr/bin/env bash
#
# Run a PHP interpreter out of an extracted Docker-image rootfs, using that
# rootfs's own dynamic loader. No chroot, no root, no Docker daemon required.
#
#   ./phpv.sh 8.4.26 -v
#   ./phpv.sh 8.4.26 -d memory_limit=64M -S 127.0.0.1:8426 -t www
#
# Expects runtimes/php-<version>/rootfs (populate with ./fetch-php.sh).
# Override the runtimes location with PHP_LAB_RUNTIMES.
#
set -euo pipefail

VER="${1:?usage: phpv.sh <version> [php args...]}"; shift
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIMES="${PHP_LAB_RUNTIMES:-$HERE/runtimes}"
R="$RUNTIMES/php-$VER/rootfs"

if [ ! -x "$R/usr/local/bin/php" ]; then
  echo "phpv: no runtime for PHP $VER at $R" >&2
  echo "      run: ./fetch-php.sh $VER" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64)  LOADER="lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
           LIBDIRS="usr/local/lib usr/lib/x86_64-linux-gnu lib/x86_64-linux-gnu" ;;
  aarch64) LOADER="lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"
           LIBDIRS="usr/local/lib usr/lib/aarch64-linux-gnu lib/aarch64-linux-gnu" ;;
  *) echo "phpv: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

LIBPATH=""
for d in $LIBDIRS; do LIBPATH="$LIBPATH:$R/$d"; done

exec "$R/$LOADER" --library-path "${LIBPATH#:}" "$R/usr/local/bin/php" "$@"
