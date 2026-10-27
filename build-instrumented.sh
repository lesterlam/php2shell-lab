#!/usr/bin/env bash
# Build an instrumented php 8.4.26 from source.
#
# Why this exists: the stage-3 measurement (see docs/ANALYSIS.md §7) is only
# reproducible if the instrumented build is. A binary is not an artefact you can
# ship in a repo, so ship the recipe.
#
# The result is a stock php 8.4.26 plus three fprintf()s that print the addresses
# involved in the stale session-id read. Nothing about the vulnerability is
# changed -- the probes only observe. Behaviour is unmodified, so this build is
# only useful for measuring, not for demonstrating the bug's effect.
#
# Build prerequisites: a C compiler, make, curl, tar. Notably NOT needed:
# autoconf, bison, re2c -- the release tarball ships a pre-generated `configure`
# and pre-generated parsers, so a source *release* builds without them. A git
# checkout would not.
#
# Usage:
#   ./build-instrumented.sh              # build into ./build-instrumented
#   BUILD_DIR=/tmp/instr ./build-instrumented.sh
set -euo pipefail

VERSION=8.4.26
# Integrity pin: the tarball this lab builds against. php.net publishes GPG
# signatures (.asc) rather than plain checksums; signature verification is left
# to the reader. This pin catches a corrupted or substituted download.
TARBALL_SHA256=c248abaebc4bb777b80968f0760da0da8e989836e896c9ff637b6775d7d37662
URL="https://www.php.net/distributions/php-$VERSION.tar.gz"

HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${BUILD_DIR:-$HERE/build-instrumented}"
SRC="$BUILD_DIR/php-$VERSION"

for tool in cc make curl tar; do
  command -v "$tool" >/dev/null || { echo "missing build tool: $tool" >&2; exit 1; }
done

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

if [ ! -f "php-$VERSION.tar.gz" ]; then
  echo "==> fetching $URL"
  curl -fsSL -o "php-$VERSION.tar.gz" "$URL"
fi

echo "==> verifying tarball"
echo "$TARBALL_SHA256  php-$VERSION.tar.gz" | sha256sum -c -

if [ ! -d "$SRC" ]; then
  echo "==> extracting"
  tar -xzf "php-$VERSION.tar.gz"
else
  echo "==> source tree present"
fi

# Use the probe-aware check, not a marker grep: an interrupted run can leave one
# probe in place, and a marker test would then skip the other two.
if python3 "$HERE/instrument-php.py" --check "$SRC" >/dev/null 2>&1; then
  echo "==> already fully instrumented"
else
  if [ -d "$SRC" ]; then
    echo "==> incomplete instrumentation -- re-extracting"
    rm -rf "$SRC"
    tar -xzf "php-$VERSION.tar.gz"
  fi
  echo "==> instrumenting"
  python3 "$HERE/instrument-php.py" "$SRC"
  python3 "$HERE/instrument-php.py" --check "$SRC"
fi

# Down-date the autotools *inputs* so make's regeneration rules cannot fire.
# On a CI runner autoconf/bison/re2c are installed, and a tarball whose mtimes
# happen to be unfavourable would then rebuild `configure` and the parsers with
# whatever tool versions the image ships -- a different build from the one this
# lab measured, on a path nobody is testing. The tarball's own pre-generated files
# are the ones we want, and an old input mtime pins that choice without needing
# those tools present at all (which is why the local build worked: they were absent).
find "$SRC" \( -name 'configure.ac' -o -name 'aclocal.m4' -o -name '*.re' -o -name '*.y' \) \
     -exec touch -d '2000-01-01T00:00:00Z' {} + 2>/dev/null || true
touch "$SRC/configure" "$SRC/Makefile.global" 2>/dev/null || true

echo "==> configuring (CLI SAPI + session only: a minimal build is a fast build)"
cd "$SRC"
if [ ! -f Makefile ]; then
  ./configure --disable-all --enable-cli --enable-session \
              --without-pear --prefix="$BUILD_DIR/install" \
              > "$BUILD_DIR/configure.log" 2>&1 || {
    echo "configure failed -- see $BUILD_DIR/configure.log" >&2; exit 1; }
fi

echo "==> building"
make -j"$(nproc)" > "$BUILD_DIR/make.log" 2>&1 || {
  echo "make failed -- see $BUILD_DIR/make.log" >&2; exit 1; }

PHP="$SRC/sapi/cli/php"
echo
echo "built: $PHP"
"$PHP" -v | head -1
"$PHP" -r 'echo "session ext: ", (extension_loaded("session") ? "yes" : "NO"), "\n";'
echo
echo "Run it with stderr captured, then point stage3.py at that log:"
echo "  PHP_CLI_SERVER_WORKERS=4 $PHP -S 127.0.0.1:18626 -t www \\"
echo "      2>logs/instr-server.log &"
echo "  ./stage3.py --port 18626 --log logs/instr-server.log all"
