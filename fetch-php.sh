#!/usr/bin/env bash
#
# Download an official PHP image from Docker Hub and extract its rootfs into
# runtimes/php-<version>/ -- using only the Registry HTTP API. This works
# without a Docker daemon, without root, and inside a container.
#
#   ./fetch-php.sh 8.4.26            # pulls php:8.4.26-cli
#   ./fetch-php.sh 8.4.26 apache     # pulls php:8.4.26-apache (for the mod_php SAPI)
#
# Result is run by ./phpv.sh.
#
set -euo pipefail

VER="${1:?usage: fetch-php.sh <version> [sapi]}"
SAPI="${2:-cli}"
TAG="$VER-$SAPI"

REPO="library/php"
REG="https://registry-1.docker.io"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIMES="${PHP_LAB_RUNTIMES:-$HERE/runtimes}"
DEST="$RUNTIMES/php-$VER"

if [ -x "$DEST/rootfs/usr/local/bin/php" ]; then
  echo "[=] $DEST already present, nothing to do"
  exit 0
fi

mkdir -p "$DEST"
cd "$DEST"

echo "[*] auth token"
TOKEN=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:$REPO:pull" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')
AUTH=(-H "Authorization: Bearer $TOKEN")
MANIFEST_ACCEPT='application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json'

echo "[*] resolving $REPO:$TAG"
curl -sf "${AUTH[@]}" -H "Accept: $MANIFEST_ACCEPT" \
  "$REG/v2/$REPO/manifests/$TAG" -o index.json

MDIG=$(python3 - <<'PY'
import json
d = json.load(open('index.json'))
if 'manifests' not in d:
    print('SELF')
else:
    for m in d['manifests']:
        p = m.get('platform', {})
        if p.get('os') == 'linux' and p.get('architecture') in ('amd64',):
            print(m['digest']); break
    else:
        raise SystemExit('no linux/amd64 manifest in index')
PY
)

if [ "$MDIG" != "SELF" ]; then
  curl -sf "${AUTH[@]}" -H "Accept: $MANIFEST_ACCEPT" \
    "$REG/v2/$REPO/manifests/$MDIG" -o manifest.json
else
  cp index.json manifest.json
fi

mkdir -p rootfs
n=0
for dg in $(python3 -c 'import json; [print(l["digest"]) for l in json.load(open("manifest.json"))["layers"]]'); do
  n=$((n+1))
  echo "[*] layer $n/$dg"
  curl -sfL "${AUTH[@]}" "$REG/v2/$REPO/blobs/$dg" -o layer.tmp
  # Docker layers are gzip (or zstd); let tar auto-detect via python magic check.
  if head -c 4 layer.tmp | od -An -tx1 | grep -q '1f 8b'; then
    tar -xzf layer.tmp -C rootfs
  elif head -c 4 layer.tmp | od -An -tx1 | grep -qi '28 b5 2f fd'; then
    tar --zstd -xf layer.tmp -C rootfs
  else
    tar -xf layer.tmp -C rootfs
  fi
  rm -f layer.tmp
done

echo "[=] done -> $DEST/rootfs"
"$HERE/phpv.sh" "$VER" -v | head -1
