#!/usr/bin/env bash
# Build liboqs into third_party/liboqs (no root required).
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
ver="${LIBOQS_VERSION:-0.16.0}"
prefix="$here/third_party/liboqs"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "== cloning liboqs $ver =="
git clone --depth 1 --branch "$ver" \
  https://github.com/open-quantum-safe/liboqs.git "$work/liboqs"

echo "== configuring =="
cmake -S "$work/liboqs" -B "$work/build" -GNinja \
  -DCMAKE_INSTALL_PREFIX="$prefix" \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_DIST_BUILD=ON

echo "== building =="
ninja -C "$work/build"

echo "== installing to $prefix =="
ninja -C "$work/build" install

echo "done. now run: make -C src"
