#!/usr/bin/env bash
# Fetch the BouncyCastle provider jar used by the interoperability test.
set -euo pipefail

ver="${BC_VERSION:-1.79}"
dest="${1:-bcprov-jdk18on-$ver.jar}"
url="https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/$ver/bcprov-jdk18on-$ver.jar"

echo "downloading $url"
curl -fsSL -o "$dest" "$url"
echo "wrote $dest"
