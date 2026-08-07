#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
mkdir -p dist

# GOARM only matters for linux/arm. 6 rather than 7 so ONE 32-bit ARM build runs
# on every Pi anybody actually volunteers -- a Zero or a 1 is armv6l, a 2/3 on a
# 32-bit OS is armv7l, and armv7 code faults on the former. The installer maps
# both of those `uname -m` values to this file.
for target in \
  linux/amd64 linux/arm64 linux/arm \
  darwin/amd64 darwin/arm64 \
  windows/amd64 windows/arm64
do
  os=${target%/*}
  arch=${target#*/}
  suffix=""
  if [ "$os" = "windows" ]; then
    suffix=".exe"
  fi
  goarm=""
  if [ "$arch" = "arm" ]; then
    goarm="6"
  fi
  output="dist/syndichan-node-${os}-${arch}${suffix}"
  echo "building ${output}"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" GOARM="$goarm" \
    go build -trimpath -ldflags="-s -w" -o "$output" ./cmd/syndichan-node
done
