#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
mkdir -p dist

for target in \
  linux/amd64 linux/arm64 \
  darwin/amd64 darwin/arm64 \
  windows/amd64 windows/arm64
do
  os=${target%/*}
  arch=${target#*/}
  suffix=""
  if [ "$os" = "windows" ]; then
    suffix=".exe"
  fi
  output="dist/syndichan-node-${os}-${arch}${suffix}"
  echo "building ${output}"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build -trimpath -ldflags="-s -w" -o "$output" ./cmd/syndichan-node
done
