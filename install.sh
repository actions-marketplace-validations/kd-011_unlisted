#!/bin/sh
# Install the unlisted release binary without Go.
#   curl -fsSL https://raw.githubusercontent.com/kd-011/unlisted/main/install.sh | sh
# UNLISTED_VERSION=v0.1.1 pins a release; UNLISTED_BIN=/usr/local/bin changes the target.
set -eu

repo=kd-011/unlisted
bin=${UNLISTED_BIN:-$HOME/.local/bin}

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) echo "no release binary for $(uname -s); try: go install github.com/$repo@latest" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) echo "no release binary for $(uname -m); try: go install github.com/$repo@latest" >&2; exit 1 ;;
esac
if [ "$os-$arch" = darwin-amd64 ]; then
  echo "no release binary for Intel Macs; try: go install github.com/$repo@latest" >&2
  exit 1
fi

if [ -n "${UNLISTED_VERSION:-}" ]; then
  base="https://github.com/$repo/releases/download/$UNLISTED_VERSION"
else
  base="https://github.com/$repo/releases/latest/download"
fi
file="unlisted_${os}_${arch}.tar.gz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$base/$file" -o "$tmp/$file"
curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt"

# Check the download against the published checksum before unpacking it.
want=$(grep " $file\$" "$tmp/checksums.txt" | cut -d' ' -f1)
if command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "$tmp/$file" | cut -d' ' -f1)
else
  got=$(shasum -a 256 "$tmp/$file" | cut -d' ' -f1)
fi
if [ -z "$want" ] || [ "$want" != "$got" ]; then
  echo "checksum mismatch for $file, not installing" >&2
  exit 1
fi

tar -xzf "$tmp/$file" -C "$tmp" unlisted
mkdir -p "$bin"
install -m 0755 "$tmp/unlisted" "$bin/unlisted"
echo "installed $("$bin/unlisted" version) to $bin/unlisted"
case ":$PATH:" in
  *":$bin:"*) ;;
  *) echo "add $bin to your PATH" ;;
esac
