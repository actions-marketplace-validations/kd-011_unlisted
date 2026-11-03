# Install

Three routes, all giving the same single static binary.

## Release binary, no Go needed

```sh
curl -fsSL https://raw.githubusercontent.com/kd-011/unlisted/main/install.sh | sh
```

The script picks the release for your OS and CPU (Linux amd64 and arm64, macOS arm64), checks it against the published `checksums.txt`, and puts `unlisted` in `~/.local/bin`. It stops if the checksum does not match.

```sh
UNLISTED_VERSION=v0.1.1 UNLISTED_BIN=/usr/local/bin sh install.sh   # pin a release, pick the directory
```

It is short enough to read before you pipe it to a shell: [install.sh](../install.sh).

To do it by hand, download `unlisted_<os>_<arch>.tar.gz` and `checksums.txt` from the [releases page](https://github.com/kd-011/unlisted/releases), run `sha256sum -c --ignore-missing checksums.txt`, and unpack it.

## With Go

```sh
go install github.com/kd-011/unlisted@latest
```

Needs Go 1.22 or newer. The binary lands in `$(go env GOPATH)/bin`.

## From a checkout

```sh
git clone https://github.com/kd-011/unlisted && cd unlisted
make build        # ./unlisted
```

There is no Intel Mac or Windows build. On those, `go install` works, with the limits in [limitations.md](limitations.md).
