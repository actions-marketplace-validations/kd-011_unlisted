VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PKG     := github.com/kd-011/unlisted
LDFLAGS := -s -w -X $(PKG)/internal/cli.Version=$(VERSION)
export CGO_ENABLED = 0

.PHONY: build test vet dist demo screenshot clean

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o unlisted .

vet:
	go vet ./...

# The race detector needs cgo, so only this target turns it back on.
test: vet
	CGO_ENABLED=1 go test -race ./...

dist:
	rm -rf dist && mkdir -p dist
	GOOS=linux  GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/unlisted_linux_amd64 .
	GOOS=linux  GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/unlisted_linux_arm64 .
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/unlisted_darwin_arm64 .
	cd dist && sha256sum unlisted_* > checksums.txt

demo: build
	./unlisted check -f demo/registry.yml --config-root demo

screenshot: build
	CLICOLOR_FORCE=1 ./unlisted check -f demo/registry.yml --config-root demo \
	  | python3 scripts/render-demo.py "unlisted check -f registry.yml" docs/demo.png

clean:
	rm -rf unlisted dist
