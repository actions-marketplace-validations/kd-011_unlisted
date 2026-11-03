---
slug: unlisted
name: unlisted
repo: .
status: active
last_verified: 2026-11-03
tags: [cli, go, homelab]
---

A read-only command line tool that compares the services you say you run with what your machine exposes. The claims below are the README's main promises, each tied to the code that keeps it.

## Features

- Reports five finding types: unregistered, dead, noauth, drift and cert. <!-- src: internal/check/types.go:9-16 -->
- Exits 0 when clean, 1 on findings that match `--fail-on`, and 2 on an error. <!-- src: internal/cli/cli.go:28-33 -->
- Makes no network calls unless `--probe` is passed, and then contacts only hostnames from the registry. <!-- src: internal/cli/cli.go:210-212, internal/cli/cli.go:236 -->
- A probe gives up after 5 seconds by default. <!-- src: internal/probe/probe.go:47-50 -->
- A certificate with fewer than 14 days left is flagged as expiring soon. <!-- src: internal/check/check.go:43-46, internal/check/check.go:478 -->
- A registry field it does not know is an error with a line number and a closest-match hint. <!-- src: internal/registry/registry.go:105-111 -->
- A service with none of `host`, `port` or `url` is rejected. <!-- src: internal/registry/registry.go:145-147 -->
- `init` refuses to overwrite an existing file unless `--force` is given. <!-- src: internal/cli/cli.go:267-269 -->
- A non-empty `NO_COLOR` turns colour off, and `--no-color` wins over everything else. <!-- src: internal/report/style.go:14-20 -->
- A source that is missing or unreadable is recorded in the report and skipped, and never stops the run. <!-- src: internal/discover/types.go:101-125 -->

## Architecture

- Builds are static with `CGO_ENABLED=0`, and CI builds one on every run. <!-- src: Makefile:4, .github/workflows/ci.yml:30 -->

## Deploy

- Releases are built for linux amd64, linux arm64 and darwin arm64. <!-- src: .goreleaser.yml:15-19 -->
- The GitHub Action skips the live sources `proc`, `docker` and `systemd` by default. <!-- src: action.yml:33-36 -->
- CI runs `go vet` and `go test -race` on every pull request and once a week. <!-- src: .github/workflows/ci.yml:9-10, .github/workflows/ci.yml:26-28 -->

<!-- auto:start -->
- go module: github.com/kd-011/unlisted
- go version: 1.22
- go requires (1): gopkg.in/yaml.v3
<!-- auto:end -->
