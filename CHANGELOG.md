# Changelog

All notable changes are listed here, newest first. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [semantic versioning](https://semver.org/).

## Unreleased

## 0.2.0 - 2026-11-03

### Added

- `unlisted demo` checks the example homelab that is built into the binary, so a fresh install has something to look at without a checkout. It reads nothing from your machine and exits 0.
- Running `unlisted` with no `registry.yml` lists everything the machine exposes and says how to write a registry, where it used to stop with an error. Naming a missing file with `-f` is still an error.
- `install.sh` installs the release binary for Linux or macOS without Go, and refuses to install if the checksum does not match.
- A note in the report when cloudflared is running but no config file with routes was found. A tunnel managed in the Cloudflare dashboard keeps its hostnames there, so unlisted cannot read them.
- Docs for install, reference, registry, the Action, limitations and alternatives. They hold what the README used to carry.

### Changed

- The README is shorter. It leads with the demo output, one install command and what not to use the tool for.
- `make screenshot` builds both demo images from `unlisted demo`.
- The release workflow uses goreleaser-action v7.3.0 (Dependabot #4). A snapshot release with GoReleaser 2 built the same three archives and checksums.

### Fixed

- Sockets and built-ins were read as ports. nginx `http://unix:/path:/uri/` and Caddy `unix//path` showed as host `unix` on port 80, and cloudflared `bastion` as port 80. They now show as sockets or `bastion` and no longer feed port checks.

## 0.1.1 - 2026-11-03

### Added

- Weekly Dependabot updates for Go modules and GitHub Actions, grouped by minor and patch with a seven-day cooldown. Updates that qualify merge on their own once CI is green.
- A weekly upkeep workflow that checks the links in the docs and the project dossier, and opens one issue per problem.
- A dossier for this repository with a committed lock file.
- Security policy, code of conduct, issue and pull request templates.

### Changed

- CI also runs once a week and can be started by hand.
- The GoReleaser action in the release workflow is pinned to a commit. The release behaves as before.

## 0.1.0

First release.

- `unlisted check` compares a registry of services with cloudflared, Caddy, nginx, Docker and listening sockets, and reports `UNREGISTERED`, `DEAD`, `NOAUTH`, `DRIFT` and `CERT` findings.
- `unlisted init` writes a registry from what the machine exposes now.
- `--probe`, JSON and Markdown output, and a GitHub Action.
