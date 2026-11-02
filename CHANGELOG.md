# Changelog

All notable changes are listed here, newest first. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [semantic versioning](https://semver.org/).

## Unreleased

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
