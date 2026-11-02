# Security

## Reporting a vulnerability

Please use GitHub private vulnerability reporting: open the Security tab of this repository and choose "Report a vulnerability". That keeps the report private until a fix is out. Please do not open a public issue for something exploitable.

Include the command you ran, a sanitised snippet of the config involved, what you expected and what happened.

## What is in scope

`unlisted` reads configuration files and system state, and writes a file only for `unlisted init`. It makes no network calls unless you pass `--probe`. The areas most worth a look:

- The Caddy, nginx and cloudflared parsers, which read files you may not fully control (includes, odd syntax, very large files).
- The Docker source, which talks to the Docker socket over plain HTTP.
- `--probe`, which contacts only the hostnames in your registry.
- `unlisted init`, which must not overwrite an existing file without `--force`.
- The GitHub Action in `action.yml`, which downloads a release binary.

## Supported versions

Only the latest release gets fixes.
