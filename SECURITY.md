# Security

## Reporting a vulnerability

Please use GitHub private vulnerability reporting. Open the Security tab of this repository and choose "Report a vulnerability". The report stays private until a fix is out. Do not open a public issue for something exploitable.

Include the command you ran, a sanitised snippet of the config involved, what you expected and what happened.

## What is in scope

`unlisted` reads configuration files and system state. Only `unlisted init` writes a file, and nothing makes a network call unless you pass `--probe`. These areas are worth a look:

- The Caddy, nginx and cloudflared parsers, which read files you may not fully control (includes, odd syntax, very large files).
- The Docker source, which talks to the Docker socket over plain HTTP.
- `--probe`, which contacts only the hostnames in your registry.
- `unlisted init`, which must not overwrite an existing file without `--force`.
- The GitHub Action in `action.yml`, which downloads a release binary.

## Supported versions

Only the latest release gets fixes.
