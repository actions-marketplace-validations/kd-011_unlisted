# GitHub Action

To check a registry that lives in a repo, for example a GitOps homelab that keeps its Caddyfile, tunnel config and registry together:

```yaml
name: unlisted
on: [push, pull_request]

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: kd-011/unlisted@v0
        with:
          registry: registry.yml
          caddyfile: caddy/Caddyfile
          cloudflared: cloudflared/config.yml
          fail-on: unregistered,dead,drift
```

The runner is not your server, so the action skips the live sources (`proc`, `docker`, `systemd`) by default and compares the registry with the config files you point it at. The inputs are `registry`, `version`, `fail-on`, `format`, `cloudflared`, `caddyfile`, `nginx-dir`, `config-root`, `skip`.

