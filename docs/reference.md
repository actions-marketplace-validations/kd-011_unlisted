# Reference

## What it finds

| Type | Meaning | Severity |
| --- | --- | --- |
| `UNREGISTERED` | Exposed (tunnel or proxy hostname, or a port bound beyond loopback) but not in the registry. | high when a hostname has no auth detected or a database port is open; medium for hostnames with auth, Docker publishes and static sites; low for a bare port |
| `DEAD` | In the registry, but nothing serves it: no tunnel or proxy rule for the host, the origin port is not listening, or (with `--probe`) the host does not answer. | medium |
| `NOAUTH` | Reachable through a tunnel or proxy hostname, no auth detected in front of it, and the registry does not declare any. | medium |
| `DRIFT` | The registry port differs from the origin port the tunnel or proxy actually uses. | medium |
| `CERT` | `--probe` only. TLS certificate expired, expiring within 14 days, or not verifying. | high, medium, low |

`NOAUTH` means no auth was detected. `unlisted` can see a Caddy `forward_auth` or an nginx `auth_basic`, but it cannot see a login screen inside the application. Declare it with `auth: app` and the finding goes away. Declare `auth: none` to mark the exposure as deliberate.

Each finding has a severity, the service, what was found, where it was found (file and line when known) and a one-line fix.


## Discovery sources

Each source is a small reader. If one is missing or unreadable, the sources line at the top of the output says so and the run carries on without it.

| Source | Reads | Gives |
| --- | --- | --- |
| cloudflared | `/etc/cloudflared/config.yml`, `~/.cloudflared/config.yml` | hostname to origin; `originRequest.access` counts as auth |
| Caddy | `/etc/caddy/Caddyfile` | site addresses, `reverse_proxy` targets, `forward_auth`, `basicauth`, `basic_auth`, `authenticate`, `authorize`, `jwtauth`, including through `import` of a snippet |
| nginx | `/etc/nginx` (`nginx.conf`, `conf.d`, `sites-enabled`) | `server_name`, `proxy_pass` (including `upstream` names), `auth_basic`, `auth_request` |
| Docker | the Docker socket, over plain HTTP | container name to published ports, and whether each is bound to `0.0.0.0` or `127.0.0.1` |
| listening sockets | `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/*/fd` | listening TCP ports and, where permitted, the owning process |
| systemd | `systemctl list-units --type=service --state=running` | the unit name for a listening process; skipped silently if unavailable |

When a tunnel points at a reverse proxy that points at an app, `unlisted` treats the hostname as one site and compares the proxy's backend with the registry.

Override any path:

```
--cloudflared FILE   --caddyfile FILE   --nginx-dir DIR   --docker-sock FILE
--skip docker,systemd,proc               leave sources out
--config-root DIR                        resolve every default path under DIR (also UNLISTED_ROOT)
```

The demo and the tests run with `--config-root`. It points every source at a fixture tree instead of the real machine (`DIR/etc/caddy/Caddyfile`, `DIR/proc/net/tcp`, `DIR/docker/containers.json`, and so on).

## Usage

```
unlisted [check] [-f registry.yml] [--json] [--format text|json|markdown]
                 [--probe] [--no-color] [--fail-on unregistered,dead,noauth,drift,cert]
unlisted init [-o registry.yml] [--force]
unlisted demo [--no-color]
unlisted version
```

| Flag | Meaning |
| --- | --- |
| `-f FILE` | Registry file. Default `registry.yml`. |
| `--json` | Machine-readable output. Schema in [docs/json.md](docs/json.md). |
| `--format markdown` | A report you can paste into an issue or a README. |
| `--probe` | HTTPS `HEAD` (falling back to `GET`) each registry hostname with a 5 second timeout; reports status and TLS expiry. Off by default. |
| `--no-color` | Plain output. `NO_COLOR` is honoured, and colour is off when stdout is not a terminal. `CLICOLOR_FORCE=1` forces it on. |
| `--fail-on LIST` | Finding types that make the exit code 1. Default `all`. Use `none` to always exit 0. |

With no `-f` and no `registry.yml` in the current directory, `check` treats the registry as empty and lists everything the machine exposes, with a note saying so. Naming a file with `-f` that does not exist is still an error.

`demo` unpacks a fake homelab that is built into the binary to a temporary directory, checks it and deletes it. It reads nothing from your machine and always exits 0.

Exit codes: `0` clean, `1` findings matching `--fail-on`, `2` error (bad flags, unreadable or invalid registry).

`init` writes the registry and never overwrites an existing file without `--force`. Use `-o -` to print instead.

### Probing

`--probe` is the only thing that touches the network, and it only contacts hostnames in the registry. It also looks for auth in front of each host (a Cloudflare Access redirect, a `401` with `WWW-Authenticate`, a redirect to a login page) and drops the `NOAUTH` finding for that host if it sees one. A `502`, `503` or `504`, or a failed connection, counts as `DEAD`.

