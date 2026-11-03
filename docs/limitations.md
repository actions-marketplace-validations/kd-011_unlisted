# Limitations

- Linux first. Listening sockets come from `/proc`, so macOS gets the config-file sources and Docker but no sockets. Windows is untested.
- No app-level auth detection. `NOAUTH` means no auth was found in the proxy or tunnel config or, with `--probe`, in the response. It cannot see a login page inside an app, so declare `auth:` for what you know.
- Tunnels managed in the Cloudflare dashboard ([the option Cloudflare recommends for most setups](https://developers.cloudflare.com/tunnel/advanced/local-management)) keep their hostnames at Cloudflare, so there is no config file to read. When cloudflared is running and no config is found, the report says so, and registry entries behind such a tunnel can show up as `DEAD`. Mark them `ignore: true` or keep a local config file for `--cloudflared`.
- A tunnel's Cloudflare Access policies live in the Cloudflare dashboard, not in the config file, so they are invisible unless you declare them or probe.
- A Caddy wildcard site (`*.example.com`) that routes by `@name host ...` matchers is one hostname to unlisted, with the first upstream it sees. The hosts inside it are not listed.
- nginx `stream` blocks are not parsed. A stream port still shows up as a listening port when it is bound.
- A container whose image name contains `nginx` or `caddy` is treated as your proxy when that proxy has sites, and its ports are left out of the listening list.
- Rootless Docker and Podman use another socket path. Pass it with `--docker-sock`. Not tested here.
- The Caddy and nginx parsers are tolerant readers and do not match the real servers. They do not follow dynamic config, `include` outside the usual directories or generated configs.
- A port bound beyond loopback is listening on all interfaces. Whether it is exposed to the internet depends on your router and firewall, which `unlisted` cannot see.
- Without root, other users' processes are not attributable, and the report says how many owners were hidden.
- Read-only. It never edits a config, restarts anything or fixes anything, and only `unlisted init` writes a file.
- No network unless you pass `--probe`.


## Roadmap

- Traefik and Nginx Proxy Manager sources
- DNS records through the Cloudflare API, to find hostnames that resolve to you with no rule behind them
- Prometheus metrics output
- macOS socket discovery

