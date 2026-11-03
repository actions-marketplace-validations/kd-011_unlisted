# Registry

`registry.yml` is a list of the services you say you run. Every field except `name` is optional, but a service needs at least one of `host`, `port` or `url`, or there is nothing to check. `unlisted init` writes a first one for you.

```yaml
services:
  - name: Jellyfin
    host: jellyfin.example.com   # public hostname
    port: 8096                   # the port the service really listens on
    auth: app                    # none | proxy | app | cloudflare-access
    owner: media                 # free text, shown nowhere important

  - name: NAS
    host: nas.example.com
    url: https://192.168.1.20:5001   # for services that live on another machine
    auth: app

  - name: SSH
    port: 22                     # no host: checked by port only
    auth: app

  - name: Old test VM
    host: test.example.com
    ignore: true                 # silences every finding for this entry
```

| Field | Meaning |
| --- | --- |
| `name` | Required. Shown in findings. |
| `host` | Public hostname. A leading `*.` registers every host beneath it. |
| `port` | The port the service listens on, compared with the tunnel or proxy origin. |
| `url` | Where the service lives when it is not on this machine. Used for the port if `port` is absent. |
| `auth` | What sits in front of it: `none` (deliberately open), `proxy` (SSO or reverse proxy auth), `app` (the application logs people in), `cloudflare-access`. Unset means "not declared", which is what `NOAUTH` fires on. |
| `owner`, `note` | Free text for humans. |
| `ignore` | `true` silences the entry, including the hostname and port it accounts for. |

Unknown fields are an error with a line number and a "did you mean" hint, so typos do not silently disable a check.

