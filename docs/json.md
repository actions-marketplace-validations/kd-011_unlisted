# JSON output

`unlisted check --json` (or `--format json`) writes one JSON document to stdout. The schema is versioned in the `schema` field. It changes only when a field is removed or changes meaning; new optional fields can appear at any time, so consumers should ignore keys they do not know.

Output is deterministic for a given machine state: no timestamps, stable ordering.

```json
{
  "schema": "unlisted/v1",
  "version": "v0.1.0",
  "registry": "registry.yml",
  "services": 16,
  "sources": [
    { "name": "cloudflared", "state": "ok", "count": 10, "unit": "rules", "paths": ["/etc/cloudflared/config.yml"] },
    { "name": "docker", "state": "absent", "count": 0 }
  ],
  "summary": {
    "total": 15,
    "by_type": { "unregistered": 9, "dead": 2, "noauth": 2, "drift": 2, "cert": 0 },
    "by_severity": { "high": 3, "medium": 9, "low": 3 },
    "fail_on": ["unregistered", "dead", "noauth", "drift", "cert"],
    "failing": 15,
    "exit_code": 1
  },
  "findings": [
    {
      "type": "unregistered",
      "severity": "high",
      "service": "old-wiki.example.com",
      "host": "old-wiki.example.com",
      "port": 8087,
      "message": "served via tunnel → localhost:8087 · no auth detected",
      "where": [{ "source": "cloudflared", "file": "/etc/cloudflared/config.yml", "line": 23 }],
      "fix": "add it to the registry, or remove the tunnel ingress rule"
    }
  ],
  "notes": []
}
```

## Fields

| Field | Type | Notes |
| --- | --- | --- |
| `schema` | string | `unlisted/v1`. |
| `version` | string | Binary version. |
| `registry` | string | Registry path as given with `-f`. |
| `services` | number | Entries in the registry. |
| `sources[]` | array | One per discovery source, always all six. |
| `sources[].state` | string | `ok`, `absent` (not on this machine), `skipped` (`--skip`) or `error` (present but unreadable; see `detail`). |
| `sources[].count`, `unit` | number, string | Headline count, for example 10 `rules`. |
| `summary.by_type` | object | Always has every type: `unregistered`, `dead`, `noauth`, `drift`, `cert`. |
| `summary.by_severity` | object | Always has `high`, `medium`, `low`. |
| `summary.fail_on` | array | The types that count toward the exit code. |
| `summary.failing` | number | Findings of those types. |
| `summary.exit_code` | number | `0` or `1`. Errors (exit 2) produce no JSON. |
| `findings[]` | array | Sorted by type, then severity, then name. Never `null`. |
| `findings[].type` | string | `unregistered`, `dead`, `noauth`, `drift` or `cert`. |
| `findings[].severity` | string | `high`, `medium` or `low`. |
| `findings[].service` | string | Registry name, or the hostname or process for unregistered items. |
| `findings[].host`, `port` | string, number | Present when known. |
| `findings[].message` | string | What was found. |
| `findings[].where[]` | array | `{source, file?, line?, detail?}`. `source` is `registry`, `cloudflared`, `caddy`, `nginx`, `docker` or `proc`. |
| `findings[].fix` | string | One-line suggestion. |
| `probes[]` | array | Only with `--probe`: `{host, status?, error?, ms?, cert_days_left?, cert_error?, auth_hint?}`. |
| `notes[]` | array | Things that could not be checked, as plain sentences. |
