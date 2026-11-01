# Contributing

Bug reports and small pull requests are welcome.

## Reporting a bug

The most useful report is a sanitised snippet of the config that was misread (a few lines of Caddyfile, nginx or tunnel config with hostnames swapped for `example.com`), the output you got and the output you expected.

## Working on the code

```sh
make test      # go vet and go test -race
make build     # static binary at ./unlisted
make demo      # run against the fake homelab in demo/
```

Go 1.22. The standard library first; the only dependency is `gopkg.in/yaml.v3`, and a new one needs a reason.

Tests never touch the real machine. They read fixtures under `testdata/` and `demo/` through `--config-root`. Do not add a test that reads `/etc` or `/proc`.

## Adding a discovery source

A source implements two methods (see `internal/discover/types.go`):

```go
type Source interface {
    Name() string
    Discover(env Env) (Result, error)
}
```

Return `ErrAbsent` when the tool or file is not there, and any other error for something present but unreadable. Neither stops the run. Resolve default paths with `env.resolve` so `--config-root` works, add a fixture under `testdata/`, a parser test, and register it in `AllSources`.

## Changing the report

`docs/demo.txt` is the committed copy of the demo report and a test compares it with the real output. After a deliberate change:

```sh
UPDATE_GOLDEN=1 go test ./internal/cli -run Demo
make screenshot   # regenerates docs/demo.png (needs Python and Pillow)
```

## Style

Plain comments that say why, not what. No emoji, and no em dashes in code, comments or docs. Keep commits small.
