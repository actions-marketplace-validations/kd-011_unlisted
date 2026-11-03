// Package demo holds the fake homelab that `unlisted demo` and the README
// screenshot run against. It is a fixture tree in the --config-root layout.
package demo

import "embed"

// Files is the whole tree: registry.yml plus etc/, proc/, docker/ and systemd/.
//
//go:embed all:registry.yml all:etc all:proc all:docker all:systemd
var Files embed.FS
