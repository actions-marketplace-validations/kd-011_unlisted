// unlisted compares the services you say you run with what your machine
// actually exposes, and reports the gaps.
package main

import (
	"os"

	"github.com/kd-011/unlisted/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
