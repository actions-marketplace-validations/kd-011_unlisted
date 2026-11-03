// Package cli wires flags to the rest of unlisted. Run returns an exit code
// instead of calling os.Exit so every path is testable.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	demofiles "github.com/kd-011/unlisted/demo"
	"github.com/kd-011/unlisted/internal/adopt"
	"github.com/kd-011/unlisted/internal/check"
	"github.com/kd-011/unlisted/internal/discover"
	"github.com/kd-011/unlisted/internal/probe"
	"github.com/kd-011/unlisted/internal/registry"
	"github.com/kd-011/unlisted/internal/report"
)

// Version is set at build time with -ldflags "-X .../internal/cli.Version=v0.1.0".
var Version = "dev"

// Exit codes. They are part of the interface: CI depends on them.
const (
	ExitClean    = 0
	ExitFindings = 1
	ExitError    = 2
)

const usage = `unlisted: diff what you say you run against what is actually exposed.

Usage:
  unlisted [check] [flags]    compare the registry with this machine (default)
  unlisted init [flags]       scan this machine and write a starter registry
  unlisted demo [flags]       run check against a built-in fake homelab
  unlisted version

Check flags:
  -f FILE            registry file (default registry.yml)
  --json             machine-readable output (same as --format json)
  --format FMT       text (default), json or markdown
  --probe            HTTPS-probe each registry host: status and TLS expiry
  --no-color         plain output (NO_COLOR is also honoured)
  --fail-on LIST     finding types that make the exit code 1
                     unregistered,dead,noauth,drift,cert,all,none (default all)

Source flags (check and init):
  --config-root DIR  resolve every default path under DIR, for fixtures
                     (env UNLISTED_ROOT)
  --cloudflared FILE cloudflared config.yml
  --caddyfile FILE   Caddyfile
  --nginx-dir DIR    nginx config directory
  --docker-sock FILE Docker socket
  --skip LIST        sources to skip: cloudflared,caddy,nginx,docker,proc,systemd

Init flags:
  -o FILE            where to write (default registry.yml, - for stdout)
  --force            overwrite an existing file

Exit codes: 0 clean, 1 findings matching --fail-on, 2 error.
`

// Run executes one invocation.
func Run(args []string, stdout, stderr io.Writer) int {
	cmd := "check"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "check":
		return runCheck(args, stdout, stderr)
	case "init":
		return runInit(args, stdout, stderr)
	case "demo":
		return runDemo(args, stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "unlisted %s\n", version())
		return ExitClean
	case "help":
		fmt.Fprint(stdout, usage)
		return ExitClean
	}
	fmt.Fprintf(stderr, "unlisted: unknown command %q\n\n%s", cmd, usage)
	return ExitError
}

func version() string {
	if Version != "dev" {
		return Version
	}
	// go install builds carry the module version in the build info.
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

type sourceFlags struct {
	root, cloudflared, caddyfile, nginxDir, dockerSock, skip string
}

func (s *sourceFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&s.root, "config-root", os.Getenv("UNLISTED_ROOT"), "")
	fs.StringVar(&s.cloudflared, "cloudflared", "", "")
	fs.StringVar(&s.caddyfile, "caddyfile", "", "")
	fs.StringVar(&s.nginxDir, "nginx-dir", "", "")
	fs.StringVar(&s.dockerSock, "docker-sock", "", "")
	fs.StringVar(&s.skip, "skip", "", "")
}

func (s sourceFlags) env() discover.Env {
	return discover.Env{
		Root: s.root, Cloudflared: s.cloudflared, Caddyfile: s.caddyfile,
		NginxDir: s.nginxDir, DockerSock: s.dockerSock, Skip: discover.ParseSkip(s.skip),
	}
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func runCheck(args []string, stdout, stderr io.Writer) int {
	return checkWith(args, stdout, stderr, "")
}

// runDemo checks the fake homelab compiled into the binary. It unpacks the
// fixture tree to a temp directory, because every source reads real paths, and
// exits 0 even with findings: the findings are the point.
func runDemo(args []string, stdout, stderr io.Writer) int {
	dir, err := os.MkdirTemp("", "unlisted-demo-")
	if err != nil {
		return fail(stderr, "%v", err)
	}
	defer os.RemoveAll(dir)
	err = fs.WalkDir(demofiles.Files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		dst := filepath.Join(dir, filepath.FromSlash(p))
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		b, err := demofiles.Files.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o644)
	})
	if err != nil {
		return fail(stderr, "unpacking the demo: %v", err)
	}
	base := []string{"-f", filepath.Join(dir, "registry.yml"), "--config-root", dir, "--fail-on", "none"}
	return checkWith(append(base, args...), stdout, stderr, "demo/registry.yml")
}

// checkWith is check. A non-empty label replaces the registry path in output.
func checkWith(args []string, stdout, stderr io.Writer, label string) int {
	fs := newFlagSet("check", stderr)
	var src sourceFlags
	src.register(fs)
	regPath := fs.String("f", "registry.yml", "")
	asJSON := fs.Bool("json", false, "")
	format := fs.String("format", "text", "")
	doProbe := fs.Bool("probe", false, "")
	noColor := fs.Bool("no-color", false, "")
	failOn := fs.String("fail-on", "all", "")
	if code, done := parse(fs, args, stdout, stderr); done {
		return code
	}

	if *asJSON {
		*format = "json"
	}
	if *format != "text" && *format != "json" && *format != "markdown" {
		return fail(stderr, "unknown --format %q (use text, json or markdown)", *format)
	}
	failTypes, err := check.ParseTypes(*failOn)
	if err != nil {
		return fail(stderr, "--fail-on: %v", err)
	}

	named := false
	fs.Visit(func(f *flag.Flag) { named = named || f.Name == "f" })

	noRegistry := false
	reg, err := registry.Load(*regPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fail(stderr, "%v", err)
		}
		if named {
			return fail(stderr, "%s not found. Run 'unlisted init' to write a starter registry, or pass -f", *regPath)
		}
		// First run: no file was asked for and none exists. Report what the
		// machine exposes instead of an error.
		reg, noRegistry = &registry.Registry{}, true
	}
	if label != "" {
		reg.Path = label
	}

	snap := discover.Run(src.env(), discover.AllSources())
	in := check.Input{Registry: reg, Snap: snap}
	if *doProbe {
		in.ProbeRan = true
		in.Probes = probe.Hosts(probeHosts(reg), probe.Options{})
	}
	rep := check.Run(in)
	rep.NoRegistry = noRegistry

	exit := ExitClean
	if rep.Failing(failTypes) > 0 {
		exit = ExitFindings
	}

	switch *format {
	case "json":
		if err := report.WriteJSON(stdout, report.BuildJSON(rep, version(), failTypes, exit)); err != nil {
			return fail(stderr, "%v", err)
		}
	case "markdown":
		report.Markdown(stdout, rep)
	default:
		f, _ := stdout.(*os.File)
		report.Text(stdout, rep, report.Style{Color: report.DetectColor(*noColor, f != nil && report.IsTTY(f))})
	}
	return exit
}

// probeHosts is every concrete registry hostname. --probe touches nothing else.
func probeHosts(reg *registry.Registry) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range reg.Services {
		if s.Ignore || s.Host == "" || strings.Contains(s.Host, "*") || seen[s.Host] {
			continue
		}
		seen[s.Host] = true
		out = append(out, s.Host)
	}
	return out
}

func runInit(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("init", stderr)
	var src sourceFlags
	src.register(fs)
	out := fs.String("o", "registry.yml", "")
	force := fs.Bool("force", false, "")
	if code, done := parse(fs, args, stdout, stderr); done {
		return code
	}

	snap := discover.Run(src.env(), discover.AllSources())
	res := adopt.Build(snap)

	if *out == "-" {
		fmt.Fprint(stdout, res.YAML)
		return ExitClean
	}
	if _, err := os.Stat(*out); err == nil && !*force {
		return fail(stderr, "%s already exists; pass --force to overwrite it, or -o to write elsewhere", *out)
	}
	if err := os.WriteFile(*out, []byte(res.YAML), 0o644); err != nil {
		return fail(stderr, "%v", err)
	}
	fmt.Fprintf(stdout, "wrote %s: %d hostnames, %d listening ports\n", *out, res.Hosts, res.Ports)
	for _, ig := range res.Ignored {
		fmt.Fprintf(stdout, "  marked ignore: %s\n", ig)
	}
	if res.AuthNone > 0 {
		fmt.Fprintf(stdout, "  %d written with auth: none because no auth was detected; review them\n", res.AuthNone)
	}
	fmt.Fprintf(stdout, "next: unlisted check -f %s\n", *out)
	return ExitClean
}

// parse handles flag errors and -h uniformly. done reports that the caller
// should return code immediately.
func parse(fs *flag.FlagSet, args []string, stdout, stderr io.Writer) (code int, done bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return ExitClean, true
		}
		return fail(stderr, "%v (see unlisted help)", err), true
	}
	if fs.NArg() > 0 {
		return fail(stderr, "unexpected argument %q (see unlisted help)", fs.Arg(0)), true
	}
	return 0, false
}

func fail(stderr io.Writer, format string, a ...any) int {
	fmt.Fprintf(stderr, "unlisted: "+format+"\n", a...)
	return ExitError
}
