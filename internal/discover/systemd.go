package discover

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Systemd is best effort: it lists running services so a listening process can
// be named after its unit. Nothing here can fail the run.
type Systemd struct{}

func (Systemd) Name() string { return "systemd" }

func (Systemd) Discover(env Env) (Result, error) {
	var out []byte
	if env.Root != "" {
		b, err := os.ReadFile(env.Path("/systemd/units.txt"))
		if err != nil {
			return Result{}, ErrAbsent
		}
		out = b
	} else {
		bin, err := exec.LookPath("systemctl")
		if err != nil {
			return Result{}, ErrAbsent
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		b, err := exec.CommandContext(ctx, bin, "list-units", "--type=service", "--state=running",
			"--no-legend", "--plain", "--no-pager").Output()
		if err != nil {
			return Result{}, ErrAbsent // booted without systemd, or no bus: skip quietly
		}
		out = b
	}
	units := ParseSystemctl(out)
	return Result{Units: units, Count: len(units), Unit: "units"}, nil
}

// ParseSystemctl reads `systemctl list-units --plain --no-legend` output.
func ParseSystemctl(data []byte) map[string]string {
	units := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || !strings.HasSuffix(f[0], ".service") {
			continue
		}
		units[f[0]] = strings.Join(f[4:], " ")
	}
	return units
}

var cgroupUnit = regexp.MustCompile(`([A-Za-z0-9:_.@\\-]+\.service)`)

// attributeUnits names listeners after their systemd unit, read from the
// process's cgroup. It only runs when the systemd source produced a unit list,
// so a machine without systemd never gets half-guessed unit names.
func attributeUnits(env Env, snap *Snapshot) {
	if len(snap.Units) == 0 {
		return
	}
	for i := range snap.Listeners {
		l := &snap.Listeners[i]
		if l.PID == 0 {
			continue
		}
		b, err := os.ReadFile(env.Path("/proc/" + strconv.Itoa(l.PID) + "/cgroup"))
		if err != nil {
			continue
		}
		all := cgroupUnit.FindAllString(string(b), -1)
		if len(all) == 0 {
			continue
		}
		l.Unit = strings.TrimSuffix(all[len(all)-1], ".service")
	}
}
