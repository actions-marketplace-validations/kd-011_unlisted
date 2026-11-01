package discover

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Proc reads listening TCP sockets from /proc/net/tcp{,6} and, where
// permissions allow, maps them to processes through /proc/*/fd. Linux only.
type Proc struct{}

func (Proc) Name() string { return "proc" }

type rawSocket struct {
	addr   net.IP
	port   int
	inode  string
	listen bool
}

func (Proc) Discover(env Env) (Result, error) {
	var socks []rawSocket
	found := false
	for _, f := range []string{"tcp", "tcp6"} {
		b, err := os.ReadFile(env.Path("/proc/net/" + f))
		if err != nil {
			continue
		}
		found = true
		socks = append(socks, ParseProcNet(b, f == "tcp6")...)
	}
	if !found {
		return Result{}, ErrAbsent
	}

	inodes := map[string]procInfo{}
	for _, s := range socks {
		if s.listen && s.inode != "0" {
			inodes[s.inode] = procInfo{}
		}
	}
	unseen := mapInodes(env, inodes)

	res := Result{Unit: "listening", Paths: []string{"/proc/net/tcp"}}
	for _, s := range socks {
		if !s.listen {
			continue
		}
		info := inodes[s.inode]
		res.Listeners = append(res.Listeners, Listener{
			Port: s.port, Addr: s.addr.String(),
			Public: !s.addr.IsLoopback(),
			PID:    info.pid, Process: info.name, Sources: []string{"proc"},
		})
	}
	res.Count = len(res.Listeners)
	if unseen > 0 && os.Geteuid() != 0 && env.Root == "" {
		// Not an error: the ports are real, only the owner is hidden.
		res.Unit = fmt.Sprintf("listening, %d owners hidden (run as root)", unseen)
	}
	return res, nil
}

// ParseProcNet parses the text of /proc/net/tcp or tcp6.
func ParseProcNet(data []byte, v6 bool) []rawSocket {
	var out []rawSocket
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		ip, port, ok := parseHexAddr(f[1], v6)
		if !ok {
			continue
		}
		out = append(out, rawSocket{addr: ip, port: port, inode: f[9], listen: f[3] == "0A"})
	}
	return out
}

// The kernel prints each 32-bit word of the address in host byte order, so on
// a little-endian machine every group of four bytes is reversed.
func parseHexAddr(s string, v6 bool) (net.IP, int, bool) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return nil, 0, false
	}
	b, err := hex.DecodeString(s[:i])
	if err != nil || (v6 && len(b) != 16) || (!v6 && len(b) != 4) {
		return nil, 0, false
	}
	for w := 0; w+4 <= len(b); w += 4 {
		b[w], b[w+1], b[w+2], b[w+3] = b[w+3], b[w+2], b[w+1], b[w]
	}
	port, err := strconv.ParseUint(s[i+1:], 16, 16)
	if err != nil {
		return nil, 0, false
	}
	ip := net.IP(b)
	if v6 {
		// ::ffff:a.b.c.d is an IPv4 socket seen through a dual-stack listener.
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
	}
	return ip, int(port), true
}

type procInfo struct {
	pid  int
	name string
}

// mapInodes fills in pid and name for each socket inode it can see and returns
// how many it could not attribute.
func mapInodes(env Env, inodes map[string]procInfo) int {
	entries, err := os.ReadDir(env.Path("/proc"))
	if err != nil {
		return len(inodes)
	}
	var pids []int
	for _, e := range entries {
		if n, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, n)
		}
	}
	sort.Ints(pids)
	for _, pid := range pids {
		dir := env.Path("/proc/" + strconv.Itoa(pid))
		fds, err := os.ReadDir(filepath.Join(dir, "fd"))
		if err != nil {
			continue // another user's process, or it just exited
		}
		var name string
		for _, fd := range fds {
			target := readLink(filepath.Join(dir, "fd", fd.Name()))
			if !strings.HasPrefix(target, "socket:[") {
				continue
			}
			ino := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			cur, want := inodes[ino]
			if !want || cur.pid != 0 {
				continue
			}
			if name == "" {
				name = processName(dir)
			}
			inodes[ino] = procInfo{pid, name}
		}
	}
	unseen := 0
	for _, v := range inodes {
		if v.pid == 0 {
			unseen++
		}
	}
	return unseen
}

// readLink resolves an fd entry. Fixtures store the target as the file's text
// because git and tarballs handle dangling symlinks badly.
func readLink(p string) string {
	if t, err := os.Readlink(p); err == nil {
		return t
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// interpreters hide what they run, so the script name is more useful.
var interpreters = map[string]bool{
	"python": true, "python3": true, "node": true, "ruby": true, "perl": true,
	"java": true, "php": true, "bash": true, "sh": true, "deno": true, "bun": true,
}

func processName(dir string) string {
	b, _ := os.ReadFile(filepath.Join(dir, "comm"))
	comm := strings.TrimSpace(string(b))
	if comm == "" {
		return ""
	}
	base := strings.TrimRight(comm, "0123456789.")
	if !interpreters[comm] && !interpreters[base] {
		return comm
	}
	cmd, _ := os.ReadFile(filepath.Join(dir, "cmdline"))
	args := strings.Split(strings.TrimRight(string(cmd), "\x00"), "\x00")
	for _, a := range args[1:] {
		if a == "-m" || strings.HasPrefix(a, "-") {
			continue
		}
		return comm + " " + filepath.Base(a)
	}
	return comm
}
