#!/usr/bin/env python3
"""Regenerate the fake /proc tree and Docker listing under demo/.

The kernel's /proc/net/tcp is hex in host byte order, which is unpleasant to
edit by hand. Add a row to LISTENERS or CONTAINERS below and run:

    python3 scripts/gen-demo-fixture.py demo

Fixture-only: process fd entries are plain files holding the link target.
"""
import json
import os
import shutil
import sys

# port, bind address, pid, comm, cmdline, systemd unit (or None)
LISTENERS = [
    (22,   "0.0.0.0",   812,  "sshd",            "sshd: /usr/sbin/sshd -D",            "ssh"),
    (80,   "0.0.0.0",   901,  "caddy",           "caddy run --config /etc/caddy/Caddyfile", "caddy"),
    (443,  "0.0.0.0",   901,  "caddy",           "caddy run --config /etc/caddy/Caddyfile", "caddy"),
    (8443, "0.0.0.0",   955,  "nginx",           "nginx: master process /usr/sbin/nginx",   "nginx"),
    (445,  "0.0.0.0",   1033, "smbd",            "/usr/sbin/smbd --foreground",        "smbd"),
    (1883, "0.0.0.0",   1102, "mosquitto",       "/usr/sbin/mosquitto -c /etc/mosquitto/mosquitto.conf", "mosquitto"),
    (3000, "127.0.0.1", 1190, "grafana",         "/usr/share/grafana/bin/grafana server", "grafana-server"),
    (3001, "127.0.0.1", 1244, "node",            "node server/server.js",              None),
    (8053, "127.0.0.1", 1301, "pihole-FTL",      "/usr/bin/pihole-FTL -f",             "pihole-FTL"),
    (8112, "127.0.0.1", 1360, "qbittorrent-nox", "/usr/bin/qbittorrent-nox --webui-port=8112", "qbittorrent-nox"),
    (8123, "0.0.0.0",   1412, "hass",            "/srv/homeassistant/bin/hass -c /config", "home-assistant"),
    (8222, "127.0.0.1", 1478, "vaultwarden",     "/usr/bin/vaultwarden",               "vaultwarden"),
    (8765, "0.0.0.0",   2217, "python3",         "python3 -m http.server 8765",    None),
    (8989, "127.0.0.1", 1533, "Sonarr",          "/opt/Sonarr/Sonarr -nobrowser",      "sonarr"),
    (9091, "127.0.0.1", 1601, "authelia",        "/usr/bin/authelia --config /etc/authelia/config.yml", None),
    # Docker publishes. docker-proxy owns the socket on the host side.
    (1880, "0.0.0.0",   3010, "docker-proxy", "/usr/bin/docker-proxy -proto tcp -host-port 1880", "docker"),
    (3100, "127.0.0.1", 3011, "docker-proxy", "/usr/bin/docker-proxy -proto tcp -host-port 3100", "docker"),
    (6379, "0.0.0.0",   3012, "docker-proxy", "/usr/bin/docker-proxy -proto tcp -host-port 6379", "docker"),
    (8010, "127.0.0.1", 3013, "docker-proxy", "/usr/bin/docker-proxy -proto tcp -host-port 8010", "docker"),
    (8081, "127.0.0.1", 3014, "docker-proxy", "/usr/bin/docker-proxy -proto tcp -host-port 8081", "docker"),
    (8087, "127.0.0.1", 3015, "docker-proxy", "/usr/bin/docker-proxy -proto tcp -host-port 8087", "docker"),
    (8088, "127.0.0.1", 3016, "docker-proxy", "/usr/bin/docker-proxy -proto tcp -host-port 8088", "docker"),
    (8096, "0.0.0.0",   3017, "docker-proxy", "/usr/bin/docker-proxy -proto tcp -host-port 8096", "docker"),
    (9000, "0.0.0.0",   3018, "docker-proxy", "/usr/bin/docker-proxy -proto tcp -host-port 9000", "docker"),
    (9999, "127.0.0.1", 3019, "docker-proxy", "/usr/bin/docker-proxy -proto tcp -host-port 9999", "docker"),
]

# name, image, host bind, host port, container port
CONTAINERS = [
    ("jellyfin",   "jellyfin/jellyfin:10.9",       "0.0.0.0",   8096, 8096),
    ("paperless",  "paperlessngx/paperless-ngx:2", "127.0.0.1", 8010, 8000),
    ("nextcloud",  "nextcloud:29-apache",          "127.0.0.1", 8081, 80),
    ("dozzle",     "amir20/dozzle:latest",         "127.0.0.1", 9999, 8080),
    ("dokuwiki",   "dokuwiki/dokuwiki:stable",     "127.0.0.1", 8087, 8080),
    ("phpmyadmin", "phpmyadmin:5",                 "127.0.0.1", 8088, 80),
    ("grafana-dev", "grafana/grafana:11.1.0",      "127.0.0.1", 3100, 3000),
    ("redis",      "redis:7-alpine",               "0.0.0.0",   6379, 6379),
    ("portainer",  "portainer/portainer-ce:2.20",  "0.0.0.0",   9000, 9000),
    ("node-red",   "nodered/node-red:3",           "0.0.0.0",   1880, 1880),
]


def hex_v4(ip):
    return "".join("%02X" % int(p) for p in reversed(ip.split(".")))


def hex_v6_wild_or_loop(ip):
    if ip == "0.0.0.0":
        return "0" * 32
    # ::1 is four little-endian words, the last being 01000000
    return "00000000" * 3 + "01000000"


def main(root):
    proc = os.path.join(root, "proc")
    shutil.rmtree(proc, ignore_errors=True)
    os.makedirs(os.path.join(proc, "net"))

    head = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
            "   uid  timeout inode\n")
    v4, v6 = [head], [head]
    inode = 40000
    for n, (port, ip, pid, comm, cmd, unit) in enumerate(LISTENERS):
        inode += 7
        line = "%4d: %s:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000 %5d        0 %d 1 0000000000000000 100 0 0 10 0\n"
        v4.append(line % (n, hex_v4(ip), port, 0, inode))
        # Wildcard binds on a dual-stack host also show up in tcp6.
        if ip == "0.0.0.0" and port in (22, 445, 1883, 8765):
            inode += 1
            v6.append(line % (n, hex_v6_wild_or_loop(ip), port, 0, inode))
            _write_pid(proc, pid, comm, cmd, unit, [inode, inode - 1])
        else:
            _write_pid(proc, pid, comm, cmd, unit, [inode])
    # An established connection must be ignored.
    v4.append("  99: 0100007F:C350 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 99999 1 0000000000000000 100 0 0 10 0\n")
    open(os.path.join(proc, "net", "tcp"), "w").write("".join(v4))
    open(os.path.join(proc, "net", "tcp6"), "w").write("".join(v6))

    ports = []
    for name, image, ip, host, private in CONTAINERS:
        entry = {"Names": ["/" + name], "Image": image, "Ports": [
            {"IP": ip, "PrivatePort": private, "PublicPort": host, "Type": "tcp"}]}
        if ip == "0.0.0.0":
            entry["Ports"].append({"IP": "::", "PrivatePort": private, "PublicPort": host, "Type": "tcp"})
        ports.append(entry)
    ports.append({"Names": ["/watchtower"], "Image": "containrrr/watchtower", "Ports": [
        {"PrivatePort": 8080, "Type": "tcp"}]})
    os.makedirs(os.path.join(root, "docker"), exist_ok=True)
    with open(os.path.join(root, "docker", "containers.json"), "w") as f:
        json.dump(ports, f, indent=1)
        f.write("\n")


_written = set()


def _write_pid(proc, pid, comm, cmd, unit, inodes):
    d = os.path.join(proc, str(pid))
    os.makedirs(os.path.join(d, "fd"), exist_ok=True)
    open(os.path.join(d, "comm"), "w").write(comm + "\n")
    # /proc/PID/cmdline separates arguments with NUL bytes.
    open(os.path.join(d, "cmdline"), "wb").write(cmd.replace(" ", "\0").encode() + b"\0")
    cg = "0::/system.slice/%s.service\n" % unit if unit else "0::/user.slice/user-1000.slice/session-3.scope\n"
    open(os.path.join(d, "cgroup"), "w").write(cg)
    base = 3 + len(os.listdir(os.path.join(d, "fd")))
    for i, ino in enumerate(inodes):
        open(os.path.join(d, "fd", str(base + i)), "w").write("socket:[%d]\n" % ino)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "demo")
