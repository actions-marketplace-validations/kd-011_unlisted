# Alternatives

`unlisted` answers one question: where do the services I wrote down and the things my machine exposes disagree. These tools answer nearby questions. I have not run them side by side on one machine, so this covers what each is for and says nothing about how they perform.

`ss -tlnp` and `docker ps` ship with the system and show what is listening and what is published. They know nothing about what you meant to run, and they cannot tell you which hostname a Caddy block or a tunnel rule serves. `unlisted` reads the same sockets and the same Docker API and adds the intent and the hostnames.

nmap scans the network and ndiff diffs two scans ([ndiff](https://nmap.org/book/ndiff-man-exit-code.html) reports changes in port state between two scan files). That is the right tool for what is reachable from outside, which `unlisted` cannot tell you because it never sees your router or firewall. A scan only finds ports, though. Cloudflare describes tunnels as outbound-only connections, so a hostname published through one has no inbound port to find. If you only run a tunnel, a scan will show nothing and `unlisted` will list the hostnames.

A dashboard such as [Homepage](https://hub.docker.com/r/gethomepage/homepage) can pick up services from Docker container labels. It shows what you labelled or configured. It does not set out to report what is exposed and was never labelled.

An uptime monitor such as [Uptime Kuma](https://github.com/louislam/uptime-kuma) checks over time that the things you list are up. That overlaps with the `DEAD` finding, which `unlisted` works out from config and sockets in one run, or with `--probe` from an HTTPS request. It does not cover exposure.

The Docker source is there because of how Docker publishes ports. Docker's [packet filtering docs](https://docs.docker.com/engine/network/packet-filtering-firewalls/) say published container ports are handled before ufw's rules see the traffic, and that a port published without an address is available on every host address. A container you forgot can be open without any firewall rule saying so. `unlisted` lists those and marks each as bound to every address or to loopback only.
