from __future__ import annotations


def parse_hosts(scanner, source_network: str) -> list[dict]:
       """Parse python-nmap scanner results into stable host records."""

       hosts = []
       for host in scanner.all_hosts():
              item = scanner[host]
              addresses = item.get("addresses", {})
              services = {}
              ports = []
              for protocol in ("tcp", "udp"):
                     for port, service in item.get(protocol, {}).items():
                            ports.append(port)
                            services[str(port)] = {**service, "protocol": protocol}
              hosts.append({
                     "ip": host,
                     "hostname": _hostname(item),
                     "state": item.state(),
                     "mac": addresses.get("mac"),
                     "source_network": source_network,
                     "ports": sorted(ports),
                     "services": services,
              })
       return hosts


def _hostname(item) -> str | None:
       for hostname in item.hostnames():
              name = hostname.get("name")
              if name:
                     return name
       return None

