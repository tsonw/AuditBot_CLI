import json
import ipaddress
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.tree import Tree

console = Console()

SCAN_PREFIXES = (
       "full_scan",
       "discovery",
       "lab_discovery",
       "audit_snapshot",
)


def _has_topology_data(data):
       return isinstance(data, dict) and bool(
              data.get("network_results")
              or data.get("hosts")
              or data.get("networks")
       )


def _sort_ip(value):
       try:
              address = ipaddress.ip_address(str(value or "0.0.0.0").split("%", 1)[0])
              return (address.version, int(address))
       except (TypeError, ValueError):
              return (0, 0)


def _sort_port(value):
       try:
              return int(value)
       except (TypeError, ValueError):
              return 0


def _display_ip_with_prefix(ip_value, network_value):
       if not ip_value:
              return "-"

       try:
              network = ipaddress.ip_network(network_value, strict=False)
       except (TypeError, ValueError):
              return ip_value

       return f"{ip_value}/{network.prefixlen}"


def _host_identity(host):
       hostname = (host.get("hostname") or "").strip()

       if hostname:
              return ("hostname", hostname.lower(), hostname)

       mac = (host.get("mac") or "").strip().lower()
       if mac:
              return ("mac", mac, f"unknown ({mac})")

       ip = host.get("ip") or "unknown"
       return ("ip", ip, f"unknown ({ip})")


def _group_hosts_by_identity(hosts):
       grouped = {}

       for host in hosts:
              key = _host_identity(host)
              grouped.setdefault(key, []).append(host)

       return grouped


def _service_label(port, service):
       name = service.get("name") or "unknown"
       product = service.get("product") or ""
       version = service.get("version") or ""
       extrainfo = service.get("extrainfo") or ""
       state = service.get("state") or "open"
       detail = " ".join(value for value in [product, version, extrainfo] if value)

       if detail:
              return f"{port}/tcp {name} ({detail}) [{state}]"

       return f"{port}/tcp {name} [{state}]"


def _group_hosts_by_network(data):
       grouped = {}

       for host in data.get("hosts", []):
              network = host.get("source_network") or "unknown network"
              grouped.setdefault(network, []).append(host)

       results = []
       known_networks = data.get("networks") or []

       for network in known_networks:
              cidr = network.get("network") or "unknown network"
              hosts = grouped.pop(cidr, [])
              results.append({
                     **network,
                     "hosts": hosts,
                     "hosts_found": len(hosts),
                     "errors": [],
              })

       for cidr, hosts in grouped.items():
              results.append({
                     "network": cidr,
                     "interface": None,
                     "ip": None,
                     "via": None,
                     "source": "hosts",
                     "scan_method": "-",
                     "hosts": hosts,
                     "hosts_found": len(hosts),
                     "errors": [],
              })

       return results


def load_latest_topology_snapshot(output_dir=Path("outputs/raw")):
       if not output_dir.exists():
              return None, None

       candidates = []

       for prefix in SCAN_PREFIXES:
              candidates.extend(output_dir.glob(f"{prefix}_*.json"))

       for path in sorted(candidates, key=lambda item: item.stat().st_mtime, reverse=True):
              try:
                     data = json.loads(path.read_text())
              except (OSError, json.JSONDecodeError):
                     continue

              if _has_topology_data(data):
                     return data, path

       return None, None


def render_topology(data, source_label=None):
       if not _has_topology_data(data):
              console.print("[yellow]No discovery data available to draw topology.[/yellow]")
              return False

       results = data.get("network_results") or _group_hosts_by_network(data)
       root = Tree("[bold cyan]Infrastructure Topology[/bold cyan]")

       if source_label:
              root.add(f"[dim]source: {escape(str(source_label))}[/dim]")

       all_hosts = []

       for result in results:
              all_hosts.extend(result.get("hosts", []))

              for error in result.get("errors", []):
                     message = error.get("error") or "unknown warning"
                     network = error.get("network") or result.get("network") or "unknown network"
                     root.add(
                            f"[red]warning:[/red] {escape(network)} "
                            f"[dim]{escape(message)}[/dim]"
                     )

       if not all_hosts:
              root.add("[dim]no hosts discovered[/dim]")
              console.print(root)
              return True

       grouped_hosts = _group_hosts_by_identity(all_hosts)

       for identity, hosts in sorted(grouped_hosts.items(), key=lambda item: item[0][2].lower()):
              hostname = identity[2]
              hosts_by_interface = {}

              for host in hosts:
                     interface_key = (
                            host.get("source_interface") or "-",
                            host.get("source_network") or "-",
                            host.get("family") or "-",
                            host.get("mac") or "-",
                            host.get("discovery_method") or "-",
                     )
                     hosts_by_interface.setdefault(interface_key, []).append(host)

              host_node = root.add(
                     f"[bold green]Host[/bold green] {escape(hostname)} "
                     f"[dim]interfaces={len(hosts_by_interface)} ips={len(hosts)}[/dim]"
              )

              for interface_key, interface_hosts in sorted(
                     hosts_by_interface.items(),
                     key=lambda item: (item[0][0], item[0][1], item[0][2])
              ):
                     interface, network, family, mac, method = interface_key
                     interface_node = host_node.add(
                            f"[bold]Interface[/bold] {escape(interface)} "
                            f"[dim]network={escape(network)} family={escape(family)} "
                            f"mac={escape(mac)} method={escape(method)}[/dim]"
                     )

                     for host in sorted(interface_hosts, key=lambda item: _sort_ip(item.get("ip"))):
                            ip_label = _display_ip_with_prefix(
                                   host.get("ip"),
                                   host.get("source_network")
                            )
                            gateway = host.get("source_gateway") or "-"
                            ip_node = interface_node.add(
                                   f"[cyan]{escape(ip_label)}[/cyan] "
                                   f"[dim]gateway={escape(gateway)}[/dim]"
                            )

                            ports = host.get("ports") or []
                            services = host.get("services") or {}

                            if not ports:
                                   ip_node.add("[dim]no open ports found in scanned range[/dim]")
                                   continue

                            for port in sorted(ports, key=_sort_port):
                                   service = services.get(port) or services.get(str(port)) or {}
                                   ip_node.add(escape(_service_label(port, service)))

       console.print(root)
       return True
