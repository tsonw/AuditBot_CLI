import json
import ipaddress
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.tree import Tree

console = Console()

SCAN_PREFIXES = (
       "comprehensive_audit",
       "full_scan",
       "discovery",
       "lab_discovery",
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


def _asset_identity(host):
       asset_id = host.get("asset_id")
       if asset_id:
              return asset_id

       hostname = (host.get("hostname") or "").strip()
       if hostname:
              return f"hostname:{hostname.lower()}"

       mac = (host.get("mac") or "").strip().lower()
       if mac:
              return f"mac:{mac}"

       ip = host.get("ip") or "unknown"
       return f"ip:{ip}"


def _asset_label(hosts):
       host = hosts[0]
       hostname = (host.get("hostname") or "").strip()
       if hostname:
              return hostname

       mac = (host.get("mac") or "").strip().lower()
       if mac:
              return f"unknown ({mac})"

       return f"unknown ({host.get('ip') or 'no-ip'})"


def _group_hosts_by_identity(hosts):
       grouped = {}

       for host in hosts:
              key = _asset_identity(host)
              grouped.setdefault(key, []).append(host)

       return grouped


def _service_label(port, service):
       name = service.get("name") or "unknown"
       protocol = service.get("protocol") or "tcp"
       product = service.get("product") or ""
       version = service.get("version") or ""
       extrainfo = service.get("extrainfo") or ""
       state = service.get("state") or "open"
       detail = " ".join(value for value in [product, version, extrainfo] if value)

       if detail:
              return f"{port}/{protocol} {name} ({detail}) [{state}]"

       return f"{port}/{protocol} {name} [{state}]"


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


def load_latest_topology_snapshot(output_dir=Path("output/raw")):
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
              root.add(f"[yellow]source: {escape(str(source_label))}[/yellow]")

       all_hosts = []

       for result in results:
              all_hosts.extend(result.get("hosts", []))

              for error in result.get("errors", []):
                     message = error.get("error") or "unknown warning"
                     network = error.get("network") or result.get("network") or "unknown network"
                     root.add(
                            f"[red]warning:[/red] {escape(network)} "
                            f"[yellow]{escape(message)}[/yellow]"
                     )

       if not all_hosts:
              root.add("[yellow]no hosts discovered[/yellow]")
              console.print(root)
              return True

       grouped_hosts = _group_hosts_by_identity(all_hosts)

       for asset_id, hosts in sorted(grouped_hosts.items(), key=lambda item: _asset_label(item[1]).lower()):
              hostname = _asset_label(hosts)
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
                     f"[yellow]asset_id={escape(asset_id)} "
                     f"confidence={escape(hosts[0].get('identity_confidence') or 'unknown')} "
                     f"interfaces={len(hosts_by_interface)} ips={len(hosts)}[/yellow]"
              )

              if hosts[0].get("identity_reason"):
                     host_node.add(
                            f"[yellow]identity: {escape(hosts[0]['identity_reason'])}[/yellow]"
                     )

              for interface_key, interface_hosts in sorted(
                     hosts_by_interface.items(),
                     key=lambda item: (item[0][0], item[0][1], item[0][2])
              ):
                     interface, network, family, mac, method = interface_key
                     interface_id = interface_hosts[0].get("interface_id") or "-"
                     interface_node = host_node.add(
                            f"[bold]Interface[/bold] {escape(interface)} "
                            f"[yellow]network={escape(network)} family={escape(family)} "
                            f"interface_id={escape(interface_id)} mac={escape(mac)} "
                            f"method={escape(method)}[/yellow]"
                     )

                     for host in sorted(interface_hosts, key=lambda item: _sort_ip(item.get("ip"))):
                            ip_label = _display_ip_with_prefix(
                                   host.get("ip"),
                                   host.get("source_network")
                            )
                            gateway = host.get("source_gateway") or "-"
                            ip_node = interface_node.add(
                                   f"[cyan]{escape(ip_label)}[/cyan] "
                                   f"[yellow]gateway={escape(gateway)}[/yellow]"
                            )

                            ports = host.get("ports") or []
                            services = host.get("services") or {}

                            if not ports:
                                   ip_node.add("[yellow]no open ports found in scanned range[/yellow]")
                                   continue

                            for port in sorted(ports, key=_sort_port):
                                   service = services.get(port) or services.get(str(port)) or {}
                                   ip_node.add(escape(_service_label(port, service)))

       console.print(root)
       return True
