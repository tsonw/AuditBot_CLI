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
              return ipaddress.IPv4Address(value or "0.0.0.0")
       except (TypeError, ValueError):
              return ipaddress.IPv4Address("0.0.0.0")


def _sort_port(value):
       try:
              return int(value)
       except (TypeError, ValueError):
              return 0


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

       for result in results:
              network = result.get("network") or "unknown network"
              interface = result.get("interface") or "-"
              scanner_ip = result.get("ip") or "-"
              source = result.get("source") or "-"
              scan_method = result.get("scan_method") or "-"
              hosts = sorted(result.get("hosts", []), key=lambda host: _sort_ip(host.get("ip")))
              host_count = result.get("hosts_found", len(hosts))

              net_node = root.add(
                     "[bold]Network[/bold] "
                     f"[cyan]{escape(network)}[/cyan] "
                     f"[dim]interface={escape(interface)} source={escape(source)} "
                     f"scan={escape(scan_method)} hosts={host_count}[/dim]"
              )

              net_node.add(f"[dim]scanner ip: {escape(scanner_ip)}[/dim]")

              if result.get("via"):
                     net_node.add(f"[yellow]gateway: {escape(result['via'])}[/yellow]")

              for error in result.get("errors", []):
                     message = error.get("error") or "unknown warning"
                     net_node.add(f"[red]warning: {escape(message)}[/red]")

              if not hosts:
                     net_node.add("[dim]no hosts discovered[/dim]")
                     continue

              for host in hosts:
                     ip = host.get("ip") or "-"
                     mac = host.get("mac") or "-"
                     method = host.get("discovery_method") or "-"
                     host_node = net_node.add(
                            f"[green]{escape(ip)}[/green] "
                            f"[dim]mac={escape(mac)} method={escape(method)}[/dim]"
                     )

                     ports = host.get("ports") or []
                     services = host.get("services") or {}

                     if not ports:
                            host_node.add("[dim]no open ports found in scanned range[/dim]")
                            continue

                     for port in sorted(ports, key=_sort_port):
                            service = services.get(port) or services.get(str(port)) or {}
                            host_node.add(escape(_service_label(port, service)))

       console.print(root)
       return True
