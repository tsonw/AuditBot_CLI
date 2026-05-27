import os
import ipaddress
import subprocess

import nmap
from scanners.network import get_reachable_networks, normalize_ip_mode
from scanners.arp_scanner import ArpScanner
from rich.console import Console
from rich import box
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

console = Console()

NMAP_PORTS = os.getenv(
       "AUDITBOT_NMAP_PORTS",
       "1-1024,2049,3000,3306,5000,5432,5672,5900,6379,8000-9000,9200,9300,10000"
)
NMAP_ARGUMENTS = f"-sV --version-light -p {NMAP_PORTS} -T4 --host-timeout 30s"
NMAP_TIMEOUT_SECONDS = 45
NMAP_HOST_DISCOVERY_ARGUMENTS = "-sn -T4 --host-timeout 10s"
NMAP_HOST_DISCOVERY_TIMEOUT_SECONDS = 180
COMPACT_TABLE_KWARGS = {
       "box": box.SIMPLE,
       "padding": (0, 1),
       "show_lines": False,
}


def _render_networks_table(networks):
       table = Table(title="Discovery Targets", **COMPACT_TABLE_KWARGS)
       table.add_column("#", justify="right")
       table.add_column("Network")
       table.add_column("Scanner IP")
       table.add_column("Family")
       table.add_column("Interface")
       table.add_column("Gateway")
       table.add_column("Source")
       table.add_column("Scan")
       table.add_column("Status")

       for index, net in enumerate(networks, start=1):
              status = net.get("scan_skipped_reason") or "ready"
              table.add_row(
                     str(index),
                     net["network"],
                     net.get("ip") or "-",
                     net.get("family") or "-",
                     net.get("interface") or "-",
                     net.get("via") or "-",
                     net.get("source") or "-",
                     net.get("scan_method") or "-",
                     status
              )

       console.print(table)


def _render_hosts_table(hosts):
       table = Table(title="Discovery Hosts", **COMPACT_TABLE_KWARGS)
       table.add_column("#", justify="right")
       table.add_column("IP")
       table.add_column("Hostname")
       table.add_column("Family")
       table.add_column("MAC")
       table.add_column("Interface")
       table.add_column("Gateway")
       table.add_column("Method")
       table.add_column("Service")

       for index, host in enumerate(hosts, start=1):
              display_ip = _display_ip_with_prefix(
                     host.get("ip"),
                     host.get("source_network")
              )
              open_ports = host.get("ports", [])
              services = host.get("services", {})
              service_details = []

              for port in open_ports:
                     service = services.get(port) or services.get(str(port)) or {}
                     name = service.get("name") or "-"
                     product = service.get("product") or ""
                     version = service.get("version") or ""
                     extrainfo = service.get("extrainfo") or ""
                     version_text = " ".join(
                            value for value in [product, version, extrainfo] if value
                     )

                     if version_text:
                            service_details.append(f"{port}:{name} ({version_text})")
                     else:
                            service_details.append(f"{port}:{name}")

              table.add_row(
                     str(index),
                     display_ip,
                     host.get("hostname") or "-",
                     host.get("family") or "-",
                     host.get("mac") or "-",
                     host.get("source_interface") or "-",
                     host.get("source_gateway") or "-",
                     host.get("discovery_method") or "-",
                     ", ".join(service_details) or "-"
              )

       console.print(table)


def _display_ip_with_prefix(ip_value, network_value):
       if not ip_value:
              return "-"

       try:
              network = ipaddress.ip_network(network_value, strict=False)
       except (TypeError, ValueError):
              return ip_value

       return f"{ip_value}/{network.prefixlen}"


def _render_errors_table(errors):
       if not errors:
              return

       table = Table(title="Discovery Warnings", **COMPACT_TABLE_KWARGS)
       table.add_column("Network")
       table.add_column("Interface")
       table.add_column("Error")

       for error in errors:
              table.add_row(
                     error.get("network") or "-",
                     error.get("interface") or "-",
                     error.get("error") or "-"
              )

       console.print(table)


def _clean_services(services):
       clean = {}

       for port, service in (services or {}).items():
              clean[str(port)] = {
                     key: service.get(key)
                     for key in ["state", "name", "product", "version", "extrainfo"]
                     if service.get(key)
              }

       return clean


def _clean_host(host):
       clean = {
              "ip": host.get("ip"),
              "hostname": host.get("hostname"),
              "family": host.get("family"),
              "mac": host.get("mac"),
              "source_interface": host.get("source_interface"),
              "source_network": host.get("source_network"),
              "source_gateway": host.get("source_gateway"),
              "discovery_method": host.get("discovery_method"),
              "ports": host.get("ports") or [],
              "services": _clean_services(host.get("services")),
       }

       return {
              key: value
              for key, value in clean.items()
              if value not in (None, "", {}, [])
       }


def _clean_error(error):
       clean = {
              "network": error.get("network"),
              "interface": error.get("interface"),
              "error": error.get("error"),
       }

       return {
              key: value
              for key, value in clean.items()
              if value not in (None, "")
       }


def _build_network_results(networks, hosts, errors):
       results = []

       for net in networks:
              network = net["network"]
              interface = net.get("interface")
              network_hosts = [
                     host
                     for host in hosts
                     if host.get("source_network") == network
                     and host.get("source_interface") == interface
              ]
              network_errors = [
                     error
                     for error in errors
                     if error.get("network") == network
                     and error.get("interface") == interface
              ]

              result = {
                     "network": net.get("network"),
                     "family": net.get("family"),
                     "interface": net.get("interface"),
                     "gateway": net.get("via"),
                     "scan_method": net.get("scan_method"),
                     "hosts_found": len(network_hosts),
                     "hosts": [_clean_host(host) for host in network_hosts],
                     "errors": [_clean_error(error) for error in network_errors],
              }

              results.append({
                     key: value
                     for key, value in result.items()
                     if value not in (None, "", [], {})
              })

       return results


def _host_from_nmap(scanner, ip_address, net):
       addresses = scanner[ip_address].get("addresses", {}) if ip_address in scanner.all_hosts() else {}

       return {
              "ip": ip_address,
              "hostname": _hostname_from_nmap(scanner, ip_address),
              "family": net.get("family") or _ip_family(ip_address),
              "mac": addresses.get("mac"),
              "source_interface": net["interface"],
              "source_network": net["network"],
              "source_gateway": net.get("via"),
              "discovery_method": net.get("scan_method") or "nmap"
       }


def _hostname_from_nmap(scanner, ip_address):
       if ip_address not in scanner.all_hosts():
              return None

       hostnames = scanner[ip_address].hostnames()

       for hostname in hostnames:
              name = hostname.get("name")
              if name:
                     return name

       return None


def _ip_family(value):
       try:
              return f"IPv{ipaddress.ip_address(str(value).split('%', 1)[0]).version}"
       except ValueError:
              return "-"


def _nmap_target(ip_address, interface=None):
       try:
              address = ipaddress.ip_address(str(ip_address).split("%", 1)[0])
       except ValueError:
              return ip_address

       if address.version == 6 and address.is_link_local and interface and "%" not in str(ip_address):
              return f"{ip_address}%{interface}"

       return ip_address


def _nmap_arguments(base_arguments, family):
       if family == "IPv6":
              return f"-6 {base_arguments}"

       return base_arguments


def _scan_ipv6_neighbors(net):
       interface = net.get("interface")
       command = ["ip", "-6", "neigh", "show"]

       if interface:
              command.extend(["dev", interface])

       try:
              result = subprocess.run(
                     command,
                     capture_output=True,
                     text=True,
                     check=False
              )
       except FileNotFoundError:
              return _scan_macos_ipv6_neighbors(net)

       if result.returncode != 0:
              details = result.stderr.strip() or "ip -6 neigh failed"
              raise RuntimeError(details)

       if result.stdout.strip() and "lladdr" not in result.stdout:
              macos_hosts = _scan_macos_ipv6_neighbors(net)
              if macos_hosts:
                     return macos_hosts

       network = ipaddress.IPv6Network(net["network"], strict=False)
       hosts = []
       seen = set()

       for line in result.stdout.splitlines():
              parts = line.split()

              if not parts:
                     continue

              ip_value = parts[0].split("%", 1)[0]

              try:
                     ip = ipaddress.IPv6Address(ip_value)
              except ValueError:
                     continue

              if ip not in network:
                     continue

              states = {part.lower() for part in parts}
              if states & {"failed", "incomplete", "permanent"}:
                     continue

              mac = None
              if "lladdr" in parts:
                     index = parts.index("lladdr")
                     if index + 1 < len(parts):
                            mac = parts[index + 1].lower()

              key = (ip_value, mac)
              if key in seen:
                     continue

              seen.add(key)
              hosts.append({
                     "ip": ip_value,
                     "family": "IPv6",
                     "mac": mac,
                     "source_interface": interface,
                     "source_network": net["network"],
                     "source_gateway": net.get("via"),
                     "discovery_method": "ndp"
              })

       return hosts


def _scan_macos_ipv6_neighbors(net):
       interface = net.get("interface")

       try:
              result = subprocess.run(
                     ["ndp", "-an"],
                     capture_output=True,
                     text=True,
                     check=False
              )
       except FileNotFoundError as exc:
              raise RuntimeError("IPv6 neighbor discovery requires ip or ndp") from exc

       if result.returncode != 0:
              details = result.stderr.strip() or "ndp -an failed"
              raise RuntimeError(details)

       network = ipaddress.IPv6Network(net["network"], strict=False)
       hosts = []
       seen = set()

       for line in result.stdout.splitlines():
              parts = line.split()

              if len(parts) < 2:
                     continue

              raw_ip = parts[0].strip("()")
              scoped_interface = None

              if "%" in raw_ip:
                     raw_ip, scoped_interface = raw_ip.split("%", 1)

              row_interface = scoped_interface
              if len(parts) > 2 and not row_interface:
                     row_interface = parts[2]

              if interface and row_interface and row_interface != interface:
                     continue

              states = {part.lower() for part in parts}
              if "permanent" in states or "(incomplete)" in states or "incomplete" in states:
                     continue

              try:
                     ip = ipaddress.IPv6Address(raw_ip)
              except ValueError:
                     continue

              if ip not in network:
                     continue

              mac = parts[1].lower()
              if mac in {"(incomplete)", "incomplete", "permanent"}:
                     mac = None

              key = (raw_ip, mac)
              if key in seen:
                     continue

              seen.add(key)
              hosts.append({
                     "ip": raw_ip,
                     "family": "IPv6",
                     "mac": mac,
                     "source_interface": interface,
                     "source_network": net["network"],
                     "source_gateway": net.get("via"),
                     "discovery_method": "ndp"
              })

       return hosts


def run_discovery(ip_mode: str | None = None):

       mode = normalize_ip_mode(ip_mode)
       networks = get_reachable_networks(mode)

       if not networks:
              message = f"No active {mode.upper()} network found"
              console.print(f"[red]Discovery blocked:[/red] {message}")
              return {
                     "network_results": [],
                     "error": message
              }

       # 1. Host discovery
       arp = ArpScanner()
       route_scanner = nmap.PortScanner()
       hosts = []
       errors = []
       seen_hosts = set()

       _render_networks_table(networks)

       with Progress(
              SpinnerColumn(),
              TextColumn("[progress.description]{task.description}"),
              BarColumn(),
              MofNCompleteColumn(),
              TimeElapsedColumn(),
              console=console
       ) as progress:
              network_task = progress.add_task("Scanning networks", total=len(networks))

              for net in networks:
                     network = net["network"]
                     interface = net["interface"]
                     scan_method = net.get("scan_method", "arp")

                     progress.update(
                            network_task,
                            description=f"Scanning {network} ({scan_method})"
                     )

                     if scan_method == "skip":
                            message = net.get("scan_skipped_reason", "network scan skipped")
                            errors.append({
                                   "interface": interface,
                                   "network": network,
                                   "error": message
                            })
                            progress.advance(network_task)
                            continue

                     if scan_method == "arp":
                            try:
                                   network_hosts = arp.scan(network, interface=interface)
                            except RuntimeError as exc:
                                   message = str(exc)
                                   errors.append({
                                          "interface": interface,
                                          "network": network,
                                          "error": message
                                   })
                                   progress.advance(network_task)
                                   continue

                            for host in network_hosts:
                                   host["source_interface"] = interface
                                   host["source_network"] = network
                                   host["source_gateway"] = net.get("via")
                                   host["discovery_method"] = "arp"
                                   host["family"] = "IPv4"

                     elif scan_method == "ndp":
                            try:
                                   network_hosts = _scan_ipv6_neighbors(net)
                            except RuntimeError as exc:
                                   message = str(exc)
                                   errors.append({
                                          "interface": interface,
                                          "network": network,
                                          "error": message
                                   })
                                   progress.advance(network_task)
                                   continue

                     else:
                            try:
                                   family = net.get("family") or "IPv4"
                                   route_scanner.scan(
                                          network,
                                          arguments=_nmap_arguments(NMAP_HOST_DISCOVERY_ARGUMENTS, family),
                                          timeout=NMAP_HOST_DISCOVERY_TIMEOUT_SECONDS
                                   )
                                   network_hosts = [
                                          _host_from_nmap(route_scanner, ip_address, net)
                                          for ip_address in route_scanner.all_hosts()
                                   ]
                            except nmap.PortScannerTimeout:
                                   message = "Nmap host discovery timeout"
                                   errors.append({
                                          "interface": interface,
                                          "network": network,
                                          "error": message
                                   })
                                   progress.advance(network_task)
                                   continue
                            except nmap.PortScannerError as exc:
                                   message = str(exc)
                                   errors.append({
                                          "interface": interface,
                                          "network": network,
                                          "error": message
                                   })
                                   progress.advance(network_task)
                                   continue

                     for host in network_hosts:
                            host.setdefault("family", net.get("family") or _ip_family(host.get("ip")))
                            key = (host["source_network"], host["ip"], host.get("mac"))
                            if key in seen_hosts:
                                   continue

                            seen_hosts.add(key)
                            hosts.append(host)

                     progress.advance(network_task)

       console.print(f"[green]Hosts found:[/green] {len(hosts)}")

       # 2. Nmap enrichment
       scanner = nmap.PortScanner()

       enriched = []

       if hosts:
              with Progress(
                     SpinnerColumn(),
                     TextColumn("[progress.description]{task.description}"),
                     BarColumn(),
                     MofNCompleteColumn(),
                     TimeElapsedColumn(),
                     console=console
              ) as progress:
                     enrich_task = progress.add_task("Enriching hosts", total=len(hosts))

                     for h in hosts:

                            try:
                                   progress.update(enrich_task, description=f"Enriching {h['ip']}")
                                   target = _nmap_target(h["ip"], h.get("source_interface"))
                                   scanner.scan(
                                          target,
                                          arguments=_nmap_arguments(NMAP_ARGUMENTS, h.get("family")),
                                          timeout=NMAP_TIMEOUT_SECONDS
                                   )
                                   nmap_host = scanner.all_hosts()[0] if scanner.all_hosts() else target

                                   enriched.append({
                                          **h,
                                          "hostname": _hostname_from_nmap(scanner, nmap_host) or h.get("hostname"),
                                          "ports": scanner[nmap_host].all_tcp() if nmap_host in scanner.all_hosts() else [],
                                          "services": scanner[nmap_host].get("tcp", {}) if nmap_host in scanner.all_hosts() else {}
                                   })

                            except nmap.PortScannerTimeout:
                                   enriched.append(h)
                            except nmap.PortScannerError as exc:
                                   errors.append({
                                          "interface": h.get("source_interface"),
                                          "network": h.get("source_network"),
                                          "error": f"Nmap error for {h['ip']}: {exc}"
                                   })
                                   enriched.append(h)
                            except Exception as exc:
                                   errors.append({
                                          "interface": h.get("source_interface"),
                                          "network": h.get("source_network"),
                                          "error": f"Discovery enrichment skipped for {h['ip']}: {exc}"
                                   })
                                   enriched.append(h)

                            progress.advance(enrich_task)

       _render_hosts_table(enriched)
       _render_errors_table(errors)
       network_results = _build_network_results(networks, enriched, errors)

       return {
              "network_results": network_results
       }
