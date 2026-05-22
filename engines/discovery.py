import os

import nmap
from scanners.network import get_reachable_networks
from scanners.arp_scanner import ArpScanner
from rich.console import Console
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


def _render_networks_table(networks):
       table = Table(title="Discovery Targets")
       table.add_column("#", justify="right")
       table.add_column("Network")
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
                     net.get("interface") or "-",
                     net.get("via") or "-",
                     net.get("source") or "-",
                     net.get("scan_method") or "-",
                     status
              )

       console.print(table)


def _render_hosts_table(hosts):
       table = Table(title="Discovery Hosts")
       table.add_column("#", justify="right")
       table.add_column("IP")
       table.add_column("MAC")
       table.add_column("Network")
       table.add_column("Interface")
       table.add_column("Gateway")
       table.add_column("Method")
       table.add_column("Ports")
       table.add_column("Service")
       table.add_column("Version")

       for index, host in enumerate(hosts, start=1):
              ports = ", ".join(str(port) for port in host.get("ports", []))
              services = host.get("services", {})
              service_names = []
              service_versions = []

              for port in host.get("ports", []):
                     service = services.get(port) or services.get(str(port)) or {}
                     name = service.get("name") or "-"
                     product = service.get("product") or ""
                     version = service.get("version") or ""
                     extrainfo = service.get("extrainfo") or ""
                     version_text = " ".join(
                            value for value in [product, version, extrainfo] if value
                     )

                     service_names.append(f"{port}:{name}")
                     service_versions.append(f"{port}:{version_text or '-'}")

              table.add_row(
                     str(index),
                     host.get("ip") or "-",
                     host.get("mac") or "-",
                     host.get("source_network") or "-",
                     host.get("source_interface") or "-",
                     host.get("source_gateway") or "-",
                     host.get("discovery_method") or "-",
                     ports or "-",
                     ", ".join(service_names) or "-",
                     ", ".join(service_versions) or "-"
              )

       console.print(table)


def _render_errors_table(errors):
       if not errors:
              return

       table = Table(title="Discovery Warnings")
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

              results.append({
                     **net,
                     "hosts_found": len(network_hosts),
                     "hosts": network_hosts,
                     "errors": network_errors
              })

       return results


def _host_from_nmap(scanner, ip_address, net):
       addresses = scanner[ip_address].get("addresses", {}) if ip_address in scanner.all_hosts() else {}

       return {
              "ip": ip_address,
              "mac": addresses.get("mac"),
              "source_interface": net["interface"],
              "source_network": net["network"],
              "source_gateway": net.get("via"),
              "discovery_method": "nmap"
       }


def run_discovery():

       networks = get_reachable_networks()

       if not networks:
              message = "No active IPv4 network found"
              console.print(f"[red]Discovery blocked:[/red] {message}")
              return {
                     "network": {},
                     "networks": [],
                     "network_results": [],
                     "hosts": [],
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

                     else:
                            try:
                                   route_scanner.scan(
                                          network,
                                          arguments=NMAP_HOST_DISCOVERY_ARGUMENTS,
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
                                   scanner.scan(
                                          h["ip"],
                                          arguments=NMAP_ARGUMENTS,
                                          timeout=NMAP_TIMEOUT_SECONDS
                                   )

                                   enriched.append({
                                          **h,
                                          "ports": scanner[h["ip"]].all_tcp() if h["ip"] in scanner.all_hosts() else [],
                                          "services": scanner[h["ip"]].get("tcp", {}) if h["ip"] in scanner.all_hosts() else {}
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
              "network": networks[0],
              "networks": networks,
              "network_results": network_results,
              "hosts": enriched,
              "errors": errors
       }
