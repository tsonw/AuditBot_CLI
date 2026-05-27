import os

import nmap
from scanners.network import get_reachable_networks, normalize_ip_mode
from scanners.arp_scanner import ArpScanner
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from engines.discovery_services.ipv6_neighbors import IPv6NeighborDiscoveryService
from engines.discovery_services.nmap_service import (
       NmapService,
       hostname_from_nmap,
       ip_family,
       nmap_target,
       os_from_nmap,
       services_with_protocol,
)
from engines.discovery_services.rendering import (
       render_errors_table,
       render_hosts_table,
       render_networks_table,
)
from engines.discovery_services.results import build_network_results

console = Console()

NMAP_PORTS = os.getenv(
       "AUDITBOT_NMAP_PORTS",
       "1-1024,2049,3000,3306,5000,5432,5672,5900,6379,8000-9000,9200,9300,10000"
)
NMAP_ARGUMENTS = f"-sV --version-light -p {NMAP_PORTS} -T4 --host-timeout 30s"
NMAP_OS_DETECTION = os.getenv("AUDITBOT_NMAP_OS_DETECTION", "1").lower() not in {"0", "false", "no"}
NMAP_TIMEOUT_SECONDS = 45
NMAP_HOST_DISCOVERY_ARGUMENTS = "-sn -T4 --host-timeout 10s"
NMAP_HOST_DISCOVERY_TIMEOUT_SECONDS = 180


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
       ipv6_neighbors = IPv6NeighborDiscoveryService()
       nmap_service = NmapService(NMAP_ARGUMENTS, os_detection=NMAP_OS_DETECTION)
       route_scanner = nmap.PortScanner()
       hosts = []
       errors = []
       seen_hosts = set()

       render_networks_table(networks)

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
                                   network_hosts = ipv6_neighbors.scan(net)
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
                                          arguments=nmap_service.host_discovery_arguments(
                                                 NMAP_HOST_DISCOVERY_ARGUMENTS,
                                                 family,
                                          ),
                                          timeout=NMAP_HOST_DISCOVERY_TIMEOUT_SECONDS
                                   )
                                   network_hosts = [
                                          nmap_service.host_from_scan(route_scanner, ip_address, net)
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
                            host.setdefault("family", net.get("family") or ip_family(host.get("ip")))
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
                                   target = nmap_target(h["ip"], h.get("source_interface"))
                                   scanner.scan(
                                          target,
                                          arguments=nmap_service.enrichment_arguments(h.get("family")),
                                          timeout=NMAP_TIMEOUT_SECONDS
                                   )
                                   nmap_host = scanner.all_hosts()[0] if scanner.all_hosts() else target

                                   enriched.append({
                                          **h,
                                          "hostname": hostname_from_nmap(scanner, nmap_host) or h.get("hostname"),
                                          "os": os_from_nmap(scanner, nmap_host) or h.get("os"),
                                          "ports": scanner[nmap_host].all_tcp() if nmap_host in scanner.all_hosts() else [],
                                          "services": services_with_protocol(
                                                 scanner[nmap_host].get("tcp", {}) if nmap_host in scanner.all_hosts() else {},
                                                 "tcp"
                                          )
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

       render_hosts_table(enriched)
       render_errors_table(errors)
       network_results = build_network_results(networks, enriched, errors)

       return {
              "network_results": network_results
       }
