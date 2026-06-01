from __future__ import annotations

import nmap

from auditbot.scanner.nmap_parser import parse_hosts


SERVICE_SCAN_ARGUMENTS = "-sV --version-light --top-ports 100 -T2"
HOST_DISCOVERY_ARGUMENTS = "-sn --max-retries 1 --host-timeout 3s"


def scan_services(cidr: str, timeout: int = 180, seed_hosts: list[dict] | None = None) -> dict:
       """Discover hosts first, then enrich discovered hosts with lightweight services."""

       hosts_by_ip = {}
       errors = []

       for host in seed_hosts or []:
              ip_value = host.get("ip")
              if not ip_value:
                     continue
              hosts_by_ip[ip_value] = {
                     "ip": ip_value,
                     "hostname": host.get("hostname"),
                     "state": host.get("state") or "observed",
                     "mac": host.get("mac"),
                     "source_network": cidr,
                     "ports": [],
                     "services": {},
                     "discovery_sources": host.get("discovery_sources") or ["seed"],
              }

       discovery_scanner = nmap.PortScanner()
       try:
              discovery_scanner.scan(cidr, arguments=HOST_DISCOVERY_ARGUMENTS, timeout=min(timeout, 60))
       except Exception as exc:
              errors.append(f"host discovery failed: {exc}")
       else:
              for host in parse_hosts(discovery_scanner, cidr):
                     hosts_by_ip[host["ip"]] = host

       target = " ".join(sorted(hosts_by_ip)) if hosts_by_ip else cidr
       service_scanner = nmap.PortScanner()
       try:
              service_scanner.scan(target, arguments=SERVICE_SCAN_ARGUMENTS, timeout=timeout)
       except Exception as exc:
              errors.append(f"service scan failed: {exc}")
       else:
              for host in parse_hosts(service_scanner, cidr):
                     existing = hosts_by_ip.get(host["ip"], {})
                     hosts_by_ip[host["ip"]] = {
                            **existing,
                            **host,
                            "ports": host.get("ports") or existing.get("ports") or [],
                            "services": host.get("services") or existing.get("services") or {},
                     }

       return {
              "cidr": cidr,
              "hosts": [hosts_by_ip[ip] for ip in sorted(hosts_by_ip, key=_ip_sort_key)],
              "error": "; ".join(errors) if errors else None,
       }


def _ip_sort_key(ip_value: str):
       parts = []
       for part in str(ip_value).split("."):
              try:
                     parts.append(int(part))
              except ValueError:
                     parts.append(0)
       return parts
