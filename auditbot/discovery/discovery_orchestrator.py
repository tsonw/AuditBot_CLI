from __future__ import annotations

from pathlib import Path
from typing import Any
import ipaddress

from auditbot.discovery.arp_collector import collect_arp
from auditbot.discovery.dns_collector import collect_dns
from auditbot.discovery.fallback_discovery import run_fallback_discovery
from auditbot.discovery.interface_collector import collect_interfaces
from auditbot.discovery.os_detector import detect_os
from auditbot.discovery.passive_capture import try_passive_capture
from auditbot.discovery.route_collector import collect_routes
from auditbot.discovery.subnet_inference import infer_candidate_subnets
from auditbot.discovery.subnet_validator import apply_authorization, validate_candidate_subnets
from auditbot.report.json_reporter import write_json_report
from auditbot.report.topology_builder import build_topology
from auditbot.scanner.service_scanner import scan_services


DEFAULT_POLICY = {
       "authorized_subnets": ["192.168.1.0/24"],
       "scan_policy": {
              "max_prefix": 24,
              "max_hosts": 256,
              "rate_limit": "low",
              "require_authorization": True,
              "passive_first": True,
              "allow_external_inference": True,
       },
}


def run_discovery_flow(
       passive: bool = False,
       no_capture: bool = False,
       seed_subnets: list[str] | None = None,
       config_path: str = "config/scan_policy.yaml",
       authorized_only: bool = True,
       scan: bool = False,
       capture_duration: int = 10,
       output: bool = True,
) -> dict:
       """Run multi-source discovery, optional authorized scan, and JSON export."""

       seed_subnets = seed_subnets or []
       policy_document = load_scan_policy(config_path)
       scan_policy = {
              **DEFAULT_POLICY["scan_policy"],
              **(policy_document.get("scan_policy") or {}),
       }
       if authorized_only:
              scan_policy["require_authorization"] = True
       authorized_subnets = policy_document.get("authorized_subnets") or DEFAULT_POLICY["authorized_subnets"]
       effective_policy = {"authorized_subnets": authorized_subnets, **scan_policy}

       os_info = detect_os()
       interface_data = collect_interfaces(os_info)
       route_data = collect_routes(os_info)
       arp_data = collect_arp(os_info)
       dns_data = collect_dns(os_info)

       capture = _capture_result_template(no_capture)
       should_capture = not no_capture and (passive or scan_policy.get("passive_first", True))
       if should_capture:
              capture = try_passive_capture(
                     interface_data.get("default_interface"),
                     os_info,
                     duration_seconds=capture_duration,
              )

       fallback = None
       if capture.get("capture_status") != "success":
              fallback = run_fallback_discovery(
                     interface_data,
                     route_data.get("routes", []),
                     arp_data.get("entries", []),
                     dns_data.get("servers", []),
                     user_seed_subnets=seed_subnets,
              )

       traceroute_ips = (fallback or {}).get("traceroute_ips", [])
       candidates = infer_candidate_subnets(
              interface_data=interface_data,
              routes=route_data.get("routes", []),
              arp_entries=arp_data.get("entries", []),
              dns_servers=dns_data.get("servers", []),
              passive_ips=capture.get("observed_ips", []),
              traceroute_ips=traceroute_ips,
              user_seed_subnets=seed_subnets,
       )

       if not scan_policy.get("allow_external_inference", True):
              candidates = [item for item in candidates if item.get("type") == "local"]

       candidates = apply_authorization(candidates, effective_policy)
       candidates = validate_candidate_subnets(candidates, effective_policy, os_info)

       scan_results = []
       if scan:
              for candidate in candidates:
                     if candidate.get("status") != "validated" or not candidate.get("authorized"):
                            continue
                     seed_hosts = _seed_hosts_for_subnet(candidate["cidr"], interface_data, arp_data, capture, fallback)
                     scan_result = scan_services(candidate["cidr"], seed_hosts=seed_hosts)
                     scan_results.append(scan_result)
                     if scan_result.get("error") and not scan_result.get("hosts"):
                            candidate["status"] = "scan_failed"
                     elif scan_result.get("error"):
                            candidate["status"] = "partially_scanned"
                     else:
                            candidate["status"] = "scanned"
                     candidate["host_count"] = len(scan_result.get("hosts") or [])

       report = _build_report(
              os_info=os_info,
              interface_data=interface_data,
              route_data=route_data,
              arp_data=arp_data,
              dns_data=dns_data,
              capture=capture,
              fallback=fallback,
              subnets=candidates,
              policy=effective_policy,
              scan_results=scan_results,
       )

       if output:
              prefix = "auditbot_scan" if scan else "auditbot_discovery"
              report["report_file"] = write_json_report(report, prefix=prefix)

       return report


def load_scan_policy(config_path: str) -> dict:
       """Load scan policy YAML, using a minimal fallback parser if PyYAML is absent."""

       path = Path(config_path)
       if not path.exists():
              return DEFAULT_POLICY.copy()
       text = path.read_text()
       try:
              import yaml

              data = yaml.safe_load(text) or {}
              return data if isinstance(data, dict) else DEFAULT_POLICY.copy()
       except Exception:
              return _parse_minimal_policy_yaml(text)


def _build_report(
       os_info: dict,
       interface_data: dict,
       route_data: dict,
       arp_data: dict,
       dns_data: dict,
       capture: dict,
       fallback: dict | None,
       subnets: list[dict],
       policy: dict,
       scan_results: list[dict],
) -> dict:
       warnings = []
       for source in (interface_data, route_data, arp_data, dns_data, capture, fallback or {}):
              warnings.extend(source.get("warnings", []))
       warnings = _dedupe(warnings)

       sources = _active_sources(capture, fallback)
       topology = build_topology(subnets, scan_results)
       return {
              "environment": {
                     "os": os_info.get("os_name"),
                     "platform": os_info.get("platform"),
                     "interface": interface_data.get("default_interface"),
                     "local_ip": interface_data.get("local_ip"),
                     "local_subnet": interface_data.get("local_subnet"),
                     "gateway": interface_data.get("gateway"),
                     "mac_address": interface_data.get("mac_address"),
              },
              "discovery": {
                     "capture_status": capture.get("capture_status"),
                     "capture_method": capture.get("method"),
                     "capture_file": capture.get("file"),
                     "fallback_used": fallback is not None,
                     "sources": sources,
                     "warnings": warnings,
              },
              "subnets": _stable_subnets(subnets),
              "scan_policy": {
                     "max_prefix": policy.get("max_prefix"),
                     "max_hosts": policy.get("max_hosts"),
                     "authorized_only": policy.get("require_authorization", True),
                     "authorized_subnets": policy.get("authorized_subnets") or [],
                     "rate_limit": policy.get("rate_limit"),
              },
              "scan_results": scan_results,
              "topology": topology,
              "raw_sources": {
                     "routes": route_data.get("routes", []),
                     "arp": arp_data.get("entries", []),
                     "dns_servers": dns_data.get("servers", []),
                     "passive_observed_ips": capture.get("observed_ips", []),
                     "fallback": fallback or {},
              },
       }


def _capture_result_template(no_capture: bool) -> dict:
       status = "skipped" if no_capture else "not_run"
       return {
              "capture_status": status,
              "method": None,
              "file": None,
              "packet_count": 0,
              "observed_ips": [],
              "warnings": ["passive capture disabled"] if no_capture else [],
       }


def _active_sources(capture: dict, fallback: dict | None) -> list[str]:
       sources = ["interface", "route_table", "arp_table", "dns"]
       if capture.get("capture_status") == "success":
              sources.append("passive_capture")
       if fallback:
              sources.extend(source for source in fallback.get("sources", []) if source not in sources)
       return sources


def _dedupe(values: list[str]) -> list[str]:
       seen = set()
       output = []
       for value in values:
              if value in seen:
                     continue
              seen.add(value)
              output.append(value)
       return output


def _stable_subnets(subnets: list[dict]) -> list[dict]:
       output = []
       for subnet in subnets:
              output.append({
                     "cidr": subnet.get("cidr"),
                     "type": subnet.get("type"),
                     "status": subnet.get("status"),
                     "confidence": subnet.get("confidence"),
                     "source": subnet.get("source") or [],
                     "authorized": subnet.get("authorized"),
                     "validation": subnet.get("validation") or {},
                     "host_count": subnet.get("host_count", 0),
              })
       return output


def _parse_minimal_policy_yaml(text: str) -> dict:
       data: dict[str, Any] = {"authorized_subnets": [], "scan_policy": {}}
       section = None
       for raw_line in text.splitlines():
              line = raw_line.split("#", 1)[0].rstrip()
              if not line.strip():
                     continue
              stripped = line.strip()
              if stripped.endswith(":") and not stripped.startswith("-"):
                     section = stripped[:-1]
                     data.setdefault(section, [] if section == "authorized_subnets" else {})
                     continue
              if section == "authorized_subnets" and stripped.startswith("-"):
                     data["authorized_subnets"].append(stripped[1:].strip())
                     continue
              if section == "scan_policy" and ":" in stripped:
                     key, value = stripped.split(":", 1)
                     data["scan_policy"][key.strip()] = _parse_scalar(value.strip())
       return data


def _parse_scalar(value: str) -> Any:
       lowered = value.lower()
       if lowered in {"true", "false"}:
              return lowered == "true"
       try:
              return int(value)
       except ValueError:
              return value


def _seed_hosts_for_subnet(
       cidr: str,
       interface_data: dict,
       arp_data: dict,
       capture: dict,
       fallback: dict | None,
) -> list[dict]:
       try:
              network = ipaddress.ip_network(cidr, strict=False)
       except ValueError:
              return []

       hosts: dict[str, dict] = {}

       local_ip = interface_data.get("local_ip")
       if _ip_in_network(local_ip, network):
              hosts[local_ip] = {
                     "ip": local_ip,
                     "mac": interface_data.get("mac_address"),
                     "state": "local",
                     "discovery_sources": ["interface"],
              }

       gateway = interface_data.get("gateway")
       if _ip_in_network(gateway, network):
              hosts.setdefault(gateway, {
                     "ip": gateway,
                     "state": "observed",
                     "discovery_sources": ["gateway"],
              })

       for entry in arp_data.get("entries", []):
              ip_value = entry.get("ip")
              if not _ip_in_network(ip_value, network):
                     continue
              existing = hosts.setdefault(ip_value, {
                     "ip": ip_value,
                     "state": entry.get("state") or "observed",
                     "discovery_sources": [],
              })
              existing["mac"] = entry.get("mac") or existing.get("mac")
              existing.setdefault("discovery_sources", []).append("arp")

       for source_name, values in (
              ("passive_capture", capture.get("observed_ips") or []),
              ("traceroute", (fallback or {}).get("traceroute_ips") or []),
       ):
              for ip_value in values:
                     if not _ip_in_network(ip_value, network):
                            continue
                     existing = hosts.setdefault(ip_value, {
                            "ip": ip_value,
                            "state": "observed",
                            "discovery_sources": [],
                     })
                     existing.setdefault("discovery_sources", []).append(source_name)

       output = []
       for host in hosts.values():
              host["discovery_sources"] = sorted(set(host.get("discovery_sources") or []))
              output.append(host)
       return sorted(output, key=lambda item: _ip_sort_key(item.get("ip")))


def _ip_in_network(ip_value: str | None, network: ipaddress.IPv4Network) -> bool:
       if not ip_value:
              return False
       try:
              address = ipaddress.ip_address(str(ip_value).split("%", 1)[0])
       except ValueError:
              return False
       return (
              address.version == 4
              and address in network
              and address != network.network_address
              and address != network.broadcast_address
              and not address.is_multicast
              and not address.is_unspecified
       )


def _ip_sort_key(ip_value: str | None):
       try:
              return int(ipaddress.ip_address(str(ip_value).split("%", 1)[0]))
       except ValueError:
              return 0
