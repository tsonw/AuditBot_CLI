from __future__ import annotations

import re

from auditbot.discovery.command import command_exists, run_command, warning_from_result


DEFAULT_TRACE_TARGETS = ["8.8.8.8"]


def run_fallback_discovery(
       interface_data: dict,
       routes: list[dict],
       arp_entries: list[dict],
       dns_servers: list[str],
       user_seed_subnets: list[str] | None = None,
) -> dict:
       """Collect non-capture discovery hints; capture failure is not fatal."""

       targets = _trace_targets(interface_data, dns_servers)
       warnings: list[str] = []
       traceroute_ips: list[str] = []
       if not command_exists("traceroute"):
              warnings.append("traceroute is not installed; traceroute fallback skipped")
       else:
              for target in targets:
                     result = run_command(["traceroute", "-n", "-m", "5", "-w", "1", target], timeout=12)
                     if warning := warning_from_result(result):
                            warnings.append(warning)
                            continue
                     traceroute_ips.extend(_extract_ips(result.stdout))

       return {
              "fallback_used": True,
              "sources": ["route_table", "arp_table", "dns", "gateway", "traceroute", "user_seed"],
              "route_ips": _route_ips(routes),
              "arp_ips": [entry["ip"] for entry in arp_entries if entry.get("ip")],
              "dns_servers": dns_servers,
              "gateway": interface_data.get("gateway"),
              "traceroute_ips": _dedupe(traceroute_ips),
              "user_seed_subnets": user_seed_subnets or [],
              "warnings": warnings,
       }


def _trace_targets(interface_data: dict, dns_servers: list[str]) -> list[str]:
       targets = []
       if interface_data.get("gateway"):
              targets.append(interface_data["gateway"])
       targets.extend(dns_servers)
       targets.extend(DEFAULT_TRACE_TARGETS)
       return _dedupe([target for target in targets if target])


def _route_ips(routes: list[dict]) -> list[str]:
       values = []
       for route in routes:
              for key in ("gateway", "source_ip"):
                     value = route.get(key)
                     if value:
                            values.append(value)
       return _dedupe(values)


def _extract_ips(text: str) -> list[str]:
       return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)


def _dedupe(values: list[str]) -> list[str]:
       seen = set()
       output = []
       for value in values:
              if value in seen:
                     continue
              seen.add(value)
              output.append(value)
       return output

