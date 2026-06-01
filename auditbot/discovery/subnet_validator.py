from __future__ import annotations

import ipaddress

from auditbot.discovery.command import command_exists, run_command, warning_from_result


def apply_authorization(candidates: list[dict], policy: dict) -> list[dict]:
       """Mark candidates as authorized or not authorized."""

       require_authorization = policy.get("require_authorization", True)
       authorized = _authorized_networks(policy.get("authorized_subnets") or [])

       for candidate in candidates:
              try:
                     network = ipaddress.ip_network(candidate["cidr"], strict=False)
              except ValueError:
                     candidate["authorized"] = False
                     candidate["status"] = "invalid"
                     continue

              is_authorized = (not require_authorization) or any(network.subnet_of(item) for item in authorized)
              candidate["authorized"] = is_authorized
              if not is_authorized:
                     candidate["status"] = "not_authorized"
       return candidates


def validate_candidate_subnets(candidates: list[dict], policy: dict, os_info: dict) -> list[dict]:
       """Validate authorized candidate subnets before scanning."""

       for candidate in candidates:
              if not candidate.get("authorized"):
                     candidate.setdefault("validation", {})["skipped_reason"] = "not authorized"
                     continue

              validation_policy = {**policy, "_candidate_source": candidate.get("source", [])}
              validation = _validate_single(candidate["cidr"], validation_policy, os_info)
              candidate["validation"] = validation
              if validation.get("valid"):
                     candidate["status"] = "validated"
                     if validation.get("evidence"):
                            candidate["source"] = sorted(set(candidate.get("source", [])) | set(validation["evidence"]))
              elif candidate.get("status") != "known":
                     candidate["status"] = "discovered"
       return candidates


def _validate_single(cidr: str, policy: dict, os_info: dict) -> dict:
       try:
              network = ipaddress.ip_network(cidr, strict=False)
       except ValueError as exc:
              return {"valid": False, "reason": str(exc), "evidence": []}

       max_prefix = int(policy.get("max_prefix", 24))
       max_hosts = int(policy.get("max_hosts", 256))
       if network.prefixlen < max_prefix or network.num_addresses > max_hosts:
              return {
                     "valid": False,
                     "reason": f"subnet exceeds policy limits: prefix /{network.prefixlen}, hosts {network.num_addresses}",
                     "evidence": [],
              }

       evidence: list[str] = []
       warnings: list[str] = []

       source_set = set(policy.get("_candidate_source") or [])
       if "interface" in source_set:
              evidence.append("interface")
       if "route_table" in source_set:
              evidence.append("route_table")
       if "user_seed" in source_set:
              evidence.append("user_seed")

       route_check = _route_check(network, os_info)
       if route_check.get("ok"):
              evidence.append("route_check")
       elif route_check.get("warning"):
              warnings.append(route_check["warning"])

       ping_hits = _ping_representative_hosts(network, os_info)
       if ping_hits:
              evidence.append("ping")

       nmap_hosts = 0
       if command_exists("nmap"):
              result = run_command(["nmap", "-sn", "--max-retries", "1", "--host-timeout", "3s", str(network)], timeout=30)
              if result.ok:
                     nmap_hosts = result.stdout.count("Nmap scan report for")
                     if nmap_hosts > 0:
                            evidence.append("nmap_sn")
              elif warning := warning_from_result(result):
                     warnings.append(warning)
       else:
              warnings.append("nmap is not installed; nmap validation skipped")

       return {
              "valid": bool(evidence),
              "route_check": route_check.get("ok", False),
              "ping_hits": ping_hits,
              "nmap_hosts": nmap_hosts,
              "evidence": sorted(set(evidence)),
              "warnings": warnings,
       }


def _route_check(network: ipaddress.IPv4Network, os_info: dict) -> dict:
       target = str(next(network.hosts(), network.network_address))
       command = ["route", "-n", "get", target] if os_info.get("is_macos") else ["ip", "route", "get", target]
       result = run_command(command, timeout=5)
       if result.ok:
              return {"ok": True}
       return {"ok": False, "warning": warning_from_result(result)}


def _ping_representative_hosts(network: ipaddress.IPv4Network, os_info: dict) -> int:
       targets = []
       hosts = list(network.hosts())
       if hosts:
              targets.append(str(hosts[0]))
              if len(hosts) > 1:
                     targets.append(str(hosts[-1]))
       hits = 0
       for target in targets[:2]:
              command = ["ping", "-c", "1", "-W", "1000" if os_info.get("is_macos") else "1", target]
              result = run_command(command, timeout=3)
              if result.ok:
                     hits += 1
       return hits


def _authorized_networks(values: list[str]) -> list[ipaddress.IPv4Network]:
       networks = []
       for value in values:
              try:
                     network = ipaddress.ip_network(value, strict=False)
              except ValueError:
                     continue
              if network.version == 4:
                     networks.append(network)
       return networks
