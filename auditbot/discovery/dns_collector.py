from __future__ import annotations

import re
from pathlib import Path

from auditbot.discovery.command import run_command, warning_from_result


def collect_dns(os_info: dict) -> dict:
       """Collect configured DNS servers."""

       warnings: list[str] = []
       raw: dict[str, str] = {}
       servers: list[str] = []

       if os_info.get("is_macos"):
              result = run_command(["scutil", "--dns"])
              raw["scutil"] = result.stdout
              if warning := warning_from_result(result):
                     warnings.append(warning)
              servers.extend(_extract_nameservers(result.stdout))
       else:
              result = run_command(["resolvectl", "status"])
              raw["resolvectl"] = result.stdout
              if result.ok:
                     servers.extend(_extract_nameservers(result.stdout))
              else:
                     if warning := warning_from_result(result):
                            warnings.append(warning)
                     resolv = _read_resolv_conf()
                     raw["resolv_conf"] = resolv
                     servers.extend(_extract_nameservers(resolv))

       return {"servers": _dedupe(servers), "warnings": warnings, "raw": raw}


def _extract_nameservers(text: str) -> list[str]:
       servers = []
       patterns = [
              r"nameserver\[[0-9]+\]\s*:\s*([0-9a-fA-F:.]+)",
              r"\bDNS Servers?:\s*([0-9a-fA-F:.]+)",
              r"^\s*nameserver\s+([0-9a-fA-F:.]+)",
       ]
       for pattern in patterns:
              servers.extend(re.findall(pattern, text, re.M))
       return [item for item in servers if item and not item.startswith("127.")]


def _read_resolv_conf() -> str:
       try:
              return Path("/etc/resolv.conf").read_text(errors="ignore")
       except OSError:
              return ""


def _dedupe(values: list[str]) -> list[str]:
       seen = set()
       output = []
       for value in values:
              if value in seen:
                     continue
              seen.add(value)
              output.append(value)
       return output

