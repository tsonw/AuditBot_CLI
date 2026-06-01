from __future__ import annotations

import re

from auditbot.discovery.command import run_command, warning_from_result


def collect_arp(os_info: dict) -> dict:
       """Collect ARP/neighbor table entries."""

       warnings: list[str] = []
       if os_info.get("is_macos"):
              result = run_command(["arp", "-a"])
              entries = _parse_macos_arp(result.stdout)
       else:
              result = run_command(["ip", "neigh"])
              entries = _parse_linux_neigh(result.stdout)
       if warning := warning_from_result(result):
              warnings.append(warning)
       return {"entries": entries, "warnings": warnings, "raw": result.stdout}


def _parse_macos_arp(text: str) -> list[dict]:
       entries = []
       for line in text.splitlines():
              match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+|incomplete)(?:\s+on\s+(\S+))?", line, re.I)
              if not match:
                     continue
              entries.append({
                     "ip": match.group(1),
                     "mac": None if match.group(2).lower() == "incomplete" else match.group(2).lower(),
                     "interface": match.group(3),
                     "state": "incomplete" if match.group(2).lower() == "incomplete" else "reachable",
                     "raw": line,
              })
       return entries


def _parse_linux_neigh(text: str) -> list[dict]:
       entries = []
       for line in text.splitlines():
              parts = line.split()
              if not parts:
                     continue
              mac = None
              if "lladdr" in parts and parts.index("lladdr") + 1 < len(parts):
                     mac = parts[parts.index("lladdr") + 1].lower()
              interface = None
              if "dev" in parts and parts.index("dev") + 1 < len(parts):
                     interface = parts[parts.index("dev") + 1]
              entries.append({
                     "ip": parts[0],
                     "mac": mac,
                     "interface": interface,
                     "state": parts[-1] if len(parts) > 1 else None,
                     "raw": line,
              })
       return entries

