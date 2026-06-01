from __future__ import annotations

import ipaddress

from auditbot.discovery.command import run_command, warning_from_result


def collect_routes(os_info: dict) -> dict:
       """Collect IPv4 routes into a normalized JSON shape."""

       warnings: list[str] = []
       if os_info.get("is_macos"):
              result = run_command(["netstat", "-rn", "-f", "inet"])
              default = run_command(["route", "-n", "get", "default"])
              routes = _parse_macos_routes(result.stdout)
              raw = {"netstat": result.stdout, "route_default": default.stdout}
              for item in (result, default):
                     if warning := warning_from_result(item):
                            warnings.append(warning)
       else:
              result = run_command(["ip", "route"])
              routes = _parse_linux_routes(result.stdout)
              raw = {"ip_route": result.stdout}
              if warning := warning_from_result(result):
                     warnings.append(warning)

       return {"routes": routes, "warnings": warnings, "raw": raw}


def _parse_linux_routes(text: str) -> list[dict]:
       routes = []
       for line in text.splitlines():
              parts = line.split()
              if not parts:
                     continue
              destination = "0.0.0.0/0" if parts[0] == "default" else parts[0]
              cidr = _normalize_destination(destination)
              if not cidr:
                     continue
              routes.append({
                     "destination": destination,
                     "cidr": cidr,
                     "gateway": _value_after(parts, "via"),
                     "interface": _value_after(parts, "dev"),
                     "source_ip": _value_after(parts, "src"),
                     "raw": line,
              })
       return routes


def _parse_macos_routes(text: str) -> list[dict]:
       routes = []
       for line in text.splitlines():
              parts = line.split()
              if len(parts) < 4 or parts[0] in {"Routing", "Internet", "Destination"}:
                     continue
              destination = "0.0.0.0/0" if parts[0] == "default" else parts[0]
              cidr = _normalize_destination(destination)
              if not cidr:
                     continue
              interface = parts[-1] if not parts[-1].isdigit() else None
              routes.append({
                     "destination": destination,
                     "cidr": cidr,
                     "gateway": parts[1] if len(parts) > 1 else None,
                     "interface": interface,
                     "source_ip": None,
                     "raw": line,
              })
       return routes


def _value_after(parts: list[str], token: str) -> str | None:
       if token not in parts:
              return None
       index = parts.index(token)
       return parts[index + 1] if index + 1 < len(parts) else None


def _normalize_destination(value: str) -> str | None:
       try:
              if "/" in value:
                     return str(ipaddress.ip_network(value, strict=False))
              if value.count(".") == 3:
                     address = ipaddress.ip_address(value)
                     if str(address) == "0.0.0.0":
                            return "0.0.0.0/0"
                     return str(ipaddress.ip_network(f"{value}/32", strict=False))
              if value.count(".") in {1, 2}:
                     octets = value.split(".")
                     prefix = len(octets) * 8
                     padded = ".".join(octets + ["0"] * (4 - len(octets)))
                     return str(ipaddress.ip_network(f"{padded}/{prefix}", strict=False))
       except ValueError:
              return None
       return None

