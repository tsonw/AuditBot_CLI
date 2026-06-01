from __future__ import annotations

import ipaddress
import re

from auditbot.discovery.command import run_command, warning_from_result


def collect_interfaces(os_info: dict) -> dict:
       """Collect default interface, gateway, local IP, subnet and MAC."""

       warnings: list[str] = []
       if os_info.get("is_macos"):
              data = _collect_macos(warnings)
       else:
              data = _collect_linux(warnings)

       data["warnings"] = warnings
       return data


def _collect_macos(warnings: list[str]) -> dict:
       route = run_command(["route", "-n", "get", "default"])
       if warning := warning_from_result(route):
              warnings.append(warning)

       default_interface = _match_line_value(route.stdout, "interface")
       gateway = _match_line_value(route.stdout, "gateway")

       netstat = run_command(["netstat", "-rn", "-f", "inet"])
       if netstat.ok and (not default_interface or not gateway):
              fallback_gateway, fallback_interface = _parse_macos_default_from_netstat(netstat.stdout)
              gateway = gateway or fallback_gateway
              default_interface = default_interface or fallback_interface
       elif warning := warning_from_result(netstat):
              warnings.append(warning)

       ifconfig = run_command(["ifconfig"])
       if warning := warning_from_result(ifconfig):
              warnings.append(warning)

       iface_block = _ifconfig_block(ifconfig.stdout, default_interface)
       if not iface_block:
              default_interface, iface_block = _first_ipv4_ifconfig_block(ifconfig.stdout)
       local_ip, local_subnet = _parse_ifconfig_ipv4(iface_block)
       mac_address = _parse_ifconfig_mac(iface_block)

       return {
              "default_interface": default_interface,
              "local_ip": local_ip,
              "local_subnet": local_subnet,
              "gateway": gateway,
              "mac_address": mac_address,
              "raw": {
                     "route_default": route.stdout,
                     "netstat": netstat.stdout,
                     "ifconfig": ifconfig.stdout,
              },
       }


def _collect_linux(warnings: list[str]) -> dict:
       route = run_command(["ip", "route"])
       if warning := warning_from_result(route):
              warnings.append(warning)

       default_interface = None
       gateway = None
       for line in route.stdout.splitlines():
              parts = line.split()
              if parts[:1] != ["default"]:
                     continue
              if "via" in parts and parts.index("via") + 1 < len(parts):
                     gateway = parts[parts.index("via") + 1]
              if "dev" in parts and parts.index("dev") + 1 < len(parts):
                     default_interface = parts[parts.index("dev") + 1]
              break

       addr_command = ["ip", "-o", "addr", "show"]
       if default_interface:
              addr_command.extend(["dev", default_interface])
       addr = run_command(addr_command)
       if warning := warning_from_result(addr):
              warnings.append(warning)

       link = run_command(["ip", "-o", "link", "show", "dev", default_interface]) if default_interface else None
       if link and (warning := warning_from_result(link)):
              warnings.append(warning)

       local_ip = None
       local_subnet = None
       for line in addr.stdout.splitlines():
              match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
              if not match:
                     continue
              local_ip = match.group(1)
              local_subnet = str(ipaddress.ip_network(match.group(0).split()[1], strict=False))
              break

       mac_address = None
       if link:
              match = re.search(r"\blink/ether\s+([0-9a-f:]{17})", link.stdout, re.I)
              if match:
                     mac_address = match.group(1).lower()

       return {
              "default_interface": default_interface,
              "local_ip": local_ip,
              "local_subnet": local_subnet,
              "gateway": gateway,
              "mac_address": mac_address,
              "raw": {
                     "ip_route": route.stdout,
                     "ip_addr": addr.stdout,
                     "ip_link": link.stdout if link else "",
              },
       }


def _match_line_value(text: str, label: str) -> str | None:
       pattern = rf"^\s*{re.escape(label)}:\s*(.+?)\s*$"
       match = re.search(pattern, text, re.M)
       return match.group(1).strip() if match else None


def _ifconfig_block(text: str, interface: str | None) -> str:
       if not interface:
              return ""
       blocks = re.split(r"\n(?=\S)", text)
       for block in blocks:
              if block.startswith(f"{interface}:"):
                     return block
       return ""


def _first_ipv4_ifconfig_block(text: str) -> tuple[str | None, str]:
       blocks = re.split(r"\n(?=\S)", text)
       for block in blocks:
              name = block.split(":", 1)[0]
              if name.startswith("lo"):
                     continue
              ip_value, _ = _parse_ifconfig_ipv4(block)
              if ip_value:
                     return name, block
       return None, ""


def _parse_macos_default_from_netstat(text: str) -> tuple[str | None, str | None]:
       for line in text.splitlines():
              parts = line.split()
              if len(parts) >= 4 and parts[0] == "default":
                     return parts[1], parts[-1]
       return None, None


def _parse_ifconfig_ipv4(block: str) -> tuple[str | None, str | None]:
       match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)", block)
       if not match:
              return None, None
       ip_value = match.group(1)
       mask_value = match.group(2)
       if mask_value.startswith("0x"):
              mask_int = int(mask_value, 16)
              mask_value = str(ipaddress.IPv4Address(mask_int))
       try:
              network = ipaddress.ip_network(f"{ip_value}/{mask_value}", strict=False)
       except ValueError:
              return ip_value, None
       return ip_value, str(network)


def _parse_ifconfig_mac(block: str) -> str | None:
       match = re.search(r"\bether\s+([0-9a-f:]{17})", block, re.I)
       return match.group(1).lower() if match else None
