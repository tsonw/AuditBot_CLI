import netifaces
import ipaddress
import os
import subprocess
from pathlib import Path

MAX_ROUTED_NETWORK_HOSTS = int(os.getenv("AUDITBOT_MAX_SCAN_HOSTS", "4096"))
DISCOVERY_TARGETS_FILE = Path("config/discovery_targets.txt")


def _default_ipv4_interface():
       gateways = netifaces.gateways()
       default_gateway = gateways.get("default", {}).get(netifaces.AF_INET)

       if not default_gateway:
              return None

       return default_gateway[1]


def get_local_networks():
       default_interface = _default_ipv4_interface()
       networks = []
       seen = set()

       for interface in netifaces.interfaces():
              iface_data = netifaces.ifaddresses(interface)

              for ip_info in iface_data.get(netifaces.AF_INET, []):
                     ip_addr = ip_info.get("addr")
                     netmask = ip_info.get("netmask")

                     if not ip_addr or not netmask:
                            continue

                     ip = ipaddress.IPv4Address(ip_addr)
                     network = ipaddress.IPv4Network(
                            f"{ip_addr}/{netmask}",
                            strict=False
                     )

                     if ip.is_loopback or ip.is_link_local or network.prefixlen == 32:
                            continue

                     key = (interface, str(network), ip_addr)
                     if key in seen:
                            continue

                     seen.add(key)
                     networks.append({
                            "interface": interface,
                            "ip": ip_addr,
                            "netmask": netmask,
                            "network": str(network),
                            "is_default": interface == default_interface,
                            "via": None,
                            "source": "interface",
                            "scan_method": "arp"
                     })

       networks.sort(key=lambda item: (not item["is_default"], item["interface"], item["network"]))
       return networks


def _parse_ip_route_line(line: str, default_interface: str | None):
       parts = line.split()

       if not parts or parts[0] == "default":
              return None

       destination = parts[0]

       if "/" not in destination:
              return None

       try:
              network = ipaddress.IPv4Network(destination, strict=False)
       except ValueError:
              return None

       if (
              network.is_loopback
              or network.is_link_local
              or network.is_multicast
              or network.is_unspecified
              or network.prefixlen == 32
       ):
              return None

       interface = None
       gateway = None
       source_ip = None

       if "dev" in parts:
              index = parts.index("dev")
              if index + 1 < len(parts):
                     interface = parts[index + 1]

       if "via" in parts:
              index = parts.index("via")
              if index + 1 < len(parts):
                     gateway = parts[index + 1]

       if "src" in parts:
              index = parts.index("src")
              if index + 1 < len(parts):
                     source_ip = parts[index + 1]

       scan_method = "nmap"
       scan_skipped_reason = None

       if network.num_addresses > MAX_ROUTED_NETWORK_HOSTS:
              scan_method = "skip"
              scan_skipped_reason = (
                     f"route is too large ({network.num_addresses} addresses); "
                     f"limit is {MAX_ROUTED_NETWORK_HOSTS}"
              )

       return {
              "interface": interface,
              "ip": source_ip,
              "netmask": str(network.netmask),
              "network": str(network),
              "is_default": interface == default_interface,
              "via": gateway,
              "source": "route",
              "scan_method": scan_method,
              "scan_skipped_reason": scan_skipped_reason
       }


def get_routed_networks():
       default_interface = _default_ipv4_interface()

       try:
              result = subprocess.run(
                     ["ip", "-4", "route", "show"],
                     capture_output=True,
                     text=True,
                     check=False
              )
       except FileNotFoundError:
              return []

       if result.returncode != 0:
              return []

       routes = []
       seen = set()

       for line in result.stdout.splitlines():
              route = _parse_ip_route_line(line, default_interface)

              if not route:
                     continue

              key = (route["interface"], route["network"], route.get("via"))
              if key in seen:
                     continue

              seen.add(key)
              routes.append(route)

       routes.sort(key=lambda item: (item["scan_method"] == "skip", item["interface"] or "", item["network"]))
       return routes


def _configured_network_record(network: ipaddress.IPv4Network):
       scan_method = "nmap"
       scan_skipped_reason = None

       if (
              network.is_loopback
              or network.is_link_local
              or network.is_multicast
              or network.is_unspecified
              or network.prefixlen == 32
       ):
              scan_method = "skip"
              scan_skipped_reason = "configured target is not a discoverable infrastructure subnet"
       elif network.num_addresses > MAX_ROUTED_NETWORK_HOSTS:
              scan_method = "skip"
              scan_skipped_reason = (
                     f"configured target is too large ({network.num_addresses} addresses); "
                     f"limit is {MAX_ROUTED_NETWORK_HOSTS}"
              )

       return {
              "interface": None,
              "ip": None,
              "netmask": str(network.netmask),
              "network": str(network),
              "is_default": False,
              "via": None,
              "source": "config",
              "scan_method": scan_method,
              "scan_skipped_reason": scan_skipped_reason
       }


def get_configured_networks(targets_file: Path = DISCOVERY_TARGETS_FILE):
       if not targets_file.exists():
              return []

       networks = []
       seen = set()

       for line in targets_file.read_text().splitlines():
              target = line.split("#", 1)[0].strip()

              if not target:
                     continue

              destination = target.split()[0]

              try:
                     network = ipaddress.IPv4Network(destination, strict=False)
              except ValueError:
                     networks.append({
                            "interface": None,
                            "ip": None,
                            "netmask": None,
                            "network": destination,
                            "is_default": False,
                            "via": None,
                            "source": "config",
                            "scan_method": "skip",
                            "scan_skipped_reason": "invalid configured network"
                     })
                     continue

              if str(network) in seen:
                     continue

              seen.add(str(network))
              networks.append(_configured_network_record(network))

       return networks


def get_reachable_networks():
       networks = get_local_networks()
       seen = {item["network"] for item in networks}
       local_networks = {item["network"] for item in networks}

       for route in get_routed_networks():
              if route["network"] in seen or route["network"] in local_networks:
                     continue

              seen.add(route["network"])
              networks.append(route)

       for configured_network in get_configured_networks():
              if configured_network["network"] in seen:
                     continue

              seen.add(configured_network["network"])
              networks.append(configured_network)

       networks.sort(key=lambda item: (
              item.get("scan_method") == "skip",
              not item.get("is_default", False),
              item.get("source") != "interface",
              item["interface"] or "",
              item["network"]
       ))
       return networks


def get_local_network():

       networks = get_local_networks()

       if not networks:
              raise RuntimeError("No active IPv4 network found")

       return networks[0]
