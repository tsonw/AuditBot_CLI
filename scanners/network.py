import netifaces
import ipaddress
import os
import subprocess
from pathlib import Path

MAX_ROUTED_NETWORK_HOSTS = int(os.getenv("AUDITBOT_MAX_SCAN_HOSTS", "4096"))
DISCOVERY_TARGETS_FILE = Path("config/discovery_targets.txt")
IP_MODE_AUTO = "auto"
IP_MODE_IPV4 = "ipv4"
IP_MODE_IPV6 = "ipv6"
VALID_IP_MODES = {IP_MODE_AUTO, IP_MODE_IPV4, IP_MODE_IPV6}


def normalize_ip_mode(ip_mode: str | None = None):
       mode = (ip_mode or os.getenv("AUDITBOT_IP_MODE") or IP_MODE_AUTO).strip().lower()

       aliases = {
              "4": IP_MODE_IPV4,
              "v4": IP_MODE_IPV4,
              "ip4": IP_MODE_IPV4,
              "6": IP_MODE_IPV6,
              "v6": IP_MODE_IPV6,
              "ip6": IP_MODE_IPV6,
       }
       mode = aliases.get(mode, mode)

       if mode not in VALID_IP_MODES:
              return IP_MODE_AUTO

       return mode


def _mode_allows_family(ip_mode: str, family: str):
       mode = normalize_ip_mode(ip_mode)
       return mode == IP_MODE_AUTO or mode == family.lower()


def _family_label(version: int):
       return f"IPv{version}"


def _is_loopback_interface(interface: str):
       return interface == "lo" or interface.startswith("lo")


def _default_interface(version: int):
       gateways = netifaces.gateways()
       address_family = netifaces.AF_INET if version == 4 else netifaces.AF_INET6
       default_gateway = gateways.get("default", {}).get(address_family)

       if not default_gateway:
              return None

       return default_gateway[1]


def _default_ipv4_interface():
       return _default_interface(4)


def _clean_ipv6_address(address: str | None):
       if not address:
              return None

       return address.split("%", 1)[0]


def _ipv6_prefixlen(ip_info):
       netmask = ip_info.get("netmask")

       if not netmask:
              return 64

       netmask = netmask.split("%", 1)[0]

       if "/" in netmask:
              try:
                     return int(netmask.rsplit("/", 1)[1])
              except ValueError:
                     return 64

       try:
              mask_value = int(ipaddress.IPv6Address(netmask))
       except ValueError:
              return 64

       return bin(mask_value).count("1")


def get_local_networks(ip_mode: str | None = None):
       mode = normalize_ip_mode(ip_mode)
       default_ipv4_interface = _default_interface(4)
       default_ipv6_interface = _default_interface(6)
       networks = []
       seen = set()

       for interface in netifaces.interfaces():
              if _is_loopback_interface(interface):
                     continue

              iface_data = netifaces.ifaddresses(interface)

              if _mode_allows_family(mode, IP_MODE_IPV4):
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

                            key = (_family_label(4), interface, str(network))
                            if key in seen:
                                   continue

                            seen.add(key)
                            networks.append({
                                   "interface": interface,
                                   "ip": ip_addr,
                                   "netmask": netmask,
                                   "network": str(network),
                                   "family": _family_label(4),
                                   "is_default": interface == default_ipv4_interface,
                                   "via": None,
                                   "source": "interface",
                                   "scan_method": "arp"
                            })

              if _mode_allows_family(mode, IP_MODE_IPV6):
                     for ip_info in iface_data.get(netifaces.AF_INET6, []):
                            ip_addr = _clean_ipv6_address(ip_info.get("addr"))

                            if not ip_addr:
                                   continue

                            prefixlen = _ipv6_prefixlen(ip_info)
                            ip = ipaddress.IPv6Address(ip_addr)
                            network = ipaddress.IPv6Network(
                                   f"{ip_addr}/{prefixlen}",
                                   strict=False
                            )

                            if (
                                   ip.is_loopback
                                   or ip.is_multicast
                                   or ip.is_unspecified
                                   or network.prefixlen == 128
                            ):
                                   continue

                            key = (_family_label(6), interface, str(network))
                            if key in seen:
                                   continue

                            seen.add(key)
                            networks.append({
                                   "interface": interface,
                                   "ip": ip_addr,
                                   "netmask": str(network.netmask),
                                   "network": str(network),
                                   "family": _family_label(6),
                                   "is_default": interface == default_ipv6_interface,
                                   "via": None,
                                   "source": "interface",
                                   "scan_method": "ndp"
                            })

       networks.sort(key=lambda item: (item["family"], not item["is_default"], item["interface"], item["network"]))
       return networks


def _parse_ip_route_line(line: str, default_interface: str | None, version: int):
       parts = line.split()

       if not parts or parts[0] == "default":
              return None

       destination = parts[0]

       if "/" not in destination:
              return None

       try:
              if version == 4:
                     network = ipaddress.IPv4Network(destination, strict=False)
              else:
                     network = ipaddress.IPv6Network(destination, strict=False)
       except ValueError:
              return None

       if (
              network.is_loopback
              or network.is_multicast
              or network.is_unspecified
              or network.prefixlen == network.max_prefixlen
       ):
              return None

       if version == 4 and network.is_link_local:
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

       scan_method = "nmap" if version == 4 else "nmap6"
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
              "family": _family_label(version),
              "is_default": interface == default_interface,
              "via": gateway,
              "source": "route",
              "scan_method": scan_method,
              "scan_skipped_reason": scan_skipped_reason
       }


def get_routed_networks(ip_mode: str | None = None):
       mode = normalize_ip_mode(ip_mode)
       route_specs = []

       if _mode_allows_family(mode, IP_MODE_IPV4):
              route_specs.append((4, _default_interface(4), ["ip", "-4", "route", "show"]))

       if _mode_allows_family(mode, IP_MODE_IPV6):
              route_specs.append((6, _default_interface(6), ["ip", "-6", "route", "show"]))

       routes = []
       seen = set()

       for version, default_interface, command in route_specs:
              try:
                     result = subprocess.run(
                            command,
                            capture_output=True,
                            text=True,
                            check=False
                     )
              except FileNotFoundError:
                     continue

              if result.returncode != 0:
                     continue

              for line in result.stdout.splitlines():
                     route = _parse_ip_route_line(line, default_interface, version)

                     if not route:
                            continue

                     key = (route["interface"], route["network"], route.get("via"))
                     if key in seen:
                            continue

                     seen.add(key)
                     routes.append(route)

       routes.sort(key=lambda item: (item["scan_method"] == "skip", item["family"], item["interface"] or "", item["network"]))
       return routes


def _configured_network_record(network):
       scan_method = "nmap" if network.version == 4 else "nmap6"
       scan_skipped_reason = None

       if (
              network.is_loopback
              or network.is_multicast
              or network.is_unspecified
              or (network.version == 4 and network.prefixlen == network.max_prefixlen)
       ):
              scan_method = "skip"
              scan_skipped_reason = "configured target is not a discoverable infrastructure subnet"
       elif network.version == 4 and network.is_link_local:
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
              "family": _family_label(network.version),
              "is_default": False,
              "via": None,
              "source": "config",
              "scan_method": scan_method,
              "scan_skipped_reason": scan_skipped_reason
       }


def get_configured_networks(targets_file: Path = DISCOVERY_TARGETS_FILE, ip_mode: str | None = None):
       mode = normalize_ip_mode(ip_mode)

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
                     network = ipaddress.ip_network(destination, strict=False)
              except ValueError:
                     networks.append({
                            "interface": None,
                            "ip": None,
                            "netmask": None,
                            "network": destination,
                            "family": "-",
                            "is_default": False,
                            "via": None,
                            "source": "config",
                            "scan_method": "skip",
                            "scan_skipped_reason": "invalid configured network"
                     })
                     continue

              family = IP_MODE_IPV4 if network.version == 4 else IP_MODE_IPV6
              if not _mode_allows_family(mode, family):
                     continue

              if str(network) in seen:
                     continue

              seen.add(str(network))
              networks.append(_configured_network_record(network))

       return networks


def get_reachable_networks(ip_mode: str | None = None):
       mode = normalize_ip_mode(ip_mode)
       networks = get_local_networks(mode)
       seen = {item["network"] for item in networks}
       local_networks = {item["network"] for item in networks}

       for route in get_routed_networks(mode):
              if route["network"] in seen or route["network"] in local_networks:
                     continue

              seen.add(route["network"])
              networks.append(route)

       for configured_network in get_configured_networks(ip_mode=mode):
              if configured_network["network"] in seen:
                     continue

              seen.add(configured_network["network"])
              networks.append(configured_network)

       networks.sort(key=lambda item: (
              item.get("scan_method") == "skip",
              item.get("family") or "",
              not item.get("is_default", False),
              item.get("source") != "interface",
              item["interface"] or "",
              item["network"]
       ))
       return networks


def get_local_network(ip_mode: str | None = None):

       mode = normalize_ip_mode(ip_mode)
       networks = get_local_networks(mode)

       if not networks:
              raise RuntimeError(f"No active {mode.upper()} network found")

       return networks[0]
