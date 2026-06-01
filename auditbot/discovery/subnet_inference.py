from __future__ import annotations

import ipaddress
from collections import defaultdict


HIGH_SOURCES = {"interface", "route_table", "user_seed"}
MEDIUM_SOURCES = {"passive_capture", "traceroute", "ping", "nmap_sn"}
LOW_SOURCES = {"dns"}


def infer_candidate_subnets(
       interface_data: dict,
       routes: list[dict],
       arp_entries: list[dict],
       dns_servers: list[str],
       passive_ips: list[str] | None = None,
       traceroute_ips: list[str] | None = None,
       user_seed_subnets: list[str] | None = None,
) -> list[dict]:
       """Infer candidate IPv4 private subnets from all discovery sources."""

       candidates: dict[str, dict] = {}
       local_subnet = interface_data.get("local_subnet")
       if local_subnet:
              _add_candidate(candidates, local_subnet, "local", "interface", "known")

       for route in routes:
              cidr = route.get("cidr")
              if _usable_private_subnet(cidr):
                     subnet_type = "local" if cidr == local_subnet else "external"
                     _add_candidate(candidates, cidr, subnet_type, "route_table", "observed")
              if route.get("gateway"):
                     _add_ip(candidates, route["gateway"], local_subnet, "route_table")

       for entry in arp_entries:
              _add_ip(candidates, entry.get("ip"), local_subnet, "arp")

       for server in dns_servers:
              _add_ip(candidates, server, local_subnet, "dns")

       for ip_value in passive_ips or []:
              _add_ip(candidates, ip_value, local_subnet, "passive_capture")

       for ip_value in traceroute_ips or []:
              _add_ip(candidates, ip_value, local_subnet, "traceroute")

       for seed in user_seed_subnets or []:
              try:
                     network = ipaddress.ip_network(seed, strict=False)
              except ValueError:
                     continue
              if network.version != 4:
                     continue
              subnet_type = "local" if str(network) == local_subnet else "external"
              _add_candidate(candidates, str(network), subnet_type, "user_seed", "observed")

       output = []
       for cidr, candidate in candidates.items():
              candidate["source"] = sorted(candidate["source"])
              candidate["confidence"] = _confidence(candidate["source"], candidate["type"], cidr, local_subnet)
              output.append(candidate)

       return sorted(output, key=lambda item: (item["type"] != "local", item["cidr"]))


def _add_ip(candidates: dict[str, dict], ip_value: str | None, local_subnet: str | None, source: str) -> None:
       if not ip_value:
              return
       try:
              address = ipaddress.ip_address(str(ip_value).split("%", 1)[0])
       except ValueError:
              return
       if address.version != 4 or not address.is_private or address.is_loopback or address.is_link_local:
              return
       if address.is_multicast or address.is_reserved or address.is_unspecified:
              return
       if str(address) == "255.255.255.255":
              return
       cidr = str(ipaddress.ip_network(f"{address}/24", strict=False))
       subnet_type = "local" if cidr == local_subnet else "external"
       _add_candidate(candidates, cidr, subnet_type, source, "observed")


def _add_candidate(candidates: dict[str, dict], cidr: str, subnet_type: str, source: str, status: str) -> None:
       try:
              network = ipaddress.ip_network(cidr, strict=False)
       except ValueError:
              return
       if network.version != 4:
              return
       key = str(network)
       if key not in candidates:
              candidates[key] = {
                     "cidr": key,
                     "type": subnet_type,
                     "status": status,
                     "confidence": "low",
                     "source": set(),
                     "validation": {},
                     "authorized": None,
              }
       candidates[key]["source"].add(source)
       if candidates[key]["status"] != "known" and status == "known":
              candidates[key]["status"] = status
       if candidates[key]["type"] != "local" and subnet_type == "local":
              candidates[key]["type"] = "local"


def _usable_private_subnet(cidr: str | None) -> bool:
       if not cidr:
              return False
       try:
              network = ipaddress.ip_network(cidr, strict=False)
       except ValueError:
              return False
       if network.version != 4:
              return False
       if network.prefixlen > 30:
              return False
       address = network.network_address
       return (
              network.is_private
              and not network.is_loopback
              and not network.is_link_local
              and not network.is_multicast
              and not address.is_reserved
              and not address.is_unspecified
              and network.prefixlen >= 8
       )


def _confidence(sources: list[str], subnet_type: str, cidr: str, local_subnet: str | None) -> str:
       source_set = set(sources)
       if source_set & HIGH_SOURCES:
              return "high"
       if "arp" in source_set and (subnet_type == "local" or cidr == local_subnet):
              return "high"
       if source_set & MEDIUM_SOURCES:
              return "medium"
       if source_set <= LOW_SOURCES:
              return "low"
       return "medium"
