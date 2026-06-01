from __future__ import annotations


def build_topology(subnets: list[dict], scan_results: list[dict] | None = None) -> dict:
       """Build a simple topology model from subnet and scan records."""

       hosts_by_subnet = {}
       for result in scan_results or []:
              hosts_by_subnet[result.get("cidr")] = result.get("hosts", [])

       return {
              "subnets": [
                     {
                            "cidr": subnet.get("cidr"),
                            "type": subnet.get("type"),
                            "status": subnet.get("status"),
                            "confidence": subnet.get("confidence"),
                            "authorized": subnet.get("authorized"),
                            "hosts": hosts_by_subnet.get(subnet.get("cidr"), []),
                            "host_count": len(hosts_by_subnet.get(subnet.get("cidr"), [])),
                     }
                     for subnet in subnets
              ]
       }
