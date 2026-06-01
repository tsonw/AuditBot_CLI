from __future__ import annotations

import nmap

from auditbot.scanner.nmap_parser import parse_hosts


def discover_hosts(cidr: str, timeout: int = 45) -> dict:
       """Run light nmap host discovery for one validated subnet."""

       scanner = nmap.PortScanner()
       try:
              scanner.scan(cidr, arguments="-sn --max-retries 1 --host-timeout 3s", timeout=timeout)
       except Exception as exc:
              return {"cidr": cidr, "hosts": [], "error": str(exc)}
       return {"cidr": cidr, "hosts": parse_hosts(scanner, cidr), "error": None}

