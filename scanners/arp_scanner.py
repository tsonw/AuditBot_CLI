import os

from scapy.all import ARP, Ether, srp
from scapy.error import Scapy_Exception
from rich.console import Console

console = Console()


class ArpScanner:

       def scan(self, network: str, interface: str | None = None):

              console.print(f"\n[cyan]Scanning network:[/cyan] {network}")
              if interface:
                     console.print(f"[cyan]Using interface:[/cyan] {interface}")

              if hasattr(os, "geteuid") and os.geteuid() != 0:
                     raise RuntimeError(
                            "ARP discovery needs root/raw socket permissions. Run: make run"
                     )

              arp = ARP(pdst=network)

              ether = Ether(dst="ff:ff:ff:ff:ff:ff")

              packet = ether / arp

              try:
                     result = srp(
                            packet,
                            iface=interface,
                            timeout=2,
                            verbose=0
                     )[0]
              except PermissionError as exc:
                     raise RuntimeError(
                            "ARP discovery needs root/raw socket permissions. Run: make run"
                     ) from exc
              except Scapy_Exception as exc:
                     if "Permission denied" in str(exc):
                            raise RuntimeError(
                                   "ARP discovery needs root/raw socket permissions. Run: make run"
                            ) from exc
                     raise RuntimeError(f"ARP discovery failed: {exc}") from exc

              hosts = []

              for sent, received in result:

                     host = {
                            "ip": received.psrc,
                            "mac": received.hwsrc
                     }

                     hosts.append(host)

              return hosts
