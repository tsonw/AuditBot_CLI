import ipaddress
import os


class NmapService:
       def __init__(self, base_arguments, os_detection=True):
              self.base_arguments = base_arguments
              self.os_detection = os_detection

       def host_from_scan(self, scanner, ip_address, net):
              addresses = scanner[ip_address].get("addresses", {}) if ip_address in scanner.all_hosts() else {}

              return {
                     "ip": ip_address,
                     "hostname": hostname_from_nmap(scanner, ip_address),
                     "family": net.get("family") or ip_family(ip_address),
                     "mac": addresses.get("mac"),
                     "source_interface": net["interface"],
                     "source_network": net["network"],
                     "source_gateway": net.get("via"),
                     "discovery_method": net.get("scan_method") or "nmap",
              }

       def host_discovery_arguments(self, base_arguments, family):
              return nmap_arguments(base_arguments, family)

       def enrichment_arguments(self, family):
              arguments = self.base_arguments

              if self.can_run_os_detection():
                     arguments = f"{arguments} -O --osscan-guess"

              return nmap_arguments(arguments, family)

       def can_run_os_detection(self):
              return self.os_detection and hasattr(os, "geteuid") and os.geteuid() == 0


def hostname_from_nmap(scanner, ip_address):
       if ip_address not in scanner.all_hosts():
              return None

       hostnames = scanner[ip_address].hostnames()

       for hostname in hostnames:
              name = hostname.get("name")
              if name:
                     return name

       return None


def os_from_nmap(scanner, ip_address):
       if ip_address not in scanner.all_hosts():
              return None

       matches = scanner[ip_address].get("osmatch", [])
       if matches:
              best = matches[0]
              name = best.get("name")
              accuracy = best.get("accuracy")

              if name and accuracy:
                     return f"{name} ({accuracy}%)"

              return name

       return None


def services_with_protocol(services, protocol):
       return {
              port: {
                     **service,
                     "protocol": protocol,
              }
              for port, service in (services or {}).items()
       }


def ip_family(value):
       try:
              return f"IPv{ipaddress.ip_address(str(value).split('%', 1)[0]).version}"
       except ValueError:
              return "-"


def nmap_target(ip_address, interface=None):
       try:
              address = ipaddress.ip_address(str(ip_address).split("%", 1)[0])
       except ValueError:
              return ip_address

       if address.version == 6 and address.is_link_local and interface and "%" not in str(ip_address):
              return f"{ip_address}%{interface}"

       return ip_address


def nmap_arguments(base_arguments, family):
       if family == "IPv6":
              return f"-6 {base_arguments}"

       return base_arguments
