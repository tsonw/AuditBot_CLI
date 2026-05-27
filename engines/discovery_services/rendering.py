import ipaddress

from rich import box
from rich.console import Console
from rich.table import Table

console = Console()

COMPACT_TABLE_KWARGS = {
       "box": box.SIMPLE,
       "padding": (0, 1),
       "show_lines": False,
}


def render_networks_table(networks):
       table = Table(title="Discovery Targets", **COMPACT_TABLE_KWARGS)
       table.add_column("#", justify="right")
       table.add_column("Network")
       table.add_column("Scanner IP")
       table.add_column("Family")
       table.add_column("Interface")
       table.add_column("Gateway")
       table.add_column("Source")
       table.add_column("Scan")
       table.add_column("Status")

       for index, net in enumerate(networks, start=1):
              status = net.get("scan_skipped_reason") or "ready"
              table.add_row(
                     str(index),
                     net["network"],
                     net.get("ip") or "-",
                     net.get("family") or "-",
                     net.get("interface") or "-",
                     net.get("via") or "-",
                     net.get("source") or "-",
                     net.get("scan_method") or "-",
                     status,
              )

       console.print(table)


def render_hosts_table(hosts):
       table = Table(title="Discovery Hosts", **COMPACT_TABLE_KWARGS)
       table.add_column("#", justify="right")
       table.add_column("IP")
       table.add_column("Hostname")
       table.add_column("OS")
       table.add_column("Family")
       table.add_column("MAC")
       table.add_column("Interface")
       table.add_column("Gateway")
       table.add_column("Method")
       table.add_column("Service")

       for index, host in enumerate(hosts, start=1):
              display_ip = display_ip_with_prefix(
                     host.get("ip"),
                     host.get("source_network"),
              )
              open_ports = host.get("ports", [])
              services = host.get("services", {})
              service_details = []

              for port in open_ports:
                     service = services.get(port) or services.get(str(port)) or {}
                     protocol = service.get("protocol") or "tcp"
                     name = service.get("name") or "-"
                     product = service.get("product") or ""
                     version = service.get("version") or ""
                     extrainfo = service.get("extrainfo") or ""
                     version_text = " ".join(
                            value for value in [product, version, extrainfo] if value
                     )

                     if version_text:
                            service_details.append(f"{port}/{protocol}:{name} ({version_text})")
                     else:
                            service_details.append(f"{port}/{protocol}:{name}")

              table.add_row(
                     str(index),
                     display_ip,
                     host.get("hostname") or "-",
                     host.get("os") or "-",
                     host.get("family") or "-",
                     host.get("mac") or "-",
                     host.get("source_interface") or "-",
                     host.get("source_gateway") or "-",
                     host.get("discovery_method") or "-",
                     ", ".join(service_details) or "-",
              )

       console.print(table)


def display_ip_with_prefix(ip_value, network_value):
       if not ip_value:
              return "-"

       try:
              network = ipaddress.ip_network(network_value, strict=False)
       except (TypeError, ValueError):
              return ip_value

       return f"{ip_value}/{network.prefixlen}"


def render_errors_table(errors):
       if not errors:
              return

       table = Table(title="Discovery Warnings", **COMPACT_TABLE_KWARGS)
       table.add_column("Network")
       table.add_column("Interface")
       table.add_column("Error")

       for error in errors:
              table.add_row(
                     error.get("network") or "-",
                     error.get("interface") or "-",
                     error.get("error") or "-",
              )

       console.print(table)
