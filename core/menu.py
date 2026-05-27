from rich.console import Console

from engines.discovery import run_discovery
from engines.dhcp_analyzer import run_dhcp_diagnostics

from collectors.raw_writer import write_raw_file

from core.flow import run_full_flow
from core.topology import load_latest_topology_snapshot, render_topology

from utils.banner import show_banner

console = Console()

LAST_DATA = {}


def _select_ip_mode():
       console.print("\n[bold cyan]IP scan mode[/bold cyan]")
       console.print("1. Auto (IPv4 + IPv6)")
       console.print("2. IPv4 only")
       console.print("3. IPv6 only")

       choice = console.input("Select IP mode [1]: ").strip().lower()
       console.clear()

       if choice in {"2", "ipv4", "4", "v4"}:
              return "ipv4"

       if choice in {"3", "ipv6", "6", "v6"}:
              return "ipv6"

       return "auto"


def _read_duration(default=60):
       duration_input = console.input(f"Capture duration seconds [{default}]: ").strip()
       console.clear()

       if not duration_input:
              return default

       try:
              return int(duration_input)
       except ValueError:
              console.print(f"[yellow]Invalid duration, using {default} seconds.[/yellow]")
              return default


def _run_dhcp_menu():
       console.print("\n[bold cyan]DHCP diagnostic mode[/bold cyan]")
       console.print("1. Local DHCP diagnostic")
       console.print("2. Passive monitor clients")
       console.print("3. Active DHCP probe")
       console.print("4. Analyze PCAP file")

       choice = console.input("Select DHCP mode [1]: ").strip()
       console.clear()

       try:
              if choice in {"2", "passive"}:
                     duration = _read_duration(120)
                     run_dhcp_diagnostics(duration_seconds=duration, mode="passive")
              elif choice in {"3", "active"}:
                     duration = _read_duration(10)
                     run_dhcp_diagnostics(duration_seconds=duration, mode="active")
              elif choice in {"4", "pcap"}:
                     file = console.input("PCAP file path: ").strip()
                     if not file:
                            console.clear()
                            console.print("[yellow]PCAP path is required.[/yellow]")
                            return

                     console.clear()
                     run_dhcp_diagnostics(file_path=file, mode="pcap")
              else:
                     file = console.input("PCAP file path (blank to capture DHCP now): ").strip()
                     duration = 60

                     if not file:
                            duration = _read_duration(60)
                     else:
                            console.clear()

                     run_dhcp_diagnostics(
                            file_path=file or None,
                            duration_seconds=duration,
                            mode="local",
                     )
       except RuntimeError as exc:
              console.print(f"[red]DHCP diagnostics stopped:[/red] {exc}")


def _show_help():
       console.print("\n[bold cyan]=== AuditBot Help ===[/bold cyan]\n")
       console.print("[bold]1. Full Flow[/bold]")
       console.print("- Detects the local network.")
       console.print("- Runs infrastructure discovery.")
       console.print("- Saves a raw JSON snapshot.")
       console.print("- Runs passive DHCP client monitoring and classifies DHCP behavior per client MAC.")
       console.print("- Skips DHCP diagnostics in IPv6-only mode because DHCP analysis is currently DHCPv4-focused.")
       console.print()
       console.print("[bold]2. Infrastructure Discovery (ARP + Nmap)[/bold]")
       console.print("- Lets you choose Auto, IPv4-only, or IPv6-only scanning.")
       console.print("- Uses ARP for local IPv4 subnet discovery.")
       console.print("- Uses Nmap for routed or configured IPv4 targets.")
       console.print("- Uses IPv6 neighbor discovery and Nmap -6 for IPv6 targets.")
       console.print("- Shows IP/prefix, hostname, family, MAC, interface, gateway, method, and services.")
       console.print()
       console.print("[bold]3. DHCP Diagnostics[/bold]")
       console.print("- Local DHCP diagnostic: checks DHCP behavior for the machine running AuditBot.")
       console.print("- Passive monitor clients: listens for DHCP traffic and classifies each client MAC separately.")
       console.print("- Active DHCP probe: sends a DHCP Discover only and listens for Offers without taking a lease.")
       console.print("- Analyze PCAP file: reads an existing capture and produces per-client DHCP results.")
       console.print("- Client Sessions can show DHCP_NORMAL, DHCP_NO_OFFER, DHCP_OFFER_NO_ACK, DHCP_NAK_RECEIVED, ROGUE_DHCP_DETECTED, and related states.")
       console.print()
       console.print("[bold]4. Draw Topology[/bold]")
       console.print("- Draws topology from the latest scan data.")
       console.print("- Groups devices by hostname first.")
       console.print("- Lists each interface and IP under that hostname.")
       console.print("- Lists open ports with service name and version under each IP.")
       console.print()
       console.print("[bold]5. Export Last Data[/bold]")
       console.print("- Exports the latest in-session scan or diagnostic data to a raw JSON file.")
       console.print("- Useful for review, debugging, or drawing topology later.")
       console.print()
       console.print("[bold]6. Help[/bold]")
       console.print("- Shows this help screen.")
       console.print()
       console.print("[bold]7. Exit[/bold]")
       console.print("- Exits AuditBot.")


def menu():

       show_banner()

       global LAST_DATA

       while True:

              console.print("\n[bold cyan]=== AuditBot Pro ===[/bold cyan]")
              console.print("1. Full Flow")
              console.print("2. Infrastructure Discovery (ARP + Nmap)")
              console.print("3. DHCP Diagnostics")
              console.print("4. Draw topology (last scan)")
              console.print("5. Export last data")
              console.print("6. Help")
              console.print("7. Exit")

              choice = console.input("Select: ")
              console.clear()

              if choice == "1":
                     ip_mode = _select_ip_mode()
                     data = run_full_flow(ip_mode=ip_mode)
                     if data:
                            LAST_DATA = data
              
              elif choice == "2":
                     ip_mode = _select_ip_mode()
                     LAST_DATA = run_discovery(ip_mode=ip_mode)
                     output_file = write_raw_file(LAST_DATA, "discovery")
                     console.print(f"[green]Discovery JSON exported:[/green] {output_file}")

              elif choice == "3":
                     _run_dhcp_menu()

              elif choice == "4":
                     if LAST_DATA:
                            render_topology(LAST_DATA, "current session")
                     else:
                            LAST_DATA, source_file = load_latest_topology_snapshot()
                            if LAST_DATA:
                                   render_topology(LAST_DATA, source_file)
                            else:
                                   console.print(
                                          "[yellow]No scan data found. Run discovery first.[/yellow]"
                                   )

              elif choice == "5":
                     write_raw_file(LAST_DATA, "audit_snapshot")

              elif choice == "6":
                     _show_help()

              elif choice == "7":
                     break
