from rich.console import Console

from engines.discovery import run_discovery
from engines.dhcp_analyzer import run_dhcp_diagnostics

from collectors.raw_writer import write_raw_file

from core.flow import run_full_flow
from core.topology import load_latest_topology_snapshot, render_topology

from utils.banner import show_banner

console = Console()

LAST_DATA = {}


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
              console.print("6. Exit")

              choice = console.input("Select: ")

              if choice == "1":
                     data = run_full_flow()
                     if data:
                            LAST_DATA = data
              
              elif choice == "2":
                     LAST_DATA = run_discovery()
                     output_file = write_raw_file(LAST_DATA, "discovery")
                     console.print(f"[green]Discovery JSON exported:[/green] {output_file}")

              elif choice == "3":
                     file = console.input("PCAP file path (blank to capture DHCP now): ").strip()
                     duration = 60

                     if not file:
                            duration_input = console.input("Capture duration seconds [60]: ").strip()
                            if duration_input:
                                   try:
                                          duration = int(duration_input)
                                   except ValueError:
                                          console.print("[yellow]Invalid duration, using 60 seconds.[/yellow]")

                     try:
                            run_dhcp_diagnostics(file_path=file or None, duration_seconds=duration)
                     except RuntimeError as exc:
                            console.print(f"[red]DHCP diagnostics stopped:[/red] {exc}")

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
                     break
