from scanners.network import get_local_network
from engines.discovery import run_discovery
from engines.dhcp_analyzer import run_dhcp_diagnostics
from collectors.raw_writer import write_raw_file
from rich.console import Console

console = Console()


def run_full_flow():

       console.print("\n[bold cyan]=== AUDITBOT FULL FLOW START ===[/bold cyan]\n")

       # STEP 1 - Network
       console.print("[1] Detecting network...")
       net = get_local_network()

       # STEP 2 - Discovery
       console.print("[2] Running discovery...")
       data = run_discovery()

       # STEP 3 - Save snapshot
       console.print("[3] Saving raw snapshot...")
       output_file = write_raw_file(data, "full_scan")
       console.print(f"[green]Discovery JSON exported:[/green] {output_file}")

       # STEP 4 - DHCP diagnostics
       console.print("[4] Running DHCP diagnostics...")
       try:
              run_dhcp_diagnostics()
       except RuntimeError as exc:
              console.print(f"[red]DHCP diagnostics stopped:[/red] {exc}")
              return data

       console.print("\n[bold green]FLOW COMPLETED[/bold green]")
       return data
