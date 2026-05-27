from scanners.network import get_local_network, normalize_ip_mode
from engines.discovery import run_discovery
from engines.dhcp_analyzer import run_dhcp_diagnostics
from collectors.raw_writer import write_raw_file
from rich.console import Console

console = Console()


def run_full_flow(ip_mode: str | None = None):
       mode = normalize_ip_mode(ip_mode)

       console.print("\n[bold cyan]=== AUDITBOT FULL FLOW START ===[/bold cyan]\n")

       # STEP 1 - Network
       console.print(f"[1] Detecting network ({mode})...")
       get_local_network(mode)

       # STEP 2 - Discovery
       console.print("[2] Running discovery...")
       data = run_discovery(ip_mode=mode)

       # STEP 3 - Save snapshot
       console.print("[3] Saving raw snapshot...")
       output_file = write_raw_file(data, "full_scan")
       console.print(f"[green]Discovery JSON exported:[/green] {output_file}")

       # STEP 4 - DHCP diagnostics
       if mode == "ipv6":
              console.print("[yellow]Skipping DHCP diagnostics: current diagnostics support DHCPv4 only.[/yellow]")
              console.print("\n[bold green]FLOW COMPLETED[/bold green]")
              return data

       console.print("[4] Running passive DHCP client monitor...")
       try:
              run_dhcp_diagnostics(mode="passive")
       except RuntimeError as exc:
              console.print(f"[red]DHCP diagnostics stopped:[/red] {exc}")
              return data

       console.print("\n[bold green]FLOW COMPLETED[/bold green]")
       return data
