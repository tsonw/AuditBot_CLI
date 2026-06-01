from rich import box
from rich.console import Console
from rich.table import Table

from config.nvd_config import NVD_DB_PATH, START_YEAR
from engines.discovery import run_discovery
from engines.dhcp_analyzer import run_dhcp_diagnostics
from vulnerabilities.nvd_downloader import NvdDownloadError, download_modified_feed, download_year_feeds
from vulnerabilities.nvd_importer import import_nvd_json, init_db
from vulnerabilities.vuln_analyzer import DEFAULT_REPORT_PATTERN, analyze_scan_file

from collectors.raw_writer import write_raw_file

from core.flow import run_full_flow
from core.topology import load_latest_topology_snapshot, render_topology

from utils.banner import show_banner

console = Console()

LAST_DATA = {}

LOCAL_NVD_NOTABLE_MIN_SCORE = 7.0


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
       console.print("[bold]1. Comprehensive Audit (DHCP + Vulnerability Scan)[/bold]")
       console.print("- Detects the local network.")
       console.print("- Runs infrastructure discovery.")
       console.print("- Runs passive DHCP client monitoring and classifies DHCP behavior per client MAC.")
       console.print("- Runs local NVD vulnerability analysis against discovered services.")
       console.print("- Saves a comprehensive raw JSON snapshot with discovery, DHCP, and vulnerability summary.")
       console.print("- Asks whether to generate a PDF report at the end.")
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
       console.print("- Groups devices by asset identity, with hostname used as the display label when available.")
       console.print("- Keeps each interface/IP separate under the asset to handle multi-interface hosts.")
       console.print("- Splits same-hostname observations in the same network when needed to avoid merging duplicate hosts.")
       console.print("- Lists open ports with service name and version under each IP.")
       console.print()
       console.print("[bold]5. Vulnerability Scan with Local NVD Database[/bold]")
       console.print("- Runs a fresh infrastructure discovery scan first.")
       console.print("- Saves the scan result as a raw JSON file.")
       console.print("- Analyzes the new scan result with the local SQLite NVD database.")
       console.print("- Displays notable CRITICAL/HIGH or CVSS >= 7.0 vulnerabilities after analysis.")
       console.print("- Warns before analysis when the local database was last updated 3 or more days ago.")
       console.print(f"- Writes results to {DEFAULT_REPORT_PATTERN}.")
       console.print()
       if _nvd_database_exists():
              console.print("[bold]6. Update NVD Local Database (Latest Modified Feed)[/bold]")
              console.print("- Downloads the official NVD JSON 2.0 modified feed.")
              console.print("- Replaces changed CVE rows and refreshes their CPE matches in SQLite.")
       else:
              console.print("[bold]6. Init NVD Local Database[/bold]")
              console.print("- Creates the local SQLite CVE database.")
              console.print("- Downloads official NVD JSON 2.0 yearly feeds from START_YEAR through the current year.")
              console.print("- Imports CVE, CVSS, CWE, descriptions, and CPE match ranges into SQLite.")
              console.print("- Does not use the NVD API.")

       console.print()
       console.print("[bold]7. Help[/bold]")
       console.print("- Shows this help screen.")
       console.print()
       console.print("[bold]8. Exit[/bold]")
       console.print("- Exits AuditBot.")


def _init_nvd_local_database_menu():
       console.print("[bold cyan][NVD] Initializing local database from yearly feeds...[/bold cyan]")
       console.print(f"[yellow]START_YEAR is {START_YEAR}. This can download many official NVD feed files.[/yellow]")
       init_db()
       json_paths = download_year_feeds(START_YEAR)

       for json_path in json_paths:
              import_nvd_json(json_path)

       console.print(f"[green]NVD local database initialized. Feeds imported: {len(json_paths)}[/green]")


def _update_nvd_local_database_menu():
       console.print("[bold cyan][NVD] Updating local database from modified feed...[/bold cyan]")
       init_db()
       try:
              json_path = download_modified_feed()
       except NvdDownloadError as exc:
              console.print(str(exc), style="red", markup=False)
              return

       import_nvd_json(json_path)
       console.print("[green]NVD local database updated.[/green]")


def _run_local_nvd_vulnerability_scan_menu():
       global LAST_DATA

       console.print("[bold cyan][1] Running fresh discovery scan for local NVD analysis...[/bold cyan]")
       scan_data = run_discovery(ip_mode="auto")
       scan_data["ip_mode"] = "auto"
       LAST_DATA = scan_data

       scan_file = write_raw_file(scan_data, "local_nvd_vulnerability_discovery")
       console.print(f"[green]Discovery JSON exported:[/green] {scan_file}")
       console.print("[bold cyan][2] Analyzing scan result with local NVD database...[/bold cyan]")

       try:
              report = analyze_scan_file(scan_file, warning_handler=_print_warning)
       except (FileNotFoundError, ValueError) as exc:
              console.print(f"[red]Local NVD vulnerability scan stopped:[/red] {exc}")
              return

       report_file = report.get("report_file") or DEFAULT_REPORT_PATTERN
       total_vulns = sum(item.get("vulnerabilities_count", 0) for item in report.get("results", []))
       console.print(f"[green]Vulnerability report exported:[/green] {report_file}")
       console.print(f"[green]Services analyzed:[/green] {len(report.get('results', []))}")
       console.print(f"[green]Vulnerabilities matched:[/green] {total_vulns}")
       _render_local_nvd_notable_vulnerabilities(report, report_file=report_file)


def _print_warning(message):
       console.print(message, style="red", markup=False)


def _render_local_nvd_notable_vulnerabilities(report, limit=15, report_file=DEFAULT_REPORT_PATTERN):
       notable = _collect_local_nvd_notable_vulnerabilities(report)

       if not notable:
              console.print("[green]No notable local NVD vulnerabilities found.[/green]")
              return

       table = Table(
              title="Notable Local NVD Vulnerabilities",
              box=box.SIMPLE,
              padding=(0, 1),
              show_lines=False,
       )
       table.add_column("#", justify="right")
       table.add_column("Host")
       table.add_column("Service")
       table.add_column("Product")
       table.add_column("CVE")
       table.add_column("Score", justify="right")
       table.add_column("Severity")
       table.add_column("Recommendation")

       for index, item in enumerate(notable[:limit], start=1):
              vulnerability = item["vulnerability"]
              service = item["service"]
              table.add_row(
                     str(index),
                     service.get("host") or "-",
                     _local_nvd_service_label(service),
                     _local_nvd_product_label(service),
                     vulnerability.get("cve_id") or "-",
                     _local_nvd_score_label(vulnerability.get("cvss_score")),
                     _local_nvd_severity_label(vulnerability.get("severity") or vulnerability.get("risk")),
                     vulnerability.get("recommendation") or "-",
              )

       console.print(table)

       remaining = len(notable) - limit
       if remaining > 0:
              console.print(f"[yellow]{remaining} additional notable vulnerabilities are available in {report_file}.[/yellow]")


def _collect_local_nvd_notable_vulnerabilities(report):
       notable = []

       for service in report.get("results", []):
              for vulnerability in service.get("vulnerabilities", []):
                     score = _safe_float(vulnerability.get("cvss_score"))
                     severity = str(vulnerability.get("severity") or vulnerability.get("risk") or "").lower()

                     if severity in {"critical", "high"} or score >= LOCAL_NVD_NOTABLE_MIN_SCORE:
                            notable.append({
                                   "service": service,
                                   "vulnerability": vulnerability,
                                   "score": score,
                            })

       return sorted(notable, key=lambda item: item["score"], reverse=True)


def _local_nvd_service_label(service):
       port = service.get("port") or "-"
       protocol = service.get("protocol") or "tcp"
       name = service.get("service") or "-"
       return f"{port}/{protocol}:{name}"


def _local_nvd_product_label(service):
       return " ".join(
              value
              for value in [service.get("product"), service.get("version")]
              if value
       ) or "-"


def _local_nvd_score_label(score):
       score_value = _safe_float(score)
       label = "-" if score in (None, "") else str(score)

       if score_value >= 9.0:
              return f"[bold red]{label}[/bold red]"
       if score_value >= 7.0:
              return f"[red]{label}[/red]"
       return label


def _local_nvd_severity_label(severity):
       value = str(severity or "-")
       normalized = value.lower()

       if normalized == "critical":
              return f"[bold red]{value}[/bold red]"
       if normalized == "high":
              return f"[red]{value}[/red]"
       if normalized == "medium":
              return f"[yellow]{value}[/yellow]"
       return value


def _safe_float(value):
       try:
              return float(value or 0)
       except (TypeError, ValueError):
              return 0.0


def _nvd_database_exists():
       return NVD_DB_PATH.exists()


def _menu_options():
       options = [
              ("1", "Comprehensive Audit (DHCP + Vulnerability Scan)", _run_comprehensive_audit_menu),
              ("2", "Infrastructure Discovery (ARP + Nmap)", _run_discovery_menu),
              ("3", "DHCP Diagnostics", _run_dhcp_menu),
              ("4", "Draw topology (last scan)", _draw_topology_menu),
              ("5", "Vulnerability Scan with Local NVD Database", _run_local_nvd_vulnerability_scan_menu),
       ]

       if _nvd_database_exists():
              options.append(("6", "Update NVD Local Database (Latest Modified Feed)", _update_nvd_local_database_menu))
              options.append(("7", "Help", _show_help))
              options.append(("8", "Exit", None))
       else:
              options.append(("6", "Init NVD Local Database", _init_nvd_local_database_menu))
              options.append(("7", "Help", _show_help))
              options.append(("8", "Exit", None))

       return options


def _run_comprehensive_audit_menu():
       global LAST_DATA

       ip_mode = _select_ip_mode()
       data = run_full_flow(ip_mode=ip_mode)
       if data:
              LAST_DATA = data


def _run_discovery_menu():
       global LAST_DATA

       ip_mode = _select_ip_mode()
       LAST_DATA = run_discovery(ip_mode=ip_mode)
       output_file = write_raw_file(LAST_DATA, "discovery")
       console.print(f"[green]Discovery JSON exported:[/green] {output_file}")


def _draw_topology_menu():
       global LAST_DATA

       if LAST_DATA:
              render_topology(LAST_DATA, "current session")
              return

       LAST_DATA, source_file = load_latest_topology_snapshot()
       if LAST_DATA:
              render_topology(LAST_DATA, source_file)
       else:
              console.print("[yellow]No scan data found. Run discovery first.[/yellow]")


def menu():

       show_banner()

       global LAST_DATA

       while True:

              console.print("\n[bold cyan]=== AuditBot Pro ===[/bold cyan]")
              if not _nvd_database_exists():
                     console.print(
                            "[bold red]WARNING: Local NVD database is not initialized. "
                            "Run option 6 before vulnerability scans.[/bold red]"
                     )

              options = _menu_options()

              for number, label, _handler in options:
                     console.print(f"{number}. {label}")

              choice = console.input("Select: ")
              console.clear()

              selected = next((option for option in options if option[0] == choice), None)
              if not selected:
                     console.print("[yellow]Invalid option.[/yellow]")
                     continue

              _number, _label, handler = selected
              if handler is None:
                     break

              handler()
