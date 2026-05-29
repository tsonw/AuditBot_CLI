from scanners.network import get_local_network, normalize_ip_mode
from engines.discovery import run_discovery
from engines.dhcp_analyzer import run_dhcp_diagnostics
from collectors.raw_writer import write_raw_file
from reports.pdf_report import generate_full_flow_report
from vulnerabilities.vuln_analyzer import analyze_scan_data
from rich.console import Console

console = Console()

NOTABLE_VULNERABILITY_MIN_SCORE = 7.0


def _confirm_report():
       answer = console.input("Create PDF report? [y/N]: ").strip().lower()
       return answer in {"y", "yes"}


def _maybe_generate_report(data):
       if not _confirm_report():
              return

       try:
              report_file = generate_full_flow_report(data)
       except OSError as exc:
              console.print(f"[red]Report generation failed:[/red] {exc}")
              return

       console.print(f"[green]PDF report generated:[/green] {report_file}")


def _print_warning(message):
       console.print(message, style="red", markup=False)


def _run_vulnerability_analysis(data):
       console.print("[4] Running local NVD vulnerability analysis...")

       try:
              report = analyze_scan_data(data, warning_handler=_print_warning)
       except (OSError, ValueError) as exc:
              console.print(f"[red]Vulnerability analysis stopped:[/red] {exc}")
              data["vulnerability_analysis"] = {
                     "error": str(exc),
              }
              return

       results = report.get("results", [])
       total_vulns = sum(item.get("vulnerabilities_count", 0) for item in results)
       notable = _collect_notable_vulnerabilities(report)

       data["vulnerability_analysis"] = {
              "report_file": report.get("report_file"),
              "services_analyzed": len(results),
              "vulnerabilities_matched": total_vulns,
              "notable_count": len(notable),
              "notable": notable[:10],
              "database": report.get("vulnerability_database") or {},
       }

       console.print(f"[green]Vulnerability report exported:[/green] {report.get('report_file')}")
       console.print(f"[green]Services analyzed:[/green] {len(results)}")
       console.print(f"[green]Vulnerabilities matched:[/green] {total_vulns}")
       console.print(f"[green]Notable vulnerabilities:[/green] {len(notable)}")


def _collect_notable_vulnerabilities(report):
       notable = []

       for service in report.get("results", []):
              for vulnerability in service.get("vulnerabilities", []):
                     score = _safe_float(vulnerability.get("cvss_score"))
                     severity = str(vulnerability.get("severity") or vulnerability.get("risk") or "").lower()

                     if severity in {"critical", "high"} or score >= NOTABLE_VULNERABILITY_MIN_SCORE:
                            notable.append({
                                   "host": service.get("host"),
                                   "hostname": service.get("hostname"),
                                   "port": service.get("port"),
                                   "protocol": service.get("protocol"),
                                   "service": service.get("service"),
                                   "product": service.get("product"),
                                   "version": service.get("version"),
                                   "cve_id": vulnerability.get("cve_id"),
                                   "cvss_score": vulnerability.get("cvss_score"),
                                   "severity": vulnerability.get("severity") or vulnerability.get("risk"),
                                   "recommendation": vulnerability.get("recommendation"),
                            })

       return sorted(notable, key=lambda item: _safe_float(item.get("cvss_score")), reverse=True)


def _safe_float(value):
       try:
              return float(value or 0)
       except (TypeError, ValueError):
              return 0.0


def run_full_flow(ip_mode: str | None = None):
       mode = normalize_ip_mode(ip_mode)

       console.print("\n[bold cyan]=== AUDITBOT COMPREHENSIVE AUDIT START ===[/bold cyan]\n")

       # STEP 1 - Network
       console.print(f"[1] Detecting network ({mode})...")
       get_local_network(mode)

       # STEP 2 - Discovery
       console.print("[2] Running discovery...")
       data = run_discovery(ip_mode=mode)
       data["ip_mode"] = mode

       # STEP 3 - DHCP diagnostics
       if mode == "ipv6":
              console.print("[yellow]Skipping DHCP diagnostics: current diagnostics support DHCPv4 only.[/yellow]")
              data["dhcp_diagnostics"] = {
                     "skipped": True,
                     "reason": "DHCP diagnostics currently support DHCPv4 only.",
              }
       else:
              console.print("[3] Running passive DHCP client monitor...")
              try:
                     data["dhcp_diagnostics"] = run_dhcp_diagnostics(mode="passive")
              except RuntimeError as exc:
                     console.print(f"[red]DHCP diagnostics stopped:[/red] {exc}")
                     data["dhcp_diagnostics"] = {
                            "error": str(exc),
                     }

       # STEP 4 - Vulnerability analysis
       _run_vulnerability_analysis(data)

       # STEP 5 - Save snapshot
       console.print("[5] Saving comprehensive audit snapshot...")
       output_file = write_raw_file(data, "comprehensive_audit")
       data["raw_file"] = output_file
       console.print(f"[green]Comprehensive audit JSON exported:[/green] {output_file}")

       console.print("\n[bold green]COMPREHENSIVE AUDIT COMPLETED[/bold green]")
       _maybe_generate_report(data)
       return data
