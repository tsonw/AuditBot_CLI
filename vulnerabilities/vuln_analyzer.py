import json
from datetime import datetime
from pathlib import Path

from config.nvd_config import NVD_DB_PATH
from vulnerabilities.cpe_matcher import build_cpe_candidates
from vulnerabilities.cve_lookup import (
    get_database_last_imported_at,
    get_database_last_update,
    lookup_cves_by_cpe,
)
from vulnerabilities.risk_classifier import classify_risk, generate_recommendation
from vulnerabilities.service_normalizer import normalize_service


DEFAULT_REPORT_DIR = Path("output") / "vuln"
DEFAULT_REPORT_PATTERN = "output/vuln/vulnerability_report.json"
DEFAULT_REPORT_PATH = DEFAULT_REPORT_DIR / "vulnerability_report.json"
DATABASE_UPDATE_WARNING_DAYS = 3


def analyze_service_vulnerabilities(service_info):
    service = normalize_service(service_info)
    product_name = service.get("product") or service.get("service")
    cpe_candidates = build_cpe_candidates(product_name, service.get("version"))
    cves = lookup_cves_by_cpe(cpe_candidates, service.get("version"))

    vulnerabilities = []
    for cve in sorted(cves, key=lambda item: float(item.get("cvss_score") or 0), reverse=True):
        risk = classify_risk(cve.get("cvss_score"))
        vulnerabilities.append({
            "cve_id": cve.get("cve_id"),
            "cvss_score": cve.get("cvss_score"),
            "severity": cve.get("severity") or risk,
            "risk": risk,
            "cwe": cve.get("cwe"),
            "description": cve.get("description"),
            "published_date": cve.get("published_date"),
            "last_modified_date": cve.get("last_modified_date"),
            "matched_cpe": cve.get("criteria"),
            "recommendation": generate_recommendation(
                service.get("product") or service.get("service"),
                service.get("version"),
                risk,
            ),
        })

    return {
        **service,
        "cpe_candidates": cpe_candidates,
        "vulnerabilities_count": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    }


def analyze_scan_result(scan_results):
    services = extract_services_from_scan(scan_results)
    print(f"[NVD] Services found for offline CVE lookup: {len(services)}")
    return [analyze_service_vulnerabilities(service) for service in services]


def analyze_scan_file(input_file, output_file=None, warning_handler=None):
    input_path = Path(input_file)
    if not input_path.exists():
        raise FileNotFoundError(f"Scan result file does not exist: {input_path}")

    with open(input_path, encoding="utf-8") as file:
        scan_results = json.load(file)

    return analyze_scan_data(scan_results, output_file, warning_handler)


def analyze_scan_data(scan_results, output_file=None, warning_handler=None):
    warn_if_database_update_recommended(warning_handler=warning_handler)

    results = analyze_scan_result(scan_results)
    report = build_report(results)
    report_path = write_report(report, output_file)
    report["report_file"] = str(report_path)
    return report


def default_vulnerability_report_file():
    output_path = DEFAULT_REPORT_PATH
    counter = 1

    while output_path.exists():
        output_path = DEFAULT_REPORT_DIR / f"vulnerability_report_{counter}.json"
        counter += 1

    return output_path


def build_report(results):
    return {
        "vulnerability_database": {
            "source": "NVD JSON 2.0 Data Feed",
            "mode": "local",
            "api_used": False,
            "last_update": get_database_last_update(),
            "last_imported_at": get_database_last_imported_at(),
            "generated_at": datetime.now().isoformat(timespec="seconds"),
        },
        "results": results,
    }


def warn_if_database_update_recommended(db_path=NVD_DB_PATH, now=None, warning_handler=None):
    warning = get_database_update_warning(db_path, now)
    if warning:
        if warning_handler:
            warning_handler(warning)
        else:
            print(f"\033[31m{warning}\033[0m")
    return warning


def get_database_update_warning(db_path=NVD_DB_PATH, now=None):
    path = Path(db_path)
    if not path.exists():
        return (
            f"[NVD] WARNING: Local vulnerability database not found at {path}. "
            "Please run 'python main.py nvd-init' before vulnerability analysis."
        )

    last_imported_at = get_database_last_imported_at(db_path)
    if not last_imported_at:
        return (
            "[NVD] WARNING: Local vulnerability database has no update timestamp. "
            "Please run 'python main.py nvd-update' before vulnerability analysis."
        )

    try:
        last_imported = datetime.fromisoformat(last_imported_at)
    except ValueError:
        return (
            f"[NVD] WARNING: Local vulnerability database update timestamp is invalid "
            f"({last_imported_at}). Please run 'python main.py nvd-update' before vulnerability analysis."
        )

    current_time = now or datetime.now()
    age_days = (current_time - last_imported).days
    if age_days < DATABASE_UPDATE_WARNING_DAYS:
        return None

    return (
        f"[NVD] WARNING: Local vulnerability database was last updated {age_days} day(s) ago "
        f"({last_imported_at}). Please run 'python main.py nvd-update' before vulnerability analysis."
    )


def write_report(report, output_file=None):
    output_path = Path(output_file) if output_file else default_vulnerability_report_file()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)

    print(f"[NVD] Vulnerability report exported: {output_path}")
    return output_path


def extract_services_from_scan(scan_results):
    if isinstance(scan_results, list):
        return scan_results

    services = []
    networks = scan_results.get("network_results", []) if isinstance(scan_results, dict) else []

    for network in networks:
        for host in network.get("hosts", []):
            for port, service in (host.get("services") or {}).items():
                services.append({
                    "host": host.get("ip"),
                    "hostname": host.get("hostname"),
                    "asset_id": host.get("asset_id"),
                    "port": port,
                    "protocol": service.get("protocol", "tcp"),
                    "service": service.get("name"),
                    "product": service.get("product"),
                    "version": service.get("version"),
                })

    return services
