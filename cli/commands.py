import typer

from cli.app import app
from config.nvd_config import START_YEAR
from core.menu import menu
from vulnerabilities.nvd_downloader import NvdDownloadError, download_modified_feed, download_year_feeds
from vulnerabilities.nvd_importer import import_nvd_json, init_db
from vulnerabilities.vuln_analyzer import analyze_scan_file


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
       if ctx.invoked_subcommand is None:
              menu()


def run():
       menu()

app.command()(run)


@app.command("nvd-init")
def nvd_init(start_year: int = START_YEAR):
       print("[NVD] Initializing local NVD vulnerability database")
       init_db()
       json_paths = download_year_feeds(start_year)

       for json_path in json_paths:
              import_nvd_json(json_path)

       print(f"[NVD] Initialization completed. Feeds imported: {len(json_paths)}")


@app.command("nvd-update")
def nvd_update():
       print("[NVD] Updating local NVD vulnerability database from modified feed")
       init_db()
       try:
              json_path = download_modified_feed()
       except NvdDownloadError as exc:
              print(f"\033[31m{exc}\033[0m")
              return

       import_nvd_json(json_path)
       print("[NVD] Update completed")


@app.command("vuln-check")
def vuln_check(input_file: str, output_file: str = ""):
       print("[NVD] Running offline vulnerability analysis")
       report = analyze_scan_file(input_file, output_file or None)
       print(f"[NVD] Services analyzed: {len(report.get('results', []))}")
       print(f"[NVD] Vulnerability report exported: {report.get('report_file')}")
