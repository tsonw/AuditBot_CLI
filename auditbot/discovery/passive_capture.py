from __future__ import annotations

import json
import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from auditbot.discovery.command import command_exists, run_command, warning_from_result


def try_passive_capture(
       interface: str | None,
       os_info: dict,
       duration_seconds: int = 10,
       output_dir: str = "output/pcaps",
) -> dict:
       """Try tshark/tcpdump/pktap/dumpcap capture paths and never raise."""

       Path(output_dir).mkdir(parents=True, exist_ok=True)
       attempts = _capture_attempts(interface, os_info)
       warnings: list[str] = []

       for attempt in attempts:
              binary = attempt["command"][0]
              if not command_exists(binary):
                     warnings.append(f"{binary} is not installed; trying next capture strategy")
                     continue

              capture_file = _capture_path(output_dir, attempt["name"], attempt["suffix"])
              command = [part.format(file=str(capture_file), duration=str(duration_seconds)) for part in attempt["command"]]
              result = _run_capture(command, duration_seconds, attempt["managed_stop"])
              if warning := warning_from_result(result):
                     warnings.append(warning)
                     continue

              packet_count = _packet_count(capture_file, result.stderr)
              if packet_count <= 0:
                     warnings.append(f"{attempt['name']} completed but captured no packets")
                     continue

              observed_ips = _extract_observed_ips(capture_file)
              try:
                     os.chmod(capture_file, 0o644)
              except OSError:
                     pass
              return {
                     "capture_status": "success",
                     "method": attempt["name"],
                     "file": str(capture_file),
                     "packet_count": packet_count,
                     "observed_ips": observed_ips,
                     "warnings": warnings,
              }

       return {
              "capture_status": "failed",
              "method": None,
              "file": None,
              "packet_count": 0,
              "observed_ips": [],
              "warnings": warnings,
       }


def _capture_attempts(interface: str | None, os_info: dict) -> list[dict]:
       attempts = []
       if interface:
              attempts.append({
                     "name": "tshark_default_interface",
                     "suffix": ".pcapng",
                     "managed_stop": False,
                     "command": ["tshark", "-i", interface, "-a", "duration:{duration}", "-w", "{file}"],
              })
              attempts.append({
                     "name": "tcpdump_default_interface",
                     "suffix": ".pcap",
                     "managed_stop": True,
                     "command": ["tcpdump", "-i", interface, "-w", "{file}"],
              })
       if os_info.get("is_macos"):
              attempts.append({
                     "name": "tcpdump_pktap_all",
                     "suffix": ".pcap",
                     "managed_stop": True,
                     "command": ["tcpdump", "-i", "pktap,all", "-w", "{file}"],
              })
       if interface:
              attempts.append({
                     "name": "dumpcap_default_interface",
                     "suffix": ".pcapng",
                     "managed_stop": False,
                     "command": ["dumpcap", "-i", interface, "-a", "duration:{duration}", "-w", "{file}"],
              })
       return attempts


def _run_capture(command: list[str], duration_seconds: int, managed_stop: bool):
       if not managed_stop:
              return run_command(command, timeout=duration_seconds + 8)

       try:
              process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
       except FileNotFoundError:
              from auditbot.discovery.command import CommandResult
              return CommandResult(command, 127, "", f"{command[0]} not found", missing=True)

       time.sleep(duration_seconds)
       if process.poll() is None:
              process.terminate()
              try:
                     stdout, stderr = process.communicate(timeout=3)
              except subprocess.TimeoutExpired:
                     process.kill()
                     stdout, stderr = process.communicate()
       else:
              stdout, stderr = process.communicate()

       from auditbot.discovery.command import CommandResult
       returncode = 0 if process.returncode in {0, -15, None} else process.returncode
       return CommandResult(command, returncode, stdout or "", stderr or "")


def _capture_path(output_dir: str, method: str, suffix: str) -> Path:
       timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
       path = Path(output_dir) / f"{method}_{timestamp}{suffix}"
       counter = 1
       while path.exists():
              path = Path(output_dir) / f"{method}_{timestamp}_{counter}{suffix}"
              counter += 1
       return path


def _packet_count(capture_file: Path, stderr: str) -> int:
       match = re.search(r"(\d+)\s+packets captured", stderr or "", re.I)
       if match:
              return int(match.group(1))
       if not capture_file.exists() or capture_file.stat().st_size <= 24:
              return 0
       if command_exists("tshark"):
              result = run_command(["tshark", "-r", str(capture_file), "-T", "fields", "-e", "frame.number"], timeout=20)
              if result.ok:
                     return len([line for line in result.stdout.splitlines() if line.strip()])
       return 1


def _extract_observed_ips(capture_file: Path) -> list[str]:
       if not command_exists("tshark"):
              return []
       result = run_command(["tshark", "-r", str(capture_file), "-T", "json"], timeout=30)
       if not result.ok:
              return []
       try:
              packets = json.loads(result.stdout)
       except json.JSONDecodeError:
              return []
       ips: set[str] = set()
       for packet in packets:
              _collect_ip_fields(packet, ips)
       return sorted(ips)


def _collect_ip_fields(value: Any, ips: set[str]) -> None:
       if isinstance(value, dict):
              for key, child in value.items():
                     if key in {"ip.src", "ip.dst", "ipv6.src", "ipv6.dst"} and isinstance(child, str):
                            ips.add(child)
                     else:
                            _collect_ip_fields(child, ips)
       elif isinstance(value, list):
              for child in value:
                     _collect_ip_fields(child, ips)

