import subprocess
import time
import os
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeRemainingColumn

from scanners.network import get_local_network

console = Console()

DEFAULT_CAPTURE_DURATION_SECONDS = 60


def start_capture(duration_seconds: int = DEFAULT_CAPTURE_DURATION_SECONDS, interface: str | None = None):

       Path("outputs/pcaps").mkdir(parents=True, exist_ok=True)

       filename = f"outputs/pcaps/capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
       capture_interface = interface or get_local_network()["interface"]

       console.print(
              f"[cyan]Capturing traffic:[/cyan] {capture_interface} "
              f"for {duration_seconds}s"
       )

       cmd = [
              "tshark",
              "-i", capture_interface,
              "-a", f"duration:{duration_seconds}",
              "-w", filename
       ]

       try:
              process = subprocess.Popen(
                     cmd,
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE,
                     text=True
              )
       except FileNotFoundError as exc:
              raise RuntimeError("tshark is not installed or not available in PATH.") from exc

       with Progress(
              SpinnerColumn(),
              TextColumn("[progress.description]{task.description}"),
              BarColumn(),
              TimeRemainingColumn(),
              console=console
       ) as progress:
              task = progress.add_task("Packet capture", total=duration_seconds)
              started_at = time.monotonic()

              while process.poll() is None:
                     elapsed = min(time.monotonic() - started_at, duration_seconds)
                     progress.update(task, completed=elapsed)
                     time.sleep(0.25)

              elapsed = min(time.monotonic() - started_at, duration_seconds)
              completed = duration_seconds if process.returncode == 0 else elapsed
              progress.update(task, completed=completed)

       stdout, stderr = process.communicate()

       if process.returncode != 0:
              details = stderr.strip() or stdout.strip() or "unknown tshark error"
              if "BPF" in details or "/dev/bpf" in details or "Operation not permitted" in details:
                     raise RuntimeError(
                            "Packet capture needs root/BPF permissions. Run: make run"
                     )
              raise RuntimeError(f"Packet capture failed: {details}")

       os.chmod(filename, 0o644)
       console.print(f"[green]Capture saved:[/green] {filename}")
       return filename
