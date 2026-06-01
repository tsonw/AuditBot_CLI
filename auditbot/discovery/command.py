from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class CommandResult:
       """Small stable wrapper around subprocess output."""

       command: list[str]
       returncode: int
       stdout: str
       stderr: str
       timed_out: bool = False
       missing: bool = False

       @property
       def ok(self) -> bool:
              return self.returncode == 0 and not self.timed_out and not self.missing


def command_exists(name: str) -> bool:
       """Return whether a command is available in PATH."""

       return shutil.which(name) is not None


def run_command(command: list[str], timeout: int = 8) -> CommandResult:
       """Run a command without shell expansion and capture all output."""

       try:
              completed = subprocess.run(
                     command,
                     capture_output=True,
                     text=True,
                     timeout=timeout,
                     check=False,
              )
       except FileNotFoundError:
              return CommandResult(command, 127, "", f"{command[0]} not found", missing=True)
       except PermissionError as exc:
              return CommandResult(command, 126, "", str(exc))
       except OSError as exc:
              return CommandResult(command, 126, "", str(exc))
       except subprocess.TimeoutExpired as exc:
              return CommandResult(
                     command,
                     124,
                     exc.stdout or "",
                     exc.stderr or "command timed out",
                     timed_out=True,
              )

       return CommandResult(command, completed.returncode, completed.stdout, completed.stderr)


def warning_from_result(result: CommandResult) -> str | None:
       """Build a short warning string for failed command attempts."""

       if result.ok:
              return None
       details = (result.stderr or result.stdout or "").strip()
       command = " ".join(result.command)
       if result.missing:
              return f"{result.command[0]} is not installed or not available in PATH"
       if result.timed_out:
              return f"{command} timed out"
       if "Operation not permitted" in details or "Permission denied" in details or "/dev/bpf" in details:
              return f"{command} needs capture/root permissions"
       return f"{command} failed: {details or result.returncode}"
