from __future__ import annotations

import platform
from pathlib import Path


def detect_os() -> dict:
       """Detect host OS and common runtime hints."""

       system = platform.system().lower()
       release = platform.release()
       os_release = _read_os_release()
       os_name = _os_name(system, os_release)

       return {
              "os_name": os_name,
              "platform": platform.platform(),
              "release": release,
              "is_macos": system == "darwin",
              "is_linux": system == "linux",
              "is_kali": "kali" in os_release.lower(),
              "is_docker": _is_docker(),
       }


def _os_name(system: str, os_release: str) -> str:
       if system == "darwin":
              return "macos"
       if "kali" in os_release.lower():
              return "kali"
       if system == "linux":
              return "linux"
       return system or "unknown"


def _read_os_release() -> str:
       path = Path("/etc/os-release")
       if not path.exists():
              return ""
       try:
              return path.read_text(errors="ignore")
       except OSError:
              return ""


def _is_docker() -> bool:
       if Path("/.dockerenv").exists():
              return True
       for path in (Path("/proc/1/cgroup"), Path("/proc/self/cgroup")):
              try:
                     content = path.read_text(errors="ignore").lower()
              except OSError:
                     continue
              if "docker" in content or "containerd" in content or "kubepods" in content:
                     return True
       return False

