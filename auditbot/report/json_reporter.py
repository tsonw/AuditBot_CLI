from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


def write_json_report(report: dict, prefix: str = "auditbot_discovery", output_dir: str = "output/raw") -> str:
       """Write a stable JSON report and return its path."""

       directory = Path(output_dir)
       directory.mkdir(parents=True, exist_ok=True)
       timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
       output_file = directory / f"{prefix}_{timestamp}.json"
       counter = 1
       while output_file.exists():
              output_file = directory / f"{prefix}_{timestamp}_{counter}.json"
              counter += 1
       output_file.write_text(json.dumps(report, indent=2, sort_keys=True))
       return str(output_file)

