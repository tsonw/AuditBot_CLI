import json
from pathlib import Path
from datetime import datetime


def write_raw_file(data, prefix="scan"):

       timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

       output_dir = Path("output/raw")

       output_dir.mkdir(parents=True, exist_ok=True)

       output_file = _unique_output_file(output_dir, f"{prefix}_{timestamp}", ".json")

       with open(output_file, "w") as f:
              json.dump(data, f, indent=4)

       return str(output_file)


def _unique_output_file(output_dir, stem, suffix):
       output_file = output_dir / f"{stem}{suffix}"
       counter = 1

       while output_file.exists():
              output_file = output_dir / f"{stem}_{counter}{suffix}"
              counter += 1

       return output_file
