import json
from pathlib import Path
from datetime import datetime


def write_raw_file(data, prefix="scan"):

       timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

       output_dir = Path("outputs/raw")

       output_dir.mkdir(parents=True, exist_ok=True)

       output_file = output_dir / f"{prefix}_{timestamp}.json"

       with open(output_file, "w") as f:
              json.dump(data, f, indent=4)

       return str(output_file)