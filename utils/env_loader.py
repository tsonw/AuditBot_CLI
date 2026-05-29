import os
from pathlib import Path


def load_env_file(path=".env"):
       env_path = Path(path)

       if not env_path.exists():
              return

       try:
              lines = env_path.read_text().splitlines()
       except OSError:
              return

       for line in lines:
              stripped = line.strip()

              if not stripped or stripped.startswith("#") or "=" not in stripped:
                     continue

              key, value = stripped.split("=", 1)
              key = key.strip()
              value = value.strip().strip('"').strip("'")

              if key and key not in os.environ:
                     os.environ[key] = value
