from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

NVD_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"
NVD_RAW_DIR = PROJECT_ROOT / "data" / "nvd" / "raw"
NVD_CACHE_DIR = PROJECT_ROOT / "data" / "nvd" / "cache"
NVD_DB_PATH = PROJECT_ROOT / "data" / "nvd" / "db" / "nvd_vulnerabilities.db"

# NVD yearly feeds currently start at 2002. Increase this value for faster lab
# initialization when historical CVEs are not needed.
START_YEAR = 2002
