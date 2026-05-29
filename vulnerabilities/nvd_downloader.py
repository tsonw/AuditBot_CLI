import gzip
import shutil
from datetime import datetime
from pathlib import Path

import requests

from config.nvd_config import NVD_BASE_URL, NVD_RAW_DIR

CONNECT_TIMEOUT_SECONDS = 5
READ_TIMEOUT_SECONDS = 120


class NvdDownloadError(RuntimeError):
    def __init__(self, message, no_internet=False):
        super().__init__(message)
        self.no_internet = no_internet


def feed_filename(feed_name):
    return f"nvdcve-2.0-{feed_name}.json.gz"


def download_feed(feed_name):
    NVD_RAW_DIR.mkdir(parents=True, exist_ok=True)

    gz_path = NVD_RAW_DIR / feed_filename(feed_name)
    json_path = gz_path.with_suffix("")
    url = f"{NVD_BASE_URL}/{gz_path.name}"

    print(f"[NVD] Downloading {url}")
    try:
        response = requests.get(url, timeout=(CONNECT_TIMEOUT_SECONDS, READ_TIMEOUT_SECONDS))
        response.raise_for_status()
    except requests.Timeout as exc:
        raise NvdDownloadError(
            "[NVD] No internet connection or NVD server is not responding. "
            "Please check your connection and run the database update again.",
            no_internet=True,
        ) from exc
    except requests.ConnectionError as exc:
        raise NvdDownloadError(
            "[NVD] No internet connection detected. "
            "Please connect to the internet before updating the vulnerability database.",
            no_internet=True,
        ) from exc
    except requests.HTTPError as exc:
        raise NvdDownloadError(f"[NVD] Failed to download feed {feed_name}: {exc}") from exc
    except requests.RequestException as exc:
        raise NvdDownloadError(
            f"[NVD] Network error while downloading feed {feed_name}: {exc}",
            no_internet=True,
        ) from exc

    gz_path.write_bytes(response.content)
    print(f"[NVD] Saved compressed feed: {gz_path}")

    with gzip.open(gz_path, "rb") as compressed, open(json_path, "wb") as extracted:
        shutil.copyfileobj(compressed, extracted)

    print(f"[NVD] Extracted JSON feed: {json_path}")
    return json_path


def download_year_feeds(start_year):
    current_year = datetime.now().year
    json_paths = []

    for year in range(int(start_year), current_year + 1):
        try:
            json_paths.append(download_feed(str(year)))
        except NvdDownloadError as exc:
            print(f"\033[31m{exc}\033[0m")
            if exc.no_internet:
                break

    return json_paths


def download_modified_feed():
    return download_feed("modified")
