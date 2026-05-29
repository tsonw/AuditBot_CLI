import sqlite3
from contextlib import closing
from pathlib import Path

from config.nvd_config import NVD_DB_PATH
from vulnerabilities.version_checker import is_version_in_range


def lookup_cves_by_cpe(cpe_candidates, detected_version, db_path=NVD_DB_PATH):
    if not cpe_candidates:
        return []

    path = Path(db_path)
    if not path.exists():
        print(f"[NVD] Local vulnerability database not found: {path}")
        return []

    results = {}

    with closing(sqlite3.connect(path)) as conn:
        conn.row_factory = sqlite3.Row

        for cpe in cpe_candidates:
            prefix = _vendor_product_prefix(cpe)
            if not prefix:
                continue

            rows = conn.execute(
                """
                SELECT
                    v.cve_id,
                    v.description,
                    v.published_date,
                    v.last_modified_date,
                    v.cvss_score,
                    v.severity,
                    v.vector_string,
                    v.cwe,
                    c.criteria,
                    c.version_start_including,
                    c.version_start_excluding,
                    c.version_end_including,
                    c.version_end_excluding
                FROM cpe_matches c
                JOIN vulnerabilities v ON v.cve_id = c.cve_id
                WHERE c.vulnerable = 1
                  AND c.criteria LIKE ?
                """,
                (f"{prefix}%",),
            ).fetchall()

            for row in rows:
                if not _criteria_matches_detected_version(row, detected_version):
                    continue

                cve_id = row["cve_id"]
                if cve_id not in results:
                    results[cve_id] = dict(row)

    return list(results.values())


def get_database_last_update(db_path=NVD_DB_PATH):
    path = Path(db_path)
    if not path.exists():
        return None

    with closing(sqlite3.connect(path)) as conn:
        row = conn.execute("SELECT MAX(last_modified_date) FROM vulnerabilities").fetchone()

    return row[0] if row and row[0] else None


def get_database_last_imported_at(db_path=NVD_DB_PATH):
    path = Path(db_path)
    if not path.exists():
        return None

    try:
        with closing(sqlite3.connect(path)) as conn:
            row = conn.execute(
                "SELECT value FROM nvd_metadata WHERE key = ?",
                ("last_imported_at",),
            ).fetchone()
    except sqlite3.OperationalError:
        return None

    return row[0] if row and row[0] else None


def _vendor_product_prefix(cpe):
    parts = _split_cpe23(cpe)
    if len(parts) < 5:
        return None

    return ":".join(parts[:5]) + ":"


def _criteria_matches_detected_version(row, detected_version):
    if not is_version_in_range(
        detected_version,
        row["version_start_including"],
        row["version_start_excluding"],
        row["version_end_including"],
        row["version_end_excluding"],
    ):
        return False

    criteria_version = _cpe_version(row["criteria"])
    if criteria_version in (None, "", "*", "-") or not detected_version:
        return True

    return _clean_version(criteria_version) == _clean_version(detected_version)


def _cpe_version(cpe):
    parts = _split_cpe23(cpe)
    if len(parts) < 6:
        return None

    return parts[5]


def _split_cpe23(cpe):
    return str(cpe or "").split(":")


def _clean_version(value):
    return str(value or "").strip().lower()
