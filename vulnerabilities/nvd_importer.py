import json
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path

from config.nvd_config import NVD_DB_PATH
from vulnerabilities.nvd_parser import (
    extract_cpe_matches,
    get_cvss,
    get_cwe,
    get_english_description,
)


def connect_db(db_path=NVD_DB_PATH):
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(path)


def init_db(db_path=NVD_DB_PATH):
    with closing(connect_db(db_path)) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                published_date TEXT,
                last_modified_date TEXT,
                cvss_score REAL,
                severity TEXT,
                vector_string TEXT,
                cwe TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cpe_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                vulnerable INTEGER,
                criteria TEXT,
                match_criteria_id TEXT,
                version_start_including TEXT,
                version_start_excluding TEXT,
                version_end_including TEXT,
                version_end_excluding TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cpe_matches_criteria ON cpe_matches(criteria)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cpe_matches_cve_id ON cpe_matches(cve_id)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS nvd_metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        conn.commit()

    print(f"[NVD] SQLite database ready: {db_path}")


def import_nvd_json(json_path, db_path=NVD_DB_PATH):
    init_db(db_path)
    path = Path(json_path)

    if not path.exists():
        raise FileNotFoundError(f"NVD JSON file does not exist: {path}")

    print(f"[NVD] Importing JSON feed: {path}")
    with open(path, encoding="utf-8") as file:
        data = json.load(file)

    imported = 0
    with closing(connect_db(db_path)) as conn:
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue

            cvss = get_cvss(item)
            conn.execute(
                """
                INSERT OR REPLACE INTO vulnerabilities (
                    cve_id,
                    description,
                    published_date,
                    last_modified_date,
                    cvss_score,
                    severity,
                    vector_string,
                    cwe
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cve_id,
                    get_english_description(item),
                    cve.get("published"),
                    cve.get("lastModified"),
                    cvss.get("score"),
                    cvss.get("severity"),
                    cvss.get("vector_string"),
                    get_cwe(item),
                ),
            )

            conn.execute("DELETE FROM cpe_matches WHERE cve_id = ?", (cve_id,))
            for cpe_match in extract_cpe_matches(item):
                conn.execute(
                    """
                    INSERT INTO cpe_matches (
                        cve_id,
                        vulnerable,
                        criteria,
                        match_criteria_id,
                        version_start_including,
                        version_start_excluding,
                        version_end_including,
                        version_end_excluding
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cve_id,
                        1 if cpe_match.get("vulnerable") else 0,
                        cpe_match.get("criteria"),
                        cpe_match.get("matchCriteriaId"),
                        cpe_match.get("versionStartIncluding"),
                        cpe_match.get("versionStartExcluding"),
                        cpe_match.get("versionEndIncluding"),
                        cpe_match.get("versionEndExcluding"),
                    ),
                )

            imported += 1

        conn.commit()

    set_metadata_value("last_imported_at", datetime.now().isoformat(timespec="seconds"), db_path)
    print(f"[NVD] Imported CVEs: {imported}")
    return imported


def set_metadata_value(key, value, db_path=NVD_DB_PATH):
    with closing(connect_db(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO nvd_metadata (key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )
        conn.commit()
