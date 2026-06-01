import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from vulnerabilities.nvd_importer import import_nvd_json, init_db, set_metadata_value
from vulnerabilities.vuln_analyzer import analyze_service_vulnerabilities, get_database_update_warning, write_report


class OfflineNvdTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "nvd.db"
        init_db(self.db_path)
        import_nvd_json(Path(__file__).parent / "mock_nvd.json", self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def analyze(self, product, version):
        with patch("vulnerabilities.vuln_analyzer.lookup_cves_by_cpe") as lookup:
            from vulnerabilities.cve_lookup import lookup_cves_by_cpe

            lookup.side_effect = lambda cpes, detected: lookup_cves_by_cpe(cpes, detected, self.db_path)
            return analyze_service_vulnerabilities({
                "host": "192.0.2.10",
                "port": 80,
                "service": "http",
                "product": product,
                "version": version,
            })

    def test_nginx_118_detects_mock_cve(self):
        result = self.analyze("nginx", "1.18.0")
        self.assertEqual(result["vulnerabilities_count"], 1)
        self.assertEqual(result["vulnerabilities"][0]["cve_id"], "CVE-2099-0001")

    def test_nginx_121_does_not_detect_mock_cve(self):
        result = self.analyze("nginx", "1.21.0")
        self.assertEqual(result["vulnerabilities_count"], 0)

    def test_unknown_product_does_not_crash(self):
        result = self.analyze("unknown product", "1.0.0")
        self.assertEqual(result["cpe_candidates"], [])
        self.assertEqual(result["vulnerabilities_count"], 0)

    def test_database_update_warning_is_silent_for_recent_import(self):
        now = datetime.now()
        set_metadata_value(
            "last_imported_at",
            (now - timedelta(days=2)).isoformat(timespec="seconds"),
            self.db_path,
        )

        warning = get_database_update_warning(self.db_path, now)

        self.assertIsNone(warning)

    def test_database_update_warning_appears_for_stale_import(self):
        now = datetime.now()
        set_metadata_value(
            "last_imported_at",
            (now - timedelta(days=3)).isoformat(timespec="seconds"),
            self.db_path,
        )

        warning = get_database_update_warning(self.db_path, now)

        self.assertIn("last updated 3 day(s) ago", warning)
        self.assertIn("nvd-update", warning)

    def test_default_report_filename_does_not_overwrite_existing_report(self):
        with (
            patch("vulnerabilities.vuln_analyzer.DEFAULT_REPORT_DIR", Path(self.temp_dir.name)),
            patch("vulnerabilities.vuln_analyzer.DEFAULT_REPORT_PATH", Path(self.temp_dir.name) / "vulnerability_report.json"),
        ):
            first_path = write_report({"results": []})
            second_path = write_report({"results": []})

        self.assertNotEqual(first_path, second_path)
        self.assertEqual(first_path.name, "vulnerability_report.json")
        self.assertEqual(second_path.name, "vulnerability_report_1.json")
        self.assertTrue(first_path.exists())
        self.assertTrue(second_path.exists())


if __name__ == "__main__":
    unittest.main()
