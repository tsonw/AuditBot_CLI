import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from collectors import raw_writer
from reports import pdf_report


class OutputPathTest(unittest.TestCase):
    def test_raw_writer_does_not_overwrite_existing_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("collectors.raw_writer.Path", side_effect=lambda value: Path(temp_dir) / "raw" if value == "output/raw" else Path(value)):
                first_path = Path(raw_writer.write_raw_file({"run": 1}, "scan"))
                second_path = Path(raw_writer.write_raw_file({"run": 2}, "scan"))

            self.assertNotEqual(first_path, second_path)
            self.assertTrue(first_path.exists())
            self.assertTrue(second_path.exists())
            self.assertTrue(first_path.name.endswith(".json"))
            self.assertTrue(second_path.name.endswith(".json"))

    def test_pdf_report_does_not_overwrite_existing_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            first_path = Path(pdf_report.generate_full_flow_report({}, output_dir=temp_dir))
            second_path = Path(pdf_report.generate_full_flow_report({}, output_dir=temp_dir))

            self.assertNotEqual(first_path, second_path)
            self.assertTrue(first_path.exists())
            self.assertTrue(second_path.exists())
            self.assertTrue(first_path.name.endswith(".pdf"))
            self.assertTrue(second_path.name.endswith(".pdf"))


if __name__ == "__main__":
    unittest.main()
