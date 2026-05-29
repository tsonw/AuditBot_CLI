import unittest
from unittest.mock import patch

import requests

from vulnerabilities.nvd_downloader import NvdDownloadError, download_modified_feed


class NvdDownloaderTest(unittest.TestCase):
    def test_modified_feed_reports_no_internet_on_connection_error(self):
        with patch("vulnerabilities.nvd_downloader.requests.get") as get:
            get.side_effect = requests.ConnectionError("network unreachable")

            with self.assertRaises(NvdDownloadError) as error:
                download_modified_feed()

        self.assertTrue(error.exception.no_internet)
        self.assertIn("No internet connection", str(error.exception))


if __name__ == "__main__":
    unittest.main()
