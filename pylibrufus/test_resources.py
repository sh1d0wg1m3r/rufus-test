import unittest
import os
from pylibrufus.resource_manager import ResourceManager, DownloadInstruction
from pylibrufus.iso_analyzer import IsoAnalyzer

class TestResourceManager(unittest.TestCase):
    def setUp(self):
        # Setup a mock res directory for testing
        self.res_path = os.path.join(os.path.dirname(__file__), "res")
        self.rm = ResourceManager(self.res_path)

    def test_local_resource(self):
        # We copied uefi-ntfs.img
        path = self.rm.get_resource_path("uefi-ntfs.img")
        self.assertIsInstance(path, str)
        self.assertTrue(path.endswith("uefi-ntfs.img"))
        self.assertTrue(os.path.exists(path))

    def test_embedded_syslinux_v4(self):
        # ldlinux_v4.sys (4.07)
        path = self.rm.get_resource_path("ldlinux.sys", "4.07")
        self.assertIsInstance(path, str)
        self.assertTrue("ldlinux_v4.sys" in path)
        self.assertTrue(os.path.exists(path))

    def test_embedded_syslinux_v6(self):
        # ldlinux_v6.sys (6.04)
        path = self.rm.get_resource_path("ldlinux.sys", "6.04")
        self.assertIsInstance(path, str)
        self.assertTrue("ldlinux_v6.sys" in path)
        self.assertTrue(os.path.exists(path))

    def test_missing_syslinux_version(self):
        # A version we don't have embedded, e.g. 6.03 /2014-10-06
        res = self.rm.get_resource_path("ldlinux.sys", "6.03", "/2014-10-06")
        self.assertIsInstance(res, DownloadInstruction)
        expected_url = "https://rufus.ie/files/syslinux-6.03/2014-10-06/ldlinux.sys"
        self.assertEqual(res.url, expected_url)

if __name__ == '__main__':
    unittest.main()
