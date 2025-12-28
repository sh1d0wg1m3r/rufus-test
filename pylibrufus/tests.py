import unittest
import os
import tempfile
import struct
from pylibrufus.patcher import Patcher
from pylibrufus.win_bypass import generate_bypass_xml, get_bypass_registry_keys, BypassOption
from pylibrufus.iso_analyzer import BootloaderType

# Mock ISO analyzer test as we don't have a real ISO file
# But we can test Patcher and WinBypass

class TestPatcher(unittest.TestCase):
    def test_patcher_finds_magic(self):
        patcher = Patcher()
        # LDLINUX_MAGIC = 0x3eb202fe
        magic = struct.pack('<I', 0x3eb202fe)

        # Create a mock ldlinux.sys file content
        # We need enough space for offsets
        # epaoffset is at magic + 22

        content = bytearray(1024)
        magic_offset = 128
        content[magic_offset:magic_offset+4] = magic

        # Set epaoffset to 512
        epa_offset = 512
        content[magic_offset+22:magic_offset+24] = struct.pack('<H', epa_offset)

        # Set some values in EPA
        # sect1ptr0 at epa_base + 14
        sect1ptr0_off = 16
        sect1ptr1_off = 18

        content[epa_offset+14:epa_offset+16] = struct.pack('<H', sect1ptr0_off)
        content[epa_offset+16:epa_offset+18] = struct.pack('<H', sect1ptr1_off)

        # Set secptroffset at epa_base + 10
        secptroffset = 600
        content[epa_offset+10:epa_offset+12] = struct.pack('<H', secptroffset)

        # Set secptrcnt at epa_base + 12
        content[epa_offset+12:epa_offset+14] = struct.pack('<H', 10)

        sectors = [1000, 1001, 1002, 1003]

        patches = patcher.calculate_patches("test.sys", content, sectors)

        self.assertTrue(len(patches) > 0)

        # Verify sect1ptr0 patch
        # Should patch offset 16 with sectors[0] & 0xFFFFFFFF
        found = False
        for p in patches:
            if p.offset == 16:
                val = struct.unpack('<I', p.data)[0]
                self.assertEqual(val, 1000)
                found = True
        self.assertTrue(found)

class TestWinBypass(unittest.TestCase):
    def test_generate_xml(self):
        # Update test to use flags that include SET_USER
        flags = BypassOption.DEFAULT | BypassOption.SET_USER
        xml = generate_bypass_xml(flags, "TestUser")
        self.assertIn("BypassTPMCheck", xml)
        self.assertIn("BypassNRO", xml)
        self.assertIn("TestUser", xml)

    def test_registry_keys(self):
        keys = get_bypass_registry_keys()
        self.assertTrue(any(k[1] == "BypassTPMCheck" for k in keys))
        self.assertTrue(any(k[1] == "BypassSecureBootCheck" for k in keys))

if __name__ == '__main__':
    unittest.main()
