import enum
import pycdlib
import os
import struct
from typing import Tuple

class BootloaderType(enum.Enum):
    UNKNOWN = 0
    SYSLINUX = 1
    GRUB2 = 2
    GRUB_LEGACY = 3
    UEFI = 4
    WINDOWS = 5
    REACTOS = 6
    KOLIBRIOS = 7

class IsoAnalyzer:
    def __init__(self, iso_path):
        self.iso_path = iso_path
        self.iso = pycdlib.PyCdlib()

    def _get_syslinux_version_from_buffer(self, buf: bytes) -> Tuple[int, str]:
        """
        Scans buffer for "LINUX " signature and extracts version.
        Returns (version_int, ext_str). e.g. (0x0603, "/2014-10-06")
        """
        linux_sig = b'LINUX '
        if len(buf) < 256:
            return 0, ""

        # Start at 64 to avoid incomplete version at beginning
        # Scan until len - 64
        for i in range(64, len(buf) - 64):
            if buf[i:i+6] == linux_sig:
                # Check for ISO or SYS prefix
                prefix = buf[i-3:i]
                if prefix not in [b'ISO', b'SYS']:
                    continue

                # Parse version number
                start = i + 6
                end = start
                while end < len(buf) and chr(buf[end]).isdigit():
                    end += 1

                if end == start:
                    continue

                try:
                    major = int(buf[start:end])
                except ValueError:
                    continue

                if major >= 256:
                    continue

                if end >= len(buf) or chr(buf[end]) != '.':
                    continue

                start2 = end + 1
                end2 = start2
                while end2 < len(buf) and chr(buf[end2]).isdigit():
                    end2 += 1

                if end2 == start2:
                    continue

                try:
                    minor = int(buf[start2:end2])
                except ValueError:
                    continue

                if minor >= 256:
                    continue

                version = (major << 8) + minor

                # Parse extra version string (date)
                # Logic from Rufus:
                # *p = '/' -> prepend '/' to the rest of the string
                # Find the end of the string (null or some other delimiter)

                current_idx = end2

                # Find null terminator
                zero_idx = buf.find(b'\x00', current_idx)
                if zero_idx == -1:
                    zero_idx = len(buf)

                # Sanitize logic from Rufus is complex (looking for duplicates),
                # but essentially it grabs the string after the version number.
                # Rufus checks if the next chars are a repetition of x.yz-

                raw_ext = buf[current_idx:zero_idx]

                # Basic cleanup: if it starts with space or '-', skip it
                # Rufus replaces the first char with '/' if it finds a valid string?
                # "Ensure that our extra version string starts with a slash" -> *p = '/'

                # If we found a valid signature, let's assume the string following is useful.
                # Decode bytes to string
                try:
                    ext_str = raw_ext.decode('latin-1', errors='ignore')
                except:
                    ext_str = ""

                # Rufus logic: "Remove the x.yz- duplicate if present"
                # For now, let's just return what we found, ensuring it starts with / if not empty
                # If it's just spaces, return empty.

                ext_str = ext_str.strip()
                if not ext_str:
                    return version, ""

                # Rufus replaces first char with '/'
                # e.g. " 2014-10-06" -> "/2014-10-06"
                if len(ext_str) > 0:
                    ext_str = "/" + ext_str[1:]

                return version, ext_str

        return 0, ""

    def analyze(self):
        """
        Analyzes the ISO and returns a list of detected bootloaders.
        Also attempts to detect Syslinux version.
        """
        self.iso.open(self.iso_path)
        detected_bootloaders = set()
        syslinux_version = None
        syslinux_ext = ""

        try:
            # Walk through the ISO
            for dirname, dirlist, filelist in self.iso.walk(iso_path='/'):
                # Normalize dirname

                # Check directories
                for d in dirlist:
                    full_dir_path = os.path.join(dirname, d).replace('\\', '/')
                    if not full_dir_path.startswith('/'):
                        full_dir_path = '/' + full_dir_path

                    full_dir_path_lower = full_dir_path.lower()

                    if full_dir_path_lower == '/efi/boot':
                        detected_bootloaders.add(BootloaderType.UEFI)

                    if full_dir_path_lower in ['/boot/grub/i386-pc', '/boot/grub2/i386-pc']:
                        detected_bootloaders.add(BootloaderType.GRUB2)

                # Check files
                for f in filelist:
                    filename = f
                    filename_lower = filename.lower()

                    # Syslinux
                    if filename_lower in ['isolinux.cfg', 'syslinux.cfg', 'extlinux.conf', 'txt.cfg', 'live.cfg']:
                        detected_bootloaders.add(BootloaderType.SYSLINUX)

                    if filename_lower == 'ldlinux.c32':
                        detected_bootloaders.add(BootloaderType.SYSLINUX)

                    # Deep scan for Syslinux version in isolinux.bin
                    if filename_lower in ['isolinux.bin', 'boot.bin'] and syslinux_version is None:
                        try:
                            # Read file content
                            bio = b""
                            with self.iso.open_file_from_iso(iso_path=os.path.join(dirname, filename)) as inf:
                                bio = inf.read()

                            ver, ext = self._get_syslinux_version_from_buffer(bio)
                            if ver != 0:
                                syslinux_version = ver
                                syslinux_ext = ext
                        except Exception as e:
                            print(f"Error reading {filename}: {e}")

                    # GRUB2
                    if filename_lower in ['grub.cfg', 'loopback.cfg']:
                        detected_bootloaders.add(BootloaderType.GRUB2)

                    # Windows / ReactOS / Others
                    dirname_lower = dirname.lower()
                    if not dirname_lower.startswith('/'):
                        dirname_lower = '/' + dirname_lower

                    if dirname_lower == '/':
                        if filename_lower == 'bootmgr':
                            detected_bootloaders.add(BootloaderType.WINDOWS)
                        if filename_lower == 'bootmgr.efi':
                            detected_bootloaders.add(BootloaderType.WINDOWS)
                            detected_bootloaders.add(BootloaderType.UEFI)
                        if filename_lower == 'grldr':
                            detected_bootloaders.add(BootloaderType.GRUB_LEGACY)
                        if filename_lower == 'kolibri.img':
                            detected_bootloaders.add(BootloaderType.KOLIBRIOS)

                    if filename_lower in ['setupldr.sys', 'freeldr.sys']:
                        detected_bootloaders.add(BootloaderType.REACTOS)

                    if dirname_lower == '/efi/boot':
                        if filename_lower in ['bootx64.efi', 'bootia32.efi', 'bootmgr.efi']:
                            detected_bootloaders.add(BootloaderType.UEFI)

        except Exception as e:
            print(f"Error analyzing ISO: {e}")
            return {'bootloaders': [BootloaderType.UNKNOWN]}
        finally:
            self.iso.close()

        result = {
            'bootloaders': list(detected_bootloaders)
        }
        if syslinux_version:
            major = syslinux_version >> 8
            minor = syslinux_version & 0xFF
            result['syslinux_version'] = f"{major}.{minor:02d}"
            result['syslinux_ext'] = syslinux_ext

        return result
