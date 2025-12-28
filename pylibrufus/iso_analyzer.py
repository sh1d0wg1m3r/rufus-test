import enum
import pycdlib
import os

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

    def analyze(self):
        """
        Analyzes the ISO and returns a list of detected bootloaders.
        """
        self.iso.open(self.iso_path)
        detected_bootloaders = set()

        try:
            # Walk through the ISO
            for dirname, dirlist, filelist in self.iso.walk(iso_path='/'):
                # Normalize dirname to match C code expectations (e.g. /path/to/dir)
                # pycdlib returns paths like '/' or '/DIR'

                # Check directories
                for d in dirlist:
                    full_dir_path = os.path.join(dirname, d).replace('\\', '/')
                    if not full_dir_path.startswith('/'):
                        full_dir_path = '/' + full_dir_path

                    # Case insensitive check
                    full_dir_path_lower = full_dir_path.lower()

                    if full_dir_path_lower == '/efi/boot':
                        detected_bootloaders.add(BootloaderType.UEFI)

                    if full_dir_path_lower in ['/boot/grub/i386-pc', '/boot/grub2/i386-pc']:
                        detected_bootloaders.add(BootloaderType.GRUB2)

                    if full_dir_path_lower == '/proxmox':
                         # Logic in C says "img_report.disable_iso = TRUE", effectively handling it separately
                         pass

                # Check files
                for f in filelist:
                    filename = f
                    full_path = os.path.join(dirname, filename).replace('\\', '/')
                    if not full_path.startswith('/'):
                        full_path = '/' + full_path

                    filename_lower = filename.lower()
                    dirname_lower = dirname.lower()
                    if not dirname_lower.startswith('/'):
                        dirname_lower = '/' + dirname_lower

                    # Syslinux
                    if filename_lower in ['isolinux.cfg', 'syslinux.cfg', 'extlinux.conf', 'txt.cfg', 'live.cfg']:
                        detected_bootloaders.add(BootloaderType.SYSLINUX)

                    if filename_lower == 'ldlinux.c32':
                        detected_bootloaders.add(BootloaderType.SYSLINUX)

                    # GRUB2
                    if filename_lower in ['grub.cfg', 'loopback.cfg']:
                         # If found, suggests GRUB, but usually directory check is stronger for GRUB2 in Rufus
                         detected_bootloaders.add(BootloaderType.GRUB2)

                    # Windows / ReactOS / Others (Root checks)
                    if dirname_lower == '/' or dirname_lower == '':
                        if filename_lower == 'bootmgr':
                            detected_bootloaders.add(BootloaderType.WINDOWS)
                        if filename_lower == 'bootmgr.efi':
                            detected_bootloaders.add(BootloaderType.WINDOWS)
                            detected_bootloaders.add(BootloaderType.UEFI)
                        if filename_lower == 'grldr':
                            detected_bootloaders.add(BootloaderType.GRUB_LEGACY)
                        if filename_lower == 'kolibri.img':
                            detected_bootloaders.add(BootloaderType.KOLIBRIOS)

                    # ReactOS
                    if filename_lower in ['setupldr.sys', 'freeldr.sys']:
                        detected_bootloaders.add(BootloaderType.REACTOS)

                    # UEFI Files
                    if dirname_lower == '/efi/boot':
                        if filename_lower in ['bootx64.efi', 'bootia32.efi', 'bootmgr.efi']:
                            detected_bootloaders.add(BootloaderType.UEFI)

        except Exception as e:
            print(f"Error analyzing ISO: {e}")
            return [BootloaderType.UNKNOWN]
        finally:
            self.iso.close()

        return list(detected_bootloaders)
