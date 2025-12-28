#!/usr/bin/env python3
import sys
import os
from pylibrufus import IsoAnalyzer, BootloaderType, resource_manager
from pylibrufus import generate_bypass_xml, BypassOption, DownloadInstruction

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 demo_rufus_linux.py <path_to_iso>")
        sys.exit(1)

    iso_path = sys.argv[1]
    if not os.path.exists(iso_path):
        print(f"Error: ISO file not found: {iso_path}")
        sys.exit(1)

    print(f"Analyzing ISO: {iso_path}...")

    try:
        analyzer = IsoAnalyzer(iso_path)
        analysis = analyzer.analyze()
        bootloaders = analysis['bootloaders']
        print(f"Detected bootloaders: {[b.name for b in bootloaders]}")

        is_windows = BootloaderType.WINDOWS in bootloaders or BootloaderType.UEFI in bootloaders
        # Simple heuristic: if it has bootmgr, it's likely Windows (or ReactOS masked)
        # But Linux can also have UEFI.
        # Better heuristic based on Rufus C code:
        is_linux = BootloaderType.SYSLINUX in bootloaders or BootloaderType.GRUB2 in bootloaders or BootloaderType.GRUB_LEGACY in bootloaders

        if BootloaderType.WINDOWS in bootloaders:
            print("\n--- Windows ISO Detected ---")
            print("Generating Windows 11 Bypass (TPM/SecureBoot/RAM)...")

            # Generate XML
            xml_content = generate_bypass_xml(BypassOption.DEFAULT | BypassOption.SET_USER, username="RufusUser")

            output_xml_path = "unattend_gen.xml"
            with open(output_xml_path, "w") as f:
                f.write(xml_content)

            print(f"Generated {output_xml_path}")
            print("\nExecution Plan:")
            print("1. Format USB drive (NTFS required for Windows > 4GB files).")
            print("2. Mount ISO and copy files to USB.")
            print(f"3. Copy {output_xml_path} to /windows/panther/unattend.xml on the USB.")
            print("   (Or /autounattend.xml in root for setup).")

        elif is_linux:
            print("\n--- Linux ISO Detected ---")

            # Syslinux handling
            if BootloaderType.SYSLINUX in bootloaders:
                syslinux_version = analysis.get('syslinux_version', 'Unknown')
                syslinux_ext = analysis.get('syslinux_ext', '')
                print(f"Syslinux Version: {syslinux_version}{syslinux_ext}")

                # Check for required resources
                # ldlinux.sys
                print("Locating Syslinux resources...")

                target_version = syslinux_version if syslinux_version != 'Unknown' else "6.04"

                res_sys = resource_manager.get_resource_path("ldlinux.sys", target_version, syslinux_ext)
                res_bss = resource_manager.get_resource_path("ldlinux.bss", target_version, syslinux_ext)

                resources = [("ldlinux.sys", res_sys), ("ldlinux.bss", res_bss)]

                print("\nExecution Plan:")
                print("1. Write ISO to USB (dd if=... of=/dev/sdX).")
                print("   OR extract files to FAT32 partition.")
                print("2. Install Syslinux bootloader.")

                for name, res in resources:
                    if isinstance(res, DownloadInstruction):
                        print(f"   [MISSING] {name}: {res.message}")
                        print(f"   -> Download from: {res.url}")
                    else:
                        print(f"   [LOCAL] Found {name} at: {res}")
                        print(f"   -> Copy to USB root or syslinux directory.")

                print("\n3. Patch ldlinux.sys using physical sector map (Linux Only):")
                print("   (Example Python Code to run after copying files)")
                print("-" * 40)
                print("from pylibrufus.linux_sectors import get_file_physical_sectors")
                print("from pylibrufus.patcher import Patcher")
                print(f"ldlinux_path = '/mnt/usb/ldlinux.sys'")
                print(f"sectors = get_file_physical_sectors(ldlinux_path)")
                print(f"patcher = Patcher()")
                print(f"with open(ldlinux_path, 'rb') as f: content = f.read()")
                print(f"patches = patcher.calculate_patches(ldlinux_path, content, sectors)")
                print(f"# Apply patches...")
                print("-" * 40)

        else:
            print("\n--- Unknown/Generic ISO Detected ---")
            print("Execution Plan:")
            print("1. Write ISO to USB using dd.")

    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
