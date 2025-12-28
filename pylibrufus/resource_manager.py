import os
from typing import Optional, Tuple

class DownloadInstruction:
    def __init__(self, url: str, filename: str, message: str):
        self.url = url
        self.filename = filename
        self.message = message

    def __repr__(self):
        return f"DownloadInstruction(url='{self.url}', filename='{self.filename}')"

class ResourceManager:
    def __init__(self, res_path: str):
        self.res_path = res_path
        # Embedded versions as found in the repo
        self.embedded_versions = {
            "4.07": "v4",
            "6.04": "v6"
        }
        self.base_url = "https://rufus.ie/files"

    def get_resource_path(self, filename: str, bootloader_version: Optional[str] = None,
                          version_ext: str = "") -> str | DownloadInstruction:
        """
        Retrieves the path to a resource.

        Args:
            filename: Name of the file (e.g. 'ldlinux.sys', 'uefi-ntfs.img')
            bootloader_version: e.g. "6.03"
            version_ext: e.g. "/2014-10-06" (including the slash)

        Returns:
            str: Absolute path to the local file.
            DownloadInstruction: If file is missing.
        """

        # 1. Handle generic UEFI resources
        if filename == "uefi-ntfs.img":
            local_path = os.path.join(self.res_path, "uefi", "uefi-ntfs.img")
            if os.path.exists(local_path):
                return os.path.abspath(local_path)
            # If missing locally (which shouldn't happen if bundled), prompt download?
            # Rufus usually embeds this. Let's assume it should be there.
            return DownloadInstruction(
                url=f"{self.base_url}/uefi-ntfs.img", # Hypothetical URL
                filename="uefi-ntfs.img",
                message="Local uefi-ntfs.img missing."
            )

        # 2. Handle Syslinux resources
        if filename.startswith("ldlinux"):
            if not bootloader_version:
                return DownloadInstruction("", filename, "Bootloader version required for ldlinux.")

            # Check if it matches embedded versions
            embedded_suffix = self.embedded_versions.get(bootloader_version)

            if embedded_suffix:
                # Map ldlinux.sys to ldlinux_vX.sys
                ext = os.path.splitext(filename)[1] # .sys or .bss
                local_name = f"ldlinux_{embedded_suffix}{ext}"
                local_path = os.path.join(self.res_path, "syslinux", local_name)

                if os.path.exists(local_path):
                    return os.path.abspath(local_path)

            # If not embedded or not found locally, construct download instruction
            # URL format: https://rufus.ie/files/syslinux-6.03/2014-10-06/ldlinux.sys
            # Note: bootloader_version is "6.03", version_ext is "/2014-10-06" (or empty)

            # Construct URL path components
            # "syslinux-VERSION" or "syslinux-VERSION/DATE"

            url_path = f"syslinux-{bootloader_version}{version_ext}"
            url = f"{self.base_url}/{url_path}/{filename}"

            return DownloadInstruction(
                url=url,
                filename=filename,
                message=f"Local resource missing for Syslinux {bootloader_version}{version_ext}. Please download."
            )

        return DownloadInstruction("", filename, "Unknown resource.")
