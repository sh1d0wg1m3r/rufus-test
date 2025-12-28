import os
import ctypes
import fcntl
from typing import List

# Constants
SECTOR_SIZE = 512
# _IOWR('f', 11, struct fiemap) on x86_64
# Size of struct fiemap is 32 bytes
FS_IOC_FIEMAP = 0xC020660B
FIEMAP_FLAG_SYNC = 0x00000001
FIEMAP_MAX_EXTENTS = 0

class fiemap_extent(ctypes.Structure):
    _fields_ = [
        ("fe_logical", ctypes.c_uint64),
        ("fe_physical", ctypes.c_uint64),
        ("fe_length", ctypes.c_uint64),
        ("fe_reserved64", ctypes.c_uint64 * 2),
        ("fe_flags", ctypes.c_uint32),
        ("fe_reserved", ctypes.c_uint32 * 3)
    ]

class fiemap(ctypes.Structure):
    _fields_ = [
        ("fm_start", ctypes.c_uint64),
        ("fm_length", ctypes.c_uint64),
        ("fm_flags", ctypes.c_uint32),
        ("fm_mapped_extents", ctypes.c_uint32),
        ("fm_extent_count", ctypes.c_uint32),
        ("fm_reserved", ctypes.c_uint32)
    ]

def get_file_physical_sectors(filepath: str) -> List[int]:
    """
    Retrieves the list of physical 512-byte sector numbers for a file.
    Uses the Linux FIEMAP ioctl.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    fd = os.open(filepath, os.O_RDONLY)
    try:
        # 1. First call: Get the number of extents
        fmap = fiemap()
        fmap.fm_start = 0
        fmap.fm_length = 0xFFFFFFFFFFFFFFFF
        fmap.fm_flags = FIEMAP_FLAG_SYNC
        fmap.fm_extent_count = 0
        fmap.fm_mapped_extents = 0

        try:
            fcntl.ioctl(fd, FS_IOC_FIEMAP, fmap)
        except OSError as e:
            # Fallback or error handling could go here
            # For now, just re-raise
            raise OSError(f"ioctl FIEMAP failed: {e}")

        extent_count = fmap.fm_mapped_extents
        if extent_count == 0:
            return []

        # 2. Allocate buffer for extents
        # We need a custom structure that contains the header + array of extents
        class fiemap_with_extents(ctypes.Structure):
            _fields_ = [
                ("fm_header", fiemap),
                ("fm_extents", fiemap_extent * extent_count)
            ]

        fmap_full = fiemap_with_extents()
        fmap_full.fm_header = fmap
        # Reset mapped_extents as it's an output in the first call but we need to tell kernel how much space we have
        fmap_full.fm_header.fm_extent_count = extent_count
        fmap_full.fm_header.fm_mapped_extents = 0

        # 3. Second call: Get the actual extent data
        fcntl.ioctl(fd, FS_IOC_FIEMAP, fmap_full)

        sectors = []

        # The number of mapped extents might be less than extent_count if something changed,
        # or we rely on fm_mapped_extents from the second call.
        actual_mapped = fmap_full.fm_header.fm_mapped_extents

        for i in range(actual_mapped):
            ext = fmap_full.fm_extents[i]

            # Convert byte offsets to sector numbers
            phys_start = ext.fe_physical
            length = ext.fe_length

            # Validation
            if phys_start % SECTOR_SIZE != 0 or length % SECTOR_SIZE != 0:
                # In rare cases (advanced formats), this might happen, but Syslinux expects 512b alignment
                # We round down/up or warn?
                # Syslinux logic strictly deals with LBA sectors.
                pass

            start_sector = phys_start // SECTOR_SIZE
            num_sectors = length // SECTOR_SIZE

            # Generate the sequence of sectors for this extent
            for s in range(num_sectors):
                sectors.append(start_sector + s)

        return sectors

    finally:
        os.close(fd)
