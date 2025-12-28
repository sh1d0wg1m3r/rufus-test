import struct
from typing import List, Tuple, Optional
from dataclasses import dataclass

# Constants from syslxint.h
LDLINUX_MAGIC = 0x3eb202fe
SECTOR_SIZE = 512

@dataclass
class PatchOperation:
    file_path: str
    offset: int
    data: bytes

@dataclass
class SyslinuxExtent:
    lba: int
    length: int

    def pack(self) -> bytes:
        # struct syslinux_extent { uint64_t lba; uint16_t len; } PACKED;
        return struct.pack('<QH', self.lba, self.length)

class Patcher:
    def __init__(self):
        pass

    def _generate_extents(self, sectors: List[int]) -> List[SyslinuxExtent]:
        """
        Generates sector extents from a list of sectors.
        Corresponds to generate_extents in syslxmod.c
        """
        extents = []
        if not sectors:
            return extents

        # syslxmod.c: generate_extents logic
        # It seems to try to merge contiguous sectors into extents.
        # But also checks for 64K alignment/crossing logic?
        # "if (sect == lba + len && xbytes < 65536 && ((addr ^ (base + xbytes - 1)) & 0xffff0000) == 0)"

        # simplified python port
        addr = 0x8000 # ldlinux.sys starts loading here
        base = addr
        length = 0
        lba = 0

        # We need to iterate through sectors
        sect_iter = iter(sectors)
        try:
            sect = next(sect_iter)
            lba = sect
            length = 1
            addr += SECTOR_SIZE
        except StopIteration:
            return []

        for sect in sect_iter:
            xbytes = (length + 1) * SECTOR_SIZE

            # Check if contiguous and within constraints
            # constraints:
            # 1. contiguous LBA (sect == lba + length)
            # 2. extent size < 65536 bytes (xbytes < 65536)
            # 3. does not cross 64KB boundary in memory? ((addr ^ (base + xbytes - 1)) & 0xffff0000) == 0

            # addr is current memory address where next sector would be loaded
            # base is memory address where current extent started

            is_contiguous = (sect == lba + length)
            size_ok = (xbytes < 65536)
            boundary_ok = ((addr ^ (base + xbytes - 1)) & 0xffff0000) == 0

            if is_contiguous and size_ok and boundary_ok:
                length += 1
            else:
                extents.append(SyslinuxExtent(lba, length))
                base = addr
                lba = sect
                length = 1

            addr += SECTOR_SIZE

        if length > 0:
            extents.append(SyslinuxExtent(lba, length))

        return extents

    def calculate_patches(self,
                          file_path: str,
                          file_content: bytes,
                          sectors: List[int],
                          raid_mode: bool = False,
                          subdir: Optional[str] = None,
                          subvol: Optional[str] = None) -> List[PatchOperation]:
        """
        Calculates the necessary patches for syslinux/ldlinux.sys.
        Corresponds to syslinux_patch in syslxmod.c
        """
        patches = []

        if not file_content:
            return patches

        boot_image_len = len(file_content)

        # Search for LDLINUX_MAGIC
        magic_bytes = struct.pack('<I', LDLINUX_MAGIC)
        # Search aligned to 4 bytes
        magic_offset = -1
        for i in range(0, boot_image_len - 4, 1): # Scan every byte? C code says "i <= dw", dw = len >> 2. Iterating uint32_t pointers.
             # "for (i = 0, wp = (const uint32_t _slimg *)boot_image; (i <= dw) && ((get_32_sl(wp) != LDLINUX_MAGIC)); i++, wp++);"
             # It scans 4-byte aligned.
             if i % 4 == 0:
                 chunk = file_content[i:i+4]
                 if chunk == magic_bytes:
                     magic_offset = i
                     break

        if magic_offset == -1:
            return [] # Magic not found

        # struct patch_area
        # offset 0: magic (4)
        # offset 4: instance (4)
        # offset 8: data_sectors (2)
        # offset 10: adv_sectors (2)
        # offset 12: dwords (4)
        # offset 16: checksum (4)
        # offset 20: maxtransfer (2)
        # offset 22: epaoffset (2)

        epa_offset_ptr = magic_offset + 22
        epa_offset = struct.unpack('<H', file_content[epa_offset_ptr:epa_offset_ptr+2])[0]

        # epa (Extended Patch Area) is at boot_image + epaoffset
        # In C: epa = slptr(boot_image, &patcharea->epaoffset);
        # slptr adds the value at offset to the base address.
        # But wait, slptr implementation:
        # static inline void _slimg *slptr(void _slimg *img, const uint16_t _slimg *offset_p) { return (char _slimg *)img + get_16_sl(offset_p); }
        # So it takes the value *at* offset_p (which is epa_offset) and adds it to img base.
        # So yes, absolute offset in file is epa_offset.

        epa_base = epa_offset

        # struct ext_patch_area offsets (relative to epa_base)
        # 0: advptroffset (2)
        # 2: diroffset (2)
        # 4: dirlen (2)
        # 6: subvoloffset (2)
        # 8: subvollen (2)
        # 10: secptroffset (2)
        # 12: secptrcnt (2)
        # 14: sect1ptr0 (2)
        # 16: sect1ptr1 (2)
        # 18: raidpatch (2)

        # First sector need pointer in boot sector
        # "set_32(ptr(sbs, &epa->sect1ptr0), sectp[0]);"
        # "set_32(ptr(sbs, &epa->sect1ptr1), sectp[0] >> 32);"
        # sect1ptr0 is an offset in the boot sector (first 512 bytes presumably, or just where sbs points).
        # sbs is (struct fat_boot_sector *)boot_sector.
        # "ptr(sbs, &epa->sect1ptr0)" -> sbs + get_16(&epa->sect1ptr0)

        sect1ptr0_offset_in_epa = epa_base + 14
        sect1ptr1_offset_in_epa = epa_base + 16

        sect1ptr0_val = struct.unpack('<H', file_content[sect1ptr0_offset_in_epa:sect1ptr0_offset_in_epa+2])[0]
        sect1ptr1_val = struct.unpack('<H', file_content[sect1ptr1_offset_in_epa:sect1ptr1_offset_in_epa+2])[0]

        # Patch boot sector (which is assumed to be part of file_content at beginning?)
        # Actually syslinux_patch takes "const sector_t *sectp".
        # And it patches "boot_image".
        # "struct fat_boot_sector *sbs = (struct fat_boot_sector *)boot_sector;"
        # So it patches the beginning of file_content.

        if sectors:
            s0 = sectors[0]
            patches.append(PatchOperation(file_path, sect1ptr0_val, struct.pack('<I', s0 & 0xFFFFFFFF)))
            patches.append(PatchOperation(file_path, sect1ptr1_val, struct.pack('<I', s0 >> 32)))

        # RAID mode
        if raid_mode:
            raidpatch_offset_in_epa = epa_base + 18
            raidpatch_val = struct.unpack('<H', file_content[raidpatch_offset_in_epa:raidpatch_offset_in_epa+2])[0]
            patches.append(PatchOperation(file_path, raidpatch_val, struct.pack('<H', 0x18CD)))

        # Set up totals
        nsect = ((boot_image_len + SECTOR_SIZE - 1) // SECTOR_SIZE) + 2
        dw = boot_image_len >> 2

        patches.append(PatchOperation(file_path, magic_offset + 8, struct.pack('<H', nsect - 2))) # data_sectors
        patches.append(PatchOperation(file_path, magic_offset + 10, struct.pack('<H', 2))) # adv_sectors
        patches.append(PatchOperation(file_path, magic_offset + 12, struct.pack('<I', dw))) # dwords

        # Set sector extents
        secptroffset_in_epa = epa_base + 10
        secptrcnt_in_epa = epa_base + 12

        secptroffset_val = struct.unpack('<H', file_content[secptroffset_in_epa:secptroffset_in_epa+2])[0]
        secptrcnt_val = struct.unpack('<H', file_content[secptrcnt_in_epa:secptrcnt_in_epa+2])[0]

        # Generate extents
        # We need to skip the first sector (sectp++) as it was used for sect1ptr
        # "generate_extents(ex, nptrs, sectp, nsect-1-2);"
        # sectp was already incremented. So sectors[1:] basically.
        # But wait, "sectp" in C is passed as argument "sectors".
        # In C:
        #   set_32(ptr(sbs, &epa->sect1ptr0), sectp[0]);
        #   sectp++;
        #   generate_extents(ex, nptrs, sectp, nsect-1-2);

        # nsect is total sectors including 2 ADV sectors.
        # So we need sectors for the data part.
        # Note: "sectors" passed to calculate_patches is the list of sectors where the file is stored on disk.

        if len(sectors) > 0:
            remaining_sectors = sectors[1:]
            # We only need enough sectors to cover the data.
            # nsect includes ADV.
            # The number of sectors to map is nsect - 1 (boot sector) - 2 (ADV).
            # Wait, "nsect = ((boot_image_len + SECTOR_SIZE - 1) >> SECTOR_SHIFT) + 2;"
            # So nsect covers the file content + 2 ADV sectors.
            # The first sector of the file is mapped in the boot sector (sect1ptr).
            # The rest of the file + ADV sectors need to be mapped in extents.

            # Actually, looking at generate_extents call: "generate_extents(ex, nptrs, sectp, nsect-1-2);"
            # It maps nsect-3 sectors.
            # It seems it maps the rest of the file content, but NOT the ADV sectors?
            # Or maybe ADV sectors are appended?
            # "advptrs = slptr(boot_image, &epa->advptroffset);"
            # "set_64_sl(&advptrs[0], sectp[nsect-1-2]);"
            # "set_64_sl(&advptrs[1], sectp[nsect-1-1]);"

            # So:
            # Sector 0: Mapped in boot sector.
            # Sector 1 to N-3: Mapped in extents.
            # Sector N-2: ADV 1
            # Sector N-1: ADV 2

            # The provided 'sectors' list should contain ALL sectors for the file + ADV area?
            # In syslinux.c:
            # "sectors = (libfat_sector_t*) calloc(ldlinux_sectors, sizeof *sectors);"
            # "ldlinux_sectors = (syslinux_ldlinux_len[0] + 2 * ADV_SIZE + SECTOR_SIZE - 1) >> SECTOR_SHIFT;"
            # So 'sectors' covers the whole thing including ADV.

            sectors_for_extents = remaining_sectors[:nsect-3] if len(remaining_sectors) >= nsect-3 else remaining_sectors

            extents = self._generate_extents(sectors_for_extents)

            ex_ptr = secptroffset_val
            for i, ext in enumerate(extents):
                if i >= secptrcnt_val:
                    break
                patches.append(PatchOperation(file_path, ex_ptr, ext.pack()))
                ex_ptr += 10 # sizeof(syslinux_extent) = 8 + 2 = 10 (packed)

            # Terminate extents with 0 if there is space?
            # "memset_sl(ex, 0, nptrs * sizeof *ex);" happens at start of generate_extents
            # So we should probably zero out the rest if we were writing to memory.
            # But here we return patches.

            # ADV pointers
            advptroffset_in_epa = epa_base + 0
            advptroffset_val = struct.unpack('<H', file_content[advptroffset_in_epa:advptroffset_in_epa+2])[0]

            # sectp is advanced by nsect-1-2 in generate_extents (conceptually).
            # "sectp[nsect-1-2]" refers to the original array offset?
            # Original array: [0, 1, ..., nsect-3, nsect-2, nsect-1]
            # sectp starts at 1.
            # So sectp[k] is original[1+k].
            # We want original[1 + nsect - 1 - 2] = original[nsect - 2]. Correct.

            if len(sectors) > nsect - 2:
                patches.append(PatchOperation(file_path, advptroffset_val, struct.pack('<Q', sectors[nsect-2])))
            if len(sectors) > nsect - 1:
                patches.append(PatchOperation(file_path, advptroffset_val + 8, struct.pack('<Q', sectors[nsect-1])))

        # Subdir
        if subdir:
            diroffset_in_epa = epa_base + 2
            dirlen_in_epa = epa_base + 4

            diroffset_val = struct.unpack('<H', file_content[diroffset_in_epa:diroffset_in_epa+2])[0]
            dirlen_val = struct.unpack('<H', file_content[dirlen_in_epa:dirlen_in_epa+2])[0]

            subdir_bytes = subdir.encode('utf-8') + b'\0'
            if len(subdir_bytes) <= dirlen_val:
                patches.append(PatchOperation(file_path, diroffset_val, subdir_bytes))

        # Subvol
        if subvol:
            subvoloffset_in_epa = epa_base + 6
            subvollen_in_epa = epa_base + 8

            subvoloffset_val = struct.unpack('<H', file_content[subvoloffset_in_epa:subvoloffset_in_epa+2])[0]
            subvollen_val = struct.unpack('<H', file_content[subvollen_in_epa:subvollen_in_epa+2])[0]

            subvol_bytes = subvol.encode('utf-8') + b'\0'
            if len(subvol_bytes) <= subvollen_val:
                patches.append(PatchOperation(file_path, subvoloffset_val, subvol_bytes))

        # Checksum
        # "set_32_sl(&patcharea->checksum, 0);"
        # "csum = LDLINUX_MAGIC;"
        # "for (i = 0, wp = (const uint32_t _slimg *)boot_image; i < dw; i++, wp++) csum -= get_32_sl(wp);"
        # "set_32_sl(&patcharea->checksum, csum);"

        # We need to calculate checksum based on the patched content.
        # Since we are returning patches, we can't easily calculate checksum of the final result
        # unless we apply patches to a temporary buffer.

        temp_buffer = bytearray(file_content)
        # Apply current patches
        for p in patches:
            # We only apply patches that are within the file content
            # Some patches (like sect1ptr in boot sector) might point to beginning of file.
            if p.offset + len(p.data) <= len(temp_buffer):
                temp_buffer[p.offset:p.offset+len(p.data)] = p.data

        # Zero out checksum field
        checksum_offset = magic_offset + 16
        temp_buffer[checksum_offset:checksum_offset+4] = b'\x00\x00\x00\x00'

        csum = LDLINUX_MAGIC
        # Sum is done on 32-bit dwords (little endian)
        for i in range(0, len(temp_buffer), 4):
            if i + 4 <= len(temp_buffer):
                val = struct.unpack('<I', temp_buffer[i:i+4])[0]
                csum = (csum - val) & 0xFFFFFFFF # Simulate 32-bit overflow/wrap

        patches.append(PatchOperation(file_path, checksum_offset, struct.pack('<I', csum)))

        return patches
