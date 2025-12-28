# pylibrufus

A Python library port of core Rufus business logic.

## Modules

### iso_analyzer.py

Analyzes ISO files to detect bootloaders.

```python
from pylibrufus.iso_analyzer import IsoAnalyzer, BootloaderType

analyzer = IsoAnalyzer("path/to/image.iso")
bootloaders = analyzer.analyze()
print(f"Detected bootloaders: {bootloaders}")
```

### patcher.py

Calculates Syslinux patches without writing to disk.

```python
from pylibrufus.patcher import Patcher

patcher = Patcher()
patches = patcher.calculate_patches(
    file_path="ldlinux.sys",
    file_content=b"...",
    sectors=[100, 101, 102, ...]
)

for p in patches:
    print(f"File: {p.file_path}, Offset: {p.offset}, Data: {p.data.hex()}")
```

### win_bypass.py

Generates Windows 11 bypass `autounattend.xml` and registry keys.

```python
from pylibrufus.win_bypass import generate_bypass_xml, get_bypass_registry_keys, BypassOption

# Generate XML
xml_content = generate_bypass_xml(BypassOption.DEFAULT, username="MyUser")
print(xml_content)

# Get Registry Keys
keys = get_bypass_registry_keys()
for k in keys:
    print(k)
```

### linux_sectors.py (Linux Only)

Retrieves physical disk sectors of a file, required for Syslinux patching.

```python
from pylibrufus.linux_sectors import get_file_physical_sectors

sectors = get_file_physical_sectors("/mnt/usb/ldlinux.sys")
print(f"File resides on sectors: {sectors}")
```

## Dependencies

* `pycdlib` (for ISO analysis)
