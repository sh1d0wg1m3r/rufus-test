from .iso_analyzer import IsoAnalyzer, BootloaderType
from .patcher import Patcher
from .win_bypass import generate_bypass_xml, get_bypass_registry_keys, BypassOption
from .resource_manager import ResourceManager, DownloadInstruction
import os

# Initialize ResourceManager with bundled resources
_RES_PATH = os.path.join(os.path.dirname(__file__), "res")
resource_manager = ResourceManager(_RES_PATH)
