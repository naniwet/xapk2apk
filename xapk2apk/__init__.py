"""xapk2apk — merge XAPK splits into a single sideloadable, v2-signed APK."""

from xapk2apk.axml import patch_manifest
from xapk2apk.merge import write_merged_apk
from xapk2apk.sign import sign_v2

__version__ = "0.1.0"
__all__ = ["patch_manifest", "write_merged_apk", "sign_v2", "__version__"]
