"""Binary AndroidManifest.xml (AXML) manipulation.

The only mutation we need is neutralising the framework attributes that gate
split-APK enforcement: clear the `requiredSplitTypes` / `splitTypes` resource
IDs in the resource map. Once the resource ID is zero, Android's
`obtainAttributes()` lookup no longer recognises the attribute as a known
framework attribute, and the split-required check is skipped.

This rewrite is in-place and length-preserving, so no chunk sizes need to be
recomputed.
"""

from __future__ import annotations

import struct

# Framework attribute resource IDs that control split-required enforcement.
# Source: AOSP `frameworks/base/core/res/res/values/public.xml` (these IDs
# are stable across SDK levels).
SPLIT_ATTR_RES_IDS: frozenset[int] = frozenset({
    0x0101064F,  # android:requiredSplitTypes
    0x0101064E,  # android:splitTypes
    0x01010591,  # android:isSplitRequired
})

# AXML chunk type IDs.
RES_XML_TYPE = 0x0003
RES_XML_RESOURCE_MAP_TYPE = 0x0180


def patch_manifest(axml: bytes) -> tuple[bytes, list[int]]:
    """Zero out resource-map entries whose value matches a split-control attr.

    Returns:
        (patched_bytes, cleared_resource_ids) — bytes is the rewritten AXML,
        same length as input. cleared_resource_ids lists which IDs were
        actually zeroed (subset of `SPLIT_ATTR_RES_IDS`).

    Raises:
        ValueError: if the input doesn't look like a binary AXML file.
    """
    if len(axml) < 8 or struct.unpack_from("<H", axml, 0)[0] != RES_XML_TYPE:
        raise ValueError("not a binary AXML file")

    buf = bytearray(axml)
    total = struct.unpack_from("<I", buf, 4)[0]
    pos = struct.unpack_from("<H", buf, 2)[0]  # root chunk header size
    cleared: list[int] = []

    while pos < total:
        ctype, chsize, csize = struct.unpack_from("<HHI", buf, pos)
        if ctype == RES_XML_RESOURCE_MAP_TYPE:
            ids_start = pos + chsize
            n = (csize - chsize) // 4
            for i in range(n):
                off = ids_start + i * 4
                rid = struct.unpack_from("<I", buf, off)[0]
                if rid in SPLIT_ATTR_RES_IDS:
                    struct.pack_into("<I", buf, off, 0)
                    cleared.append(rid)
        pos += csize

    return bytes(buf), cleared
