"""APK ZIP writer with .so page-alignment.

Why we write ZIP manually instead of using `zipfile.ZipFile`:

The base APK has `extractNativeLibs="false"` in its manifest, which means
shared libraries are loaded directly from the APK without extraction. For
this to work, each `.so` entry must be:

    1. STORED (no compression)
    2. page-aligned — its data offset (after the local file header) must
       be a multiple of 4096 bytes

`zipfile.ZipFile` doesn't expose offset control. So we emit local file
headers + central directory + EOCD by hand, padding the `extra` field of
each .so entry to the right alignment.

`resources.arsc` similarly needs STORED + 4-byte alignment so the runtime
can mmap it.
"""

from __future__ import annotations

import struct
import zipfile
import zlib

PAGE_ALIGNMENT = 4096
ARSC_ALIGNMENT = 4

# ZIP signatures.
_LFH_SIG = 0x04034B50
_CD_SIG = 0x02014B50
_EOCD_SIG = 0x06054B50

# Android alignment extra-field record id.
_ALIGN_EXTRA_ID = 0xD935


def _aligned_extra(name: str, current_offset: int, alignment: int) -> bytes:
    """Build a ZIP extra-field record that pads a local file header so the
    file content begins at `alignment`-byte boundary.

    Local file header layout: 30 fixed bytes + filename + extra + data.
    The data starts at `current_offset + 30 + len(filename) + len(extra)`.
    """
    base = current_offset + 30 + len(name.encode("utf-8"))
    pad = (alignment - base % alignment) % alignment
    if pad == 0:
        return b""
    # ZIP extra records are at minimum 4 bytes (id + size). To carry a
    # meaningful payload (we put the alignment value as 2 bytes) we need >=6.
    # If the requested pad is smaller than that, bump by `alignment` until
    # we have room — adding `alignment` keeps the resulting data aligned.
    while pad < 6:
        pad += alignment
    payload_len = pad - 4
    record = struct.pack("<HHH", _ALIGN_EXTRA_ID, payload_len, alignment)
    record += b"\x00" * (payload_len - 2)
    assert len(record) == pad
    return record


# Original-signing-related entries we strip from the base APK before writing.
_SIGNING_FILE_SUFFIXES = (".SF", ".RSA", ".DSA", ".EC")


def _is_original_signing_file(name: str) -> bool:
    if not name.startswith("META-INF/"):
        return False
    if name == "META-INF/MANIFEST.MF":
        return True
    return name.endswith(_SIGNING_FILE_SUFFIXES)


def write_merged_apk(
    base_apk: str,
    abi_apk: str | None,
    output_path: str,
    patched_manifest: bytes,
) -> None:
    """Write a merged APK that combines base APK entries (with patched
    manifest) and native libs from the ABI split.

    Args:
        base_apk: path to base APK (e.g., com.foo.app.apk).
        abi_apk: path to ABI split APK (e.g., config.arm64_v8a.apk), or
            None to skip native lib injection.
        output_path: where to write the merged (unsigned) APK.
        patched_manifest: bytes to write in place of the base APK's
            AndroidManifest.xml (typically from `axml.patch_manifest`).
    """
    base_z = zipfile.ZipFile(base_apk)
    abi_z = zipfile.ZipFile(abi_apk) if abi_apk else None

    out = open(output_path, "wb")
    cd_records: list[bytes] = []

    def write_entry(arc: str, data: bytes, *, stored: bool, align: int = 0) -> None:
        """Append a ZIP entry — local file header + (extra) + data — and
        record its central directory entry."""
        method = 0 if stored else 8
        if stored:
            comp = data
        else:
            c = zlib.compressobj(6, zlib.DEFLATED, -15)  # raw deflate
            comp = c.compress(data) + c.flush()
        crc = zipfile.crc32(data) & 0xFFFFFFFF

        local_offset = out.tell()
        extra = _aligned_extra(arc, local_offset, align) if align else b""
        name_b = arc.encode("utf-8")

        # Local file header.
        lfh = struct.pack(
            "<IHHHHHIIIHH",
            _LFH_SIG, 20, 0x0800, method, 0, 0x21,
            crc, len(comp), len(data),
            len(name_b), len(extra),
        )
        out.write(lfh + name_b + extra + comp)

        # Central directory record (held in memory; flushed at end).
        cd = struct.pack(
            "<IHHHHHHIIIHHHHHII",
            _CD_SIG, 20, 20, 0x0800, method, 0, 0x21,
            crc, len(comp), len(data),
            len(name_b), len(extra), 0, 0, 0, 0, local_offset,
        )
        cd_records.append(cd + name_b + extra)

    # 1) Base APK entries — patched manifest, drop original signing files.
    for info in base_z.infolist():
        n = info.filename
        if _is_original_signing_file(n):
            continue
        data = patched_manifest if n == "AndroidManifest.xml" else base_z.read(n)
        stored = info.compress_type == 0
        align = 0
        if n.startswith("lib/") and n.endswith(".so"):
            stored, align = True, PAGE_ALIGNMENT
        elif n == "resources.arsc":
            stored, align = True, ARSC_ALIGNMENT
        write_entry(n, data, stored=stored, align=align)

    # 2) Native libs from the ABI split.
    if abi_z is not None:
        for info in abi_z.infolist():
            if info.filename.startswith("lib/") and info.filename.endswith(".so"):
                write_entry(
                    info.filename, abi_z.read(info.filename),
                    stored=True, align=PAGE_ALIGNMENT,
                )

    # 3) Central directory and EOCD.
    cd_offset = out.tell()
    cd_blob = b"".join(cd_records)
    out.write(cd_blob)
    eocd = struct.pack(
        "<IHHHHIIH",
        _EOCD_SIG, 0, 0,
        len(cd_records), len(cd_records),
        len(cd_blob), cd_offset, 0,
    )
    out.write(eocd)

    out.close()
    base_z.close()
    if abi_z is not None:
        abi_z.close()
