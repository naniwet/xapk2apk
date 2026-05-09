"""Tests for the ZIP writer + alignment helper."""

from __future__ import annotations

import os
import struct
import tempfile
import zipfile
from pathlib import Path

import pytest

from xapk2apk.merge import (
    PAGE_ALIGNMENT,
    _aligned_extra,
    _is_original_signing_file,
    write_merged_apk,
)


# ----- _aligned_extra ------------------------------------------------------

class TestAlignedExtra:
    def test_zero_when_already_aligned(self):
        # name "x" → header overhead = 30 + 1 = 31. At offset 4065,
        # data starts at 4096 — already aligned.
        assert _aligned_extra("x", 4065, 4096) == b""

    def test_pads_to_alignment(self):
        name = "lib/arm64-v8a/foo.so"
        offset = 1234
        extra = _aligned_extra(name, offset, 4096)
        data_offset = offset + 30 + len(name.encode()) + len(extra)
        assert data_offset % 4096 == 0

    def test_pads_for_4_byte_arsc_alignment(self):
        name = "resources.arsc"
        # Pick offsets that exercise different residues mod 4.
        for off in range(100, 200):
            extra = _aligned_extra(name, off, 4)
            data_off = off + 30 + len(name.encode()) + len(extra)
            assert data_off % 4 == 0

    def test_handles_small_pad(self):
        # If the natural pad is < 6 bytes (extra-record minimum is 4 + 2),
        # the helper bumps by `alignment` so there's room for the record
        # while keeping data aligned.
        name = "y"  # short name
        # Find an offset where the natural pad would be 1, 2, ... 5 bytes.
        for natural_pad in range(1, 6):
            base_data_off = (4096 - natural_pad)  # we want offset+31+pad = 4096
            offset = base_data_off - 31
            extra = _aligned_extra(name, offset, 4096)
            assert len(extra) >= 6
            data_off = offset + 30 + len(name.encode()) + len(extra)
            assert data_off % 4096 == 0


# ----- _is_original_signing_file -------------------------------------------

@pytest.mark.parametrize("name,expected", [
    ("META-INF/MANIFEST.MF", True),
    ("META-INF/CERT.SF", True),
    ("META-INF/CERT.RSA", True),
    ("META-INF/CERT.DSA", True),
    ("META-INF/CERT.EC", True),
    ("META-INF/services/com.foo.Bar", False),  # service registration, keep
    ("AndroidManifest.xml", False),
    ("classes.dex", False),
    ("lib/arm64-v8a/libfoo.so", False),
])
def test_is_original_signing_file(name, expected):
    assert _is_original_signing_file(name) == expected


# ----- write_merged_apk end-to-end -----------------------------------------

def _make_minimal_axml(total_extra: bytes = b"") -> bytes:
    """Build a tiny but valid binary AXML root + empty string pool."""
    sp_header = 28
    sp_size = sp_header  # no strings
    sp = struct.pack(
        "<HHIIIIII",
        0x0001, sp_header, sp_size, 0, 0, 0x100, sp_header, 0,
    )
    body = sp + total_extra
    total = 8 + len(body)
    return struct.pack("<HHI", 0x0003, 8, total) + body


def _make_dummy_apk(path: str, *, with_so: bool = False, with_arsc: bool = False) -> None:
    """Create a minimal APK-like ZIP for round-trip tests."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", _make_minimal_axml())
        z.writestr("classes.dex", b"\x00" * 100)
        if with_arsc:
            z.writestr("resources.arsc", b"\x00" * 200)
        if with_so:
            zi = zipfile.ZipInfo("lib/arm64-v8a/libtest.so")
            zi.compress_type = zipfile.ZIP_STORED
            z.writestr(zi, b"\xde\xad\xbe\xef" * 256)
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        z.writestr("META-INF/CERT.SF", "stale signature\n")
        z.writestr("META-INF/CERT.RSA", b"\x00" * 16)


def test_merge_drops_signing_files(tmp_path):
    base = tmp_path / "base.apk"
    out = tmp_path / "merged.apk"
    _make_dummy_apk(str(base))

    with zipfile.ZipFile(base) as z:
        manifest = z.read("AndroidManifest.xml")

    write_merged_apk(str(base), None, str(out), manifest)

    with zipfile.ZipFile(out) as z:
        names = set(z.namelist())
    assert "META-INF/MANIFEST.MF" not in names
    assert "META-INF/CERT.SF" not in names
    assert "META-INF/CERT.RSA" not in names
    assert "AndroidManifest.xml" in names
    assert "classes.dex" in names


def test_merge_aligns_so_files(tmp_path):
    base = tmp_path / "base.apk"
    out = tmp_path / "merged.apk"
    _make_dummy_apk(str(base), with_so=True)

    with zipfile.ZipFile(base) as z:
        manifest = z.read("AndroidManifest.xml")

    write_merged_apk(str(base), None, str(out), manifest)

    # Walk the local file headers to confirm .so data offset is page-aligned.
    data = out.read_bytes()
    i = 0
    so_offsets = []
    while i < len(data) - 30:
        if data[i:i + 4] != b"PK\x03\x04":
            i += 1
            continue
        name_len = struct.unpack_from("<H", data, i + 26)[0]
        extra_len = struct.unpack_from("<H", data, i + 28)[0]
        name = data[i + 30:i + 30 + name_len].decode("utf-8")
        data_off = i + 30 + name_len + extra_len
        if name.endswith(".so"):
            so_offsets.append((name, data_off))
        csize = struct.unpack_from("<I", data, i + 18)[0]
        i = data_off + csize

    assert so_offsets, "no .so entries written"
    for name, off in so_offsets:
        assert off % PAGE_ALIGNMENT == 0, f"{name} at offset {off} not page-aligned"


def test_merge_substitutes_manifest(tmp_path):
    base = tmp_path / "base.apk"
    out = tmp_path / "merged.apk"
    _make_dummy_apk(str(base))

    sentinel_manifest = _make_minimal_axml(b"\x42" * 16)
    write_merged_apk(str(base), None, str(out), sentinel_manifest)

    with zipfile.ZipFile(out) as z:
        assert z.read("AndroidManifest.xml") == sentinel_manifest


def test_merge_injects_native_libs(tmp_path):
    base = tmp_path / "base.apk"
    abi = tmp_path / "config.arm64_v8a.apk"
    out = tmp_path / "merged.apk"
    _make_dummy_apk(str(base))
    # Build an ABI split with a single .so.
    with zipfile.ZipFile(abi, "w") as z:
        zi = zipfile.ZipInfo("lib/arm64-v8a/libinjected.so")
        zi.compress_type = zipfile.ZIP_STORED
        z.writestr(zi, b"INJECTED" * 100)

    with zipfile.ZipFile(base) as z:
        manifest = z.read("AndroidManifest.xml")
    write_merged_apk(str(base), str(abi), str(out), manifest)

    with zipfile.ZipFile(out) as z:
        names = set(z.namelist())
        assert "lib/arm64-v8a/libinjected.so" in names
        assert z.read("lib/arm64-v8a/libinjected.so") == b"INJECTED" * 100
