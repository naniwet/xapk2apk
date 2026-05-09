"""Tests for `xapk2apk.axml.patch_manifest`."""

from __future__ import annotations

import struct

import pytest

from xapk2apk.axml import patch_manifest


def _build_axml(resource_ids: list[int]) -> bytes:
    """Synthesise a minimal AXML — root header + dummy string pool +
    resource map filled with the given IDs. Enough to exercise the
    chunk-walk logic of `patch_manifest` without needing a real manifest.
    """
    # Dummy string pool: one short UTF-8 string per resource ID.
    n = len(resource_ids)
    string_data = b""
    offsets = []
    for i in range(n):
        offsets.append(len(string_data))
        s = f"a{i:02d}".encode("utf-8")
        # UTF-8 string layout: u8 utf16-len, u8 utf8-len, bytes, NUL.
        string_data += bytes([len(s), len(s)]) + s + b"\x00"
    # 4-byte align
    while len(string_data) % 4:
        string_data += b"\x00"

    sp_header_size = 28
    strings_start = sp_header_size + 4 * n
    sp_size = strings_start + len(string_data)
    sp = struct.pack(
        "<HHIIIIII",
        0x0001,          # RES_STRING_POOL_TYPE
        sp_header_size,
        sp_size,
        n,               # stringCount
        0,               # styleCount
        0x100,           # flags: UTF-8
        strings_start,
        0,
    )
    for off in offsets:
        sp += struct.pack("<I", off)
    sp += string_data

    # Resource map: header(8) + IDs(4*n).
    rm_size = 8 + 4 * n
    rm = struct.pack("<HHI", 0x0180, 8, rm_size)
    for rid in resource_ids:
        rm += struct.pack("<I", rid)

    # Root XML header.
    total = 8 + len(sp) + len(rm)
    return struct.pack("<HHI", 0x0003, 8, total) + sp + rm


def test_clears_required_split_types():
    axml = _build_axml([0x01010001, 0x0101064F, 0x01010002])
    out, cleared = patch_manifest(axml)
    assert cleared == [0x0101064F]

    # Read back the resource map to confirm zero.
    rm_start = len(out) - 4 * 3  # IDs are the last 12 bytes (3 × uint32)
    ids = struct.unpack_from("<3I", out, rm_start)
    assert ids == (0x01010001, 0x00000000, 0x01010002)


def test_clears_split_types_and_required():
    axml = _build_axml([0x0101064E, 0x0101064F, 0x01010003])
    out, cleared = patch_manifest(axml)
    assert sorted(cleared) == [0x0101064E, 0x0101064F]
    rm_start = len(out) - 4 * 3  # IDs are the last 12 bytes (3 × uint32)
    ids = struct.unpack_from("<3I", out, rm_start)
    assert ids == (0, 0, 0x01010003)


def test_clears_is_split_required():
    axml = _build_axml([0x01010591])
    out, cleared = patch_manifest(axml)
    assert cleared == [0x01010591]


def test_no_split_attrs_no_change():
    ids = [0x01010001, 0x01010002, 0x01010003]
    axml = _build_axml(ids)
    out, cleared = patch_manifest(axml)
    assert cleared == []
    assert out == axml  # bit-identical


def test_byte_length_preserved():
    axml = _build_axml([0x0101064F, 0x0101064E, 0x01010001])
    out, _ = patch_manifest(axml)
    assert len(out) == len(axml)


def test_idempotent():
    axml = _build_axml([0x0101064F, 0x0101064E, 0x01010001])
    once, _ = patch_manifest(axml)
    twice, cleared2 = patch_manifest(once)
    assert once == twice
    assert cleared2 == []  # nothing left to clear


def test_rejects_non_axml():
    with pytest.raises(ValueError):
        patch_manifest(b"\x00\x00\x00\x00\x00\x00\x00\x00")
    with pytest.raises(ValueError):
        patch_manifest(b"too short")
