"""Tests for APK Signature Scheme v2 signer."""

from __future__ import annotations

import struct
import zipfile

import pytest

from xapk2apk.sign import APK_SIG_MAGIC, APK_SIG_V2_ID, sign_v2


def _make_zip(path: str) -> None:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("file1.txt", b"hello world")
        z.writestr("file2.bin", b"\x00\x01\x02\x03" * 1024)


def test_signed_zip_still_readable(tmp_path):
    src = tmp_path / "in.zip"
    out = tmp_path / "signed.apk"
    _make_zip(str(src))

    sign_v2(str(src), str(out))

    # All original entries are still present and readable.
    with zipfile.ZipFile(out) as z:
        assert z.read("file1.txt") == b"hello world"
        assert z.read("file2.bin") == b"\x00\x01\x02\x03" * 1024


def test_signing_block_present(tmp_path):
    src = tmp_path / "in.zip"
    out = tmp_path / "signed.apk"
    _make_zip(str(src))
    sign_v2(str(src), str(out))

    data = out.read_bytes()
    # The magic must appear; it sits 24 bytes before EOCD (= 16 magic + 8
    # trailing block size).
    assert APK_SIG_MAGIC in data
    magic_off = data.rfind(APK_SIG_MAGIC)

    # Read trailing size right before magic.
    trailing_size = struct.unpack_from("<Q", data, magic_off - 8)[0]
    # The leading size field sits at (magic_off + 16) - 8 - trailing_size
    # backed up by the block size + 8 (size field itself).
    block_start = magic_off + 16 - 8 - trailing_size
    leading_size = struct.unpack_from("<Q", data, block_start)[0]
    assert leading_size == trailing_size

    # First pair after the leading size: uint64 pair-size, uint32 id, value.
    pair_id = struct.unpack_from("<I", data, block_start + 16)[0]
    assert pair_id == APK_SIG_V2_ID


def test_eocd_cd_offset_updated(tmp_path):
    src = tmp_path / "in.zip"
    out = tmp_path / "signed.apk"
    _make_zip(str(src))

    src_size = src.stat().st_size
    src_data = src.read_bytes()
    src_cd_offset = struct.unpack_from("<I", src_data, src_size - 22 + 16)[0]

    block_size = sign_v2(str(src), str(out))

    out_data = out.read_bytes()
    out_size = out.stat().st_size
    out_cd_offset = struct.unpack_from("<I", out_data, out_size - 22 + 16)[0]
    assert out_cd_offset == src_cd_offset + block_size


def test_round_trip_verify_with_apksigtool(tmp_path):
    """If apksigtool is installed, use it as a third-party verifier."""
    apksigtool = pytest.importorskip("apksigtool")  # noqa: F841
    import subprocess
    src = tmp_path / "in.zip"
    out = tmp_path / "signed.apk"
    _make_zip(str(src))
    sign_v2(str(src), str(out))
    r = subprocess.run(
        ["apksigtool", "verify", str(out)],
        capture_output=True, text=True,
    )
    assert "v2 verified" in (r.stdout + r.stderr), (r.stdout, r.stderr)
