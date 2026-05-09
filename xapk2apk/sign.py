"""APK Signature Scheme v2 signer.

Spec: https://source.android.com/docs/security/features/apksigning/v2

We generate a fresh self-signed RSA-2048 certificate, compute the v2
chunked-SHA256 digest over the APK contents, and insert an "APK Signing
Block" between the ZIP entries and the central directory. The EOCD's CD
offset is updated to point past the signing block.

Why v2 only:
  - v1 (jar-style) is rejected by Android 11+ for new installs.
  - v3 is for key rotation, which makes no sense for a self-signed sideload.
  - v2 alone covers Android 7.0+ (API 24+).
"""

from __future__ import annotations

import io
import os
import struct
from datetime import datetime, timezone
from hashlib import sha256
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

APK_SIG_MAGIC = b"APK Sig Block 42"
APK_SIG_V2_ID = 0x7109871A
SIG_ALGO_RSA_PKCS1_SHA256 = 0x0103

CHUNK_SIZE = 1 << 20  # 1 MiB

# Self-signed cert metadata (cosmetic; cert is brand-new every run).
_CERT_SUBJECT = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sideload"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Sideload Cert"),
])


def _u32(x: int) -> bytes:
    return struct.pack("<I", x)


def _u64(x: int) -> bytes:
    return struct.pack("<Q", x)


def _lp(b: bytes) -> bytes:
    """Length-prefix a byte string with a uint32 LE length."""
    return _u32(len(b)) + b


def _make_self_signed() -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_CERT_SUBJECT)
        .issuer_name(_CERT_SUBJECT)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now.replace(year=now.year + 30))
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _chunk_sha256(chunk: bytes) -> bytes:
    """Per-chunk leaf digest: SHA256(0xa5 || u32_le(len) || chunk)."""
    h = sha256()
    h.update(b"\xa5")
    h.update(_u32(len(chunk)))
    h.update(chunk)
    return h.digest()


def _section_digests(stream: io.BufferedReader, start: int, end: int) -> list[bytes]:
    digests = []
    stream.seek(start)
    remaining = end - start
    while remaining > 0:
        n = min(CHUNK_SIZE, remaining)
        digests.append(_chunk_sha256(stream.read(n)))
        remaining -= n
    return digests


def _bytes_digests(data: bytes) -> list[bytes]:
    return [
        _chunk_sha256(data[off:off + CHUNK_SIZE])
        for off in range(0, len(data), CHUNK_SIZE)
    ]


def _find_eocd(path: str) -> Tuple[int, bytes]:
    """Locate the EOCD record at the tail of the ZIP."""
    sz = os.path.getsize(path)
    with open(path, "rb") as f:
        # Fast path: no comment, EOCD is exactly the last 22 bytes.
        f.seek(sz - 22)
        eocd = f.read(22)
        if eocd[:4] == b"PK\x05\x06":
            return sz - 22, eocd
        # Slow path: search backwards (max comment length 0xFFFF).
        f.seek(max(0, sz - 65557))
        tail = f.read()
        i = tail.rfind(b"PK\x05\x06")
        if i < 0:
            raise ValueError("EOCD not found")
        eocd_start = sz - len(tail) + i
        f.seek(eocd_start)
        return eocd_start, f.read()


def _final_digest(z_d, cd_d, eocd_d) -> bytes:
    """Top-level v2 digest: SHA256(0x5a || u32_le(num_chunks) || all leaves)."""
    top = sha256()
    top.update(b"\x5a")
    all_d = z_d + cd_d + eocd_d
    top.update(_u32(len(all_d)))
    for d in all_d:
        top.update(d)
    return top.digest()


def _build_v2_block(final_digest: bytes,
                    cert_der: bytes,
                    pub_der: bytes,
                    signature: bytes) -> bytes:
    """Assemble the APK Signing Block for a single signer."""
    digests_seq = _lp(_u32(SIG_ALGO_RSA_PKCS1_SHA256) + _lp(final_digest))
    certs_seq = _lp(cert_der)
    additional_attrs = _lp(b"")
    signed_data = _lp(digests_seq) + _lp(certs_seq) + additional_attrs

    sigs_seq = _lp(_u32(SIG_ALGO_RSA_PKCS1_SHA256) + _lp(signature))
    signer = _lp(signed_data) + _lp(sigs_seq) + _lp(pub_der)
    signers = _lp(_lp(signer))

    pair = _u64(4 + len(signers)) + _u32(APK_SIG_V2_ID) + signers
    block_size = len(pair) + 8 + 16  # +trailing size +magic
    return _u64(block_size) + pair + _u64(block_size) + APK_SIG_MAGIC


def sign_v2(unsigned_path: str, signed_path: str) -> int:
    """Sign `unsigned_path` with APK Signature Scheme v2 → `signed_path`.

    Returns the size of the inserted signing block in bytes.
    """
    key, cert = _make_self_signed()
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    pub_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    eocd_off, eocd = _find_eocd(unsigned_path)
    cd_offset = struct.unpack_from("<I", eocd, 16)[0]
    cd_size = struct.unpack_from("<I", eocd, 12)[0]
    if cd_offset + cd_size != eocd_off:
        raise ValueError("malformed ZIP: CD does not abut EOCD")

    # Compute three sets of chunked digests.
    with open(unsigned_path, "rb") as f:
        z_d = _section_digests(f, 0, cd_offset)
        cd_d = _section_digests(f, cd_offset, cd_offset + cd_size)
    # The "modified" EOCD has its CD-offset field set to where the signing
    # block will sit (= original cd_offset, since SB hasn't been inserted yet).
    # In our case this is already the value it has, so no actual change.
    eocd_d = _bytes_digests(bytes(eocd))

    final = _final_digest(z_d, cd_d, eocd_d)

    # Sign the signed_data (which contains digests + certs + attrs).
    digests_seq = _lp(_u32(SIG_ALGO_RSA_PKCS1_SHA256) + _lp(final))
    certs_seq = _lp(cert_der)
    additional_attrs = _lp(b"")
    signed_data = _lp(digests_seq) + _lp(certs_seq) + additional_attrs
    signature = key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())

    sig_block = _build_v2_block(final, cert_der, pub_der, signature)

    # Write the signed APK.
    new_cd_offset = cd_offset + len(sig_block)
    with open(unsigned_path, "rb") as fin, open(signed_path, "wb") as fout:
        # Stream zip-entries section.
        rem = cd_offset
        while rem > 0:
            chunk = fin.read(min(1 << 20, rem))
            fout.write(chunk)
            rem -= len(chunk)
        # Insert signing block, then original CD.
        fout.write(sig_block)
        fin.seek(cd_offset)
        fout.write(fin.read(cd_size))
        # Patched EOCD with shifted CD offset.
        new_eocd = bytearray(eocd)
        struct.pack_into("<I", new_eocd, 16, new_cd_offset)
        fout.write(new_eocd)

    return len(sig_block)
