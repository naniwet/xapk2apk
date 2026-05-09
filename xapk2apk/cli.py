"""Command-line driver: glue patch_manifest + write_merged_apk + sign_v2."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import zipfile
from pathlib import Path

from xapk2apk import __version__
from xapk2apk.axml import patch_manifest
from xapk2apk.merge import write_merged_apk
from xapk2apk.sign import sign_v2


SUPPORTED_ABIS = ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]


def _detect_inputs(input_path: Path, abi: str) -> tuple[str, str | None, list[str]]:
    """Resolve the input (file or directory) into (base_apk, abi_apk, names).

    If `input_path` is an .xapk / .apks / .zip file, it's extracted into a
    temp dir first. The base APK is whichever .apk doesn't start with
    `config.` (or, as a fallback, the largest .apk).
    """
    if input_path.is_file() and input_path.suffix.lower() in (".xapk", ".apks", ".zip"):
        tmp = Path(tempfile.mkdtemp(prefix="xapk2apk_"))
        with zipfile.ZipFile(input_path) as z:
            z.extractall(tmp)
        input_path = tmp

    apks = sorted(p for p in input_path.glob("*.apk"))
    if not apks:
        raise SystemExit(f"no .apk files found in {input_path}")

    base = next((p for p in apks if not p.name.startswith("config.")), None)
    if base is None:
        base = max(apks, key=lambda p: p.stat().st_size)

    abi_filename = f"config.{abi.replace('-', '_')}.apk"
    abi_split = next((p for p in apks if p.name == abi_filename), None)

    return str(base), str(abi_split) if abi_split else None, [p.name for p in apks]


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="xapk2apk",
        description="merge XAPK splits into a single sideloadable APK",
    )
    p.add_argument("input", help=".xapk / .apks file or directory of split APKs")
    p.add_argument(
        "-a", "--abi",
        default="arm64-v8a",
        choices=SUPPORTED_ABIS,
        help="ABI to merge (default: arm64-v8a)",
    )
    p.add_argument("-o", "--out", default=None, help="output APK path")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)

    base, abi_apk, names = _detect_inputs(Path(args.input).resolve(), args.abi)
    print(f"detected splits: {names}")
    print(f"base APK: {base}")
    print(f"ABI split ({args.abi}): {abi_apk or '(none — base only)'}")

    out_path = args.out or f"merged-{Path(base).stem}-{args.abi}.apk"
    out_path = str(Path(out_path).resolve())

    print("[1/3] patching AndroidManifest.xml")
    with zipfile.ZipFile(base) as z:
        manifest = z.read("AndroidManifest.xml")
    patched, cleared = patch_manifest(manifest)
    print(f"  cleared resource IDs: {[hex(r) for r in cleared] or '(none)'}")

    with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
        unsigned = tmp.name
    try:
        print(f"[2/3] merging → unsigned APK")
        write_merged_apk(base, abi_apk, unsigned, patched)
        print(f"  unsigned size: {os.path.getsize(unsigned):,} bytes")

        print(f"[3/3] signing v2 → {out_path}")
        block_sz = sign_v2(unsigned, out_path)
        print(f"  signed size: {os.path.getsize(out_path):,} bytes "
              f"(sig block {block_sz} bytes)")
    finally:
        if os.path.exists(unsigned):
            os.unlink(unsigned)

    print(f"\ndone. install with: adb install -r {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
