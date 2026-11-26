"""Verify native ABI, loader alignment and ZIP delivery, not source declarations."""
import argparse
import json
from pathlib import Path
import struct
import zipfile


def validate_elf(data: bytes) -> dict:
    if len(data) < 64 or data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("Expected complete little-endian ELF64")
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine != 183:
        raise ValueError("Native ABI is not AArch64")
    table = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    if size < 56 or not 1 <= count <= 256 or table + size * count > len(data):
        raise ValueError("Truncated or invalid program headers")
    loads = 0
    for index in range(count):
        kind, _, offset, address, _, file_size, memory_size, alignment = struct.unpack_from("<IIQQQQQQ", data, table + index * size)
        if kind != 1:
            continue
        loads += 1
        if alignment < 16384 or alignment & (alignment - 1) or offset % alignment != address % alignment:
            raise ValueError("Native LOAD segment violates Android 16KiB alignment")
        if memory_size < file_size or offset + file_size > len(data):
            raise ValueError("Invalid native LOAD extent")
    if not loads:
        raise ValueError("Native ELF has no LOAD segments")
    return {"machine": "AArch64", "load_segments": loads, "alignment": "16KiB-compatible"}


def verify_archive(path: Path) -> dict:
    expected = {"libloft_ffi.so", "libgojni.so", "libjnidispatch.so"}
    libraries = {}
    with path.open("rb") as source, zipfile.ZipFile(source) as archive:
        if sum(entry.file_size for entry in archive.infolist()) > 512 * 1024 * 1024:
            raise ValueError("APK inspection exceeds bounded artifact size")
        for entry in archive.infolist():
            if not entry.filename.startswith("lib/") or not entry.filename.endswith(".so"):
                continue
            if not entry.filename.startswith("lib/arm64-v8a/"):
                raise ValueError("APK advertises an unverified native ABI")
            if entry.compress_type != zipfile.ZIP_STORED:
                raise ValueError("Native libraries must be stored for direct loading")
            source.seek(entry.header_offset + 26)
            lengths = source.read(4)
            if len(lengths) != 4:
                raise ValueError("Truncated ZIP native header")
            name_size, extra_size = struct.unpack("<HH", lengths)
            offset = entry.header_offset + 30 + name_size + extra_size
            if offset % 16384:
                raise ValueError("Native ZIP entry is not aligned to 16KiB")
            libraries[entry.filename] = validate_elf(archive.read(entry))
    if not expected.issubset({Path(name).name for name in libraries}):
        raise ValueError("APK is missing required Rust/Go/JNA native libraries")
    return {"result": "PASS", "apk": path.name, "native_libraries": libraries}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = verify_archive(args.artifact) if args.artifact.suffix == ".apk" else validate_elf(args.artifact.read_bytes())
    rendered = json.dumps(result, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n")
    print(rendered)


if __name__ == "__main__":
    main()
