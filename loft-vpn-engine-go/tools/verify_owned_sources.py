#!/usr/bin/env python3
"""Verify every linked source/license byte using only this owned checkout.

The source path and source digest describe provenance. They are never opened;
clean build verification uses owned_sha256 and explicit mobile patch records.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys


DIGEST = re.compile(r"[0-9a-f]{64}\Z")
GATEWAY_PIN = "a984911c8aa0e932c885bb298134031432eb82b7"


class SourceError(Exception):
    """A bounded public verification code, independent of filesystem errors."""


def reject(code):
    raise SourceError("loft.sources." + code)


def destination(value):
    if not isinstance(value, str) or len(value) > 512 or not re.fullmatch(r"[A-Za-z0-9._/-]+", value):
        reject("unsafe_destination")
    path = PurePosixPath(value)
    if path.is_absolute() or path.parts[0] != "third_party" or any(part in {".", ".."} for part in path.parts):
        reject("unsafe_destination")
    if str(path) != value or value == "third_party/SOURCE-LOCK.json":
        reject("unsafe_destination")
    return path


def file_digest(path):
    if not path.is_file() or path.stat().st_size > 16777216:
        reject("digest_mismatch")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(65536):
            digest.update(block)
    return digest.hexdigest()


def verify(root):
    party = root / "third_party"
    manifest_path = party / "SOURCE-LOCK.json"
    if party.is_symlink() or manifest_path.is_symlink():
        reject("unsafe_destination")
    if manifest_path.stat().st_size > 2097152:
        reject("invalid_manifest")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1 or manifest.get("gateway_commit") != GATEWAY_PIN:
        reject("invalid_manifest")
    files = manifest.get("files")
    patches = manifest.get("mobile_patches")
    if not isinstance(files, list) or not files or len(files) > 4096 or not isinstance(patches, list) or len(patches) > 256:
        reject("invalid_manifest")
    coverage = set()
    patch_ids = set()
    for patch in patches:
        if not isinstance(patch, dict) or not isinstance(patch.get("id"), str) or patch["id"] in patch_ids:
            reject("invalid_manifest")
        patch_ids.add(patch["id"])
        paths = patch.get("files")
        if not isinstance(paths, list) or not paths or len(paths) > 4096:
            reject("invalid_manifest")
        coverage.update(str(destination(path)) for path in paths)
    recorded = set()
    changed = set()
    for entry in files:
        if not isinstance(entry, dict):
            reject("invalid_manifest")
        relative = str(destination(entry.get("destination")))
        if relative in recorded:
            reject("invalid_manifest")
        recorded.add(relative)
        owned = entry.get("owned_sha256")
        if not isinstance(owned, str) or not DIGEST.fullmatch(owned):
            reject("invalid_manifest")
        kind = entry.get("source_kind", "source_snapshot")
        if kind == "source_snapshot":
            source_hash = entry.get("source_sha256")
            if not isinstance(source_hash, str) or not DIGEST.fullmatch(source_hash):
                reject("invalid_manifest")
            if source_hash != owned:
                changed.add(relative)
        elif kind == "mobile_addition" and entry.get("source_sha256") is None:
            changed.add(relative)
        else:
            reject("invalid_manifest")
        path = root / relative
        if any(parent.is_symlink() for parent in (path, *path.parents) if parent != root.parent):
            reject("unsafe_destination")
        if file_digest(path) != owned:
            reject("digest_mismatch")
    present = set()
    for path in party.rglob("*"):
        if path.is_symlink():
            reject("unsafe_destination")
        if path.is_file() and path != manifest_path:
            present.add(path.relative_to(root).as_posix())
        elif not path.is_file() and not path.is_dir():
            reject("unsafe_destination")
    if present != recorded:
        reject("unrecorded_file")
    if not changed.issubset(coverage) or not coverage.issubset(recorded):
        reject("unrecorded_patch")
    return {"status": "verified", "gateway_commit": GATEWAY_PIN, "verified_files": len(recorded), "patched_files": len(changed), "provenance_paths_read": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        receipt = verify(args.root.resolve())
    except SourceError as error:
        receipt = {"status": "rejected", "code": str(error)}
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        receipt = {"status": "rejected", "code": "loft.sources.invalid_manifest"}
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["status"] == "verified" else 2


if __name__ == "__main__":
    sys.exit(main())
