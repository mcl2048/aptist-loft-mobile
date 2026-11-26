"""Verify delivery bytes against private task/node credentials without printing them."""
import argparse
import base64
import binascii
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import parse_qsl, unquote, urlsplit
import zipfile

MIN_SECRET_BYTES = 12
MAX_PRIVATE_INPUT = 2 * 1024 * 1024
MAX_ARTIFACT_ENTRY = 128 * 1024 * 1024
MAX_ARTIFACT_TOTAL = 512 * 1024 * 1024
MAX_INDEX_BYTES = 4 * 1024 * 1024
MAX_ENTRIES = 20000
READ_CHUNK = 64 * 1024
KNOWN_PAT = re.compile(rb"(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]{10,512}")


class InspectionError(ValueError):
    """Only fixed codes, never exception text or private content, reach output."""


def private_key_forms(value: str) -> list[bytes]:
    forms = [value.encode()]
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return forms
    if b"PRIVATE KEY-----" not in decoded:
        return forms
    forms.append(decoded)
    # Scan decoded PEM/DER too: native code need not retain its URI encoding.
    pem = re.search(rb"-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----\s*([A-Za-z0-9+/=\s]+)-----END (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----", decoded)
    if pem is not None:
        try:
            forms.append(base64.b64decode(re.sub(rb"\s+", b"", pem[1]), validate=True))
        except (binascii.Error, ValueError):
            pass
    return forms


def extract_credentials(text: str) -> list[bytes]:
    values = [m.group().encode() for m in re.finditer(r"(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]{10,512}", text)]
    for match in re.finditer(r"(?:socks5|socks|hyrakenx|hyraken-pro)://[^\s<>\"']+", text, re.I):
        uri = match.group()
        values.append(uri.encode())
        try:
            parsed = urlsplit(uri)
            for value in (parsed.username, parsed.password):
                if value:
                    values.append(unquote(value).encode())
            for key, value in parse_qsl(parsed.query):
                if key.lower() in ("key", "password", "seed", "client_secret") and value:
                    values.append(value.encode())
                    if key.lower() == "key":
                        values.extend(private_key_forms(value))
        except ValueError:
            continue
    return list(dict.fromkeys(value for value in values if len(value) >= MIN_SECRET_BYTES))


def contains_credential(data: bytes, credentials: list[bytes]) -> bool:
    return KNOWN_PAT.search(data) is not None or any(len(value) >= MIN_SECRET_BYTES and value in data for value in credentials)


def read_private(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_PRIVATE_INPUT + 1)
    if len(data) > MAX_PRIVATE_INPUT:
        raise InspectionError("private_input_too_large")
    return data


def scan_stream(stream, size: int, credentials: list[bytes]) -> bool:
    if size < 0 or size > MAX_ARTIFACT_ENTRY:
        raise InspectionError("entry_too_large")
    overlap = max(523, max((len(value) - 1 for value in credentials), default=0))
    retained = b""
    matched = False
    remaining = size
    while remaining:
        chunk = stream.read(min(READ_CHUNK, remaining))
        if not chunk:
            raise InspectionError("truncated_entry")
        remaining -= len(chunk)
        data = retained + chunk
        matched = matched or contains_credential(data, credentials)
        retained = data[-overlap:] if overlap else b""
    return matched


def safe_label(name: str, credentials: list[bytes]) -> str:
    return "[redacted path]" if contains_credential(name.encode(), credentials) else name


def scan_index(root: Path, credentials: list[bytes]) -> tuple[int, list[dict]]:
    # Read the actual index blobs, not mutable worktree bytes. No network fetch.
    environment = dict(os.environ, GIT_NO_LAZY_FETCH="1")
    with subprocess.Popen(["git", "ls-files", "--stage", "-z"], cwd=root, env=environment,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        listing = process.stdout.read(MAX_INDEX_BYTES + 1)
        if len(listing) > MAX_INDEX_BYTES:
            process.kill()
            raise InspectionError("index_too_large")
        if process.wait(timeout=10):
            raise InspectionError("index_unavailable")
    entries = [entry for entry in listing.split(b"\0") if entry]
    if len(entries) > MAX_ENTRIES:
        raise InspectionError("index_too_many_entries")
    failures = []
    cache = {}
    for entry in entries:
        metadata, encoded_name = entry.split(b"\t", 1)
        _, oid, stage = metadata.split()
        if stage != b"0" or re.fullmatch(rb"[0-9a-f]{40,64}", oid) is None:
            raise InspectionError("index_unmerged_or_invalid")
        name = encoded_name.decode("utf-8")
        if oid not in cache:
            size = int(subprocess.check_output(["git", "cat-file", "-s", oid.decode()],
                       cwd=root, env=environment, stderr=subprocess.DEVNULL, timeout=10))
            with subprocess.Popen(["git", "cat-file", "blob", oid.decode()], cwd=root, env=environment,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
                try:
                    cache[oid] = scan_stream(process.stdout, size, credentials)
                except Exception:
                    process.kill()
                    raise
                if process.wait(timeout=10):
                    raise InspectionError("index_blob_unavailable")
        if cache[oid] or contains_credential(encoded_name, credentials):
            failures.append({"path": safe_label(name, credentials), "kind": "private credential"})
    return len(entries), failures


def scan_artifact(path: Path, credentials: list[bytes]) -> tuple[int, list[dict]]:
    if path.stat().st_size > MAX_ARTIFACT_TOTAL:
        raise InspectionError("artifact_too_large")
    failures = []
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_ENTRIES or sum(entry.file_size for entry in entries) > MAX_ARTIFACT_TOTAL:
            raise InspectionError("artifact_expansion_too_large")
        for entry in entries:
            with archive.open(entry) as stream:
                matched = scan_stream(stream, entry.file_size, credentials)
            if matched or contains_credential(entry.filename.encode(), credentials):
                label = safe_label(path.name + ":" + entry.filename, credentials)
                failures.append({"path": label, "kind": "private credential"})
    return len(entries), failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        credentials = []
        for name in ("Prompt/Task-Now.txt", "guide/TEST.TXT"):
            path = root / name
            if path.exists():
                credentials.extend(extract_credentials(read_private(path).decode("utf-8")))
        credentials = list(dict.fromkeys(credentials))
        inspected, failures = scan_index(root, credentials)
        for path in args.apk:
            count, artifact_failures = scan_artifact(path, credentials)
            inspected += count
            failures.extend(artifact_failures)
        result = {"result": "PASS" if not failures else "FAIL", "inspected": inspected,
                  "scope": "git_index_and_artifact_members",
                  "private_inputs_available": bool(credentials), "failures": failures}
        status = int(bool(failures))
    except (ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        result = {"result": "ERROR", "error_code": str(error) if isinstance(error, InspectionError) else "inspection_failed"}
        status = 2
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n")
    print(rendered)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
