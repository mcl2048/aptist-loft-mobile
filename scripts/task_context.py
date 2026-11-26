"""Private-task reader. Its CLI deliberately has no secret-output operation."""
import argparse
import hashlib
import json
from pathlib import Path
import re

MAX_TASK_BYTES = 64 * 1024
TOKEN = re.compile(r"(?:github_pat_|gh[pousr]_)[A-Za-z0-9_]{10,512}")
TOKEN_FIELD = re.compile(r"^\[\s*Github\s+Token\s*\]\s*(\S+)", re.I | re.M)
REPOSITORY = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git")


def redact_text(text: str) -> str:
    text = re.sub(r"^.*\[\s*Github\s+Token\s*\].*$", "[Github Token] [REDACTED]", text, flags=re.I | re.M)
    return TOKEN.sub("[REDACTED]", text)


def credential(text: str) -> str:
    """Only authenticated transport/askpass callers may consume this value."""
    match = TOKEN_FIELD.search(text)
    if match is None or TOKEN.fullmatch(match[1]) is None:
        raise ValueError("Task credential missing or invalid")
    return match[1]


def public_context(text: str) -> dict:
    task = re.search(r'^\[\s*Task\s+No\.\s*\]\s*"([^"\n]+)"', text, re.I | re.M)
    repo = re.search(r"^\[\s*交付仓库\s*\]\s*(\S+)", text, re.M)
    if task is None or repo is None or REPOSITORY.fullmatch(repo[1]) is None:
        raise ValueError("Task metadata missing or unsafe repository address")
    try:
        credential(text)
        present = True
    except ValueError:
        present = False
    return {
        "task_no": task[1].strip(),
        "repository": repo[1],
        "credential_present": present,
        "task_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }


def read_task(path: Path) -> str:
    with path.open("rb") as file:
        raw = file.read(MAX_TASK_BYTES + 1)
    if len(raw) > MAX_TASK_BYTES:
        raise ValueError("Task exceeds bounded input limit")
    return raw.decode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task", type=Path, default=Path(__file__).resolve().parents[1] / "Prompt/Task-Now.txt")
    parser.add_argument("--redacted", action="store_true")
    args = parser.parse_args()
    text = read_task(args.task)
    print(redact_text(text) if args.redacted else json.dumps(public_context(text), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
