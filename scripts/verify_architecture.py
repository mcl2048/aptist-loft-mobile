"""Verify the reviewed direct dependency boundary of loft-core."""
import argparse
import json
from pathlib import Path
import tomllib

# Reviewed crypto, configuration validation and data-only serialization.
# New direct dependencies require a conscious policy and source review; platform,
# HTTP, database and binding implementations belong in adapter crates.
APPROVED_DOMAIN_DEPENDENCIES = frozenset({
    "base64", "rustls", "serde", "sha2", "x509-parser", "zeroize",
})


def violations(manifest: dict, workspace: dict) -> list[str]:
    inherited = workspace.get("workspace", {}).get("dependencies", {})
    sections = [("dependencies", manifest.get("dependencies", {}))]
    for name, configuration in manifest.get("target", {}).items():
        sections.append((f"target.{name}.dependencies", configuration.get("dependencies", {})))
    failures = []
    for section, dependencies in sections:
        for name, declaration in dependencies.items():
            if isinstance(declaration, dict) and declaration.get("workspace") is True:
                if name not in inherited:
                    failures.append(f"{section}:{name}:unresolved_workspace_dependency")
                    continue
                declaration = inherited[name]
            if isinstance(declaration, str):
                options = {}
            elif isinstance(declaration, dict):
                options = declaration
            else:
                failures.append(f"{section}:{name}:invalid_dependency")
                continue
            package = options.get("package", name)
            if package not in APPROVED_DOMAIN_DEPENDENCIES or "path" in options or "git" in options:
                failures.append(f"{section}:{name}:unapproved_domain_dependency")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args()
    try:
        with (arguments.root / "loft-core-rust/Cargo.toml").open("rb") as stream:
            workspace = tomllib.load(stream)
        with (arguments.root / "loft-core-rust/crates/loft-core/Cargo.toml").open("rb") as stream:
            core = tomllib.load(stream)
        failures = violations(core, workspace)
    except (OSError, ValueError, TypeError, AttributeError):
        print(json.dumps({"result": "ERROR", "error_code": "manifest_unavailable_or_invalid"}))
        return 2
    print(json.dumps({"result": "FAIL" if failures else "PASS", "scope": "loft-core_direct_production_dependencies", "violations": failures}, indent=2))
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
