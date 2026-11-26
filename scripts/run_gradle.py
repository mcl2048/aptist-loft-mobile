"""Run pinned Gradle with task-local Java proxy settings, never global config."""
import ipaddress
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import urlsplit


def proxy_properties(environment: dict[str, str]) -> list[str]:
    raw = environment.get("HTTPS_PROXY") or environment.get("https_proxy") or environment.get("HTTP_PROXY") or environment.get("http_proxy")
    if not raw:
        return []
    try:
        parsed = urlsplit(raw)
        if parsed.scheme != "http" or parsed.username is not None or parsed.password is not None:
            raise ValueError
        host = parsed.hostname
        port = parsed.port or 80
        if not host or parsed.path not in ("", "/") or parsed.query or parsed.fragment or not 1 <= port <= 65535:
            raise ValueError
        if ":" in host:
            ipaddress.IPv6Address(host)
        elif re.fullmatch(r"[A-Za-z0-9._-]+", host) is None:
            raise ValueError
    except ValueError:
        # Do not echo proxy URLs: they can contain real authentication material.
        raise ValueError("Proxy must be a valid credential-free HTTP CONNECT address") from None
    return [
        f"-Dhttp.proxyHost={host}", f"-Dhttp.proxyPort={port}",
        f"-Dhttps.proxyHost={host}", f"-Dhttps.proxyPort={port}",
        "-Dhttp.nonProxyHosts=localhost|127.*|[::1]",
    ]


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    executable = Path(os.environ.get("LOFT_GRADLE_BIN", str(Path.home() / ".local/share/loft-mobile/gradle-8.13/bin/gradle")))
    if not executable.is_file():
        print("Pinned Gradle is missing; follow docs/build.md.", file=sys.stderr)
        return 2
    environment = os.environ.copy()
    environment.setdefault("JAVA_HOME", "/usr/lib/jvm/java-21-openjdk-amd64")
    try:
        properties = proxy_properties(environment)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    # Argument arrays, no eval/shell interpolation or credential-bearing output.
    return subprocess.run([str(executable), *properties, *sys.argv[1:]], cwd=root, env=environment, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
