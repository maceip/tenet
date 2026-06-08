#!/usr/bin/env python3
"""Build a tiny offline ``tenet-web`` binary for the website xterm demo.

No mixnet, QUIC, attestation, or live network code — only the local HTTP/SSE
bridge and canned Berlin replay.
"""

from __future__ import annotations

import argparse
import platform
import subprocess
import sys
from pathlib import Path

PYINSTALLER_VERSION = "6.20.0"

_EXCLUDES = (
    "aioquic",
    "pqcrypto",
    "nacl",
    "cryptography",
    "httpx",
    "anthropic",
    "openai",
    "tenet.experts.live_client",
    "tenet.experts.live_enclave",
    "tenet.mixnet",
    "tenet.packet",
)


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--name",
        default=f"tenet-web-{_platform_tag()}",
        help="Output executable name under dist/.",
    )
    parser.add_argument(
        "--venv",
        default=str(root / "build" / "pyinstaller-web-venv"),
        help="Build virtualenv path.",
    )
    parser.add_argument("--skip-install", action="store_true")
    args = parser.parse_args(argv)

    venv = Path(args.venv)
    python = venv / ("Scripts/python.exe" if platform.system() == "Windows" else "bin/python")
    if not args.skip_install:
        if not python.exists():
            subprocess.check_call([sys.executable, "-m", "venv", str(venv)], cwd=root)
        subprocess.check_call([str(python), "-m", "pip", "install", "--upgrade", "pip"], cwd=root)
        subprocess.check_call(
            [str(python), "-m", "pip", "install", "-e", ".", f"pyinstaller=={PYINSTALLER_VERSION}"],
            cwd=root,
        )

    pyinstaller = venv / ("Scripts/pyinstaller.exe" if platform.system() == "Windows" else "bin/pyinstaller")
    build_dir = root / "build" / "pyinstaller-web"
    spec_dir = root / "build" / "pyinstaller-web-spec"
    dist_dir = root / "dist"
    spec_dir.mkdir(parents=True, exist_ok=True)
    dist_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(pyinstaller),
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name",
        args.name,
        "--distpath",
        str(dist_dir),
        "--workpath",
        str(build_dir),
        "--specpath",
        str(spec_dir),
        "--paths",
        str(root),
        "--hidden-import",
        "tenet.edges.cli.serve",
        "--hidden-import",
        "tenet.edges.cli.web_demo",
        "--hidden-import",
        "tenet.edges.cli.http_cors",
    ]
    for module in _EXCLUDES:
        cmd.extend(["--exclude-module", module])
    cmd.append(str(root / "scripts" / "entry_web_demo.py"))

    subprocess.check_call(cmd, cwd=root)
    artifact = dist_dir / _binary_filename(args.name)
    if not artifact.exists():
        raise SystemExit(f"expected artifact was not created: {artifact}")
    subprocess.check_call([str(artifact), "--help"], cwd=root)
    # Quick offline serve smoke (healthz + one POST) on ephemeral port.
    import json
    import socket
    import subprocess as sp
    import time
    import urllib.request

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = sp.Popen([str(artifact), "--port", str(port)], cwd=root)
    try:
        for _ in range(30):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=0.5) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
                    if body.get("mode") == "tenet-serve-offline":
                        break
            except OSError:
                time.sleep(0.1)
        else:
            raise SystemExit("tenet-web smoke: healthz never became ready")
    finally:
        proc.terminate()
        proc.wait(timeout=5)
    print(f"Built {artifact}")
    return 0


def _platform_tag() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "darwin":
        return "macos-arm64" if machine == "arm64" else f"macos-{machine}"
    if system == "linux":
        return f"linux-{machine}"
    if system == "windows":
        return f"windows-{machine}"
    return f"{system}-{machine}"


def _binary_filename(name: str) -> str:
    return f"{name}.exe" if platform.system() == "Windows" else name


if __name__ == "__main__":
    raise SystemExit(main())
