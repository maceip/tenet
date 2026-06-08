#!/usr/bin/env python3
"""Build the unified ``tenet`` CLI as a one-file platform binary.

The build is intentionally local-platform only: run this script once on macOS,
once on Linux, and once on Windows to produce the release artifacts for each
platform.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


PYINSTALLER_VERSION = "6.20.0"


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--name",
        default=f"tenet-{_platform_tag()}",
        help="Output executable name under dist/.",
    )
    parser.add_argument(
        "--venv",
        default=str(root / "build" / "pyinstaller-venv"),
        help="Build virtualenv path.",
    )
    parser.add_argument(
        "--pyinstaller-version",
        default=PYINSTALLER_VERSION,
        help="PyInstaller version to install into the build virtualenv.",
    )
    parser.add_argument(
        "--skip-install",
        action="store_true",
        help="Reuse the build virtualenv without installing/upgrading dependencies.",
    )
    parser.add_argument(
        "--no-smoke",
        action="store_true",
        help="Skip running the produced binary with --help.",
    )
    parser.add_argument(
        "--also-name",
        default="",
        help=(
            "Copy the built binary to dist/<also-name>. A bare prefix like "
            "'tenet' expands to tenet-<current-platform>."
        ),
    )
    parser.add_argument(
        "--aw-binary",
        default=os.environ.get("AW_BINARY", ""),
        help="Path to a platform-native aw executable to embed in the one-file binary.",
    )
    parser.add_argument(
        "--no-embed-aw",
        action="store_true",
        help="Do not embed aw; the produced binary will require aw on PATH.",
    )
    args = parser.parse_args(argv)

    venv = Path(args.venv)
    python = _venv_python(venv)
    if not args.skip_install:
        _ensure_venv(root, venv)
        _run(
            [str(python), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"],
            root,
        )
        _run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "-e",
                ".",
                f"pyinstaller=={args.pyinstaller_version}",
            ],
            root,
        )

    pyinstaller = _venv_bin(venv, "pyinstaller")
    if not pyinstaller.exists():
        raise SystemExit(f"missing PyInstaller at {pyinstaller}; rerun without --skip-install")

    # Bake build identity (version + build_ref) into the binary so it knows its
    # own release for the trust gate / "update available" notice. Restored after.
    buildinfo_path = root / "tenet" / "_buildinfo.py"
    buildinfo_backup = buildinfo_path.read_text(encoding="utf-8") if buildinfo_path.exists() else None
    _write_buildinfo(buildinfo_path, root)

    build_dir = root / "build" / "pyinstaller"
    spec_dir = root / "build" / "pyinstaller-spec"
    dist_dir = root / "dist"
    spec_dir.mkdir(parents=True, exist_ok=True)
    dist_dir.mkdir(parents=True, exist_ok=True)

    pyinstaller_cmd = [
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
        "--collect-submodules",
        "tenet",
    ]
    aw_binary = None if args.no_embed_aw else _resolve_aw_binary(args.aw_binary)
    if aw_binary is not None:
        pyinstaller_cmd.extend(
            ["--add-binary", f"{aw_binary}{_pyinstaller_pathsep()}tenet_embedded"]
        )
    else:
        print("warning: aw was not embedded; binary will require aw on PATH", file=sys.stderr)
    pyinstaller_cmd.append(str(root / "tenet" / "__main__.py"))
    try:
        _run(pyinstaller_cmd, root)
    finally:
        if buildinfo_backup is not None:
            buildinfo_path.write_text(buildinfo_backup, encoding="utf-8")

    artifact = dist_dir / _binary_filename(args.name)
    if not artifact.exists():
        raise SystemExit(f"expected artifact was not created: {artifact}")
    if not args.no_smoke:
        _run([str(artifact), "--help"], root)
    if args.also_name:
        alias_name = args.also_name
        if "-" not in alias_name:
            alias_name = f"{alias_name}-{_platform_tag()}"
        alias = dist_dir / _binary_filename(alias_name)
        shutil.copy2(artifact, alias)
        print(f"Also built {alias}")
    print(f"Built {artifact}")
    return 0


def _write_buildinfo(path: Path, root: Path) -> None:
    """Generate tenet/_buildinfo.py with the release version + build_ref.

    Values come from TENET_VERSION / TENET_BUILD_REF (CI sets them to the tag +
    run url), falling back to ``git describe`` for local builds.
    """
    import datetime

    version = os.environ.get("TENET_VERSION", "").strip()
    build_ref = os.environ.get("TENET_BUILD_REF", "").strip()
    if not version or not build_ref:
        try:
            desc = subprocess.run(
                ["git", "describe", "--tags", "--always", "--dirty"],
                cwd=str(root), capture_output=True, text=True, timeout=5,
            ).stdout.strip()
        except Exception:
            desc = ""
        version = version or desc or "0.1.0"
        build_ref = build_ref or desc or "local"
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    path.write_text(
        '"""Build identity (generated by scripts/build_binary.py at build time)."""\n\n'
        f"VERSION = {version!r}\n"
        f"BUILD_REF = {build_ref!r}\n"
        f"BUILD_TIME = {now!r}\n",
        encoding="utf-8",
    )


def _ensure_venv(root: Path, venv: Path) -> None:
    if _venv_python(venv).exists():
        return
    _run([sys.executable, "-m", "venv", str(venv)], root)


def _resolve_aw_binary(path: str) -> Path | None:
    candidates: list[Path] = []
    if path:
        candidates.append(Path(path).expanduser())
    found = shutil.which("aw")
    if found:
        candidates.append(Path(found))
    candidates.append(Path.home() / ".cargo" / "bin" / _binary_filename("aw"))
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    return None


def _pyinstaller_pathsep() -> str:
    return ";" if os.name == "nt" else ":"


def _run(cmd: list[str], cwd: Path) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=str(cwd), check=True)


def _platform_tag() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "darwin":
        system = "macos"
    elif system == "windows":
        system = "windows"
    elif system == "linux":
        system = "linux"
    machine = {
        "aarch64": "arm64",
        "arm64": "arm64",
        "x86_64": "x86_64",
        "amd64": "x86_64",
    }.get(machine, machine)
    return f"{system}-{machine}"


def _venv_bin(venv: Path, name: str) -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    scripts = "Scripts" if os.name == "nt" else "bin"
    return venv / scripts / f"{name}{suffix}"


def _venv_python(venv: Path) -> Path:
    return _venv_bin(venv, "python")


def _binary_filename(name: str) -> str:
    if platform.system().lower() == "windows" and not name.endswith(".exe"):
        return f"{name}.exe"
    return name


if __name__ == "__main__":
    raise SystemExit(main())
