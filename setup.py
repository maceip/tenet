"""Minimal setuptools shim for legacy callers and editable builds.

All package metadata, dependencies, entry points, and package discovery
are declared in pyproject.toml (PEP 621). This file exists only so that
"python setup.py ..." or very old tooling still works; modern uv/pip/build
front-ends use the pyproject.toml build backend exclusively.
"""
from setuptools import setup

if __name__ == "__main__":
    setup()
