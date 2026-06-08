"""Build identity, baked at release time.

These defaults are for source / dev runs. ``scripts/build_binary.py`` overwrites
this file with real values during a CI build so the frozen binary knows its own
version + build_ref (git tag + CI run) — the transparency stamp behind an
"update available" notice. See ``tenet/trust_gate.py``.
"""

VERSION = "0.1.0"
BUILD_REF = "dev"
BUILD_TIME = ""
