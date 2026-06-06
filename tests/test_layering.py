"""Architecture enforced as a test, not a document.

Dependencies point DOWN only. Each module's layer is its folder; a module may
import its own layer or lower, never higher. The substrate (packet, base,
mixnet, enclave) can never import a capability or edge.

This is the rule that would have caught the p2p-search work that assumed it
could connect to an expert directly: connectivity goes over the mixnet, so a
capability holds an opaque handle, not a peer id. The folder a contributor drops
their module into *is* its layer, and CI checks the import direction.

ALLOWLIST is current debt — empty means the layering is clean.
"""

from __future__ import annotations

import ast
import pathlib

TENET = pathlib.Path(__file__).resolve().parent.parent / "tenet"

# Layer order: a module may import layers <= its own.
PACKET, BASE, MIXNET, ENCLAVE, CAPABILITY, EDGE = 0, 1, 2, 3, 4, 5
BASE_MODULES = {"config", "log_events", "envelope", "handles"}  # tenet/<name>.py


def _layer_of_module(dotted: str) -> int | None:
    """Layer for a tenet.* dotted module path (None if not a tenet module)."""
    parts = dotted.split(".")
    if not parts or parts[0] != "tenet" or len(parts) < 2:
        return None
    top = parts[1]
    if top == "packet":
        return PACKET
    if top == "mixnet":
        return MIXNET
    if top == "enclave":
        return ENCLAVE
    if top == "edges":
        return EDGE
    if len(parts) == 2:  # tenet.<leaf> — a base/shared module at the root
        return BASE
    # any other subpackage (experts, llm, and future search/payment/...) is a capability
    return CAPABILITY


def _layer_of_path(path: pathlib.Path) -> int | None:
    rel = path.relative_to(TENET)
    parts = rel.with_suffix("").parts
    if len(parts) == 1:  # tenet/<name>.py
        return BASE if parts[0] in BASE_MODULES else None
    return _layer_of_module("tenet." + ".".join(parts))


def _imported_tenet_modules(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            if node.module.startswith("tenet"):
                out.add(node.module)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("tenet"):
                    out.add(alias.name)
    return out


LAYER_NAMES = {0: "packet", 1: "base", 2: "mixnet", 3: "enclave", 4: "capability", 5: "edge"}

# Upward edges still present. Empty == clean. Add (importer_module, imported_module).
ALLOWLIST: set[tuple[str, str]] = set()


def test_dependencies_point_down_only():
    violations: set[tuple[str, str]] = set()
    for path in TENET.rglob("*.py"):
        if path.name == "__init__.py" or path.name == "__main__.py":
            continue
        own = _layer_of_path(path)
        if own is None:
            continue
        importer = "tenet." + ".".join(path.relative_to(TENET).with_suffix("").parts)
        for imported in _imported_tenet_modules(path):
            target = _layer_of_module(imported)
            if target is not None and target > own:
                violations.add((importer, imported))

    unexpected = violations - ALLOWLIST
    stale = ALLOWLIST - violations
    assert not unexpected, (
        "upward import(s) — a module imported a higher layer. The substrate must "
        f"never depend on a capability/edge: {sorted(unexpected)}"
    )
    assert not stale, f"allowlist entries no longer exist — delete them: {sorted(stale)}"


# Only these capability/edge modules may touch mixnet connectivity internals.
# This is the search-dev tripwire: a capability holds an opaque HANDLE and routes
# through the client send path (tenet.experts.client) — it never reaches raw
# transport/peer-addressing. The list is the send-path + daemon owners; a NEW
# entry is a red flag (route through tenet.experts.client instead). The p2p-search
# work that assumed it could connect to an expert directly would fail here on day
# one rather than after days of code.
SANCTIONED_MIXNET_USERS = {
    "tenet.experts.client",        # the client send path
    "tenet.experts.matcher",       # resolves handles -> sealed routes
    "tenet.experts.gate_b_nodes",  # topology/relay ops
    "tenet.edges.cli.expert",      # runs an expert mixnet node
    "tenet.edges.cli.relay",       # runs a relay mixnet node
    "tenet.edges.cli.supernode",   # runs a reachability-relay node
}


def test_only_sanctioned_modules_touch_mixnet_internals():
    violations: set[tuple[str, str]] = set()
    for path in TENET.rglob("*.py"):
        if path.name == "__main__.py":
            continue
        if _layer_of_path(path) not in {CAPABILITY, EDGE}:
            continue  # substrate touching mixnet is fine; down-only covers it
        importer = "tenet." + ".".join(path.relative_to(TENET).with_suffix("").parts)
        if importer in SANCTIONED_MIXNET_USERS:
            continue
        for imported in _imported_tenet_modules(path):
            if imported.startswith("tenet.mixnet"):
                violations.add((importer, imported))
    assert not violations, (
        "a capability/edge reached into mixnet internals. Connectivity goes over "
        "the mixnet via opaque handles — route through tenet.experts.client, do "
        "not hold peer ids or open raw transport. (If it genuinely owns transport, "
        f"add it to SANCTIONED_MIXNET_USERS.) Offenders: {sorted(violations)}"
    )
