"""Shared fixtures for tenet integration tests."""

from __future__ import annotations

import os

import pytest

from tests.helpers import write_wire_cluster


@pytest.fixture
def wire_cluster_factory(tmp_path):
    def _factory(*node_ids: str, payload_size: int = 2048):
        return write_wire_cluster(tmp_path, node_ids=node_ids, payload_size=payload_size)

    return _factory


def pytest_addoption(parser):
    parser.addoption(
        "--run-live",
        action="store_true",
        default=False,
        help="run tests marked live (production attested matcher)",
    )


def pytest_configure(config):
    if config.getoption("--run-live") or os.environ.get("TENET_RUN_LIVE"):
        config.option.markexpr = "live"


def pytest_collection_modifyitems(config, items):
    crypto_modules = {"test_outfox.py", "test_mixnet.py", "test_scherer2023_fixes.py"}
    for item in items:
        if item.path.name in crypto_modules:
            item.add_marker(pytest.mark.crypto)
