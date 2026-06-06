"""Tests for config/live-enclave.json and loader (no network)."""

import json

import pytest

from tenet.experts.live_enclave import DEFAULT_CONFIG_PATH, LiveEnclaveConfig, build_attested_client


def test_default_live_enclave_config_loads():
    config = LiveEnclaveConfig.load()
    assert config.url.startswith("https://")
    assert len(config.approved_value_x) == 1
    assert len(config.approved_value_x[0]) == 96
    assert len(config.tls_spki_hash) == 64


def test_live_enclave_config_round_trip(tmp_path):
    raw = json.loads(DEFAULT_CONFIG_PATH.read_text(encoding="utf-8"))
    path = tmp_path / "live.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    loaded = LiveEnclaveConfig.load(path)
    assert loaded.url == str(raw["url"]).rstrip("/")


def test_build_attested_client_wires_policy():
    config = LiveEnclaveConfig.load()
    client = build_attested_client(config)
    assert client.base_url == config.url
    assert client._policy.require_spki_pin is True


def test_live_enclave_config_rejects_http(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(
        json.dumps(
            {
                "schema": "por.live_enclave.v1",
                "url": "http://127.0.0.1:8080/",
                "approved_value_x": ["a" * 96],
                "tls_spki_hash": "b" * 64,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="https"):
        LiveEnclaveConfig.load(path)
