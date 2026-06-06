"""Optional live attestation tests against the production Nitro matcher.

Skipped unless TENET_RUN_LIVE=1 or pytest --run-live (needs `aw` on PATH).
"""

import json
import os
import shutil

import pytest

from tenet.experts.live_enclave import DEFAULT_CONFIG_PATH, LiveEnclaveConfig, check_live_enclave, match_live_enclave

pytestmark = pytest.mark.live


@pytest.fixture(scope="module")
def live_config() -> LiveEnclaveConfig:
    path = os.environ.get("TENET_LIVE_ENCLAVE_CONFIG", str(DEFAULT_CONFIG_PATH))
    return LiveEnclaveConfig.load(path)


@pytest.fixture(scope="module")
def require_aw():
    if shutil.which("aw") is None:
        pytest.skip("aw not on PATH — run ./scripts/install-aw.sh")


def test_live_aw_check_json(live_config, require_aw):
    import subprocess

    proc = subprocess.run(
        ["aw", "check", "--json", live_config.url.rstrip("/")],
        capture_output=True,
        text=True,
        timeout=live_config.timeout,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    line = next(l for l in proc.stdout.splitlines() if l.strip().startswith("{"))
    payload = json.loads(line)
    assert payload.get("schema") == "runcard.check.v1"
    assert payload.get("value_x") in live_config.approved_value_x


def test_live_enclave_policy_check(live_config, require_aw):
    summary = check_live_enclave(live_config)
    assert summary["ok"] is True
    assert summary["tls_spki_hash"].lower() == live_config.tls_spki_hash.lower()


def test_live_enclave_match(live_config, require_aw):
    result = match_live_enclave(
        live_config,
        prompt="Tell me about Monet and impressionist painting.",
        max_records=4,
    )
    assert result["mode"]
    assert result["candidate_count"] >= 1


def test_live_enclave_expert_plan(live_config, require_aw):
    from tenet.experts.live_expert import plan_live_expert

    result = plan_live_expert(
        live_config,
        prompt="Explain Rust ownership and the borrow checker.",
    )
    assert result["ok"] is True
    assert result["discovery_mode"] == "plain_matcher_v1"


@pytest.mark.network_beta
def test_live_enclave_mailbox_send(live_config, require_aw):
    from tenet.experts.live_client import LiveMailboxClientConfig, send_live_enclave_summary

    mailbox = LiveMailboxClientConfig.load()
    result = send_live_enclave_summary(
        live_config,
        mailbox,
        prompt="Tell me about Monet and impressionist painting.",
    )
    assert result["ok"] is True
    assert result["via_mailbox"] is True
    assert "matched via live attested mailbox" in str(result["response_text"])
