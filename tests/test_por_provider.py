import pytest

from tenet.config import ProviderConfig
from tenet.llm.provider import ProviderError, provider_mode, stream_expert_reply, stream_frontier_reply


def test_provider_mode_requires_real_provider(monkeypatch):
    monkeypatch.delenv("POR_PROVIDER", raising=False)

    try:
        provider_mode()
    except ProviderError as exc:
        assert "POR_PROVIDER or daemon.provider is required" in str(exc)
    else:
        raise AssertionError("missing provider must not synthesize a response")


def test_provider_mode_rejects_removed_harness_provider():
    with pytest.raises(ValueError, match="unsupported provider"):
        ProviderConfig(provider="harness")


def test_provider_mode_uses_daemon_provider_config():
    config = ProviderConfig(provider="openai", model="gpt-test", api_key_env="OPENAI_API_KEY")

    assert provider_mode(config) == "openai"


def test_configured_real_provider_does_not_synthesize_reply(monkeypatch):
    from tenet.envelope import PromptRequestEnvelope

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    config = ProviderConfig(provider="openai", model="gpt-test", api_key_env="OPENAI_API_KEY")
    envelope = PromptRequestEnvelope.visible_prompt(
        prompt="What is impressionism?",
        selected_peer_id="expert_art",
        requested_expertise="art",
    )

    try:
        "".join(stream_expert_reply(envelope, "expert_art", config))
    except ProviderError as exc:
        assert "OPENAI_API_KEY" in str(exc)
    else:
        raise AssertionError("configured real provider must not synthesize a reply")


def test_frontier_reply_requires_real_provider(monkeypatch):
    monkeypatch.delenv("POR_PROVIDER", raising=False)

    try:
        "".join(stream_frontier_reply("Explain basalt", reason="no match"))
    except ProviderError as exc:
        assert "POR_PROVIDER or daemon.provider is required" in str(exc)
    else:
        raise AssertionError("frontier fallback must not synthesize an answer")


def test_provider_error_fields():
    err = ProviderError("boom", status=503, retryable=True)
    assert err.status == 503
    assert err.retryable is True
