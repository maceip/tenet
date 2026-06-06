from por.provider import ProviderError, provider_mode, stream_expert_reply, stream_frontier_reply


def test_harness_expert_reply_default():
    from por.envelope import PromptRequestEnvelope

    envelope = PromptRequestEnvelope.visible_prompt(
        prompt="What is impressionism?",
        selected_peer_id="expert_art",
        requested_expertise="art",
    )
    text = "".join(stream_expert_reply(envelope, "expert_art"))
    assert "[wire-harness expert_reply]" in text
    assert "llm_called=no" in text


def test_harness_frontier_reply_default():
    text = "".join(stream_frontier_reply("Explain basalt", reason="no match"))
    assert "[wire-harness frontier_fallback]" in text
    assert "expert_used=no" in text


def test_provider_mode_defaults_to_harness():
    assert provider_mode() == "harness"


def test_provider_error_fields():
    err = ProviderError("boom", status=503, retryable=True)
    assert err.status == 503
    assert err.retryable is True
