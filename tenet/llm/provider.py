"""Expert and frontier provider replies for production exits."""

from __future__ import annotations

import json
import os
from typing import Iterator, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from tenet.config import ProviderConfig
from tenet.envelope import PromptRequestEnvelope


SUPPORTED_PROVIDERS = frozenset({"anthropic", "openai"})


class ProviderError(RuntimeError):
    """Raised when an upstream LLM/provider call fails."""

    def __init__(self, message: str, *, status: int | None = None, retryable: bool = False):
        super().__init__(message)
        self.status = status
        self.retryable = retryable


def provider_mode(provider_config: ProviderConfig | None = None) -> str:
    if provider_config is not None:
        mode = provider_config.provider.strip().lower()
    else:
        mode = os.environ.get("POR_PROVIDER", "").strip().lower()
    if not mode:
        raise ProviderError("POR_PROVIDER or daemon.provider is required")
    if mode not in SUPPORTED_PROVIDERS:
        raise ProviderError(f"unsupported provider: {mode!r}")
    return mode


def stream_expert_reply(
    envelope: PromptRequestEnvelope,
    peer_id: str,
    provider_config: ProviderConfig | None = None,
) -> Iterator[str]:
    prompt = envelope.prompt_text()
    mode = provider_mode(provider_config)
    if mode == "anthropic":
        yield from _anthropic_reply(
            prompt,
            system=_expert_system(peer_id, envelope),
            provider_config=provider_config,
        )
        return
    if mode == "openai":
        yield from _openai_reply(
            prompt,
            system=_expert_system(peer_id, envelope),
            provider_config=provider_config,
        )
        return
    raise ProviderError(f"unsupported provider: {mode!r}")


def stream_frontier_reply(
    prompt: str,
    reason: str | None = None,
    provider_config: ProviderConfig | None = None,
) -> Iterator[str]:
    mode = provider_mode(provider_config)
    if mode == "anthropic":
        yield from _anthropic_reply(
            prompt,
            system="You are a general-purpose assistant. Answer clearly and concisely.",
            provider_config=provider_config,
        )
        return
    if mode == "openai":
        yield from _openai_reply(
            prompt,
            system="You are a general-purpose assistant. Answer clearly and concisely.",
            provider_config=provider_config,
        )
        return
    raise ProviderError(f"unsupported provider: {mode!r}")


def expert_reply_chunks(
    envelope: PromptRequestEnvelope,
    peer_id: str,
    *,
    chunk_size: int = 256,
    provider_config: ProviderConfig | None = None,
) -> Sequence[str]:
    text = "".join(stream_expert_reply(envelope, peer_id, provider_config))
    if not text:
        return [""]
    return [text[i : i + chunk_size] for i in range(0, len(text), chunk_size)]


def make_reply_handler(provider_config: ProviderConfig | None = None):
    """Build a node-runtime ``ReplyHandler`` backed by this provider (Seam A).

    The substrate (``tenet.mixnet.node_runtime``) accepts an injected handler so it never
    imports the LLM. Capabilities/edges that run an expert call this to wire the
    provider in.
    """

    def handler(envelope: PromptRequestEnvelope, peer_id: str) -> Sequence[str]:
        return expert_reply_chunks(envelope, peer_id, provider_config=provider_config)

    return handler


def _expert_system(peer_id: str, envelope: PromptRequestEnvelope) -> str:
    expertise = envelope.intent_descriptor.get("requested_expertise") or "general"
    return (
        f"You are expert peer {peer_id} specializing in {expertise}. "
        "Answer using domain-specific detail."
    )


def _anthropic_reply(
    prompt: str,
    *,
    system: str,
    provider_config: ProviderConfig | None = None,
) -> Iterator[str]:
    api_key = _api_key(provider_config, "ANTHROPIC_API_KEY")
    if not api_key:
        env_name = provider_config.api_key_env if provider_config else "ANTHROPIC_API_KEY"
        raise ProviderError(f"{env_name} is required for provider=anthropic")
    model = provider_config.model if provider_config and provider_config.model else os.environ.get(
        "POR_ANTHROPIC_MODEL",
        "claude-sonnet-4-6",
    )
    body = json.dumps(
        {
            "model": model,
            "max_tokens": int(os.environ.get("POR_MAX_TOKENS", "1024")),
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
    ).encode("utf-8")
    req = Request(
        _provider_url(provider_config, "https://api.anthropic.com/v1/messages", "/v1/messages"),
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
    )
    try:
        with urlopen(req, timeout=_provider_timeout(provider_config)) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        raise ProviderError(
            f"anthropic HTTP {exc.code}",
            status=exc.code,
            retryable=exc.code in {429, 500, 502, 503, 504},
        ) from exc
    except URLError as exc:
        raise ProviderError(f"anthropic network error: {exc.reason}", retryable=True) from exc

    parts = []
    for block in payload.get("content", []):
        if block.get("type") == "text" and isinstance(block.get("text"), str):
            parts.append(block["text"])
    text = "".join(parts).strip()
    if not text:
        raise ProviderError("anthropic returned empty content")
    yield text


def _openai_reply(
    prompt: str,
    *,
    system: str,
    provider_config: ProviderConfig | None = None,
) -> Iterator[str]:
    api_key = _api_key(provider_config, "OPENAI_API_KEY")
    if not api_key:
        env_name = provider_config.api_key_env if provider_config else "OPENAI_API_KEY"
        raise ProviderError(f"{env_name} is required for provider=openai")
    model = provider_config.model if provider_config and provider_config.model else os.environ.get(
        "POR_OPENAI_MODEL",
        "gpt-4o-mini",
    )
    body = json.dumps(
        {
            "model": model,
            "max_tokens": int(os.environ.get("POR_MAX_TOKENS", "1024")),
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        }
    ).encode("utf-8")
    req = Request(
        _provider_url(
            provider_config,
            "https://api.openai.com/v1/chat/completions",
            "/v1/chat/completions",
        ),
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    try:
        with urlopen(req, timeout=_provider_timeout(provider_config)) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        raise ProviderError(
            f"openai HTTP {exc.code}",
            status=exc.code,
            retryable=exc.code in {429, 500, 502, 503, 504},
        ) from exc
    except URLError as exc:
        raise ProviderError(f"openai network error: {exc.reason}", retryable=True) from exc

    choices = payload.get("choices") or []
    if not choices:
        raise ProviderError("openai returned no choices")
    message = choices[0].get("message") or {}
    text = message.get("content")
    if not isinstance(text, str) or not text.strip():
        raise ProviderError("openai returned empty content")
    yield text.strip()


def _api_key(provider_config: ProviderConfig | None, default_env: str) -> str:
    if provider_config is not None:
        if provider_config.api_key_env:
            return (provider_config.resolve_api_key() or "").strip()
        return os.environ.get(default_env, "").strip()
    return os.environ.get(default_env, "").strip()


def _provider_timeout(provider_config: ProviderConfig | None) -> float:
    if provider_config is not None:
        return provider_config.timeout_seconds
    return float(os.environ.get("POR_PROVIDER_TIMEOUT", "120"))


def _provider_url(
    provider_config: ProviderConfig | None,
    default_url: str,
    default_path: str,
) -> str:
    if provider_config is None or not provider_config.base_url:
        return default_url
    base = provider_config.base_url.rstrip("/")
    if base.endswith(default_path):
        return base
    return f"{base}{default_path}"
