"""Expert and frontier provider replies for production exits."""

from __future__ import annotations

import json
import os
from typing import Iterator, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .envelope import PromptRequestEnvelope


class ProviderError(RuntimeError):
    """Raised when an upstream LLM/provider call fails."""

    def __init__(self, message: str, *, status: int | None = None, retryable: bool = False):
        super().__init__(message)
        self.status = status
        self.retryable = retryable


def provider_mode() -> str:
    return os.environ.get("POR_PROVIDER", "harness").strip().lower() or "harness"


def stream_expert_reply(
    envelope: PromptRequestEnvelope,
    peer_id: str,
) -> Iterator[str]:
    prompt = envelope.prompt_text()
    expertise = envelope.intent_descriptor.get("requested_expertise") or "auto"
    mode = provider_mode()
    if mode == "harness":
        yield _harness_expert_reply(peer_id, prompt, expertise)
        return
    if mode == "anthropic":
        yield from _anthropic_reply(prompt, system=_expert_system(peer_id, envelope))
        return
    if mode == "openai":
        yield from _openai_reply(prompt, system=_expert_system(peer_id, envelope))
        return
    raise ProviderError(f"unsupported POR_PROVIDER: {mode!r}")


def stream_frontier_reply(prompt: str, reason: str | None = None) -> Iterator[str]:
    mode = provider_mode()
    if mode == "harness":
        yield _harness_frontier_reply(prompt, reason)
        return
    if mode == "anthropic":
        yield from _anthropic_reply(
            prompt,
            system="You are a general-purpose assistant. Answer clearly and concisely.",
        )
        return
    if mode == "openai":
        yield from _openai_reply(
            prompt,
            system="You are a general-purpose assistant. Answer clearly and concisely.",
        )
        return
    raise ProviderError(f"unsupported POR_PROVIDER: {mode!r}")


def expert_reply_chunks(
    envelope: PromptRequestEnvelope,
    peer_id: str,
    *,
    chunk_size: int = 256,
) -> Sequence[str]:
    text = "".join(stream_expert_reply(envelope, peer_id))
    if not text:
        return [""]
    return [text[i : i + chunk_size] for i in range(0, len(text), chunk_size)]


def _harness_expert_reply(peer_id: str, prompt: str, expertise: str) -> str:
    return (
        f"[wire-harness expert_reply] peer={peer_id} expertise={expertise!r} "
        f"prompt_len={len(prompt)} llm_called=no"
    )


def _harness_frontier_reply(prompt: str, reason: str | None) -> str:
    return (
        f"[wire-harness frontier_fallback] prompt_len={len(prompt)} "
        f"expert_used=no reason={reason or 'no expert selected'}"
    )


def _expert_system(peer_id: str, envelope: PromptRequestEnvelope) -> str:
    expertise = envelope.intent_descriptor.get("requested_expertise") or "general"
    return (
        f"You are expert peer {peer_id} specializing in {expertise}. "
        "Answer using domain-specific detail."
    )


def _anthropic_reply(prompt: str, *, system: str) -> Iterator[str]:
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        raise ProviderError("ANTHROPIC_API_KEY is required for POR_PROVIDER=anthropic")
    model = os.environ.get("POR_ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
    body = json.dumps(
        {
            "model": model,
            "max_tokens": int(os.environ.get("POR_MAX_TOKENS", "1024")),
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
    ).encode("utf-8")
    req = Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
    )
    try:
        with urlopen(req, timeout=float(os.environ.get("POR_PROVIDER_TIMEOUT", "120"))) as resp:
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


def _openai_reply(prompt: str, *, system: str) -> Iterator[str]:
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise ProviderError("OPENAI_API_KEY is required for POR_PROVIDER=openai")
    model = os.environ.get("POR_OPENAI_MODEL", "gpt-4o-mini")
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
        "https://api.openai.com/v1/chat/completions",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    try:
        with urlopen(req, timeout=float(os.environ.get("POR_PROVIDER_TIMEOUT", "120"))) as resp:
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
