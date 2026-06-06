"""Versioned Layer 7 request envelopes for tenet.

The envelope is the payload delivered to the selected expert/exit peer. Relays
carry it as opaque bytes. Future prompt-hiding or proof-of-execution work should
change this envelope payload mode, not the relay packet format.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from hashlib import sha256
from typing import Sequence
from uuid import uuid4


APP_ENVELOPE_VERSION = "por.app.v1"
VISIBLE_PROMPT_V1 = "visible_prompt_v1"
CONFIDENTIAL_PROMPT_V1 = "confidential_prompt_v1"
HYBRID_RETURN_PATH_V2 = "hybrid_return_path_v2"
PROOF_NONE = "none"


def _default_streaming_return_descriptor() -> dict[str, object]:
    from tenet.packet.ta_claims import streaming_return_descriptor

    return streaming_return_descriptor(mode=HYBRID_RETURN_PATH_V2)


@dataclass(frozen=True)
class PromptRequestEnvelope:
    version: str
    request_id: str
    selected_peer_id: str | None
    mode: str
    provider_request: dict[str, object]
    intent_descriptor: dict[str, object]
    prompt_payload: dict[str, object]
    return_descriptor: dict[str, object]
    proof_requirements: tuple[str, ...] = (PROOF_NONE,)
    client_extensions: tuple[str, ...] = field(default_factory=tuple)
    privacy_warnings: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def visible_prompt(
        cls,
        prompt: str,
        selected_peer_id: str | None,
        requested_expertise: str | None = None,
        provider_request: dict[str, object] | None = None,
        return_descriptor: dict[str, object] | None = None,
        proof_requirements: Sequence[str] = (PROOF_NONE,),
        client_extensions: Sequence[str] = (),
        privacy_warnings: Sequence[str] = (),
        request_id: str | None = None,
        extra_intent: dict[str, object] | None = None,
    ) -> "PromptRequestEnvelope":
        intent = {
            "requested_expertise": requested_expertise,
            "prompt_sha256": sha256(prompt.encode("utf-8")).hexdigest(),
        }
        if extra_intent:
            intent.update(extra_intent)

        return cls(
            version=APP_ENVELOPE_VERSION,
            request_id=request_id or uuid4().hex,
            selected_peer_id=selected_peer_id,
            mode=VISIBLE_PROMPT_V1,
            provider_request=provider_request or {"provider": "frontier", "stream": True},
            intent_descriptor=intent,
            prompt_payload={
                "content_type": "text/plain",
                "encoding": "utf-8",
                "text": prompt,
            },
            return_descriptor=return_descriptor or _default_streaming_return_descriptor(),
            proof_requirements=tuple(proof_requirements),
            client_extensions=tuple(client_extensions),
            privacy_warnings=tuple(privacy_warnings),
        )

    def to_json(self) -> str:
        self.validate()
        raw = asdict(self)
        raw["intent_descriptor"] = {
            key: value
            for key, value in raw["intent_descriptor"].items()
            if value is not None and key != "prompt_sha256"
        }
        raw["prompt_payload"] = {
            key: value
            for key, value in raw["prompt_payload"].items()
            if key not in {"content_type", "encoding"}
        }
        if tuple(raw.get("proof_requirements") or ()) == (PROOF_NONE,):
            raw.pop("proof_requirements", None)
        raw.pop("client_extensions", None)
        if not raw.get("privacy_warnings"):
            raw.pop("privacy_warnings", None)
        return json.dumps(raw, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, data: str | bytes) -> "PromptRequestEnvelope":
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        raw = json.loads(data)
        envelope = cls(
            version=raw["version"],
            request_id=raw["request_id"],
            selected_peer_id=raw.get("selected_peer_id"),
            mode=raw["mode"],
            provider_request=dict(raw["provider_request"]),
            intent_descriptor=dict(raw["intent_descriptor"]),
            prompt_payload=dict(raw["prompt_payload"]),
            return_descriptor=dict(raw["return_descriptor"]),
            proof_requirements=tuple(raw.get("proof_requirements", (PROOF_NONE,))),
            client_extensions=tuple(raw.get("client_extensions", ())),
            privacy_warnings=tuple(raw.get("privacy_warnings", ())),
        )
        envelope.validate()
        return envelope

    def prompt_text(self) -> str:
        if self.mode != VISIBLE_PROMPT_V1:
            raise ValueError("prompt text is not available for confidential envelopes")
        text = self.prompt_payload.get("text")
        if not isinstance(text, str):
            raise ValueError("visible prompt envelope is missing text")
        return text

    def validate(self) -> None:
        if self.version != APP_ENVELOPE_VERSION:
            raise ValueError(f"unsupported envelope version: {self.version}")
        if self.mode not in {VISIBLE_PROMPT_V1, CONFIDENTIAL_PROMPT_V1}:
            raise ValueError(f"unsupported prompt mode: {self.mode}")
        if not self.request_id:
            raise ValueError("request_id is required")
        if "mode" not in self.return_descriptor:
            raise ValueError("return_descriptor.mode is required")
        if self.return_descriptor.get("stream") and "ta_claim" not in self.return_descriptor:
            raise ValueError(
                "streaming return_descriptor requires ta_claim (TA-3); "
                "use tenet.packet.ta_claims.streaming_return_descriptor()"
            )
        if self.mode == VISIBLE_PROMPT_V1 and "text" not in self.prompt_payload:
            raise ValueError("visible prompt envelope requires prompt_payload.text")
