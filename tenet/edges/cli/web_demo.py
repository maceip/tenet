"""Offline website demo — zero network imports, canned Berlin flow."""

from __future__ import annotations

import re
import time
from typing import Callable, Iterator

EventWriter = Callable[[str, dict[str, object]], None]


def offline_ask_summary(prompt: str, expertise: str | None = None) -> dict[str, object]:
    """Return the same shape as a live ask without touching the network."""
    if _matches_berlin_demo(prompt):
        return {
            "ok": True,
            "response_text": (
                "expert: listing A is Marzahn — 40 min out, recycled photos. classic scam. skip.\n"
                "expert: book listing B — Neukölln / Reuterkiez. that's where berlin actually lives.\n"
                "↳ switched pick: A → B\n"
                "decision made. you didn't have to."
            ),
            "selected_handle": "berlin.expert~tenet",
            "fallback_used": False,
            "degraded_anonymity": False,
            "offline": True,
        }
    return {
        "ok": True,
        "response_text": (
            "offline demo — networking disabled.\n"
            "try: find me an airbnb in berlin\n"
            "or run tenet serve (without --offline) for the live network."
        ),
        "selected_handle": "demo.expert~tenet",
        "fallback_used": False,
        "degraded_anonymity": False,
        "offline": True,
    }


def stream_offline_ask(
    prompt: str,
    *,
    expertise: str | None = None,
    write: EventWriter,
    pause: Callable[[float], None] = time.sleep,
) -> dict[str, object]:
    """Emit SSE-shaped events for the website xterm demo."""
    request_id = "offline"
    write("status", {"request_id": request_id, "text": "offline demo — network disabled"})
    pause(0.35)
    write("status", {"request_id": request_id, "text": "matching experts… (simulated)"})
    pause(0.45)

    if _matches_berlin_demo(prompt):
        write("status", {"request_id": request_id, "text": "3 candidates found. about to book the cheapest, 4.8★ …"})
        pause(0.5)
        write("status", {"request_id": request_id, "text": "HTTP 402 Payment Required · €0.05 EURD · algorand"})
        pause(0.4)
        write("status", {"request_id": request_id, "text": "✓ paid · tx 4F9A…21BC ↗"})
        pause(0.45)
        write("status", {"request_id": request_id, "text": "routing question over the mixnet → berlin local expert"})
        pause(0.55)

    result = offline_ask_summary(prompt, expertise)
    response_text = str(result["response_text"])
    for line in response_text.splitlines():
        write("chunk", {"request_id": request_id, "data": line})
        pause(0.22)

    write(
        "done",
        {
            "request_id": request_id,
            "ok": True,
            "response": response_text,
            "selected_handle": result.get("selected_handle"),
            "fallback_used": False,
            "degraded_anonymity": False,
            "offline": True,
        },
    )
    return result


def iter_offline_script(prompt: str) -> Iterator[tuple[str, str]]:
    """Plain (kind, text) lines for terminal replay tools."""
    yield "cmd", f"agent: {prompt.strip()}"
    if not _matches_berlin_demo(prompt):
        yield "dim", "offline demo — networking disabled"
        summary = offline_ask_summary(prompt)
        for line in str(summary["response_text"]).splitlines():
            yield "exp", line
        return
    yield "dim", "3 candidates found. about to book the cheapest, 4.8★ …"
    yield "dim", "consulting the tenet expert network before committing"
    yield "pay", "HTTP 402 Payment Required · €0.05 EURD · algorand"
    yield "ok", "✓ paid · tx 4F9A…21BC ↗"
    yield "dim", "routing question over the mixnet → berlin local expert"
    yield "exp", "expert: listing A is Marzahn — 40 min out, recycled photos. classic scam. skip."
    yield "exp", "expert: book listing B — Neukölln / Reuterkiez. that's where berlin actually lives."
    yield "sw", "↳ switched pick: A → B"
    yield "done", "decision made. you didn't have to."


def _matches_berlin_demo(prompt: str) -> bool:
    lower = prompt.lower()
    return bool(re.search(r"\b(berlin|airbnb)\b", lower))
