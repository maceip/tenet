from __future__ import annotations

from tenet.edges.cli.web_demo import offline_ask_summary, stream_offline_ask


def test_offline_berlin_prompt():
    result = offline_ask_summary("find me an airbnb in berlin")
    assert result["ok"] is True
    assert result["offline"] is True
    assert "Neukölln" in str(result["response_text"])


def test_offline_generic_prompt():
    result = offline_ask_summary("what is the weather")
    assert result["ok"] is True
    assert "offline demo" in str(result["response_text"]).lower()


def test_stream_offline_emits_done():
    events: list[tuple[str, dict[str, object]]] = []

    def write(event: str, data: dict[str, object]) -> None:
        events.append((event, data))

    stream_offline_ask(
        "find me an airbnb in berlin",
        write=write,
        pause=lambda _s: None,
    )
    kinds = [event for event, _data in events]
    assert "status" in kinds
    assert "chunk" in kinds
    assert kinds[-1] == "done"
