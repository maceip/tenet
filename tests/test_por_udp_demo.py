import pytest

from por.udp_demo import run_demo
from tests.helpers import has_log_event, parse_json_log_events


@pytest.mark.integration
@pytest.mark.product
def test_udp_demo_expert_mode_streams_over_process_nodes():
    result = run_demo(timeout=8.0)

    assert result.selected_peer_id == "expert_art"
    assert result.degraded_anonymity is True
    assert result.fallback_used is False
    assert "[wire-harness expert_reply]" in result.response_text
    assert "llm_called=no" in result.response_text
    events = parse_json_log_events(result.node_logs)
    assert has_log_event(events, "forward_hop")
    assert has_log_event(events, "expert_exit")
    assert has_log_event(events, "forward_hop", field="prompt_visible", value=False)
    assert has_log_event(events, "expert_exit", field="prompt_visible", value=True)
    assert has_log_event(events, "circuit_hop")
    assert "event=stream_chunk" in result.client_logs
