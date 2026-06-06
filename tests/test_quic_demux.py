"""QUIC demux_datagram unit tests — no aioquic required."""

from tenet.mixnet.quic_transport import demux_datagram
from tenet.mixnet.reach_wire import REACH_REGISTER, REACH_HEARTBEAT


def test_reach_dispatched_to_on_reach():
    calls = []
    data = REACH_REGISTER + b'\x00' * 20
    demux_datagram(data, on_reach=lambda d: calls.append(("reach", d)))
    assert len(calls) == 1
    assert calls[0][0] == "reach"


def test_forward_dispatched_to_on_mix():
    calls = []
    data = b'\x00' + b'\x00' * 100
    demux_datagram(data, on_mix=lambda d: calls.append(("mix", d)))
    assert len(calls) == 1
    assert calls[0][0] == "mix"


def test_circuit_dispatched_to_on_mix():
    calls = []
    data = b'\x01' + b'\x00' * 50
    demux_datagram(data, on_mix=lambda d: calls.append(("mix", d)))
    assert len(calls) == 1


def test_shutdown_dispatched_to_on_mix():
    calls = []
    demux_datagram(b'\x02', on_mix=lambda d: calls.append(d))
    assert len(calls) == 1


def test_unknown_dispatched_to_on_opaque():
    calls = []
    data = b'\xff' + b'\x00' * 30
    demux_datagram(data, on_opaque=lambda d: calls.append(("opaque", d)))
    assert len(calls) == 1
    assert calls[0][0] == "opaque"


def test_no_handler_no_crash():
    demux_datagram(REACH_HEARTBEAT + b'\x00' * 20)
    demux_datagram(b'\x00' + b'\x00' * 50)
    demux_datagram(b'\xff' + b'\x00' * 10)


def test_reach_not_dispatched_to_mix():
    mix_calls = []
    reach_calls = []
    data = REACH_REGISTER + b'\x00' * 20
    demux_datagram(
        data,
        on_reach=lambda d: reach_calls.append(d),
        on_mix=lambda d: mix_calls.append(d),
    )
    assert len(reach_calls) == 1
    assert len(mix_calls) == 0


def test_outfox_not_dispatched_to_reach():
    reach_calls = []
    mix_calls = []
    demux_datagram(
        b'\x00' + b'\x00' * 100,
        on_reach=lambda d: reach_calls.append(d),
        on_mix=lambda d: mix_calls.append(d),
    )
    assert len(reach_calls) == 0
    assert len(mix_calls) == 1
