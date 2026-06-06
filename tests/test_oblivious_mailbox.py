"""PlainMailbox.resolve_handle is access-pattern oblivious in the handle."""

from tenet.handles import OpaqueHandleIssuer
from tenet.experts.matcher import PlainMailbox


def _mailbox(n):
    issuer = OpaqueHandleIssuer(b"oblivious-mailbox-secret")
    records = [
        issuer.record(peer_id=f"peer-{i}", manifest_digest="d" * 64, mailbox_id="m")
        for i in range(n)
    ]
    box = PlainMailbox()
    for i, record in enumerate(records):
        box.add(
            record=record,
            routing_kem_pk_hex=f"{i:02x}" * 32,
            peer_address={"peer_id": record.handle, "slot": i},
        )
    return box, records


def _trace(box, handle):
    acc = []
    box.resolve_handle(handle, on_access=acc.append)
    return acc


def test_resolution_access_pattern_independent_of_handle():
    box, records = _mailbox(5)
    order = [r.handle for r in records]

    first = _trace(box, records[0].handle)
    last = _trace(box, records[4].handle)
    missing = _trace(box, "z" * 16)

    # every resolve scans all entries in the same fixed order, target or not
    assert first == last == missing == order


def test_resolution_is_still_correct():
    box, records = _mailbox(5)
    hit = box.resolve_handle(records[2].handle)
    assert hit is not None
    assert hit.routing_kem_pk_hex == f"{2:02x}" * 32
    assert hit.peer_address["slot"] == 2

    assert box.resolve_handle("z" * 16) is None
