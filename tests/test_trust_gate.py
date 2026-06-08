"""Contract for the client trust gate (consume half of the trust-update rail)."""

from __future__ import annotations

import hashlib
import json
import time

from nacl.signing import SigningKey

from tenet.mixnet.control.descriptors import (
    SoftwareIdentityDescriptor,
    TrustUpdateDescriptor,
)
from tenet.mixnet.control.records import (
    RECORD_TYPE_SOFTWARE_IDENTITY,
    RECORD_TYPE_TRUST_UPDATE,
    ControlRecord,
    sign_control_record,
)
from tenet.trust_gate import (
    TRUST_BUNDLE_SCHEMA,
    UNKNOWN,
    UP_TO_DATE,
    UPDATE_AVAILABLE,
    evaluate,
    load_trust_state,
    self_code_hash,
)


# ---- pure evaluate() ----

def _tu(*hashes: str) -> TrustUpdateDescriptor:
    return TrustUpdateDescriptor(
        update_id="u1", issuer="join-pack-root", policy="release",
        approved_code_hashes=tuple(hashes),
    )


def test_up_to_date():
    st = evaluate("aa", _tu("aa", "bb"))
    assert st.state == UP_TO_DATE and st.ok


def test_update_available():
    latest = SoftwareIdentityDescriptor(identity_id="tenet", code_hash="bb", version="0.2.0")
    st = evaluate("aa", _tu("bb"), latest)
    assert st.state == UPDATE_AVAILABLE
    assert st.latest_version == "0.2.0"
    assert st.ok  # soft by default


def test_unknown_unrecognized_build():
    st = evaluate("aa", _tu("bb"))
    assert st.state == UNKNOWN


def test_unknown_when_no_approved_set():
    st = evaluate("aa", _tu())
    assert st.state == UNKNOWN


def test_required_blocks_when_not_up_to_date():
    st = evaluate("aa", _tu("bb"), required=True)
    assert st.state == UNKNOWN
    assert st.ok is False  # hard fail-closed


def test_required_ok_when_up_to_date():
    st = evaluate("aa", _tu("aa"), required=True)
    assert st.state == UP_TO_DATE and st.ok


def test_self_code_hash(tmp_path):
    f = tmp_path / "art.bin"
    f.write_bytes(b"hello tenet")
    assert self_code_hash(str(f)) == hashlib.sha256(b"hello tenet").hexdigest()
    assert self_code_hash(str(tmp_path / "missing")) == ""


# ---- signed-bundle round trip via load_trust_state ----

class _Roots:
    def __init__(self, roots, threshold=1):
        self.update_roots = roots
        self.threshold = threshold


class _Pack:
    def __init__(self, roots, threshold=1):
        self.control_bootstrap = _Roots(roots, threshold)
        self.trust_update_url = None


def _signed_bundle(tmp_path, *, approved, software=None, required=False, sign_key=None):
    sk = sign_key or SigningKey.generate()
    root_hex = sk.encode().hex()
    now = time.time()
    tu = _tu(*approved)
    rec = ControlRecord(
        network_id="default", key=tu.key, record_type=RECORD_TYPE_TRUST_UPDATE,
        seq=1, issued_at=now, expires_at=now + 3600, value=tu.to_dict(),
    )
    bundle = {
        "schema": TRUST_BUNDLE_SCHEMA,
        "required": required,
        "trust_update": sign_control_record(rec, signing_key_hex=root_hex, key_id="join-pack-root").to_dict(),
    }
    if software is not None:
        sid = SoftwareIdentityDescriptor(identity_id="tenet", code_hash=software[0], version=software[1])
        srec = ControlRecord(
            network_id="default", key=sid.key, record_type=RECORD_TYPE_SOFTWARE_IDENTITY,
            seq=1, issued_at=now, expires_at=now + 3600, value=sid.to_dict(),
        )
        bundle["software_identity"] = sign_control_record(
            srec, signing_key_hex=root_hex, key_id="join-pack-root").to_dict()
    path = tmp_path / "trust-update.json"
    path.write_text(json.dumps(bundle))
    return f"file://{path}", sk.verify_key.encode().hex()


def test_load_trust_state_roundtrip_up_to_date(tmp_path):
    url, verify_hex = _signed_bundle(tmp_path, approved=["deadbeef"])
    pack = _Pack({"join-pack-root": verify_hex})
    st = load_trust_state(pack, url=url, self_hash="deadbeef")
    assert st.state == UP_TO_DATE


def test_load_trust_state_update_available(tmp_path):
    url, verify_hex = _signed_bundle(
        tmp_path, approved=["newhash"], software=("newhash", "0.3.0"))
    pack = _Pack({"join-pack-root": verify_hex})
    st = load_trust_state(pack, url=url, self_hash="oldhash")
    assert st.state == UPDATE_AVAILABLE and st.latest_version == "0.3.0"


def test_load_trust_state_fails_closed_on_bad_signature(tmp_path):
    url, _verify_hex = _signed_bundle(tmp_path, approved=["deadbeef"])
    # Wrong root key in the pack -> signature must not verify -> UNKNOWN (fail closed).
    wrong = SigningKey.generate().verify_key.encode().hex()
    pack = _Pack({"join-pack-root": wrong})
    st = load_trust_state(pack, url=url, self_hash="deadbeef")
    assert st.state == UNKNOWN


def test_load_trust_state_fails_soft_on_unreachable_source(tmp_path):
    pack = _Pack({"join-pack-root": "00"})
    # Unreachable source -> fail soft to UNKNOWN, never raises (offline, no network).
    st = load_trust_state(pack, url=f"file://{tmp_path}/nope.json", self_hash="deadbeef")
    assert st.state == UNKNOWN
