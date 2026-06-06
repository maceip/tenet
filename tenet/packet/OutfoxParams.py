"""Outfox parameters and cryptographic primitives.

Implements the building blocks from Rial, Piotrowska, Halpin (2025):
"Outfox: a Postquantum Packet Format for Layered Mixnets"
(arXiv:2412.19937v2)

Extended with tenet protocol additions:
  - ML-DSA-65 (Dilithium) signatures for payload integrity
  - Per-layer timestamps for replay rejection
  - Dummy traffic flag (protocol-level, not policy)
  - Return-path circuit setup material

Primitives:
  KEM   - Key Encapsulation Mechanism (X25519, extensible to ML-KEM)
  KDF   - HKDF-SHA256 key derivation
  AEAD  - ChaCha20-Poly1305 authenticated encryption
  SE    - LIONESS wide-block PRP (length-preserving, IND$-CCA)
  SIG   - ML-DSA-65 post-quantum signatures
"""

import struct
import time as _time
from os import urandom
from hashlib import sha256
import hmac as hmac_mod

from nacl.bindings import (
    crypto_scalarmult_base,
    crypto_scalarmult,
    crypto_aead_chacha20poly1305_ietf_encrypt,
    crypto_aead_chacha20poly1305_ietf_decrypt,
)

# AES-CTR backend selection. All three implement the *same* AES-CTR with the
# full 128-bit IV as the initial counter, so the wire format is identical
# regardless of which is active (proven in test_aes_ctr_backends). Each backend
# is smoke-tested before selection, so a backend that imports but can't actually
# run (e.g. pycryptodome's ctypes .so loader breaks under Android/Chaquopy) is
# skipped in favour of the next:
#   1. cryptography  (Rust+OpenSSL)  — desktop default
#   2. pycryptodome  (plain C)       — C target without Rust
#   3. pyaes         (pure Python)   — last resort (Android/Chaquopy); slower


def _make_cryptography_aes_ctr():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    def _aes_ctr(key, iv, data):
        enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
        return enc.update(data) + enc.finalize()

    return _aes_ctr


def _make_pycryptodome_aes_ctr():
    from Crypto.Cipher import AES
    from Crypto.Util import Counter

    def _aes_ctr(key, iv, data):
        ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
        return AES.new(key, AES.MODE_CTR, counter=ctr).encrypt(data)

    return _aes_ctr


def _make_pyaes_aes_ctr():
    import pyaes

    def _aes_ctr(key, iv, data):
        ctr = pyaes.Counter(initial_value=int.from_bytes(iv, "big"))
        return pyaes.AESModeOfOperationCTR(key, counter=ctr).encrypt(data)

    return _aes_ctr


def _select_aes_ctr():
    probe_key = b"\x00" * 16
    probe_iv = b"\x00" * 16
    for name, factory in (
        ("cryptography", _make_cryptography_aes_ctr),
        ("pycryptodome", _make_pycryptodome_aes_ctr),
        ("pyaes", _make_pyaes_aes_ctr),
    ):
        try:
            fn = factory()
            if len(fn(probe_key, probe_iv, b"abc")) == 3:  # smoke test
                return fn, name
        except Exception:
            continue
    raise RuntimeError("no working AES-CTR backend available")


_aes_ctr, AES_CTR_BACKEND = _select_aes_ctr()

# ML-DSA-65 (Dilithium) backend. `pqcrypto` (PQClean C bindings) is preferred,
# but its cffi build is hard to cross-compile for Android, so fall back to the
# pure-Python `dilithium-py`. Both implement FIPS 204 ML-DSA-65 with identical
# key/signature encodings, so signatures are interoperable across the two (a
# pqcrypto node verifies a dilithium-py client's signature and vice versa —
# proven in test_ml_dsa_backends). dilithium-py is slower but fine for a client.
try:
    from pqcrypto.sign.ml_dsa_65 import (
        generate_keypair as dilithium_generate_keypair,
        sign as dilithium_sign,
        verify as dilithium_verify,
    )

    ML_DSA_BACKEND = "pqcrypto"
except Exception:  # pragma: no cover - exercised on Android (dilithium-py)
    from dilithium_py.ml_dsa import ML_DSA_65 as _ML_DSA_65

    def dilithium_generate_keypair():
        return _ML_DSA_65.keygen()

    def dilithium_sign(secret_key, message):
        return _ML_DSA_65.sign(secret_key, message)

    def dilithium_verify(public_key, message, signature):
        return _ML_DSA_65.verify(public_key, message, signature)

    ML_DSA_BACKEND = "dilithium-py"


class KEM_X25519:
    """X25519-based Key Encapsulation Mechanism.

    Not post-quantum secure, but compatible with existing infrastructure.
    Drop-in replaceable with ML-KEM-768 or X-Wing for post-quantum security.
    """
    CIPHERTEXT_SIZE = 32
    PUBLIC_KEY_SIZE = 32
    SECRET_KEY_SIZE = 32
    SHARED_KEY_SIZE = 32

    @staticmethod
    def keygen():
        sk = urandom(32)
        pk = crypto_scalarmult_base(sk)
        return pk, sk

    @staticmethod
    def encapsulate(pk):
        eph_sk = urandom(32)
        c = crypto_scalarmult_base(eph_sk)
        shk = crypto_scalarmult(eph_sk, pk)
        return shk, c

    @staticmethod
    def decapsulate(c, sk):
        # libsodium's crypto_scalarmult clamps the scalar and masks the high
        # bit of the input point (RFC 7748), so non-canonical ciphertexts are
        # normalised rather than exploitable. We additionally reject degenerate
        # *outputs*: an all-zero shared secret (the small-subgroup / low-order
        # point result) and any value outside the canonical field range
        # (x >= 2^255 - 19). Together these cover the small-subgroup attack
        # without a separate in_group check on the input.
        try:
            shk = crypto_scalarmult(sk, c)
        except Exception:
            return None
        if shk == b'\x00' * 32:
            return None
        x = int.from_bytes(shk, 'little')
        if x >= 2**255 - 19:
            return None
        return shk


AEAD_TAG_SIZE = 16
AEAD_NONCE = b'\x00' * 12
TIMESTAMP_SIZE = 8
FLAG_SIZE = 1
CIRCUIT_TTL_SECONDS = 120
MAX_FUTURE_SKEW_SECONDS = 2
# Exit-side streaming cadence (traffic-analysis mitigation v1). During an active
# session the exit emits at most one circuit packet per interval; empty ticks
# send keepalives so gaps between SSE tokens are not visibly idle on the wire.
# This does NOT provide network-wide constant-rate mixing (spec §2 non-goals).
CIRCUIT_PACE_INTERVAL_MS = 50

FLAG_REAL = b'\x00'
FLAG_DUMMY = b'\x01'

CIRCUIT_MAGIC = b'POR2'
CIRCUIT_TYPE = b'\x01'
FORWARD_TYPE = b'\x00'


def hkdf(ikm, length, salt=None, info=b""):
    """HKDF-SHA256 (RFC 5869)."""
    if salt is None:
        salt = b'\x00' * 32
    prk = hmac_mod.new(salt, ikm, sha256).digest()
    t = b""
    okm = b""
    for i in range(1, (length + 31) // 32 + 1):
        t = hmac_mod.new(prk, t + info + bytes([i]), sha256).digest()
        okm += t
    return okm[:length]


def derive_circuit_key(key_seed, inbound_link_cid):
    """Derive a per-hop circuit key from seed and this hop's inbound link CID.

    Uses HKDF-SHA256 with domain separation per spec v3 §5.
    """
    return hkdf(key_seed, 16, salt=inbound_link_cid, info=b"circuit")


def aead_encrypt(key, plaintext):
    """ChaCha20-Poly1305 AEAD. Returns (ciphertext, tag)."""
    ct_with_tag = crypto_aead_chacha20poly1305_ietf_encrypt(
        plaintext, None, AEAD_NONCE, key)
    return ct_with_tag[:-AEAD_TAG_SIZE], ct_with_tag[-AEAD_TAG_SIZE:]


def aead_decrypt(key, ciphertext, tag):
    """ChaCha20-Poly1305 AEAD. Returns plaintext or raises."""
    from nacl.exceptions import CryptoError
    try:
        return crypto_aead_chacha20poly1305_ietf_decrypt(
            ciphertext + tag, None, AEAD_NONCE, key)
    except CryptoError:
        raise ValueError("AEAD decryption failed")


def make_timestamp():
    """8-byte big-endian millisecond timestamp."""
    return struct.pack(">Q", int(_time.time() * 1000))


def check_timestamp(
    ts_bytes,
    max_age_sec=CIRCUIT_TTL_SECONDS,
    max_future_skew_sec=MAX_FUTURE_SKEW_SECONDS,
):
    """Reject stale timestamps, allowing small cross-host clock skew."""
    ts_ms = struct.unpack(">Q", ts_bytes)[0]
    now_ms = int(_time.time() * 1000)
    age_sec = (now_ms - ts_ms) / 1000.0
    return -max_future_skew_sec <= age_sec <= max_age_sec


def sign_payload(sk, payload):
    """ML-DSA-65 signature over payload bytes."""
    return dilithium_sign(sk, payload)


def verify_payload(pk, payload, signature):
    """Verify ML-DSA-65 signature. Returns True/False."""
    try:
        return dilithium_verify(pk, payload, signature) is not False
    except (TypeError, ValueError):
        return False


def generate_signing_keypair():
    """Generate ML-DSA-65 (Dilithium3) signing keypair."""
    return dilithium_generate_keypair()


class OutfoxParams:
    """Outfox packet format parameters.

    Per-hop KEM, AEAD headers, and formal KDF.
    Extended with per-layer timestamps, dummy flag, and return-path circuits.
    """

    def __init__(self, kem=None, k=16, payload_size=1024, routing_size=16, max_hops=5):
        self.kem = kem or KEM_X25519()
        self.k = k
        self.payload_size = payload_size
        self.routing_size = routing_size
        self.max_hops = max_hops
        self.per_hop_meta_size = TIMESTAMP_SIZE + FLAG_SIZE

        sizes = self.header_sizes(max_hops)
        self.surb_size = sizes[0] + k

        self.zero_iv = b'\x00' * 16

    def derive_keys(self, shk, c, pk):
        """Derive header key (32 bytes) and payload key (k bytes) from shared secret."""
        ctx = c + pk
        material = hkdf(shk, 32 + self.k, info=ctx)
        s_h = material[:32]
        s_p = material[32:32 + self.k]
        return s_h, s_p

    def header_sizes(self, num_hops, circuit_setup=False):
        """Compute header byte size at each layer.

        Each layer's AEAD plaintext: routing + timestamp + flag [+ circuit_fields] + inner_header.
        Circuit fields: 16 (inbound_cid) + 16 (seed) + routing_size (next_hop) + 16 (outbound_cid) + 2 (ttl).
        """
        ct = self.kem.CIPHERTEXT_SIZE
        r = self.routing_size
        t = AEAD_TAG_SIZE
        m = TIMESTAMP_SIZE + FLAG_SIZE
        circ = (16 + 16 + r + 16 + 2) if circuit_setup else 0
        sizes = [0] * num_hops
        sizes[num_hops - 1] = ct + r + m + circ + t
        for i in range(num_hops - 2, -1, -1):
            sizes[i] = ct + (r + m + circ + sizes[i + 1]) + t
        return sizes

    def aes_ctr(self, k, m, iv=None):
        if iv is None:
            iv = self.zero_iv
        return _aes_ctr(k, iv, m)

    def lioness_enc(self, key, message):
        assert len(key) == self.k
        assert len(message) >= self.k * 2
        k1 = sha256(message[self.k:] + key + b'1').digest()[:self.k]
        c = self.aes_ctr(key, message[:self.k], iv=k1)
        r1 = c + message[self.k:]
        c = self.aes_ctr(key, r1[self.k:], iv=r1[:self.k])
        r2 = r1[:self.k] + c
        k3 = sha256(r2[self.k:] + key + b'3').digest()[:self.k]
        c = self.aes_ctr(key, r2[:self.k], iv=k3)
        r3 = c + r2[self.k:]
        c = self.aes_ctr(key, r3[self.k:], r3[:self.k])
        return r3[:self.k] + c

    def lioness_dec(self, key, message):
        assert len(key) == self.k
        assert len(message) >= self.k * 2
        r4_short, r4_long = message[:self.k], message[self.k:]
        r3_long = self.aes_ctr(key, r4_long, iv=r4_short)
        r3_short = r4_short
        k3 = sha256(r3_long + key + b'3').digest()[:self.k]
        r2_short = self.aes_ctr(key, r3_short, iv=k3)
        r2_long = r3_long
        r1_long = self.aes_ctr(key, r2_long, iv=r2_short)
        r1_short = r2_short
        k0 = sha256(r1_long + key + b'1').digest()[:self.k]
        c = self.aes_ctr(key, r1_short, iv=k0)
        return c + r1_long

    def se_enc(self, key, plaintext):
        """SE.Enc: length-preserving symmetric encryption (LIONESS PRP)."""
        return self.lioness_enc(key, plaintext)

    def se_dec(self, key, ciphertext):
        """SE.Dec: length-preserving symmetric decryption."""
        return self.lioness_dec(key, ciphertext)


def test_outfox_params():
    p = OutfoxParams()

    pk, sk = p.kem.keygen()
    shk, c = p.kem.encapsulate(pk)
    shk2 = p.kem.decapsulate(c, sk)
    assert shk == shk2

    s_h, s_p = p.derive_keys(shk, c, pk)
    assert len(s_h) == 32
    assert len(s_p) == p.k

    pt = b"hello world!!!!!" * 4
    ct, tag = aead_encrypt(s_h, pt)
    assert aead_decrypt(s_h, ct, tag) == pt

    msg = urandom(128)
    enc = p.se_enc(s_p, msg)
    assert p.se_dec(s_p, enc) == msg

    sizes = p.header_sizes(4)
    assert sizes[3] < sizes[2] < sizes[1] < sizes[0]
