"""SPKI-pinned TLS transport for the enclave plane (STATUS.md item 5).

`runcard check` proves, at bootstrap, that the endpoint's TLS leaf cert is bound
to the TEE quote: it recomputes ``sha256(cert_spki)`` and checks it equals
``eat.tls_spki_hash`` (runcards ``net::attested_tls::spki_hash_of_cert`` →
``sha256`` of the cert's SubjectPublicKeyInfo DER). That guarantee only covers
the connection runcards itself opened. The "bootstrap once, then cheap" pattern
means subsequent enclave-plane calls do **not** re-run ``runcard check`` — so
those connections must be pinned to the *same* SPKI, or a network attacker could
swap in a different cert after bootstrap.

This module enforces that pin. It deliberately does **not** verify a CA chain:
attested TLS authenticates by attestation, not by a public CA (mirroring
runcards' ``build_unchecked_client_config`` / ``NoVerify``). Authentication is
the SPKI pin alone. A mismatch raises ``SpkiPinError`` — a fail-closed error, so
a caller never silently downgrades to an unpinned/unattested transport (invariant
R1: security level is a network property, not a per-call toggle).

This is the leaf module of the enclave-trust error hierarchy: it owns
``EnclaveAttestationError`` (re-exported by ``tenet.enclave.enclave_attest`` for
backward compatibility) so that ``SpkiPinError`` can subclass it without an
import cycle.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import ssl
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class EnclaveAttestationError(RuntimeError):
    """The enclave plane could not be trusted.

    Raising this is the fail-closed path: callers must not fall back to an
    unattested transport in response.
    """


class SpkiPinError(EnclaveAttestationError):
    """The TLS leaf cert's SPKI did not match the pinned (attested) value.

    Fail-closed: this means the connection is not terminating at the TEE-resident
    key that ``runcard check`` bound to the quote — a MITM/relay, or a different
    endpoint. The request must abort, not retry unpinned.
    """


def spki_sha256_hex(der_cert: bytes) -> str:
    """``sha256`` of the cert's SubjectPublicKeyInfo DER, hex.

    Byte-identical to runcards' ``spki_hash_of_cert``: that hashes
    ``cert.subject_public_key_info.encode_der()``; ``cryptography``'s
    ``public_bytes(DER, SubjectPublicKeyInfo)`` produces the same DER.
    """
    cert = x509.load_der_x509_certificate(der_cert)
    spki_der = cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(spki_der).hexdigest()


def assert_peer_spki(der_cert: bytes | None, pinned_spki_hex: str) -> None:
    """Raise ``SpkiPinError`` unless the peer leaf cert matches the pin."""
    if not der_cert:
        raise SpkiPinError("enclave presented no TLS certificate to pin against")
    actual = spki_sha256_hex(der_cert)
    if not hmac.compare_digest(actual, pinned_spki_hex.lower()):
        raise SpkiPinError(
            f"enclave TLS SPKI {actual} does not match pinned {pinned_spki_hex.lower()}"
        )


def build_pinned_opener(pinned_spki_hex: str) -> urllib.request.OpenerDirector:
    """An ``urllib`` opener that pins every HTTPS connection to ``pinned_spki_hex``.

    No CA verification (attested TLS is self-signed by design); the SPKI pin is
    the sole authentication. The check runs right after the TLS handshake, before
    any request bytes are sent, so a wrong endpoint never receives the payload.
    """
    pin = pinned_spki_hex.lower()

    # CERT_NONE so a self-signed attested cert is accepted by rustls/openssl;
    # getpeercert(binary_form=True) still returns the leaf DER under CERT_NONE,
    # which is what we actually authenticate against.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    class _PinnedHTTPSConnection(http.client.HTTPSConnection):
        def connect(self) -> None:  # type: ignore[override]
            super().connect()
            assert_peer_spki(self.sock.getpeercert(binary_form=True), pin)

    class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(_PinnedHTTPSConnection, req, context=context)

    return urllib.request.build_opener(_PinnedHTTPSHandler())
