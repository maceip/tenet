"""STATUS.md item 5: SPKI-pinned opener authenticates by public key, end-to-end.

Stands up a real local HTTPS server with a self-signed cert (exactly the shape of
attested TLS: no CA chain) and proves the pinned opener accepts the matching SPKI
and fails closed on a mismatch.
"""

import datetime
import http.server
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

from tenet.enclave.attested_transport import (
    SpkiPinError,
    assert_peer_spki,
    build_pinned_opener,
    spki_sha256_hex,
)


def _self_signed(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "enclave.test")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = tmp_path / "cert.pem"
    key_pem = tmp_path / "key.pem"
    cert_pem.write_bytes(cert.public_bytes(Encoding.PEM))
    key_pem.write_bytes(
        key.private_bytes(
            Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert, str(cert_pem), str(key_pem)


@pytest.fixture
def https_server(tmp_path):
    cert, cert_pem, key_pem = _self_signed(tmp_path)

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *_a):
            pass

    class QuietHTTPServer(http.server.HTTPServer):
        # The wrong-pin client drops the socket before sending its request, which
        # the handler thread sees as a connection error. That is the expected
        # fail-closed behaviour, so don't dump a traceback for it.
        def handle_error(self, request, client_address):
            pass

    httpd = QuietHTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_pem, key_pem)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{port}/", cert
    finally:
        httpd.shutdown()
        thread.join(timeout=2)


def test_spki_hash_matches_certs_own_public_key():
    # The hash of the leaf DER's SPKI equals the hash of the key's own SPKI DER.
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    import hashlib

    direct = hashlib.sha256(
        key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    ).hexdigest()
    assert spki_sha256_hex(cert.public_bytes(Encoding.DER)) == direct


def test_assert_peer_spki_rejects_missing_cert():
    with pytest.raises(SpkiPinError, match="no TLS certificate"):
        assert_peer_spki(None, "00" * 32)


def test_pinned_opener_accepts_matching_spki(https_server):
    url, cert = https_server
    pin = spki_sha256_hex(cert.public_bytes(Encoding.DER))
    with build_pinned_opener(pin).open(url, timeout=5) as resp:
        assert resp.read() == b"ok"


def test_pinned_opener_rejects_wrong_spki(https_server):
    url, _cert = https_server
    with pytest.raises(SpkiPinError, match="does not match pinned"):
        build_pinned_opener("00" * 32).open(url, timeout=5)
