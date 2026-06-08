"""Client-side attestation gate for the enclave plane.

This is the tenet client side of the TEE hardening (STATUS.md item 4).
The wire shape from ``enclave_plane.py`` stays unchanged; this module decides
*whether to trust* an enclave-plane endpoint before any matcher/mailbox call is
issued.

Trust model (attested-workload `docs/DESIGN.md`): "bootstrap once, then cheap".
A client verifies the enclave's attested-TLS receipt once, binds it to the TLS
channel, caches it, then trusts subsequent cheap calls.

Division of labour — we do NOT reimplement quote verification (attested-workload
invariant: "do not modify the core quote verifier"). The cryptographic checks
(quote signature chain, ``report_data`` binding, ``sha256(cert_spki) ==
eat.tls_spki_hash`` channel binding, Value X registry lookup) are delegated to
``aw check <url>`` (attested-workload ``src/main.rs`` ``cmd_check``). What lives
here is the policy tenet owns: which Value X builds we accept,
which TEE platforms we accept, and **fail-closed** enforcement — the client never
silently downgrades to an unattested transport (rule R1: security level is a
network property, not a per-call toggle).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Protocol, runtime_checkable

# The fail-closed error hierarchy lives in the leaf transport module so that
# SpkiPinError can subclass EnclaveAttestationError without an import cycle.
# Re-exported here so existing callers keep importing it from tenet.enclave.enclave_attest.
from tenet.enclave.attested_transport import EnclaveAttestationError, SpkiPinError


ACCEPTED_TEE_PLATFORMS = frozenset({"nitro", "sev-snp", "tdx"})

# `aw check` (attested-workload src/main.rs cmd_check) prints these labels to stderr.
_CHECK_VALUE_X_LABEL = "Value X:"
_CHECK_PLATFORM_LABEL = "Platform:"
# Debug form of platform_enum() -> our policy platform string.
_PLATFORM_NORMALIZE = {"tdx": "tdx", "nitro": "nitro", "sevsnp": "sev-snp", "snp": "sev-snp"}


@dataclass(frozen=True)
class VerifiedAttestation:
    """A receipt whose cryptographic checks have already passed (in runcards).

    The fields here are what tenet *policy* reasons about. The crypto that
    proves they are authentic (quote chain + channel binding) happened in the
    verifier before this object was constructed.
    """

    value_x: str
    platform: str
    tls_spki_hash: str
    registry_status: str = "unknown"
    receipt_url: str = ""


@dataclass(frozen=True)
class EnclaveTrustPolicy:
    """tenet-owned acceptance policy over a verified attestation."""

    approved_value_x: frozenset[str]
    accepted_platforms: frozenset[str] = ACCEPTED_TEE_PLATFORMS
    # Registry status is a secondary, opt-in signal. Empty = not enforced (the
    # primary gate is Value X + platform + the crypto `aw check` performs).
    accepted_registry_status: frozenset[str] = frozenset()
    # Item 5: require the verified attestation to carry the TLS SPKI hash so the
    # client can pin subsequent connections. Off by default (the plain-HTTP
    # stand-in carries no SPKI); turn on for real attested-TLS deployments. When
    # on, an attestation without an SPKI, or an inner client that cannot pin,
    # fails closed.
    require_spki_pin: bool = False

    def evaluate(self, att: VerifiedAttestation) -> None:
        """Raise ``EnclaveAttestationError`` unless the attestation is acceptable.

        Fail closed: an empty ``approved_value_x`` rejects everything, so a
        misconfigured deployment does not silently trust an arbitrary enclave.
        """
        if not self.approved_value_x:
            raise EnclaveAttestationError(
                "no approved Value X configured; refusing to trust any enclave"
            )
        if att.platform not in self.accepted_platforms:
            raise EnclaveAttestationError(
                f"tee platform not accepted: {att.platform!r} "
                f"(accepted: {sorted(self.accepted_platforms)})"
            )
        if att.value_x not in self.approved_value_x:
            raise EnclaveAttestationError(
                f"enclave Value X not in approved set: {att.value_x}"
            )
        if self.accepted_registry_status and att.registry_status not in self.accepted_registry_status:
            raise EnclaveAttestationError(
                f"registry status not accepted: {att.registry_status!r} "
                f"(accepted: {sorted(self.accepted_registry_status)})"
            )


@runtime_checkable
class RuncardVerifier(Protocol):
    """Adapter that performs runcards' cryptographic verification of an endpoint.

    Implementations MUST raise ``EnclaveAttestationError`` on any verification
    failure and only return a ``VerifiedAttestation`` when the quote chain and
    channel binding have passed.
    """

    def verify(self, base_url: str) -> VerifiedAttestation: ...


@dataclass
class SubprocessRuncardVerifier:
    """Real verifier: delegates cryptographic checks to ``aw`` (or legacy ``runcard``).

    ``aw check <url>`` (attested-workload ``cmd_check``) opens attested TLS to the
    TLS to the endpoint, extracts the EAT from the leaf cert's CMW extension (OID
    2.23.133.5.4.9 — the EAT is **CBOR embedded in the certificate**, not a JSON
    document fetched over HTTP), checks ``sha256(cert_spki) == eat.tls_spki_hash``
    (channel binding), verifies the platform quote signature + ``report_data``
    binding, and walks the stage chain (Value X must be stable across it). A zero
    exit code means every one of those passed. It prints the verified ``Platform``
    and ``Value X`` to stderr, which we parse for policy.

    We do NOT reimplement any of that crypto. Validated via attested-workload
    ``chain_e2e`` and Nitro/TDX ``hardware_regression`` fixtures (no live TEE for
    verification; fresh quotes need hardware).

    Output: prefers ``aw check --json`` (schema ``runcard.check.v1``); falls back
    to parsing human stderr for older verifiers without ``--json``.
    """

    runcard_bin: str = "aw"
    timeout: float = 30.0

    def verify(self, base_url: str) -> VerifiedAttestation:
        url = base_url.rstrip("/")
        runcard_bin = self._resolve_runcard_bin()
        try:
            proc = subprocess.run(
                [runcard_bin, "check", "--json", url],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise EnclaveAttestationError(
                f"could not run `{self.runcard_bin} check`: {exc}"
            ) from exc
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip() or f"exit {proc.returncode}"
            raise EnclaveAttestationError(f"aw check failed for {url}: {detail}")
        att = self._parse_json_output(proc.stdout, url)
        if att is not None:
            return att
        # Fallback: an older runcard without --json prints only the stderr log.
        return self._parse_check_output(proc.stderr, url)

    def _resolve_runcard_bin(self) -> str:
        configured = self.runcard_bin
        pathish = (
            os.sep in configured
            or (os.altsep is not None and os.altsep in configured)
            or Path(configured).is_absolute()
        )
        if pathish:
            return configured
        embedded_root = Path(getattr(sys, "_MEIPASS", "")) / "tenet_embedded"
        names = [configured]
        if os.name == "nt" and not configured.lower().endswith(".exe"):
            names.append(f"{configured}.exe")
        for name in names:
            candidate = embedded_root / name
            if candidate.is_file():
                return str(candidate)
        if embedded_root.is_dir():
            for candidate in sorted(embedded_root.glob("aw*")):
                if candidate.is_file():
                    return str(candidate)
        return configured

    @classmethod
    def _parse_json_output(cls, stdout: str, receipt_url: str) -> "VerifiedAttestation | None":
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                raw = json.loads(line)
            except ValueError:
                continue
            if not isinstance(raw, dict) or raw.get("schema") != "runcard.check.v1":
                continue
            value_x = str(raw.get("value_x", ""))
            platform_raw = str(raw.get("platform", ""))
            if not value_x or not platform_raw:
                raise EnclaveAttestationError(
                    "runcard check --json missing value_x / platform"
                )
            return VerifiedAttestation(
                value_x=value_x,
                # runcards emits `tls_spki_hash` (the SPKI it bound the EAT to);
                # this is the value the client pins subsequent connections to (item 5).
                tls_spki_hash=str(raw.get("tls_spki_hash", "")),
                platform=cls._normalize_platform(platform_raw),
                registry_status=str(raw.get("registry_status", "unknown")),
                receipt_url=receipt_url,
            )
        return None

    @classmethod
    def _parse_check_output(cls, stderr: str, receipt_url: str) -> VerifiedAttestation:
        value_x = cls._field(stderr, _CHECK_VALUE_X_LABEL)
        platform_raw = cls._field(stderr, _CHECK_PLATFORM_LABEL)
        if not value_x or not platform_raw:
            raise EnclaveAttestationError(
                "runcard check passed but Value X / Platform could not be parsed "
                "from its output"
            )
        return VerifiedAttestation(
            value_x=value_x,
            platform=cls._normalize_platform(platform_raw),
            tls_spki_hash="",  # channel binding already enforced inside `runcard check`
            registry_status="unknown",
            receipt_url=receipt_url,
        )

    @staticmethod
    def _field(stderr: str, label: str) -> str | None:
        for line in stderr.splitlines():
            idx = line.find(label)
            if idx != -1:
                return line[idx + len(label):].strip()
        return None

    @staticmethod
    def _normalize_platform(raw: str) -> str:
        # cmd_check prints the Debug form of platform_enum(), e.g. "Some(Tdx)".
        token = raw.strip()
        if token.startswith("Some(") and token.endswith(")"):
            token = token[len("Some("):-1]
        key = token.replace("-", "").replace("_", "").lower()
        platform = _PLATFORM_NORMALIZE.get(key)
        if platform is None:
            raise EnclaveAttestationError(f"unrecognized runcard platform: {raw!r}")
        return platform


class AttestedEnclavePlaneClient:
    """Wraps an enclave-plane client and gates every call on attestation.

    The inner client is any object exposing the enclave-plane interface
    (``discover``, ``routing_kem_pk_hex``, ``relay_path_for_handle``,
    ``deliver_to_handle``, ``mailbox_delivery_enabled``,
    ``mailbox_datagram_delivery_enabled``, ``base_url``). On first
    use it verifies the endpoint once (bootstrap-once) and caches the result; if
    verification or policy fails it raises and **never** calls the inner client.
    """

    def __init__(
        self,
        inner: object,
        *,
        verifier: RuncardVerifier,
        policy: EnclaveTrustPolicy,
        log: Callable[[str], None] | None = None,
    ) -> None:
        self._inner = inner
        self._verifier = verifier
        self._policy = policy
        self._log = log or (lambda _message: None)
        self._attestation: VerifiedAttestation | None = None

    @property
    def base_url(self) -> str:
        return self._inner.base_url

    @property
    def mailbox_delivery_enabled(self) -> bool:
        return bool(getattr(self._inner, "mailbox_delivery_enabled", False))

    @property
    def mailbox_datagram_delivery_enabled(self) -> bool:
        return bool(getattr(self._inner, "mailbox_datagram_delivery_enabled", True))

    @property
    def attestation(self) -> VerifiedAttestation | None:
        return self._attestation

    @property
    def pinned_spki(self) -> str | None:
        """SPKI hash bound by the verified receipt.

        On ``establish`` this is applied to the inner client's transport (item 5) so
        every subsequent connection is pinned to the TEE-resident TLS key that
        ``runcard check`` bound to the quote. A connection to any other cert then
        fails closed with ``SpkiPinError``.
        """
        return self._attestation.tls_spki_hash if self._attestation else None

    def establish(self) -> VerifiedAttestation:
        """Verify + apply policy once. Idempotent (bootstrap-once)."""
        if self._attestation is not None:
            return self._attestation
        att = self._verifier.verify(self._inner.base_url)
        self._policy.evaluate(att)
        self._apply_spki_pin(att)
        self._attestation = att
        self._log(
            "client event=enclave_attested "
            f"platform={att.platform} value_x={att.value_x[:16]} "
            f"status={att.registry_status} pinned={bool(att.tls_spki_hash)}"
        )
        return att

    def _apply_spki_pin(self, att: VerifiedAttestation) -> None:
        """Pin the inner transport to the attested SPKI (item 5), or fail closed.

        The inner client opts in by exposing ``set_tls_pin(spki_hex)``. If the
        policy requires pinning but the attestation carries no SPKI, or the inner
        client cannot pin, we refuse rather than continue unpinned.
        """
        setter = getattr(self._inner, "set_tls_pin", None)
        if att.tls_spki_hash and callable(setter):
            setter(att.tls_spki_hash)
            return
        if self._policy.require_spki_pin:
            if not att.tls_spki_hash:
                raise EnclaveAttestationError(
                    "policy requires an SPKI pin but the attestation carried none "
                    "(use `runcard check --json`, which emits tls_spki_hash)"
                )
            raise EnclaveAttestationError(
                "policy requires an SPKI pin but the enclave-plane client cannot "
                "pin its transport (no set_tls_pin)"
            )

    def _ensure(self) -> None:
        if self._attestation is not None:
            return
        try:
            self.establish()
        except EnclaveAttestationError as exc:
            self._log(f"client event=enclave_attestation_rejected reason={exc}")
            raise

    def discover(self, request):
        self._ensure()
        return self._inner.discover(request)

    def routing_kem_pk_hex(self, handle: str):
        self._ensure()
        return self._inner.routing_kem_pk_hex(handle)

    def relay_path_for_handle(self, handle: str) -> tuple[str, ...]:
        self._ensure()
        return self._inner.relay_path_for_handle(handle)

    def deliver_to_handle(self, handle: str, datagram: bytes, *, timeout: float) -> Iterable[bytes]:
        self._ensure()
        return self._inner.deliver_to_handle(handle, datagram, timeout=timeout)


# Preferred name for new code; SubprocessRuncardVerifier kept for compatibility.
SubprocessAttestedWorkloadVerifier = SubprocessRuncardVerifier
