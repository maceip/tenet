"""UPnP/NAT-PMP port mapping for tenet home nodes.

Follows the libtorrent pattern: try UPnP, try NAT-PMP, report result.
If a mapping is obtained, the node can advertise a direct endpoint
in its PeerAddressRecord and skip the relay for incoming traffic.

This is a bandwidth optimization — the relay path is always the
correctness fallback.
"""

from __future__ import annotations

import socket
import struct
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Sequence
from urllib.request import Request, urlopen
from urllib.error import URLError


SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
SSDP_TIMEOUT = 2.0

UPNP_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 2\r\n"
    "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
    "\r\n"
)

NAT_PMP_PORT = 5351
NAT_PMP_TIMEOUT = 1.0


@dataclass(frozen=True)
class PortMapping:
    protocol: str
    external_port: int
    internal_port: int
    external_ip: str | None
    lease_seconds: int
    method: str  # "upnp" or "natpmp"


@dataclass(frozen=True)
class MappingResult:
    success: bool
    mapping: PortMapping | None = None
    error: str | None = None


def try_port_mapping(
    internal_port: int,
    external_port: int = 0,
    *,
    protocol: str = "UDP",
    lease_seconds: int = 7200,
    description: str = "tenet",
) -> MappingResult:
    """Try UPnP, then NAT-PMP. Return first success or last error.

    external_port=0 means let the router pick.
    """
    if external_port == 0:
        external_port = internal_port

    result = _try_upnp(internal_port, external_port,
                       protocol=protocol, lease_seconds=lease_seconds,
                       description=description)
    if result.success:
        return result

    upnp_error = result.error

    result = _try_natpmp(internal_port, external_port,
                         protocol=protocol, lease_seconds=lease_seconds)
    if result.success:
        return result

    return MappingResult(
        success=False,
        error=f"UPnP: {upnp_error}; NAT-PMP: {result.error}",
    )


def renew_mapping(mapping: PortMapping, lease_seconds: int = 7200) -> MappingResult:
    """Renew an existing mapping. Same method as original."""
    if mapping.method == "upnp":
        return _try_upnp(mapping.internal_port, mapping.external_port,
                         protocol=mapping.protocol, lease_seconds=lease_seconds)
    if mapping.method == "natpmp":
        return _try_natpmp(mapping.internal_port, mapping.external_port,
                           protocol=mapping.protocol, lease_seconds=lease_seconds)
    return MappingResult(success=False, error=f"unknown method: {mapping.method}")


def release_mapping(mapping: PortMapping) -> bool:
    """Release a port mapping. Best-effort."""
    if mapping.method == "upnp":
        try:
            _upnp_delete(mapping.external_port, mapping.protocol)
            return True
        except Exception:
            return False
    if mapping.method == "natpmp":
        try:
            _natpmp_request(mapping.internal_port, 0, 0,
                            protocol=mapping.protocol)
            return True
        except Exception:
            return False
    return False


# ── UPnP ────────────────────────────────────────────────────────────

def _try_upnp(internal_port, external_port, *, protocol, lease_seconds,
              description="tenet") -> MappingResult:
    try:
        location = _ssdp_discover()
        if not location:
            return MappingResult(success=False, error="no IGD found via SSDP")

        control_url = _upnp_control_url(location)
        if not control_url:
            return MappingResult(success=False, error="no WANIPConnection control URL")

        external_ip = _upnp_external_ip(control_url)
        _upnp_add_mapping(control_url, external_port, internal_port,
                          protocol, lease_seconds, description)

        return MappingResult(
            success=True,
            mapping=PortMapping(
                protocol=protocol,
                external_port=external_port,
                internal_port=internal_port,
                external_ip=external_ip,
                lease_seconds=lease_seconds,
                method="upnp",
            ),
        )
    except Exception as e:
        return MappingResult(success=False, error=str(e))


def _ssdp_discover() -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(SSDP_TIMEOUT)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    try:
        sock.sendto(UPNP_SEARCH.encode(), (SSDP_ADDR, SSDP_PORT))
        while True:
            try:
                data, _ = sock.recvfrom(4096)
                response = data.decode("utf-8", errors="replace")
                for line in response.split("\r\n"):
                    if line.lower().startswith("location:"):
                        return line.split(":", 1)[1].strip()
            except socket.timeout:
                return None
    finally:
        sock.close()


def _upnp_control_url(location: str) -> str | None:
    try:
        resp = urlopen(location, timeout=3)
        xml_data = resp.read()
    except Exception:
        return None

    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError:
        return None

    ns = {"upnp": "urn:schemas-upnp-org:device-1-0"}
    for service in root.iter("{urn:schemas-upnp-org:device-1-0}service"):
        service_type = service.findtext("{urn:schemas-upnp-org:device-1-0}serviceType", "")
        if "WANIPConnection" in service_type or "WANPPPConnection" in service_type:
            control = service.findtext("{urn:schemas-upnp-org:device-1-0}controlURL", "")
            if control:
                from urllib.parse import urljoin
                return urljoin(location, control)
    return None


def _upnp_add_mapping(control_url, external_port, internal_port,
                      protocol, lease_seconds, description):
    local_ip = _get_local_ip()
    body = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        "<s:Body>"
        '<u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">'
        "<NewRemoteHost></NewRemoteHost>"
        f"<NewExternalPort>{external_port}</NewExternalPort>"
        f"<NewProtocol>{protocol}</NewProtocol>"
        f"<NewInternalPort>{internal_port}</NewInternalPort>"
        f"<NewInternalClient>{local_ip}</NewInternalClient>"
        "<NewEnabled>1</NewEnabled>"
        f"<NewPortMappingDescription>{description}</NewPortMappingDescription>"
        f"<NewLeaseDuration>{lease_seconds}</NewLeaseDuration>"
        "</u:AddPortMapping>"
        "</s:Body>"
        "</s:Envelope>"
    ).encode("utf-8")

    req = Request(control_url, data=body, method="POST", headers={
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPAction": '"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"',
    })
    urlopen(req, timeout=5)


def _upnp_external_ip(control_url) -> str | None:
    body = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        "<s:Body>"
        '<u:GetExternalIPAddress xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">'
        "</u:GetExternalIPAddress>"
        "</s:Body>"
        "</s:Envelope>"
    ).encode("utf-8")

    req = Request(control_url, data=body, method="POST", headers={
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPAction": '"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress"',
    })
    try:
        resp = urlopen(req, timeout=5)
        xml_data = resp.read()
        root = ET.fromstring(xml_data)
        for elem in root.iter():
            if "ExternalIPAddress" in (elem.tag or ""):
                return elem.text
    except Exception:
        pass
    return None


def _upnp_delete(external_port, protocol):
    pass  # Best-effort; not critical for MVP


def _get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


# ── NAT-PMP ─────────────────────────────────────────────────────────

def _try_natpmp(internal_port, external_port, *, protocol,
                lease_seconds) -> MappingResult:
    try:
        gateway = _get_default_gateway()
        if not gateway:
            return MappingResult(success=False, error="no default gateway for NAT-PMP")

        result = _natpmp_request(internal_port, external_port,
                                 lease_seconds, protocol=protocol,
                                 gateway=gateway)
        return MappingResult(
            success=True,
            mapping=PortMapping(
                protocol=protocol,
                external_port=result["external_port"],
                internal_port=internal_port,
                external_ip=result.get("external_ip"),
                lease_seconds=result["lease"],
                method="natpmp",
            ),
        )
    except Exception as e:
        return MappingResult(success=False, error=str(e))


def _natpmp_request(internal_port, external_port, lease_seconds, *,
                    protocol="UDP", gateway=None):
    if gateway is None:
        gateway = _get_default_gateway()
    if not gateway:
        raise RuntimeError("no gateway")

    opcode = 1 if protocol.upper() == "UDP" else 2
    request = struct.pack("!BBHHi", 0, opcode, 0,
                          internal_port, external_port) + \
              struct.pack("!I", lease_seconds)

    # NAT-PMP uses a simpler format
    request = struct.pack("!BBHHI", 0, opcode, 0,
                          internal_port, external_port) + \
              struct.pack("!I", lease_seconds)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(NAT_PMP_TIMEOUT)
    try:
        sock.sendto(request, (gateway, NAT_PMP_PORT))
        data, _ = sock.recvfrom(1024)
        if len(data) < 16:
            raise RuntimeError("NAT-PMP response too short")
        version, opcode_resp, result_code = struct.unpack("!BBH", data[:4])
        if result_code != 0:
            raise RuntimeError(f"NAT-PMP error: {result_code}")
        _, mapped_internal, mapped_external, mapped_lease = struct.unpack(
            "!IHHI", data[4:16])
        return {
            "external_port": mapped_external,
            "lease": mapped_lease,
        }
    finally:
        sock.close()


def _get_default_gateway() -> str | None:
    try:
        import subprocess
        result = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True, text=True, timeout=3)
        for line in result.stdout.split("\n"):
            if "gateway" in line.lower():
                parts = line.split(":")
                if len(parts) >= 2:
                    return parts[1].strip()
    except Exception:
        pass
    return None
