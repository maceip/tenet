"""UPnP/NAT-PMP port mapping tests.

Unit tests for the mapping logic. Actual UPnP/NAT-PMP requires a
real router, so we test the API surface and failure handling.
"""

from por.upnp import (
    try_port_mapping, renew_mapping, release_mapping,
    PortMapping, MappingResult, _get_local_ip,
)


def test_try_port_mapping_fails_gracefully_without_router():
    """No router on test network — both UPnP and NAT-PMP fail cleanly."""
    result = try_port_mapping(4433, lease_seconds=60)
    assert isinstance(result, MappingResult)
    assert result.success is False
    assert result.error is not None
    assert "UPnP" in result.error
    assert result.mapping is None


def test_renew_upnp_mapping_fails_gracefully():
    """Renewing a mapping that doesn't exist fails cleanly."""
    mapping = PortMapping(
        protocol="UDP", external_port=4433, internal_port=4433,
        external_ip=None, lease_seconds=3600, method="upnp",
    )
    result = renew_mapping(mapping, lease_seconds=3600)
    assert result.success is False


def test_renew_natpmp_mapping_fails_gracefully():
    """NAT-PMP renew without gateway fails cleanly."""
    mapping = PortMapping(
        protocol="UDP", external_port=4433, internal_port=4433,
        external_ip=None, lease_seconds=3600, method="natpmp",
    )
    result = renew_mapping(mapping, lease_seconds=3600)
    assert result.success is False


def test_release_unknown_method():
    mapping = PortMapping(
        protocol="UDP", external_port=4433, internal_port=4433,
        external_ip=None, lease_seconds=3600, method="unknown",
    )
    assert release_mapping(mapping) is False


def test_get_local_ip_returns_string():
    ip = _get_local_ip()
    assert isinstance(ip, str)
    assert len(ip) > 0


def test_mapping_result_dataclass():
    r = MappingResult(success=True, mapping=PortMapping(
        protocol="UDP", external_port=4433, internal_port=4433,
        external_ip="1.2.3.4", lease_seconds=7200, method="upnp",
    ))
    assert r.success
    assert r.mapping.external_ip == "1.2.3.4"
    assert r.mapping.method == "upnp"
