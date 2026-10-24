"""Tests for picking the guest's LAN address out of what its agent reports, and for MACs in one form."""

from __future__ import annotations

import ipaddress
from ipaddress import IPv4Address

import pytest
from pydantic import TypeAdapter, ValidationError

from pve_winrepair.domain.addresses import AmbiguousAddressError, MacAddress, lan_address, normalise_mac

OLD_PREFIX = "192.0.2."
NET = ipaddress.IPv4Network("192.0.2.0/24")
SAME = ["192.0.2.0", "192.0.2.1", "192.0.2.50", "192.0.2.255", "192.0.3.1", "192.0.20.1",
        "192.0.21.5", "198.51.100.7", "127.0.0.1", "169.254.3.4", "10.0.0.5"]  # fmt: skip


@pytest.mark.parametrize("ip", SAME)
def test_the_network_keeps_exactly_what_the_old_prefix_kept(ip: str) -> None:
    assert (lan_address([IPv4Address(ip)], NET) == IPv4Address(ip)) is ip.startswith(OLD_PREFIX)


def test_without_a_subnet_the_only_candidate_is_taken() -> None:
    addresses = [IPv4Address("127.0.0.1"), IPv4Address("169.254.1.1"), IPv4Address("192.0.2.9")]
    assert lan_address(addresses, None) == IPv4Address("192.0.2.9")


def test_a_repeated_address_is_one_candidate() -> None:
    assert lan_address([IPv4Address("192.0.2.9"), IPv4Address("192.0.2.9")], None) == IPv4Address("192.0.2.9")


def test_without_a_subnet_several_candidates_are_refused_by_name() -> None:
    # Docker guests also carry a 172.x switch address; picking the first one lands on an address
    # the node cannot reach.
    with pytest.raises(AmbiguousAddressError) as caught:
        lan_address([IPv4Address("172.17.0.1"), IPv4Address("192.0.2.9")], None)
    assert caught.value.candidates == (IPv4Address("172.17.0.1"), IPv4Address("192.0.2.9"))
    assert str(caught.value) == "several candidate LAN addresses: 172.17.0.1, 192.0.2.9"


# --- MACs ------------------------------------------------------------------------------------

_MAC: TypeAdapter[str] = TypeAdapter(MacAddress)


@pytest.mark.parametrize(
    ("text", "normalised"),
    [
        ("BC:24:11:AA:BB:CC", "BC:24:11:AA:BB:CC"),
        ("bc:24:11:aa:bb:cc", "BC:24:11:AA:BB:CC"),
        ("bc-24-11-aa-bb-cc", "BC:24:11:AA:BB:CC"),
        ("BC:24:11:AA:BB", None),
        ("BC:24:11:AA:BB:CC:DD", None),
        ("BC:24-11:AA:BB:CC", None),
        ("BC 24 11 AA BB CC", None),
        ("BC:24:11:AA:BB:CG", None),
        ("BC:24:11:AA:BB:CC\n", None),
        (f"BC:24:11:AA:BB:C{chr(0x0662)}", None),
        ("", None),
    ],
)
def test_a_mac_is_normalised_to_upper_case_colons_or_refused(text: str, normalised: str | None) -> None:
    assert normalise_mac(text) == normalised
    if normalised is not None:
        assert _MAC.validate_python(text) == normalised
        return
    with pytest.raises(ValidationError) as caught:
        _MAC.validate_python(text)
    assert [error["msg"] for error in caught.value.errors()] == [
        "Value error, not a MAC address (six hex octets, one separator)"
    ]
