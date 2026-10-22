"""Tests for picking the guest's LAN address out of what its agent reports."""

from __future__ import annotations

import ipaddress

import pytest

from pve_winrepair.domain.addresses import AmbiguousAddressError, lan_address

OLD_PREFIX = "192.0.2."
NET = ipaddress.IPv4Network("192.0.2.0/24")
SAME = ["192.0.2.0", "192.0.2.1", "192.0.2.50", "192.0.2.255", "192.0.3.1", "192.0.20.1",
        "192.0.21.5", "198.51.100.7", "127.0.0.1", "169.254.3.4", "10.0.0.5"]  # fmt: skip


@pytest.mark.parametrize("ip", SAME)
def test_the_network_keeps_exactly_what_the_old_prefix_kept(ip: str) -> None:
    assert (lan_address([ip], NET) == ip) is ip.startswith(OLD_PREFIX)


def test_the_one_divergence_is_a_leading_zero_the_agent_never_sends() -> None:
    # The old prefix kept "192.0.2.050"; ipaddress refuses leading zeros (Python >= 3.9.5).
    assert "192.0.2.050".startswith(OLD_PREFIX)
    assert lan_address(["192.0.2.050"], NET) is None


def test_without_a_subnet_the_only_candidate_is_taken() -> None:
    assert lan_address(["127.0.0.1", "169.254.1.1", "192.0.2.9"], None) == "192.0.2.9"


def test_without_a_subnet_several_candidates_are_refused_by_name() -> None:
    # Docker guests also carry a 172.x switch address; picking the first one lands on an address
    # the node cannot reach.
    with pytest.raises(AmbiguousAddressError) as caught:
        lan_address(["172.17.0.1", "192.0.2.9"], None)
    assert caught.value.candidates == ("172.17.0.1", "192.0.2.9")
