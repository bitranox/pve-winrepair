"""Tests for picking the guest's LAN address out of what its agent reports."""

from __future__ import annotations

import ipaddress

import pytest

from pve_winrepair.domain.addresses import AmbiguousAddressError, lan_address, normalise_mac, vm_macs

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


# --- the VM's NIC MACs, as qm config lists them ---------------------------------------------


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


def test_vm_macs_reads_every_net_line_whatever_the_model() -> None:
    config = (
        "boot: order=scsi0;net0\n"
        "net0: virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,firewall=1\n"
        "net1: e1000=bc:24:11:00:00:01,bridge=vmbr1,tag=40\n"
        "net2: vmxnet3=BC:24:11:00:00:02,bridge=vmbr0\n"
        "net13: rtl8139=BC:24:11:00:00:03,bridge=vmbr0,link_down=1\n"
        "scsi0: local-zfs:vm-1-disk-0,size=64G\n"
    )
    assert vm_macs(config) == frozenset(
        {"BC:24:11:AA:BB:CC", "BC:24:11:00:00:01", "BC:24:11:00:00:02", "BC:24:11:00:00:03"}
    )


def test_vm_macs_ignores_what_is_not_a_net_device_line() -> None:
    config = (
        "description: moved from net0: virtio=BC:24:11:99:99:99\n"
        "#net0: virtio=BC:24:11:99:99:98,bridge=vmbr0\n"
        "netx: virtio=BC:24:11:99:99:97\n"
        "scsi0: local-zfs:vm-1-disk-0,size=64G\n"
    )
    assert vm_macs(config) == frozenset()


def test_vm_macs_takes_the_macaddr_key_too() -> None:
    assert vm_macs("net0: model=virtio,macaddr=BC:24:11:AA:BB:CC,bridge=vmbr0\n") == {"BC:24:11:AA:BB:CC"}
