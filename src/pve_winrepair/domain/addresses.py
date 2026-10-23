"""The guest's addresses: its LAN address among those its agent reports, and the VM's NIC MACs.

A guest can carry several IPv4 addresses: docker hosts add a Hyper-V/NAT switch (172.x) the node
cannot reach, and every guest has loopback and possibly link-local ones. With the LAN configured
(``[guest] subnet``) the first address inside it is the one; without it, a single candidate is
taken and several are refused rather than guessed.

A guest reached by an address the operator typed (``--ip``) is bound to its VM by MAC: the VM's
``netN`` devices in ``qm config`` (:func:`vm_macs`) against the MACs the guest's own adapters report.
Both sides are compared in one normal form (:func:`normalise_mac`).
"""

from __future__ import annotations

import re
from ipaddress import IPv4Address
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable
    from ipaddress import IPv4Network

__all__ = ["AmbiguousAddressError", "lan_address", "normalise_mac", "vm_macs"]

# Six hex octets with ONE separator throughout (a colon or a dash); ASCII ranges, never \d or \w.
_MAC = re.compile(r"[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4}")
# A network device line of ``qm config``: ``net0: virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,...``. The
# model key (virtio, e1000, vmxnet3, rtl8139, ...) varies; the MAC is the value of that key, or of
# ``macaddr`` in the long form.
_NET_LINE = re.compile(r"net[0-9]+:[ \t]*(\S+)")


class AmbiguousAddressError(ValueError):
    """Several addresses could be the LAN one and no subnet says which.

    Attributes:
        candidates: Every candidate, in the order the agent reported them.
    """

    def __init__(self, candidates: tuple[str, ...]) -> None:
        """Name the ``candidates``."""
        super().__init__(f"several candidate LAN addresses: {', '.join(candidates)}")
        self.candidates = candidates


def _candidates(addresses: Iterable[str]) -> list[IPv4Address]:
    """The parseable IPv4 addresses that are neither loopback nor link-local, deduplicated, in order."""
    found: dict[IPv4Address, None] = {}
    for text in addresses:
        try:
            address = IPv4Address(text)
        except ValueError:  # not dotted-quad IPv4: an IPv6 address, a leading zero, garbage
            continue
        if not (address.is_loopback or address.is_link_local):
            found.setdefault(address, None)
    return list(found)


def lan_address(addresses: Iterable[str], network: IPv4Network | None) -> str | None:
    """The guest's LAN address among ``addresses``, or None when there is none.

    Args:
        addresses: The IPv4 addresses the agent reported, as text; anything unparseable is skipped.
        network: The LAN (``[guest] subnet``), or None when it is not configured.

    Returns:
        The first candidate inside ``network``; without a network, the only candidate.

    Raises:
        AmbiguousAddressError: No network is configured and there is more than one candidate.

    Example:
        >>> from ipaddress import IPv4Network
        >>> lan_address(["172.17.0.1", "192.0.2.9"], IPv4Network("192.0.2.0/24"))
        '192.0.2.9'
        >>> lan_address(["127.0.0.1", "192.0.2.9"], None)
        '192.0.2.9'
    """
    candidates = _candidates(addresses)
    if network is not None:
        return next((str(address) for address in candidates if address in network), None)
    if len(candidates) > 1:
        raise AmbiguousAddressError(tuple(str(address) for address in candidates))
    return str(candidates[0]) if candidates else None


def normalise_mac(text: str) -> str | None:
    """``text`` as ``AA:BB:CC:DD:EE:FF``, or None when it is not six hex octets with one separator.

    Example:
        >>> normalise_mac("bc-24-11-aa-bb-cc"), normalise_mac("bc:24:11")
        ('BC:24:11:AA:BB:CC', None)
    """
    if not _MAC.fullmatch(text):
        return None
    return text.upper().replace("-", ":")


def vm_macs(qm_config: str) -> frozenset[str]:
    """The MAC of every ``netN`` device in ``qm config`` output, normalised.

    Only lines that start with ``net<N>:`` count: a ``description:`` quoting a device line is no
    device. Within the device's property string, any ``key=<MAC>`` value is its MAC.

    Example:
        >>> sorted(vm_macs("net0: virtio=bc:24:11:aa:bb:cc,bridge=vmbr0\\nscsi0: local:vm-1-disk-0\\n"))
        ['BC:24:11:AA:BB:CC']
    """
    found: set[str] = set()
    for line in qm_config.splitlines():
        device = _NET_LINE.fullmatch(line.rstrip())
        if device is None:
            continue
        for item in device.group(1).split(","):
            mac = normalise_mac(item.partition("=")[2])
            if mac is not None:
                found.add(mac)
    return frozenset(found)
