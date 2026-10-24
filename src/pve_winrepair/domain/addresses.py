"""The guest's addresses: its LAN address among those its agent reports, and MACs in one normal form.

A guest can carry several IPv4 addresses: docker hosts add a Hyper-V/NAT switch (172.x) the node
cannot reach, and every guest has loopback and possibly link-local ones. With the LAN configured
(``[guest] subnet``) the first address inside it is the one; without it, a single candidate is
taken and several are refused rather than guessed.

A guest reached by an address the operator typed (``--ip``) is bound to its VM by MAC: the VM's
``netN`` devices in ``qm config`` against the MACs the guest's own adapters report (:data:`MacAddress`).
Both sides are compared in one normal form (:func:`normalise_mac`).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Annotated

from pydantic import AfterValidator

if TYPE_CHECKING:
    from collections.abc import Iterable
    from ipaddress import IPv4Address, IPv4Network

__all__ = ["AmbiguousAddressError", "MacAddress", "lan_address", "normalise_mac"]

# Six hex octets with ONE separator throughout (a colon or a dash); ASCII ranges, never \d or \w.
_MAC = re.compile(r"[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4}")


class AmbiguousAddressError(ValueError):
    """Several addresses could be the LAN one and no subnet says which.

    Attributes:
        candidates: Every candidate, in the order the agent reported them.
    """

    def __init__(self, candidates: tuple[IPv4Address, ...]) -> None:
        """Name the ``candidates``."""
        super().__init__(f"several candidate LAN addresses: {', '.join(map(str, candidates))}")
        self.candidates = candidates


def _candidates(addresses: Iterable[IPv4Address]) -> list[IPv4Address]:
    """The addresses that are neither loopback nor link-local, deduplicated, in order."""
    found: dict[IPv4Address, None] = {}
    for address in addresses:
        if not (address.is_loopback or address.is_link_local):
            found.setdefault(address, None)
    return list(found)


def lan_address(addresses: Iterable[IPv4Address], network: IPv4Network | None) -> IPv4Address | None:
    """The guest's LAN address among ``addresses``, or None when there is none.

    Args:
        addresses: The IPv4 addresses the agent reported.
        network: The LAN (``[guest] subnet``), or None when it is not configured.

    Returns:
        The first candidate inside ``network``; without a network, the only candidate.

    Raises:
        AmbiguousAddressError: No network is configured and there is more than one candidate.

    Example:
        >>> from ipaddress import IPv4Address as A, IPv4Network
        >>> lan_address([A("172.17.0.1"), A("192.0.2.9")], IPv4Network("192.0.2.0/24"))
        IPv4Address('192.0.2.9')
        >>> lan_address([A("127.0.0.1"), A("192.0.2.9")], None)
        IPv4Address('192.0.2.9')
    """
    candidates = _candidates(addresses)
    if network is not None:
        return next((address for address in candidates if address in network), None)
    if len(candidates) > 1:
        raise AmbiguousAddressError(tuple(candidates))
    return candidates[0] if candidates else None


def normalise_mac(text: str) -> str | None:
    """``text`` as ``AA:BB:CC:DD:EE:FF``, or None when it is not six hex octets with one separator.

    Example:
        >>> normalise_mac("bc-24-11-aa-bb-cc"), normalise_mac("bc:24:11")
        ('BC:24:11:AA:BB:CC', None)
    """
    if not _MAC.fullmatch(text):
        return None
    return text.upper().replace("-", ":")


def _mac(text: str) -> str:
    """``text`` normalised (:func:`normalise_mac`); a value that is no MAC is refused.

    Raises:
        ValueError: ``text`` is not six hex octets with one separator. The value is not repeated:
            it came from outside.
    """
    mac = normalise_mac(text)
    if mac is None:
        raise ValueError("not a MAC address (six hex octets, one separator)")
    return mac


#: A MAC address as a boundary model holds it: validated and normalised to ``AA:BB:CC:DD:EE:FF``.
MacAddress = Annotated[str, AfterValidator(_mac)]
