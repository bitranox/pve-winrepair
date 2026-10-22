"""Pick the guest's LAN address out of the addresses its agent reports.

A guest can carry several IPv4 addresses: docker hosts add a Hyper-V/NAT switch (172.x) the node
cannot reach, and every guest has loopback and possibly link-local ones. With the LAN configured
(``[guest] subnet``) the first address inside it is the one; without it, a single candidate is
taken and several are refused rather than guessed.
"""

from __future__ import annotations

from ipaddress import IPv4Address
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable
    from ipaddress import IPv4Network

__all__ = ["AmbiguousAddressError", "lan_address"]


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
