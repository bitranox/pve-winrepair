"""The packed guest tool as the node knows it, and what a push left on the guest.

:class:`PackedTool` names the node's packed tool and the content address it gets on the guest
(``C:\\winrepair\\winrepair_guest-<first 16 hex of its sha256>.ps1``); :class:`Pushed` is the
result of putting it there. The ssh adapter (:mod:`pve_winrepair.adapters.guest_ssh`) builds and
pushes them.
"""

from __future__ import annotations

import ntpath
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

__all__ = ["PackedTool", "Pushed"]


@dataclass(frozen=True)
class PackedTool:
    """The packed tool on this node and the content address it gets on the guest.

    Attributes:
        source: The packed tool on this node.
        guest_path: Its content address on the guest.
        sha256: Its full sha256, which every guest copy is checked against before it runs.
    """

    source: Path
    guest_path: str
    sha256: str

    @property
    def staged(self) -> str:
        """The profile copy's name: plain, so ssh and scp resolve it in the ssh user's profile."""
        return ntpath.basename(self.guest_path)


@dataclass(frozen=True)
class Pushed:
    """Where the tool is on the guest, and whether this push copied it (False: already there).

    Attributes:
        path: The content address.
        copied: Whether this push copied it in.
        staged_left: Why the profile copy could not be removed, or None once it is gone. A copy
            left there is not a failure of the push: only an administrator can write the profile,
            and the next push overwrites it.
    """

    path: str
    copied: bool
    staged_left: str | None = None
