"""Where a repair's installation media come from, and how they reach the guest.

:class:`LocalMedia` is a directory on the machine running the tool: its entries are copied into the
guest by the guest's own scp (through the node when the node is remote). Every entry goes, in name
order, so a run copies exactly what :meth:`pathlib.Path.iterdir` lists.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # The guest's copy returns a finished process; this module only names its type.
    import subprocess  # nosec B404
    from pathlib import Path

    from pve_winrepair.application.ports import GuestPort, MediaSource

__all__ = ["LocalMedia"]


@dataclass(frozen=True)
class LocalMedia:
    """The media in a directory on this machine."""

    directory: Path

    def check(self) -> str | None:
        """Why the directory cannot be staged from: it is missing or empty; None when it can."""
        if not self.directory.is_dir():
            return f"media directory missing: {self.directory}"
        if next(self.directory.iterdir(), None) is None:
            return f"media directory is empty: {self.directory}"
        return None

    def copy_into(self, guest: GuestPort, dest: str, *, timeout: float) -> subprocess.CompletedProcess[str]:
        """scp every entry, in name order, into the guest directory ``dest``."""
        return guest.copy_to([str(p) for p in sorted(self.directory.iterdir())], dest, timeout=timeout)


if TYPE_CHECKING:
    _assert_local_media: MediaSource = LocalMedia(Path())
