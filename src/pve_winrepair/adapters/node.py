"""The PVE node a driver runs on: how it runs ``qm`` and ssh, waits, and reaches a guest.

:class:`Node` is the one bundle the drivers take, and the tests' seam: a fake runner and clock passed
here observe every node and guest call in order. :func:`run` is the production runner.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from pve_winrepair.adapters.guest_ssh import TOOL_DIR, Guest, run

if TYPE_CHECKING:
    # qm runs through the runner; this module only names the finished process's type.
    import subprocess  # nosec B404
    from collections.abc import Callable
    from pathlib import Path

    from pve_winrepair.domain.envelope import Runner
    from pve_winrepair.domain.settings import SshSettings

__all__ = ["Node", "run"]


@dataclass(frozen=True)
class Node:
    """The PVE node a driver runs on: how it runs ``qm`` and ssh, waits, and reaches a guest.

    One bundle so every PVE step and every guest call goes through the same runner; the tests pass
    a fake runner and clock here and observe the whole sequence of node and guest calls in order.
    """

    ssh: SshSettings
    runner: Runner = run
    clock: Callable[[], float] = time.time
    sleep: Callable[[float], None] = time.sleep
    tool_dir: Path = TOOL_DIR

    def qm(self, *args: str, timeout: int = 600) -> subprocess.CompletedProcess[str]:
        """Run ``qm`` on this node."""
        return self.runner(["qm", *args], timeout)

    def guest(self, ip: str) -> Guest:
        """The guest at ``ip``, reached with this node's ssh settings, tool dir and runner."""
        return Guest(ip, ssh_settings=self.ssh, tool_dir=self.tool_dir, runner=self.runner)
