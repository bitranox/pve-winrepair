"""The PVE node a driver runs on: how it runs ``qm`` and ssh, waits, and reaches a guest.

:class:`Node` is the one bundle the drivers take, and the tests' seam: a fake runner and clock passed
here observe every node and guest call in order. :func:`run` is the production runner. A node with a
:class:`~pve_winrepair.domain.node_link.NodeLink` is a remote one: ``qm`` runs there over ssh and
every guest call is routed through it. :meth:`Node.media` is the media a run stages
(:mod:`pve_winrepair.adapters.media`).

The VM's own configuration, its snapshot list and a snapshot's outcome are parsed here, where ``qm`` answers
(:mod:`pve_winrepair.domain.vm_config`), so no driver reads ``qm`` text; a guest's address becomes
text only here too, where ssh needs it as an argument.
"""

from __future__ import annotations

# The preflight catches the runner's own timeout and failure to start, as subprocess.run raises them.
import subprocess  # nosec B404
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from pve_winrepair.adapters.guest_ssh import TOOL_DIR, Guest, run
from pve_winrepair.adapters.media import LocalMedia
from pve_winrepair.domain.vm_config import (
    SnapshotResult,
    VmConfigRead,
    parse_snapshot_names,
    parse_snapshot_result,
    parse_vm_config,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from ipaddress import IPv4Address

    from pve_winrepair.application.ports import MediaSource
    from pve_winrepair.domain.envelope import Runner
    from pve_winrepair.domain.node_link import NodeLink
    from pve_winrepair.domain.settings import SshSettings

__all__ = ["Node", "run"]

#: Seconds the preflight waits for the node; ssh's own ``ConnectTimeout`` (20 s) ends a dead connect first.
_PREFLIGHT_TIMEOUT = 30


@dataclass(frozen=True)
class Node:
    """The PVE node a driver runs on: how it runs ``qm`` and ssh, waits, and reaches a guest.

    One bundle so every PVE step and every guest call goes through the same runner; the tests pass
    a fake runner and clock here and observe the whole sequence of node and guest calls in order.
    """

    ssh: SshSettings
    # None: this machine is the node, and every argv is exactly what it was before remote nodes existed.
    link: NodeLink | None = None
    runner: Runner = run
    clock: Callable[[], float] = time.time
    sleep: Callable[[float], None] = time.sleep
    tool_dir: Path = TOOL_DIR

    def qm(self, *args: str, timeout: int = 600) -> subprocess.CompletedProcess[str]:
        """Run ``qm`` on this node: here, or over ssh on the linked node."""
        argv = ["qm", *args] if self.link is None else self.link.ssh_argv(["qm", *args])
        return self.runner(argv, timeout)

    def check_link(self) -> str | None:
        """Why the linked node cannot be used, or None (also when there is no link).

        One round trip proves the node answers, accepts the key, has a known host key, and has
        ``qm``. Exit codes are not interpreted beyond 0 / 1: ssh's own text says what failed.
        """
        if self.link is None:
            return None
        prefix = f"node {self.link.target} is not usable"
        try:
            proc = self.runner(self.link.ssh_argv(["command", "-v", "qm"]), _PREFLIGHT_TIMEOUT)
        except subprocess.TimeoutExpired:
            return f"{prefix}: no answer within {_PREFLIGHT_TIMEOUT} s"
        except OSError as exc:
            return f"{prefix}: ssh could not start ({exc})"
        if proc.returncode == 0:
            return None
        lines = proc.stderr.strip().splitlines()
        return f"{prefix}: {lines[-1]}" if lines else f"{prefix}: no qm there (not a PVE node?)"

    def vm_config(self, vmid: int) -> VmConfigRead:
        """``qm config <vmid>``: its exit code, the output a refusal quotes, and its stdout parsed."""
        proc = self.qm("config", str(vmid), timeout=60)
        return VmConfigRead(
            returncode=proc.returncode, output=proc.stderr or proc.stdout, config=parse_vm_config(proc.stdout)
        )

    def snapshots(self, vmid: int) -> frozenset[str]:
        """The names ``qm listsnapshot <vmid>`` lists, without PVE's ``current`` marker."""
        return parse_snapshot_names(self.qm("listsnapshot", str(vmid), timeout=60).stdout)

    def snapshot(self, vmid: int, name: str, description: str) -> SnapshotResult:
        """``qm snapshot <vmid> <name> --description <description>``: exit code, stderr, and whether it froze the fs."""
        proc = self.qm("snapshot", str(vmid), name, "--description", description, timeout=900)
        return parse_snapshot_result(proc.returncode, proc.stdout, proc.stderr)

    def guest(self, ip: IPv4Address) -> Guest:
        """The guest at ``ip``, reached with this node's ssh settings and tool dir, through the linked node if any."""
        runner = self.runner if self.link is None else self.link.jumped(self.runner)
        return Guest(str(ip), ssh_settings=self.ssh, tool_dir=self.tool_dir, runner=runner)

    def media(self, directory: str, *, from_node: bool) -> MediaSource:
        """The media in ``directory``; always on this machine until node-side media exist (Task 2.7)."""
        return LocalMedia(Path(directory))
