"""Where a repair's installation media come from, and how they reach the guest.

:class:`LocalMedia` is a directory on the machine running the tool: its entries are copied into the
guest by the guest's own scp (through the node when the node is remote). Every entry goes, in name
order, so a run copies exactly what :meth:`pathlib.Path.iterdir` lists.

:class:`NodeMedia` is a directory on a remote node: the node's own scp copies it into the guest on the
node's network, so the media never cross the link from this machine. The node logs in to the guest
with the operator's key through the forwarded ssh-agent (``ssh -A``), so that key is never stored there.
"""

from __future__ import annotations

# The node-side copy catches the runner's own timeout and failure to start, as subprocess.run raises them.
import subprocess  # nosec B404
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from pve_winrepair.application.ports import GuestPort, MediaSource
    from pve_winrepair.domain.envelope import Runner
    from pve_winrepair.domain.node_link import NodeLink
    from pve_winrepair.domain.settings import SshSettings

__all__ = ["LocalMedia", "NodeMedia"]

#: The node-side check, run as ``sh -c <it> sh <dir>``: 10 = no forwarded agent, 11 = no directory, 12 = empty.
_CHECK = 'test -n "$SSH_AUTH_SOCK" || exit 10; test -d "$1" || exit 11; test -n "$(ls -A -- "$1")" || exit 12'
#: The node-side copy, run as ``sh -c <it> sh <dir> <target> <scp options...>``: every entry by glob,
#: from inside the dir.
_COPY = 'dir=$1; target=$2; shift 2; cd -- "$dir" && exec scp -q -r "$@" -- * "$target"'
_AGENT_TIMEOUT = 10
_CHECK_TIMEOUT = 30
#: ``ssh-add -l``'s refusals by exit code (man ssh-add: 1 = the agent holds no identity, 2 = no agent).
_AGENT_REASONS = {
    1: "--media node needs the guest key in your ssh-agent, which holds none: ssh-add {key}",
    2: "--media node needs an ssh-agent holding the guest key ([ssh] key): none is reachable (ssh-add -l exit 2)",
}
_CHECK_REASONS = {
    10: "node {target} did not get the forwarded agent (SSH_AUTH_SOCK is empty): allow agent forwarding there",
    11: "media directory missing on node {target}: {directory}",
    12: "media directory is empty on node {target}: {directory}",
}


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


@dataclass(frozen=True)
class NodeMedia:
    """The media in a directory on a remote node, copied node -> guest on the node's own network.

    The node's scp logs in to the guest with the operator's key through the forwarded agent, so it
    must not carry ``IdentitiesOnly=yes`` (no identity file is configured on the node) and checks the
    guest against the node's own known_hosts: ``[ssh] known_hosts_file`` names a file on THIS machine.
    """

    directory: str
    link: NodeLink
    ssh: SshSettings
    runner: Runner

    def check(self) -> str | None:
        """Why the node's media cannot be staged from (no agent, no forwarding, no or empty dir); None when they can."""
        # The agent first: without a key in it the node is not asked at all.
        return self._agent_problem() or self._node_problem()

    def _agent_problem(self) -> str | None:
        """Why this machine's ssh-agent cannot lend the node a key, or None when it holds one."""
        agent = self._run(["ssh-add", "-l"], _AGENT_TIMEOUT)
        if isinstance(agent, str):
            return agent
        reason = _AGENT_REASONS.get(agent.returncode)
        return None if reason is None else reason.format(key=self.ssh.key)

    def _node_problem(self) -> str | None:
        """Why the node cannot stage from its directory (no forwarded agent, no or empty dir), or None."""
        argv = self.link.ssh_argv(["sh", "-c", _CHECK, "sh", self.directory], forward_agent=True)
        node = self._run(argv, _CHECK_TIMEOUT)
        if isinstance(node, str):
            return node
        if node.returncode == 0:
            return None
        reason = _CHECK_REASONS.get(node.returncode)
        if reason is not None:
            return reason.format(target=self.link.target, directory=self.directory)
        lines = node.stderr.strip().splitlines()
        return f"cannot check the media on node {self.link.target}: {lines[-1] if lines else f'exit {node.returncode}'}"

    def copy_into(self, guest: GuestPort, dest: str, *, timeout: float) -> subprocess.CompletedProcess[str]:
        """The node scp's every entry into the guest directory ``dest``; a timeout comes back as a failed process."""
        checking = "yes" if self.ssh.strict_host_key_checking else "no"
        options = [
            "-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey",
            "-o", f"StrictHostKeyChecking={checking}", "-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=30",
        ]  # fmt: skip
        target = f"{self.ssh.user}@{guest.ip}:{dest}"
        argv = self.link.ssh_argv(["sh", "-c", _COPY, "sh", self.directory, target, *options], forward_agent=True)
        try:
            return self.runner(argv, timeout)
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(argv, 255, "", f"media transfer: timed out after {timeout:g} s")
        except OSError as exc:
            return subprocess.CompletedProcess(argv, 255, "", f"media transfer: could not run ssh: {exc}")

    def _run(self, argv: list[str], timeout: float) -> subprocess.CompletedProcess[str] | str:
        """The finished process, or why it did not finish (a timeout, a command that could not start)."""
        try:
            return self.runner(argv, timeout)
        except subprocess.TimeoutExpired:
            return f"{argv[0]} gave no answer within {timeout:g} s"
        except OSError as exc:
            return f"could not run {argv[0]}: {exc}"


if TYPE_CHECKING:
    from pve_winrepair.adapters.guest_ssh import run

    _assert_local_media: MediaSource = LocalMedia(Path())
    _assert_node_media: MediaSource = NodeMedia("", NodeLink("", "", "", ""), SshSettings(), run)
