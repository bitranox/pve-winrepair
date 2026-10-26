"""Where a repair's installation media come from, and how they reach the guest.

:class:`LocalMedia` is a directory on the machine running the tool: its entries are copied into the
guest by the guest's own scp (through the node when the node is remote). Every entry goes, in name
order, so a run copies exactly what :meth:`pathlib.Path.iterdir` lists.

:class:`NodeMedia` is a directory on a remote node: the node's own scp copies it into the guest on the
node's network, so the media never cross the link from this machine. The node logs in to the guest
with the operator's key through the forwarded ssh-agent (``ssh -A``), so that key is never stored there.
With ``[ssh] strict_host_key_checking`` on, it checks the guest against the host key THIS machine already
checked: the guest's lines from ``[ssh] known_hosts_file`` travel with the copy into a temporary file on
the node. With it off, the node checks no host key, as this machine does not either. Either way the
node's own known_hosts files are neither read nor written.
"""

from __future__ import annotations

# The node-side copy catches the runner's own timeout and failure to start, as subprocess.run raises them.
import subprocess  # nosec B404
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from pve_winrepair.application.ports import TransferTimeoutError

if TYPE_CHECKING:
    from pve_winrepair.application.ports import GuestPort, MediaSource
    from pve_winrepair.domain.envelope import Runner
    from pve_winrepair.domain.node_link import NodeLink
    from pve_winrepair.domain.settings import SshSettings

__all__ = ["LocalMedia", "NodeMedia"]

#: The node-side check, run as ``sh -c <it> sh <dir>``: 10 = no forwarded agent, 11 = no directory, 12 = no
#: entry the copy takes. It asks the same ``*`` glob :data:`_COPY` hands scp, which skips names starting with
#: ".": an unmatched glob stays the literal word, which neither exists nor is a link (a dangling link the glob
#: matched still counts). ``ls -A`` would count dot entries, so a directory holding only those would pass
#: here and reach scp with a literal ``*`` after the snapshot.
_CHECK = (
    'test -n "$SSH_AUTH_SOCK" || exit 10; test -d "$1" || exit 11; '
    'set -- "$1"/*; test -e "$1" || test -L "$1" || exit 12'
)
#: The node-side copy, run as ``sh -c <it> sh <dir> <target> <guest host keys> <scp options...>``: every
#: entry by glob, from inside the dir. Empty host keys mean no check (``[ssh] strict_host_key_checking``
#: off): no known_hosts is read or written, nor any temporary file made. Otherwise the lines go to a
#: private temporary file (umask 077) in ``${TMPDIR:-/tmp}``, the only known_hosts scp consults
#: (GlobalKnownHostsFile=/dev/null), strictly: they were checked on this machine. The explicit mktemp
#: template is what puts it there everywhere: a bare ``mktemp`` picks its own directory, and BSD's
#: (macOS) ignores TMPDIR. In both modes KnownHostsCommand=none comes first (ssh keeps
#: an option's first value), so a KnownHostsCommand in the node's ssh config adds no key beside them.
#: No exec: the EXIT trap removes the file once scp is done, and a signal exits through it as well; the
#: script's status is scp's.
_COPY = (
    "dir=$1; target=$2; keys=$3; shift 3; "
    'if test -z "$keys"; then '
    'set -- -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null "$@"; '
    'else umask 077; known=$(mktemp "${TMPDIR:-/tmp}/pvewr-known.XXXXXX") || exit 1; '
    'trap \'rm -f -- "$known"\' EXIT; trap "exit 129" HUP; trap "exit 130" INT; trap "exit 143" TERM; '
    'printf "%s\\n" "$keys" > "$known" || exit 1; '
    'set -- -o "UserKnownHostsFile=$known" -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes "$@"; fi; '
    'cd -- "$dir" || exit 1; scp -q -r -o KnownHostsCommand=none "$@" -- * "$target"'
)
#: The node scp's options after the trust options :data:`_COPY` sets itself.
_COPY_OPTIONS = (
    "-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey",
    "-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=30",
)  # fmt: skip
_AGENT_TIMEOUT = 10
_KEYGEN_TIMEOUT = 10
_CHECK_TIMEOUT = 30
#: ``ssh-add -l``'s refusals by exit code (man ssh-add: 1 = the agent holds no identity, 2 = no agent).
_AGENT_REASONS = {
    1: "--media node needs the guest key in your ssh-agent, which holds none: ssh-add {key}",
    2: "--media node needs an ssh-agent holding the guest key ([ssh] key): none is reachable (ssh-add -l exit 2)",
}
_CHECK_REASONS = {
    10: "node {target} did not get the forwarded agent (SSH_AUTH_SOCK is empty): allow agent forwarding there",
    11: "media directory missing on node {target}: {directory}",
    12: 'media directory is empty on node {target}: {directory} (names starting with "." are not copied)',
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
    must not carry ``IdentitiesOnly=yes`` (no identity file is configured on the node). With
    ``[ssh] strict_host_key_checking`` on, it checks the guest against the lines ``ssh-keygen -F`` finds
    for it in ``[ssh] known_hosts_file`` on THIS machine, where :meth:`GuestPort.push_tool` has connected
    to the guest before the media are staged; without such a line the copy is refused rather than
    trusting anything the node holds. With it off, nothing is read here and the node checks no key.
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
        """The node's scp copies every entry into the guest directory ``dest``.

        With strict host key checking, refused (a failed process, the node never called) when this machine
        holds no host key for the guest.

        Raises:
            TransferTimeoutError: The copy did not finish within ``timeout``.
        """
        keys = ""  # no check: what _COPY runs without a host key
        if self.ssh.strict_host_key_checking:
            known = self._guest_host_keys(guest.ip)
            if isinstance(known, str):
                return subprocess.CompletedProcess(["ssh-keygen"], 255, "", known)
            keys = "\n".join(known)
        target = f"{self.ssh.user}@{guest.ip}:{dest}"
        remote = ["sh", "-c", _COPY, "sh", self.directory, target, keys, *_COPY_OPTIONS]
        argv = self.link.ssh_argv(remote, forward_agent=True)
        try:
            return self.runner(argv, timeout)
        except subprocess.TimeoutExpired as exc:
            raise TransferTimeoutError(f"media transfer: timed out after {timeout:g} s") from exc
        except OSError as exc:
            return subprocess.CompletedProcess(argv, 255, "", f"media transfer: could not run ssh: {exc}")

    def _guest_host_keys(self, ip: str) -> list[str] | str:
        """The guest's lines in this machine's ``[ssh] known_hosts_file``, or why there are none to hand over."""
        # ssh expands a leading "~" itself, ssh-keygen -f does not: expanded here the way ssh would. Any
        # other path is passed as written, never normalised, so the message names the configured file.
        configured = self.ssh.known_hosts_file
        file = str(Path(configured).expanduser()) if configured.startswith("~") else configured
        found = self._run(["ssh-keygen", "-F", ip, "-f", file], _KEYGEN_TIMEOUT)
        if isinstance(found, str):
            return f"cannot read the host key of guest {ip} from {file}: {found}"
        # ssh-keygen -F exits 1 when no line matches, and prints a "# Host ... found" comment before each line.
        lines = [line for line in found.stdout.splitlines() if line.strip() and not line.startswith("#")]
        if found.returncode == 0 and lines:
            return lines
        if found.returncode in (0, 1):
            return (
                f"no host key for guest {ip} in {file}: --media node trusts only the guest key this machine "
                "checked; connect to the guest once from here (or run --media local)"
            )
        stderr = found.stderr.strip().splitlines()
        cause = stderr[-1] if stderr else f"ssh-keygen exit {found.returncode}"
        return f"cannot read the host key of guest {ip} from {file}: {cause}"

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
