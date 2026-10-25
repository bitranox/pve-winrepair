"""How this machine reaches a PVE node it does not run on: ssh to the node, and the node as the jump to its guests.

A remote command goes to the node as ONE word, quoted with :func:`shlex.join`: ssh joins its remote
argv with spaces and the node's login shell splits it again, so an unquoted ``--description "before
an in-place repair upgrade"`` would reach ``qm`` as five words. The guests sit on the node's network,
so every guest ssh and scp is routed through the node with a ``ProxyCommand`` carrying the NODE key;
plain ``-J`` cannot, since it would offer the guest key to the node. That ``ProxyCommand`` is one
string: on POSIX :func:`shlex.join` quotes it for ssh's ``/bin/sh -c``; Win32-OpenSSH parses it itself
and reads POSIX single quotes as part of a path (measured, OpenSSH_for_Windows 10.0p2), so on Windows
its two path words are double-quoted instead. The path characters neither form carries (whitespace in
the known_hosts file, ``"``, ``%``) are refused when a link is built, by the rules in
:mod:`pve_winrepair.domain.ssh_paths` that the settings apply at load. The node's host key is checked
strictly: a node is a stable host, and a changed key is exactly what must stop a run.
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from typing import TYPE_CHECKING

from pve_winrepair.domain.ssh_paths import jump_key_problem, known_hosts_problem

if TYPE_CHECKING:
    # The runner returns a finished process; this module only names its type.
    import subprocess  # nosec B404
    from collections.abc import Sequence

    from pve_winrepair.domain.envelope import Runner

__all__ = ["NodeLink"]

_NODE_OPTS = (
    "-o", "BatchMode=yes",
    "-o", "PreferredAuthentications=publickey",
    "-o", "IdentitiesOnly=yes",
    "-o", "StrictHostKeyChecking=yes",
    "-o", "ConnectTimeout=20",
    "-o", "ServerAliveInterval=30",
)  # fmt: skip
_JUMPED = frozenset({"ssh", "scp"})


@dataclass(frozen=True)
class NodeLink:
    """The ssh connection to a remote PVE node: host, login user, this machine's key, the known_hosts file."""

    host: str
    user: str
    key: str
    # Required, never defaulted: the node's host key is checked strictly, against this file.
    known_hosts: str

    def __post_init__(self) -> None:
        # The same rules the settings apply at load, so no caller can build a link ssh would misread.
        problem = jump_key_problem(self.key) or known_hosts_problem(self.known_hosts, through_jump=True)
        if problem:
            raise ValueError(problem)

    @property
    def target(self) -> str:
        """``user@host`` as ssh takes it."""
        return f"{self.user}@{self.host}"

    def ssh_argv(self, remote: Sequence[str]) -> list[str]:
        """ssh to the node running ``remote`` there, as one quoted word the node's shell splits back exactly."""
        return ["ssh", "-i", self.key, *self._options(), self.target, shlex.join(remote)]

    def proxy_command(self, *, windows: bool | None = None) -> str:
        """The ``ProxyCommand`` that carries a guest connection through the node, logging in with the node key.

        On POSIX it is :func:`shlex.join`-quoted for ssh's ``/bin/sh -c``. Win32-OpenSSH parses the string
        itself and reads POSIX single quotes as part of the path (measured, OpenSSH_for_Windows 10.0p2), so on
        Windows the two path words are double-quoted - always, also when they hold no space, which is the form
        that was measured to work. ``windows`` defaults to the machine running the tool.

        Example:
            >>> link = NodeLink(host="pve1", user="root", key="/k", known_hosts="/kh")
            >>> link.proxy_command(windows=True).split(" -o ")[-1]
            '"UserKnownHostsFile=/kh" -W %h:%p root@pve1'
            >>> link.proxy_command(windows=False).split(" -o ")[-1]
            'UserKnownHostsFile=/kh -W %h:%p root@pve1'
        """
        if os.name == "nt" if windows is None else windows:
            known = f'"UserKnownHostsFile={self.known_hosts}"'
            return " ".join(["ssh", "-i", f'"{self.key}"', *_NODE_OPTS, "-o", known, "-W", "%h:%p", self.target])
        return shlex.join(["ssh", "-i", self.key, *self._options(), "-W", "%h:%p", self.target])

    def _options(self) -> tuple[str, ...]:
        # One place for both commands: the node connection and the jump check the same host key file.
        # The Windows ProxyCommand spells the same options with its path word double-quoted.
        return (*_NODE_OPTS, "-o", f"UserKnownHostsFile={self.known_hosts}")

    def jumped(self, runner: Runner, *, windows: bool | None = None) -> Runner:
        """``runner`` with every ssh and scp routed through the node; any other argv passes unchanged.

        ``windows`` picks the :meth:`proxy_command` form, defaulting to the machine running the tool.
        """
        proxy = ("-o", f"ProxyCommand={self.proxy_command(windows=windows)}")

        def run(cmd: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
            if cmd and cmd[0] in _JUMPED:
                return runner([cmd[0], *proxy, *cmd[1:]], timeout)
            return runner(cmd, timeout)

        return run
