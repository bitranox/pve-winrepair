"""How this machine reaches a PVE node it does not run on: ssh to the node, and the node as the jump to its guests.

A remote command goes to the node as ONE word, quoted with :func:`shlex.join`: ssh joins its remote
argv with spaces and the node's login shell splits it again, so an unquoted ``--description "before
an in-place repair upgrade"`` would reach ``qm`` as five words. The guests sit on the node's network,
so every guest ssh and scp is routed through the node with a ``ProxyCommand`` carrying the NODE key;
plain ``-J`` cannot, since it would offer the guest key to the node. The node's host key is checked
strictly: a node is a stable host, and a changed key is exactly what must stop a run.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from typing import TYPE_CHECKING

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
    """The ssh connection to a remote PVE node: its host, the login user, and this machine's key for it."""

    host: str
    user: str
    key: str

    @property
    def target(self) -> str:
        """``user@host`` as ssh takes it."""
        return f"{self.user}@{self.host}"

    def ssh_argv(self, remote: Sequence[str]) -> list[str]:
        """ssh to the node running ``remote`` there, as one quoted word the node's shell splits back exactly."""
        return ["ssh", "-i", self.key, *_NODE_OPTS, self.target, shlex.join(remote)]

    def proxy_command(self) -> str:
        """The ``ProxyCommand`` that carries a guest connection through the node, logging in with the node key."""
        return shlex.join(["ssh", "-i", self.key, *_NODE_OPTS, "-W", "%h:%p", self.target])

    def jumped(self, runner: Runner) -> Runner:
        """``runner`` with every ssh and scp routed through the node; any other argv passes unchanged."""
        proxy = ("-o", f"ProxyCommand={self.proxy_command()}")

        def run(cmd: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
            if cmd and cmd[0] in _JUMPED:
                return runner([cmd[0], *proxy, *cmd[1:]], timeout)
            return runner(cmd, timeout)

        return run
