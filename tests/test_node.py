"""Tests for the node bundle: one runner for ``qm`` and every guest, and the port the drivers take."""

from __future__ import annotations

from typing import TYPE_CHECKING

from guest_fakes import GUEST_IP, USER, FakeRunner, Reply

from pve_winrepair.adapters.guest_ssh import ssh_options
from pve_winrepair.adapters.node import Node
from pve_winrepair.domain.settings import SshSettings

if TYPE_CHECKING:
    from pve_winrepair.application.ports import NodePort

KEY = "/keys/test.key"
SSH = SshSettings(key=KEY, user=USER)


def _ssh(*remote: str) -> list[str]:
    return ["ssh", "-i", KEY, *ssh_options(SSH), f"{USER}@{GUEST_IP}", *remote]


def test_a_node_reaches_its_guests_and_qm_through_one_runner() -> None:
    runner = FakeRunner().on("hostname", Reply(0)).on("qm", Reply(0, "status: running\n"))
    node = Node(ssh=SSH, runner=runner)
    node.guest(GUEST_IP).ssh("hostname", timeout=5.0)
    node.qm("status", "100", timeout=30)
    assert runner.calls == [_ssh("hostname"), ["qm", "status", "100"]]
    assert runner.timeouts == [5.0, 30]


def test_node_satisfies_node_port() -> None:
    # pyright checks the assignment: a Protocol data member that is a plain attribute fails it.
    port: NodePort = Node(ssh=SshSettings(key="/k"))
    assert port.guest("192.0.2.10").ip == "192.0.2.10"
