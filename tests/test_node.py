"""Tests for the node bundle: one runner for ``qm`` and every guest, and the port the drivers take."""

from __future__ import annotations

from ipaddress import IPv4Address
from typing import TYPE_CHECKING

from guest_fakes import GUEST_IP, USER, FakeRunner, Reply

from pve_winrepair.adapters.guest_ssh import ssh_options
from pve_winrepair.adapters.node import Node
from pve_winrepair.domain.settings import SshSettings
from pve_winrepair.domain.vm_config import SnapshotResult, VmConfig, VmConfigRead, parse_vm_config

if TYPE_CHECKING:
    from pve_winrepair.application.ports import NodePort

KEY = "/keys/test.key"
SSH = SshSettings(key=KEY, user=USER)


def _ssh(*remote: str) -> list[str]:
    return ["ssh", "-i", KEY, *ssh_options(SSH), f"{USER}@{GUEST_IP}", *remote]


def test_a_node_reaches_its_guests_and_qm_through_one_runner() -> None:
    runner = FakeRunner().on("hostname", Reply(0)).on("qm", Reply(0, "status: running\n"))
    node = Node(ssh=SSH, runner=runner)
    node.guest(IPv4Address(GUEST_IP)).ssh("hostname", timeout=5.0)
    node.qm("status", "100", timeout=30)
    assert runner.calls == [_ssh("hostname"), ["qm", "status", "100"]]
    assert runner.timeouts == [5.0, 30]


def test_node_satisfies_node_port() -> None:
    # pyright checks the assignment: a Protocol data member that is a plain attribute fails it.
    port: NodePort = Node(ssh=SshSettings(key="/k"))
    assert port.guest(IPv4Address("192.0.2.10")).ip == "192.0.2.10"


def test_the_vm_config_is_one_qm_config_call_parsed() -> None:
    text = "scsi0: local-zfs:vm-1-disk-0,size=64G\nnet0: virtio=BC:24:11:AA:BB:CC,bridge=vmbr0\n"
    runner = FakeRunner().on("qm", Reply(0, text))
    read = Node(ssh=SSH, runner=runner).vm_config(100)
    assert read == VmConfigRead(returncode=0, output=text, config=parse_vm_config(text))
    assert (runner.calls, runner.timeouts) == ([["qm", "config", "100"]], [60])


def test_a_failed_qm_config_keeps_its_exit_code_and_quotes_stderr_first() -> None:
    runner = FakeRunner().on("qm", Reply(2, "", "Configuration file 'nodes/x/qemu-server/100.conf' does not exist"))
    read = Node(ssh=SSH, runner=runner).vm_config(100)
    assert read == VmConfigRead(
        returncode=2, output="Configuration file 'nodes/x/qemu-server/100.conf' does not exist", config=VmConfig()
    )


def test_the_snapshots_are_one_qm_listsnapshot_call_parsed() -> None:
    tree = (
        "`-> pre_winrepair              2026-10-24 10:00:00     before an in-place repair upgrade\n"
        "    `-> current                                        You are here!\n"
    )
    runner = FakeRunner().on("qm", Reply(0, tree))
    assert Node(ssh=SSH, runner=runner).snapshots(100) == frozenset({"pre_winrepair"})
    assert (runner.calls, runner.timeouts) == ([["qm", "listsnapshot", "100"]], [60])


def test_a_snapshot_is_one_qm_snapshot_call_with_its_description() -> None:
    runner = FakeRunner().on("qm", Reply(0))
    result = Node(ssh=SSH, runner=runner).snapshot(100, "pre_winrepair", "before an in-place repair upgrade")
    assert result == SnapshotResult(returncode=0, stderr="", fs_frozen=False)
    assert runner.calls == [
        ["qm", "snapshot", "100", "pre_winrepair", "--description", "before an in-place repair upgrade"]
    ]
    assert runner.timeouts == [900]


def test_a_snapshot_whose_output_announces_the_freeze_reports_fs_frozen() -> None:
    # PVE's AbstractConfig prints this line on stdout only when it fsfreezes the guest first.
    runner = FakeRunner().on("qm", Reply(0, "freeze guest filesystem\nsnapshotting 'drive-scsi0' (local-zfs:x)\n"))
    assert Node(ssh=SSH, runner=runner).snapshot(100, "s1", "d").fs_frozen is True


def test_a_freeze_line_on_stderr_counts_too() -> None:
    runner = FakeRunner().on("qm", Reply(0, "", "freeze guest filesystem\n"))
    assert Node(ssh=SSH, runner=runner).snapshot(100, "s1", "d").fs_frozen is True


def test_a_failed_snapshot_keeps_its_exit_code_and_stderr() -> None:
    runner = FakeRunner().on("qm", Reply(255, "", "snapshot feature is not available\n"))
    result = Node(ssh=SSH, runner=runner).snapshot(100, "s1", "d")
    assert result == SnapshotResult(returncode=255, stderr="snapshot feature is not available\n", fs_frozen=False)
