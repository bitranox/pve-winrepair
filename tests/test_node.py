"""Tests for the node bundle: one runner for ``qm`` and every guest, and the port the drivers take."""

from __future__ import annotations

import subprocess
from ipaddress import IPv4Address
from typing import TYPE_CHECKING

import pytest
from guest_fakes import GUEST_IP, NODE_LINK, USER, FakeRunner, Reply, route

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


def test_without_a_link_qm_runs_here_exactly_as_before() -> None:
    runner = FakeRunner().on("qm", Reply(0, "status: running\n"))
    Node(ssh=SSH, runner=runner).qm("status", "100", timeout=30)
    assert runner.calls == [["qm", "status", "100"]]


def test_with_a_link_qm_runs_on_the_node_as_one_quoted_command() -> None:
    runner = FakeRunner().on("qm", Reply(0))
    Node(ssh=SSH, link=NODE_LINK, runner=runner).snapshot(100, "s1", "before an in-place repair upgrade")
    assert runner.calls == [
        NODE_LINK.ssh_argv(["qm", "snapshot", "100", "s1", "--description", "before an in-place repair upgrade"])
    ]
    assert runner.timeouts == [900]


def test_with_a_link_the_parsed_reads_go_to_the_node_too() -> None:
    runner = FakeRunner().on("qm", Reply(0, "scsi0: local-zfs:vm-1-disk-0,size=64G\n"))
    read = Node(ssh=SSH, link=NODE_LINK, runner=runner).vm_config(100)
    assert read.config.disks[0].storage == "local-zfs"
    assert runner.calls == [NODE_LINK.ssh_argv(["qm", "config", "100"])]


def test_with_a_link_the_guest_is_reached_through_the_node() -> None:
    runner = FakeRunner().on("hostname", Reply(0))
    Node(ssh=SSH, link=NODE_LINK, runner=runner).guest(IPv4Address(GUEST_IP)).ssh("hostname", timeout=5.0)
    assert runner.calls == [["ssh", "-o", f"ProxyCommand={NODE_LINK.proxy_command()}", *_ssh("hostname")[1:]]]


def test_the_fakes_route_a_remote_qm_call_as_qm() -> None:
    assert route(NODE_LINK.ssh_argv(["qm", "status", "1"])) == "qm"


def test_the_fakes_route_a_remote_call_by_its_first_word() -> None:
    assert route(NODE_LINK.ssh_argv(["command", "-v", "qm"])) == "command"


def test_no_link_needs_no_preflight_call() -> None:
    runner = FakeRunner()
    assert Node(ssh=SSH, runner=runner).check_link() is None
    assert runner.calls == []


def test_a_usable_node_answers_the_preflight() -> None:
    runner = FakeRunner().on("command", Reply(0, "/usr/sbin/qm\n"))
    assert Node(ssh=SSH, link=NODE_LINK, runner=runner).check_link() is None
    assert runner.calls == [NODE_LINK.ssh_argv(["command", "-v", "qm"])]


@pytest.mark.parametrize(
    "stderr",
    [
        "Host key verification failed.",
        "root@pve1: Permission denied (publickey).",
        "ssh: connect to host pve1 port 22: Connection timed out",
    ],
)
def test_a_link_failure_is_reported_in_ssh_s_own_words(stderr: str) -> None:
    runner = FakeRunner().on("command", Reply(255, "", stderr + "\n"))
    assert Node(ssh=SSH, link=NODE_LINK, runner=runner).check_link() == f"node root@pve1 is not usable: {stderr}"


def test_ssh_s_last_line_is_the_reason_after_its_warnings() -> None:
    stderr = (
        "Warning: Permanently added 'pve1' (ED25519) to the list of known hosts.\n"
        "root@pve1: Permission denied (publickey).\n"
    )
    runner = FakeRunner().on("command", Reply(255, "", stderr))
    assert Node(ssh=SSH, link=NODE_LINK, runner=runner).check_link() == (
        "node root@pve1 is not usable: root@pve1: Permission denied (publickey)."
    )


def test_an_ssh_that_cannot_start_is_reported() -> None:
    runner = FakeRunner().on("command", FileNotFoundError(2, "No such file or directory", "ssh"))
    reason = Node(ssh=SSH, link=NODE_LINK, runner=runner).check_link()
    assert reason == "node root@pve1 is not usable: ssh could not start ([Errno 2] No such file or directory: 'ssh')"


def test_a_host_without_qm_is_no_pve_node() -> None:
    runner = FakeRunner().on("command", Reply(1))
    assert (
        Node(ssh=SSH, link=NODE_LINK, runner=runner).check_link()
        == "node root@pve1 is not usable: no qm there (not a PVE node?)"
    )


def test_a_preflight_that_times_out_is_reported() -> None:
    runner = FakeRunner().on("command", subprocess.TimeoutExpired(["ssh"], 30))
    reason = Node(ssh=SSH, link=NODE_LINK, runner=runner).check_link()
    assert reason is not None and reason.startswith("node root@pve1 is not usable: no answer within 30 s")
