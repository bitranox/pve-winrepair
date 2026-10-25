"""Tests for where a repair's installation media come from: :class:`LocalMedia` and :class:`NodeMedia`.

:class:`LocalMedia` is a directory on this machine, :class:`NodeMedia` one on a remote node.

Every copy goes through the ``FakeRunner`` seam - the guest's own scp for local media, the node's
scp over ``ssh -A`` for node media - so these tests see the argv and the timeout the real transfer
would get.
"""

from __future__ import annotations

import shlex
import subprocess
from typing import TYPE_CHECKING

import pytest
from guest_fakes import GUEST_IP, NODE_LINK, USER, Answer, FakeRunner, Reply, make_guest

from pve_winrepair.adapters.media import LocalMedia, NodeMedia
from pve_winrepair.domain.settings import SshSettings

if TYPE_CHECKING:
    from pathlib import Path

MEDIA = "/mnt/iso"


def test_local_media_copies_every_entry_in_name_order(tmp_path: Path) -> None:
    for name in ("sources", "boot", "setup.exe"):
        (tmp_path / name).touch()
    runner = FakeRunner().on("scp", Reply(0))
    LocalMedia(tmp_path).copy_into(make_guest(runner), "D:\\upgrade\\", timeout=5400)
    assert runner.calls[0][-4:-1] == [str(tmp_path / n) for n in ("boot", "setup.exe", "sources")]
    assert runner.timeouts == [5400]


def test_local_media_refuses_a_missing_and_an_empty_directory(tmp_path: Path) -> None:
    assert LocalMedia(tmp_path / "gone").check() == f"media directory missing: {tmp_path / 'gone'}"
    assert LocalMedia(tmp_path).check() == f"media directory is empty: {tmp_path}"
    (tmp_path / "setup.exe").touch()
    assert LocalMedia(tmp_path).check() is None


def _node_media(runner: FakeRunner, *, strict: bool = True) -> NodeMedia:
    return NodeMedia(
        MEDIA, NODE_LINK, SshSettings(key="/keys/guest.key", user=USER, strict_host_key_checking=strict), runner
    )


def test_a_usable_node_media_dir_is_checked_with_one_agent_and_one_node_call() -> None:
    runner = FakeRunner().on("ssh-add", Reply(0, "256 SHA256:x guest (ED25519)\n")).on("sh", Reply(0))
    assert _node_media(runner).check() is None
    assert runner.calls[0] == ["ssh-add", "-l"]
    assert runner.calls[1][:2] == ["ssh", "-A"] and shlex.split(runner.calls[1][-1])[-1] == MEDIA
    assert len(runner.calls) == 2


@pytest.mark.parametrize(
    ("agent", "node", "reason"),
    [
        (Reply(2, "", "Could not open a connection to your authentication agent.\n"), None, "needs an ssh-agent"),
        (Reply(1, "The agent has no identities.\n"), None, "ssh-add /keys/guest.key"),
        (OSError("No such file or directory: 'ssh-add'"), None, "could not run ssh-add: No such file"),
        (subprocess.TimeoutExpired(["ssh-add"], 10), None, "ssh-add gave no answer within 10 s"),
        (Reply(0, "256 k\n"), Reply(10), "did not get the forwarded agent"),
        (Reply(0, "256 k\n"), Reply(11), "media directory missing on node root@pve1: /mnt/iso"),
        (Reply(0, "256 k\n"), Reply(12), "media directory is empty on node root@pve1: /mnt/iso"),
        (
            Reply(0, "256 k\n"),
            Reply(255, "", "ssh: connect to host pve1 port 22: Connection refused\n"),
            "Connection refused",
        ),
        (Reply(0, "256 k\n"), Reply(7), "cannot check the media on node root@pve1: exit 7"),
        (Reply(0, "256 k\n"), subprocess.TimeoutExpired(["ssh"], 30), "ssh gave no answer within 30 s"),
    ],
)  # fmt: skip
def test_unusable_node_media_are_refused_in_one_sentence(agent: Answer, node: Answer | None, reason: str) -> None:
    runner = FakeRunner().on("ssh-add", agent)
    if node is not None:
        runner.on("sh", node)
    message = _node_media(runner).check()
    assert message is not None and reason in message
    # An agent that cannot serve the guest key stops the check before the node is asked.
    assert len(runner.calls) == (1 if node is None else 2)


def test_the_node_copies_with_the_forwarded_key_and_never_identities_only() -> None:
    runner = FakeRunner().on("sh", Reply(0))
    _node_media(runner, strict=False).copy_into(make_guest(runner), "D:\\upgrade\\", timeout=5400)
    remote = shlex.split(runner.calls[0][-1])
    assert runner.calls[0][:2] == ["ssh", "-A"] and runner.timeouts == [5400]
    # sh -c <script> <$0> <dir> <target> <scp options...>
    assert remote[:2] == ["sh", "-c"] and remote[3:6] == ["sh", MEDIA, f"{USER}@{GUEST_IP}:D:\\upgrade\\"]
    assert remote[6:] == [
        "-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey",
        "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=30",
    ]  # fmt: skip
    assert "StrictHostKeyChecking=no" in remote and not any(w.startswith("IdentitiesOnly") for w in remote)
    assert not any(w.startswith("UserKnownHostsFile") for w in remote)  # the node's own default (plan risk 3)


def test_a_node_copy_that_times_out_is_a_failed_transfer() -> None:
    runner = FakeRunner().on("sh", subprocess.TimeoutExpired(["ssh"], 5400))
    proc = _node_media(runner).copy_into(make_guest(runner), "D:\\upgrade\\", timeout=5400)
    assert (proc.returncode, proc.stderr) == (255, "media transfer: timed out after 5400 s")


def test_a_node_copy_whose_ssh_cannot_start_is_a_failed_transfer() -> None:
    runner = FakeRunner().on("sh", OSError("No such file or directory: 'ssh'"))
    proc = _node_media(runner).copy_into(make_guest(runner), "D:\\upgrade\\", timeout=5400)
    assert (proc.returncode, proc.stderr) == (
        255,
        "media transfer: could not run ssh: No such file or directory: 'ssh'",
    )
