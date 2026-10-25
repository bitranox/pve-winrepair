"""Tests for the ssh argv to a remote node and the jump through it."""

from __future__ import annotations

import os
import shlex
import subprocess  # nosec B404
from typing import TYPE_CHECKING

import pytest
from guest_fakes import GUEST_IP, KEY, NODE_LINK, USER, FakeRunner, Reply

from pve_winrepair.domain.node_link import NodeLink

if TYPE_CHECKING:
    from collections.abc import Sequence


def test_a_remote_command_is_one_quoted_word_after_the_target() -> None:
    argv = NODE_LINK.ssh_argv(["qm", "snapshot", "100", "s1", "--description", "before an in-place repair upgrade"])
    assert argv[:3] == ["ssh", "-i", "/keys/node.key"]
    assert argv[-2] == "root@pve1"
    # The node's shell splits this back into exactly the words given (measured: unquoted, it splits the description).
    assert shlex.split(argv[-1]) == [
        "qm",
        "snapshot",
        "100",
        "s1",
        "--description",
        "before an in-place repair upgrade",
    ]


def test_quotes_and_empty_words_survive_the_node_shell() -> None:
    words = ["qm", "set", "100", "--description", "it's", ""]
    assert shlex.split(NODE_LINK.ssh_argv(words)[-1]) == words


def test_the_node_connection_is_strict_about_its_host_key_and_never_prompts() -> None:
    argv = NODE_LINK.ssh_argv(["true"])
    options = {argv[i + 1] for i, token in enumerate(argv) if token == "-o"}
    assert {"BatchMode=yes", "StrictHostKeyChecking=yes", "IdentitiesOnly=yes"} <= options


def test_the_node_ssh_checks_the_node_against_the_configured_known_hosts() -> None:
    argv = NODE_LINK.ssh_argv(["qm", "status", "1"])
    after_opts = argv.index("ServerAliveInterval=30") + 1  # the last of _NODE_OPTS
    assert argv[after_opts:] == ["-o", "UserKnownHostsFile=/keys/known_hosts_node", "root@pve1", "qm status 1"]


def test_the_proxy_command_checks_the_node_against_the_same_file() -> None:
    assert NODE_LINK.proxy_command(windows=False).endswith(
        "-o UserKnownHostsFile=/keys/known_hosts_node -W %h:%p root@pve1"
    )


def test_the_proxy_command_reaches_the_guest_through_the_node_with_the_node_key() -> None:
    words = shlex.split(NODE_LINK.proxy_command(windows=False))
    assert words[:3] == ["ssh", "-i", "/keys/node.key"]
    assert words[-3:] == ["-W", "%h:%p", "root@pve1"]


def test_a_node_key_path_with_a_space_stays_one_word_in_the_proxy_command() -> None:
    link = NodeLink(host="pve1", user="root", key="/home/a b/node.key", known_hosts="/keys/known_hosts_node")
    assert shlex.split(link.proxy_command(windows=False))[2] == "/home/a b/node.key"


def test_the_jumped_runner_adds_the_proxy_to_ssh_and_scp_only() -> None:
    inner = FakeRunner().on("hostname", Reply(0)).on("scp", Reply(0))
    jumped = NODE_LINK.jumped(inner)
    # The fake routes an ssh call by the token naming its own guest user, so the argv uses its constants.
    jumped(["ssh", "-i", KEY, f"{USER}@{GUEST_IP}", "hostname"], 5.0)
    jumped(["scp", "-q", "-i", KEY, "a", f"{USER}@{GUEST_IP}:C:\\x\\"], 5.0)
    for call in inner.calls:
        assert call[1:3] == ["-o", f"ProxyCommand={NODE_LINK.proxy_command()}"]
    assert inner.timeouts == [5.0, 5.0]


def test_the_jumped_runner_passes_anything_else_through_unchanged() -> None:
    seen: list[list[str]] = []

    def inner(cmd: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
        seen.append(list(cmd))
        return subprocess.CompletedProcess(list(cmd), 0, "", "")

    NODE_LINK.jumped(inner)(["qm", "status", "100"], 30)
    assert seen == [["qm", "status", "100"]]


#: A Windows node link: a spaced key path, and a known_hosts path with none (spaces there are refused).
WIN = NodeLink(host="pve1", user="root", key=r"C:\Users\srv admin\keys\node.key", known_hosts=r"C:\Users\operator\kh")


def test_on_windows_the_paths_are_double_quoted_exactly_as_measured() -> None:
    assert WIN.proxy_command(windows=True) == (
        r'ssh -i "C:\Users\srv admin\keys\node.key" -o BatchMode=yes -o PreferredAuthentications=publickey '
        r"-o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=20 -o ServerAliveInterval=30 "
        r'-o "UserKnownHostsFile=C:\Users\operator\kh" -W %h:%p root@pve1'
    )


def test_on_posix_the_command_is_shlex_joined() -> None:
    assert NODE_LINK.proxy_command(windows=False) == (
        "ssh -i /keys/node.key -o BatchMode=yes -o PreferredAuthentications=publickey -o IdentitiesOnly=yes "
        "-o StrictHostKeyChecking=yes -o ConnectTimeout=20 -o ServerAliveInterval=30 "
        "-o UserKnownHostsFile=/keys/known_hosts_node -W %h:%p root@pve1"
    )


@pytest.mark.parametrize(
    ("key", "known_hosts", "reason"),
    [
        ("/k%h/node.key", "/kh", "must not contain %"),
        ('C:\\a"b', "C:\\kh", "must not contain a double quote"),
        ("/k", "/a b/kh", "must not contain whitespace"),
        ("/k", "/kh%p", "must not contain %"),
    ],
)
def test_a_link_refuses_a_path_no_quoting_carries(key: str, known_hosts: str, reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        NodeLink(host="pve1", user="root", key=key, known_hosts=known_hosts)


def test_without_an_argument_the_running_platform_decides() -> None:
    assert NODE_LINK.proxy_command() == NODE_LINK.proxy_command(windows=os.name == "nt")


def test_the_jumped_runner_carries_the_platform_form() -> None:
    runner = FakeRunner().on("hostname", Reply(0))
    NODE_LINK.jumped(runner, windows=True)(["ssh", "-i", KEY, f"{USER}@{GUEST_IP}", "hostname"], 5.0)
    assert runner.calls[0][1:3] == ["-o", f"ProxyCommand={NODE_LINK.proxy_command(windows=True)}"]
