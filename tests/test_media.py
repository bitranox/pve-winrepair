"""Tests for where a repair's installation media come from: :class:`LocalMedia` and :class:`NodeMedia`.

:class:`LocalMedia` is a directory on this machine, :class:`NodeMedia` one on a remote node.

Every copy goes through the ``FakeRunner`` seam - the guest's own scp for local media, the node's
scp over ``ssh -A`` for node media - so these tests see the argv and the timeout the real transfer
would get.
"""

from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from guest_fakes import (
    GUEST_HOST_KEY,
    GUEST_IP,
    GUEST_KNOWN,
    NODE_LINK,
    USER,
    Answer,
    FakeRunner,
    Reply,
    make_guest,
)

from pve_winrepair.adapters.media import LocalMedia, NodeMedia
from pve_winrepair.domain.settings import SshSettings

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


#: The guest known_hosts file of the node-media tests, as configured on this machine.
KNOWN_HOSTS = "/home/op/.ssh/known_hosts"
#: The scp options the node passes after the trust options its script sets itself.
NODE_SCP_OPTIONS = [
    "-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey",
    "-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=30",
]  # fmt: skip
#: How the node script's scp checks the guest: only against the lines handed over from this machine.
NODE_TRUST = '-o "UserKnownHostsFile=$known" -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes'
#: How it runs scp with ``[ssh] strict_host_key_checking = false``: no check, and no known_hosts read or written.
NODE_NO_CHECK = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null"
#: The option every node scp gets first, in both modes: no KnownHostsCommand from the node's ssh config adds keys.
NO_KNOWN_HOSTS_COMMAND = ["-o", "KnownHostsCommand=none"]
#: A line for the guest that no longer matches it (rebuilt at the same address).
STALE_KNOWN = f"# Host {GUEST_IP} found: line 1 \n{GUEST_IP} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIStaleKey\n"


def _node_media(
    runner: FakeRunner, *, strict: bool = True, known_hosts: str = KNOWN_HOSTS, directory: str = MEDIA
) -> NodeMedia:
    ssh = SshSettings(key="/keys/guest.key", user=USER, strict_host_key_checking=strict, known_hosts_file=known_hosts)
    return NodeMedia(directory, NODE_LINK, ssh, runner)


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


def test_the_node_copies_with_the_forwarded_key_trusting_the_guest_key_read_here() -> None:
    runner = FakeRunner().on("ssh-keygen", Reply(0, GUEST_KNOWN)).on("sh", Reply(0))
    _node_media(runner, strict=True).copy_into(make_guest(runner), "D:\\upgrade\\", timeout=5400)
    # First the guest's line from THIS machine's known_hosts, then the one node call.
    assert runner.calls[0] == ["ssh-keygen", "-F", GUEST_IP, "-f", KNOWN_HOSTS]
    remote = shlex.split(runner.calls[1][-1])
    target = f"{USER}@{GUEST_IP}:D:\\upgrade\\"
    # sh -c <script> <$0> <dir> <target> <guest host keys> <scp options...>; the key line, spaces and all,
    # comes back as one word, the ssh-keygen comment line dropped.
    assert runner.calls[1] == NODE_LINK.ssh_argv(
        ["sh", "-c", remote[2], "sh", MEDIA, target, GUEST_HOST_KEY, *NODE_SCP_OPTIONS], forward_agent=True
    )
    assert runner.timeouts == [10, 5400]
    # Strict on the node: the key was checked here already.
    assert NODE_TRUST in remote[2]
    assert not any(w.startswith(("StrictHostKeyChecking", "UserKnownHostsFile", "IdentitiesOnly")) for w in remote[3:])


@pytest.mark.parametrize(
    "keygen",
    [Reply(1, ""), Reply(0, STALE_KNOWN), Reply(255, "", f"Cannot stat {KNOWN_HOSTS}: No such file or directory\n")],
    ids=["missing", "stale", "no-file"],
)
def test_without_strict_checking_the_node_copy_reads_no_key_here_and_checks_none_there(keygen: Reply) -> None:
    runner = FakeRunner().on("ssh-keygen", keygen).on("sh", Reply(0))
    proc = _node_media(runner, strict=False).copy_into(make_guest(runner), "D:\\upgrade\\", timeout=5400)
    # No ssh-keygen call at all: a missing, stale or unreadable line here cannot refuse the copy.
    assert proc.returncode == 0 and len(runner.calls) == 1 and runner.timeouts == [5400]
    remote = shlex.split(runner.calls[0][-1])
    target = f"{USER}@{GUEST_IP}:D:\\upgrade\\"
    # The empty host-key word is the script's "no check": no key line travels to the node.
    assert runner.calls[0] == NODE_LINK.ssh_argv(
        ["sh", "-c", remote[2], "sh", MEDIA, target, "", *NODE_SCP_OPTIONS], forward_agent=True
    )
    assert NODE_NO_CHECK in remote[2]


def test_a_leading_tilde_in_the_guest_known_hosts_is_expanded_as_ssh_does(monkeypatch: pytest.MonkeyPatch) -> None:
    # HOME (USERPROFILE on Windows) is an external edge: ssh expands "~" against it, ssh-keygen -f does not.
    monkeypatch.setenv("HOME", "/home/op")
    monkeypatch.setenv("USERPROFILE", "/home/op")
    runner = FakeRunner().on("ssh-keygen", Reply(0, GUEST_KNOWN)).on("sh", Reply(0))
    _node_media(runner, known_hosts="~/.ssh/kh").copy_into(make_guest(runner), "D:\\upgrade\\", timeout=5400)
    assert runner.calls[0] == ["ssh-keygen", "-F", GUEST_IP, "-f", str(Path("/home/op/.ssh/kh"))]


def test_every_host_key_line_of_the_guest_is_handed_over() -> None:
    revoked = f"@revoked {GUEST_IP} ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ"
    found = f"{GUEST_KNOWN}# Host {GUEST_IP} found: line 2 REVOKED\r\n{revoked}\r\n"
    runner = FakeRunner().on("ssh-keygen", Reply(0, found)).on("sh", Reply(0))
    _node_media(runner).copy_into(make_guest(runner), "D:\\upgrade\\", timeout=5400)
    assert shlex.split(runner.calls[1][-1])[6] == f"{GUEST_HOST_KEY}\n{revoked}"


@pytest.mark.parametrize(
    ("keygen", "reason"),
    [
        (Reply(1, ""), f"no host key for guest {GUEST_IP} in {KNOWN_HOSTS}"),
        (Reply(0, "# Host 192.0.2.10 found: line 1 \n"), f"no host key for guest {GUEST_IP} in {KNOWN_HOSTS}"),
        (
            Reply(255, "", f"Cannot stat {KNOWN_HOSTS}: No such file or directory\n"),
            f"cannot read the host key of guest {GUEST_IP} from {KNOWN_HOSTS}: "
            f"Cannot stat {KNOWN_HOSTS}: No such file or directory",
        ),
        (
            OSError("No such file or directory: 'ssh-keygen'"),
            f"cannot read the host key of guest {GUEST_IP} from {KNOWN_HOSTS}: could not run ssh-keygen: ",
        ),
        (
            subprocess.TimeoutExpired(["ssh-keygen"], 10),
            f"cannot read the host key of guest {GUEST_IP} from {KNOWN_HOSTS}: ssh-keygen gave no answer within 10 s",
        ),
    ],
    ids=["not-found", "comments-only", "no-file", "no-ssh-keygen", "timeout"],
)  # fmt: skip
def test_without_the_guest_key_here_the_node_copy_is_refused_before_the_node_is_called(
    keygen: Answer, reason: str
) -> None:
    runner = FakeRunner().on("ssh-keygen", keygen)
    proc = _node_media(runner).copy_into(make_guest(runner), "D:\\upgrade\\", timeout=5400)
    assert proc.returncode == 255 and proc.stderr.startswith(reason)
    # Fail closed: never the node's own known_hosts instead.
    assert [call[0] for call in runner.calls] == ["ssh-keygen"]


#: A stand-in scp: records its argv, the known_hosts file it was given and what the temp dir holds while it runs.
_RECORDING_SCP = """#!{python}
import json, os, stat, sys
argv = sys.argv[1:]
known = next(a.split("=", 1)[1] for a in argv if a.startswith("UserKnownHostsFile="))
with open(known, encoding="utf-8") as stream:
    content = stream.read()
mode = stat.S_IMODE(os.stat(known).st_mode)
held = sorted(os.listdir(os.environ["TMPDIR"]))
with open(os.environ["SCP_RECORD"], "w", encoding="utf-8") as out:
    json.dump({{"argv": argv, "known": known, "content": content, "mode": mode, "cwd": os.getcwd(), "tmp": held}}, out)
sys.exit(int(os.environ.get("SCP_EXIT", "0")))
"""


def _run_the_node_script(tmp_path: Path, *, strict: bool, scp_exit: int) -> tuple[Path, Path, dict[str, object]]:
    """Run the node-side copy's recorded words under a real ``sh`` with a recording scp first on PATH.

    Returns the media directory, the script's temp directory and what the scp saw.
    """
    media = tmp_path / "media"
    media.mkdir()
    (media / "setup.exe").write_bytes(b"MZ")
    (media / "sources").mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    scp = bin_dir / "scp"
    scp.write_text(_RECORDING_SCP.format(python=sys.executable), encoding="utf-8")
    scp.chmod(0o755)
    scratch = tmp_path / "tmp"
    scratch.mkdir()
    runner = FakeRunner().on("ssh-keygen", Reply(0, GUEST_KNOWN)).on("sh", Reply(0))
    _node_media(runner, directory=str(media), strict=strict).copy_into(
        make_guest(runner), "D:\\upgrade\\", timeout=5400
    )
    # Run exactly the words the node's shell would split back out of the recorded ssh call.
    words = shlex.split(runner.calls[-1][-1])
    record = tmp_path / "record.json"
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "TMPDIR": str(scratch),
        "SCP_RECORD": str(record),
        "SCP_EXIT": str(scp_exit),
    }
    done = subprocess.run(words, env=env, capture_output=True, text=True, encoding="utf-8", check=False)  # noqa: S603
    assert (done.returncode, done.stderr) == (scp_exit, "")
    seen: dict[str, object] = json.loads(record.read_text(encoding="utf-8"))
    return media, scratch, seen


@pytest.mark.os_posix
@pytest.mark.parametrize("scp_exit", [0, 3])
def test_the_node_script_hands_scp_the_guest_key_in_a_private_temp_file_it_removes(
    tmp_path: Path, scp_exit: int
) -> None:
    media, scratch, seen = _run_the_node_script(tmp_path, strict=True, scp_exit=scp_exit)
    known = str(seen["known"])
    assert seen["content"] == f"{GUEST_HOST_KEY}\n"
    assert int(str(seen["mode"])) & (stat.S_IRWXG | stat.S_IRWXO) == 0
    assert seen["argv"] == [
        "-q", "-r", *NO_KNOWN_HOSTS_COMMAND, "-o", f"UserKnownHostsFile={known}",
        "-o", "GlobalKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=yes", *NODE_SCP_OPTIONS,
        "--", "setup.exe", "sources", f"{USER}@{GUEST_IP}:D:\\upgrade\\",
    ]  # fmt: skip
    assert Path(str(seen["cwd"])).resolve() == media.resolve()
    assert Path(known).parent.resolve() == scratch.resolve()
    assert seen["tmp"] == [Path(known).name]  # the key file, and only it, while scp ran
    assert list(scratch.iterdir()) == []  # the temp file is gone on this exit path too


@pytest.mark.os_posix
@pytest.mark.parametrize("scp_exit", [0, 3])
def test_without_strict_checking_the_node_script_runs_scp_unchecked_and_writes_no_temp_file(
    tmp_path: Path, scp_exit: int
) -> None:
    media, scratch, seen = _run_the_node_script(tmp_path, strict=False, scp_exit=scp_exit)
    assert seen["argv"] == [
        "-q", "-r", *NO_KNOWN_HOSTS_COMMAND, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "GlobalKnownHostsFile=/dev/null", *NODE_SCP_OPTIONS, "--", "setup.exe", "sources",
        f"{USER}@{GUEST_IP}:D:\\upgrade\\",
    ]  # fmt: skip
    assert Path(str(seen["cwd"])).resolve() == media.resolve()
    # No temp file while scp ran, and none after: nothing was ever created there.
    assert seen["tmp"] == [] and list(scratch.iterdir()) == []


def test_a_node_copy_that_times_out_is_a_failed_transfer() -> None:
    runner = FakeRunner().on("ssh-keygen", Reply(0, GUEST_KNOWN)).on("sh", subprocess.TimeoutExpired(["ssh"], 5400))
    proc = _node_media(runner).copy_into(make_guest(runner), "D:\\upgrade\\", timeout=5400)
    assert (proc.returncode, proc.stderr) == (255, "media transfer: timed out after 5400 s")


def test_a_node_copy_whose_ssh_cannot_start_is_a_failed_transfer() -> None:
    runner = FakeRunner().on("ssh-keygen", Reply(0, GUEST_KNOWN)).on("sh", OSError("No such file or directory: 'ssh'"))
    proc = _node_media(runner).copy_into(make_guest(runner), "D:\\upgrade\\", timeout=5400)
    assert (proc.returncode, proc.stderr) == (
        255,
        "media transfer: could not run ssh: No such file or directory: 'ssh'",
    )
