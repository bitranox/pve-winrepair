"""Tests for the guest ssh adapter: the argv it builds, the push and its hashes, the profile copy.

Every call goes through the injected runner (``guest_fakes.FakeRunner``); nothing reaches ssh.
The envelopes come from the guest tool's own ``envelope`` module and data models. How an answer is
read is tested in ``test_envelope.py``, the node bundle in ``test_node.py``.
"""

from __future__ import annotations

import base64
import hashlib
import ntpath
import re
import subprocess
from typing import TYPE_CHECKING
from unittest.mock import ANY

import guest_fakes
import pytest
from guest_fakes import (
    GUEST_IP,
    PROFILE_ACL,
    PROFILE_PATH,
    PROFILE_SDDL,
    TOOL_DIR,
    TOOL_PATH,
    USER,
    FakeRunner,
    Reply,
    answer,
    certutil_output,
    crashed,
    expected_guest_path,
    hashes_to,
    locked,
    profile_reply,
    state_log,
)

from pve_winrepair.adapters import guest_ssh
from pve_winrepair.adapters.config.loader import get_config
from pve_winrepair.adapters.config.settings import load_settings
from pve_winrepair.adapters.guest_ssh import Guest, ssh_options
from pve_winrepair.adapters.node import Node
from pve_winrepair.application.guest_state import read_run_state
from pve_winrepair.domain.envelope import (
    POWERSHELL,
    GuestInternalError,
    GuestNoAnswerError,
    GuestProtocolError,
    GuestPushError,
    guest_stderr,
)
from pve_winrepair.domain.settings import SshSettings
from pve_winrepair_guest import lockdown
from pve_winrepair_guest.probes import BuildInfo, SetupReport
from pve_winrepair_guest.upgrade import LockDirsReport

if TYPE_CHECKING:
    from pathlib import Path

KEY = "/keys/test.key"
SSH = SshSettings(key=KEY, user=USER)
BUILD = BuildInfo(current_build="26200", ubr=8973, build="26200.8973")


def _guest(runner: FakeRunner, tool_dir: Path | None = None) -> Guest:
    return Guest(GUEST_IP, ssh_settings=SSH, tool_dir=tool_dir or TOOL_DIR, runner=runner)


# --- argv -----------------------------------------------------------------------------------


def test_tool_call_runs_the_packed_tool_with_json_over_ssh() -> None:
    runner = FakeRunner().on("prepare", answer("prepare", {"gate": "PASS"}))
    _guest(runner).tool("prepare", "--stage-root", "D:\\upgrade", timeout=900)
    assert runner.calls == [
        [
            "ssh",
            "-i",
            KEY,
            *ssh_options(SSH),
            f"{USER}@{GUEST_IP}",
            # By full path, never through PATH; cmd.exe (the guest's ssh shell) expands %SystemRoot%.
            "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            TOOL_PATH,
            "prepare",
            "--stage-root",
            "D:\\upgrade",
            "--json",
        ]
    ]
    assert runner.timeouts == [900]


def test_ssh_options_map_strict_host_key_checking_to_yes_and_no() -> None:
    assert "StrictHostKeyChecking=yes" in ssh_options(SshSettings(key="/k", strict_host_key_checking=True))
    assert "StrictHostKeyChecking=no" in ssh_options(SshSettings(key="/k", strict_host_key_checking=False))


def test_ssh_options_pass_the_known_hosts_file_through_unexpanded() -> None:
    # ssh expands ~ itself, as it did for the old literal value; expanding here would bind
    # the file to the HOME of whoever builds the argv.
    opts = ssh_options(SshSettings(key="/k", known_hosts_file="~/.ssh/known_hosts_guests"))
    assert "UserKnownHostsFile=~/.ssh/known_hosts_guests" in opts
    assert "UserKnownHostsFile=/dev/null" not in opts
    assert {"BatchMode=yes", "PreferredAuthentications=publickey"} <= set(opts)


def test_the_configured_user_and_key_reach_ssh_and_scp() -> None:
    runner = FakeRunner().on("hostname", Reply(0, "GUEST\r\n"))
    ssh = SshSettings(key="/k/guest.key", user="admin")
    guest = Guest(GUEST_IP, ssh_settings=ssh, tool_dir=TOOL_DIR, runner=runner)
    guest.ssh("hostname", timeout=5.0)
    assert runner.calls[0][:3] == ["ssh", "-i", "/k/guest.key"]
    assert f"admin@{GUEST_IP}" in runner.calls[0]


def _ssh(*remote: str) -> list[str]:
    return ["ssh", "-i", KEY, *ssh_options(SSH), f"{USER}@{GUEST_IP}", *remote]


def _packed(tmp_path: Path, text: str = "# packed\n") -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "winrepair_guest.ps1").write_text(text, encoding="utf-8")
    return tmp_path / "winrepair_guest.ps1"


def _staged(dest: str) -> str:
    """The tool's admin-only copy: its plain name, which ssh and scp resolve in the ssh user's profile."""
    return ntpath.basename(dest)


def _lock_dirs_call(dest: str) -> list[str]:
    return _ssh(*POWERSHELL, _staged(dest), "lock-dirs", "--tool", dest, "--json")


def _hash_call(path: str) -> list[str]:
    return _ssh(r"%SystemRoot%\System32\certutil.exe", "-hashfile", path, "SHA256")


def _probe_call() -> list[str]:
    """The profile probe; its encoded script is pinned by the probe's own test."""
    return _ssh(POWERSHELL[0], "-NoProfile", "-NonInteractive", "-EncodedCommand", ANY)


def _pushing(source: Path, *, present: bool = False) -> FakeRunner:
    reply = answer("lock-dirs", locked(present=present))
    return (
        FakeRunner()
        .on("scp", Reply(0))
        .on("certutil", hashes_to(source))
        .on("lock-dirs", reply)
        .on("copy", Reply(0))
        .on("move", Reply(0))
        .on("del", Reply(0))
    )


def _sha(source: Path) -> str:
    return hashlib.sha256(source.read_bytes()).hexdigest()


def test_push_tool_locks_the_tool_directory_before_it_writes_into_it(tmp_path: Path) -> None:
    source = _packed(tmp_path)
    dest = expected_guest_path(source)
    runner = _pushing(source)
    pushed = _guest(runner, tmp_path).push_tool()
    assert (pushed.path, pushed.copied, pushed.staged_left) == (dest, True, None)
    # The tool first lands in the ssh user's profile, which only SYSTEM, Administrators and that user
    # may write; its bytes are checked against the node's digest before it runs, and from there lock-dirs
    # creates and locks C:\winrepair. Only then is it copied in (beside the final name, then renamed:
    # a cut copy never sits at the name a run executes), and the copy in place is hashed again.
    assert runner.calls == [
        _probe_call(),
        ["scp", "-q", "-i", KEY, *ssh_options(SSH), str(source), f"{USER}@{GUEST_IP}:{_staged(dest)}"],
        _hash_call(_staged(dest)),
        _lock_dirs_call(dest),
        _ssh("copy", "/Y", "/B", _staged(dest), f"{dest}.part"),
        _ssh("move", "/Y", f"{dest}.part", dest),
        _hash_call(dest),
        _ssh("del", "/Q", _staged(dest)),
    ]


def test_push_tool_never_overwrites_a_tool_already_on_the_guest(tmp_path: Path) -> None:
    source = _packed(tmp_path)
    dest = expected_guest_path(source)
    runner = _pushing(source, present=True)
    pushed = _guest(runner, tmp_path).push_tool()
    # A live SYSTEM run may be executing exactly this file; lock-dirs checked its bytes against its name,
    # and the full digest is read back before anything runs it.
    assert (pushed.path, pushed.copied) == (dest, False)
    assert [runner.calls[0], *runner.calls[2:]] == [
        _probe_call(),
        _hash_call(_staged(dest)),
        _lock_dirs_call(dest),
        _hash_call(dest),
        _ssh("del", "/Q", _staged(dest)),
    ]


def test_a_changed_tool_gets_a_new_guest_path(tmp_path: Path) -> None:
    old = _guest(FakeRunner(), _packed(tmp_path / "old", "# v1\n").parent).tool_path
    new = _guest(FakeRunner(), _packed(tmp_path / "new", "# v2\n").parent).tool_path
    assert old != new
    assert old == expected_guest_path(tmp_path / "old" / "winrepair_guest.ps1")
    assert new == expected_guest_path(tmp_path / "new" / "winrepair_guest.ps1")


def test_tool_calls_run_the_pushed_content_address(tmp_path: Path) -> None:
    source = _packed(tmp_path)
    runner = _pushing(source, present=True).on("setup-alive", answer("setup-alive", {"alive": False}))
    guest = _guest(runner, tmp_path)
    guest.push_tool()
    guest.tool("setup-alive", timeout=300)
    assert runner.calls[-1][runner.calls[-1].index("-File") + 1] == expected_guest_path(source)


def test_push_tool_refuses_a_missing_packed_tool_before_any_call(tmp_path: Path) -> None:
    runner = FakeRunner()
    missing = r"winrepair_guest.ps1 is missing: the package is missing its guest tool - reinstall pve-winrepair"
    with pytest.raises(GuestPushError, match=missing):
        _guest(runner, tmp_path).push_tool()
    assert runner.calls == []


def _routes(runner: FakeRunner) -> list[str]:
    return [c[0] if c[0] == "scp" else guest_fakes.route(c) for c in runner.calls]


def _writes_into_the_tool_dir(runner: FakeRunner) -> list[str]:
    return [route for route in _routes(runner) if route in ("copy", "move")]


def _other_digest(source: Path) -> str:
    return hashlib.sha256(source.read_bytes() + b"planted").hexdigest()


def test_push_tool_refuses_a_profile_copy_whose_bytes_are_not_the_tool_and_never_runs_it(
    tmp_path: Path,
) -> None:
    source = _packed(tmp_path)
    runner = _pushing(source)
    runner.replies["certutil"] = [Reply(0, certutil_output(_other_digest(source)))]
    with pytest.raises(GuestPushError, match=f"expected {_sha(source)}"):
        _guest(runner, tmp_path).push_tool()
    # Nothing ran it: no lock-dirs, nothing copied in; the copy that is not the tool is deleted.
    assert _routes(runner) == [PROFILE_ACL, "scp", "certutil", "del"]


def test_push_tool_refuses_when_the_copy_in_place_does_not_hash_to_the_tool(tmp_path: Path) -> None:
    source = _packed(tmp_path)
    runner = _pushing(source)
    good = Reply(0, certutil_output(_sha(source)))
    runner.replies["certutil"] = [good, Reply(0, certutil_output(_other_digest(source)))]
    dest = expected_guest_path(source)
    with pytest.raises(GuestPushError, match=re.escape(dest)):
        _guest(runner, tmp_path).push_tool()
    assert _routes(runner) == [PROFILE_ACL, "scp", "certutil", "lock-dirs", "copy", "move", "certutil", "del"]


@pytest.mark.parametrize(
    "stdout",
    [
        "",
        "CertUtil: -hashfile-Befehl ist fehlgeschlagen: 0x80070002\r\n",
        certutil_output("ab" * 32) + certutil_output("cd" * 32),
    ],
    ids=["empty", "no-hash-line", "two-hashes"],
)
def test_push_tool_refuses_a_hash_it_cannot_read(tmp_path: Path, stdout: str) -> None:
    source = _packed(tmp_path)
    runner = _pushing(source)
    runner.replies["certutil"] = [Reply(0, stdout)]
    with pytest.raises(GuestPushError, match="SHA256"):
        _guest(runner, tmp_path).push_tool()
    assert "lock-dirs" not in _routes(runner)


def test_push_tool_reads_the_spaced_hex_of_an_older_certutil(tmp_path: Path) -> None:
    source = _packed(tmp_path)
    digest = _sha(source)
    spaced = " ".join(digest[i : i + 2] for i in range(0, len(digest), 2)).upper()
    runner = _pushing(source, present=True)
    runner.replies["certutil"] = [Reply(0, certutil_output(spaced))]
    assert _guest(runner, tmp_path).push_tool().copied is False


@pytest.mark.parametrize(
    ("route", "reply", "routes"),
    [
        ("scp", Reply(1, "", "Connection reset"), [PROFILE_ACL, "scp", "del"]),
        ("certutil", Reply(1, "", "Zugriff verweigert"), [PROFILE_ACL, "scp", "certutil", "del"]),
        ("lock-dirs", Reply(255, "", "Connection reset"), [PROFILE_ACL, "scp", "certutil", "lock-dirs", "del"]),
        ("copy", Reply(1, "", "Zugriff verweigert"), [PROFILE_ACL, "scp", "certutil", "lock-dirs", "copy", "del"]),
        (
            "move",
            Reply(1, "", "Zugriff verweigert"),
            [PROFILE_ACL, "scp", "certutil", "lock-dirs", "copy", "move", "del"],
        ),
    ],
    ids=["scp", "hash", "lock-dirs", "copy", "move"],
)
def test_push_tool_deletes_the_profile_copy_when_a_step_fails(
    tmp_path: Path, route: str, reply: Reply, routes: list[str]
) -> None:
    source = _packed(tmp_path)
    runner = _pushing(source)
    runner.replies[route] = [reply]
    with pytest.raises(GuestPushError):
        _guest(runner, tmp_path).push_tool()
    assert _routes(runner) == routes
    assert runner.calls[-1] == _ssh("del", "/Q", _staged(expected_guest_path(source)))


def test_push_tool_deletes_the_profile_copy_when_lock_dirs_refuses_and_writes_nothing_into_the_tool_dir(
    tmp_path: Path,
) -> None:
    source = _packed(tmp_path)
    reason = r"C:\winrepair held files before it was locked: remove it (rd /s /q C:\winrepair) and rerun"
    refused = LockDirsReport(TOOL_PATH, False, None, (), "FAILED", reason)
    runner = _pushing(source)
    runner.replies["lock-dirs"] = [answer("lock-dirs", refused, ok=False)]
    with pytest.raises(GuestPushError, match=r"rd /s /q C:\\winrepair"):
        _guest(runner, tmp_path).push_tool()
    assert _writes_into_the_tool_dir(runner) == []
    assert _routes(runner)[-1] == "del"


def test_push_tool_carries_the_guest_traceback_of_a_crashed_lock_dirs(tmp_path: Path) -> None:
    source = _packed(tmp_path)
    runner = _pushing(source)
    runner.replies["lock-dirs"] = [crashed("lock-dirs", OSError("pywin32 unavailable"))]
    with pytest.raises(GuestPushError, match="pywin32 unavailable") as caught:
        _guest(runner, tmp_path).push_tool()
    assert guest_stderr(caught.value) == ("Traceback ...",)
    assert _writes_into_the_tool_dir(runner) == []
    assert _routes(runner)[-1] == "del"


def test_push_tool_reports_a_profile_copy_it_could_not_delete_without_failing_the_push(
    tmp_path: Path,
) -> None:
    source = _packed(tmp_path)
    runner = _pushing(source)
    runner.replies["del"] = [Reply(1, "", "Zugriff verweigert")]
    pushed = _guest(runner, tmp_path).push_tool()
    assert pushed.copied is True
    assert pushed.staged_left is not None
    assert "Zugriff verweigert" in pushed.staged_left


def test_a_failed_push_names_a_profile_copy_it_could_not_delete_and_keeps_its_cause(tmp_path: Path) -> None:
    source = _packed(tmp_path)
    runner = _pushing(source)
    runner.replies["copy"] = [Reply(1, "", "Datentraeger voll")]
    runner.replies["del"] = [Reply(1, "", "Zugriff verweigert")]
    with pytest.raises(GuestPushError) as caught:
        _guest(runner, tmp_path).push_tool()
    message = str(caught.value)
    assert "Datentraeger voll" in message
    assert "Zugriff verweigert" in message
    assert _staged(expected_guest_path(source)) in message


# --- the verified profile copy (the apply-and-verify driver after the apply reboot) ----------


def test_stage_tool_runs_later_calls_from_the_verified_profile_copy(tmp_path: Path) -> None:
    source = _packed(tmp_path)
    dest = expected_guest_path(source)
    runner = _pushing(source).on("build", answer("build", BUILD))
    staged = _guest(runner, tmp_path).stage_tool()
    staged.tool("build", timeout=300)
    assert runner.calls[2] == _hash_call(_staged(dest))
    assert runner.calls[-1][runner.calls[-1].index("-File") + 1] == _staged(dest)
    # Nothing is copied into C:\winrepair and nothing is deleted yet: the caller still runs it.
    assert _routes(runner) == [PROFILE_ACL, "scp", "certutil", "build"]
    assert staged.remove_profile_copy() is None
    assert runner.calls[-1] == _ssh("del", "/Q", _staged(dest))


def test_a_staged_guest_keeps_the_digest_it_verified_when_the_node_file_changes_afterwards(tmp_path: Path) -> None:
    # The profile copy was hashed against this digest; a later re-read of the node's file (an
    # upgrade of the package mid-run) must not make the staged guest name other bytes.
    source = _packed(tmp_path, "# v1\n")
    verified = guest_ssh.packed_tool(tmp_path)
    staged = _guest(_pushing(source), tmp_path).stage_tool()
    source.write_text("# v2\n", encoding="utf-8")
    assert guest_ssh.packed_tool(tmp_path).sha256 != verified.sha256
    assert staged.packed == verified
    assert staged.tool_path == _staged(verified.guest_path)


def test_stage_tool_refuses_and_deletes_a_profile_copy_that_is_not_the_tool(tmp_path: Path) -> None:
    source = _packed(tmp_path)
    runner = _pushing(source)
    runner.replies["certutil"] = [Reply(0, certutil_output(_other_digest(source)))]
    with pytest.raises(GuestPushError, match="profile"):
        _guest(runner, tmp_path).stage_tool()
    assert _routes(runner) == [PROFILE_ACL, "scp", "certutil", "del"]


def test_remove_profile_copy_reports_a_failed_delete(tmp_path: Path) -> None:
    source = _packed(tmp_path)
    runner = _pushing(source)
    runner.replies["del"] = [subprocess.TimeoutExpired("ssh", 60)]
    staged = _guest(runner, tmp_path).stage_tool()
    left = staged.remove_profile_copy()
    assert left is not None
    assert "timed out" in left


# --- the profile's descriptor, read before a copy goes there ---------------------------------

# Builtin Users may add and change files: any local account could swap the copy before it runs.
LAX_SDDL = PROFILE_SDDL + "(A;OICI;FW;;;BU)"


def _guest_remote(call: list[str]) -> list[str]:
    """The remote command line of an ssh call: everything after ``user@host``."""
    return call[call.index(f"{USER}@{GUEST_IP}") + 1 :]


def test_stage_tool_refuses_a_profile_others_can_write_and_copies_nothing(tmp_path: Path) -> None:
    source = _packed(tmp_path)
    runner = _pushing(source).on(PROFILE_ACL, profile_reply(LAX_SDDL))
    with pytest.raises(GuestPushError) as caught:
        guest_ssh.stage_tool(GUEST_IP, guest_ssh.packed_tool(tmp_path), ssh=SSH, runner=runner)
    message = str(caught.value)
    assert PROFILE_PATH in message
    assert "BU may write" in message
    assert "nothing was copied" in message
    # The probe alone ran: no scp, and no delete of a copy that was never made.
    assert _routes(runner) == [PROFILE_ACL]


def test_push_tool_refuses_a_profile_others_can_write_and_locks_nothing(tmp_path: Path) -> None:
    source = _packed(tmp_path)
    runner = _pushing(source).on(PROFILE_ACL, profile_reply(LAX_SDDL))
    with pytest.raises(GuestPushError, match="can be written by others") as caught:
        _guest(runner, tmp_path).push_tool()
    assert "BU may write" in str(caught.value)
    assert "scp" not in _routes(runner)
    assert "lock-dirs" not in _routes(runner)
    assert _routes(runner) == [PROFILE_ACL]


def test_a_profile_only_trusted_principals_can_write_is_probed_right_before_the_copy(tmp_path: Path) -> None:
    source = _packed(tmp_path)
    runner = _pushing(source)
    staged = _guest(runner, tmp_path).stage_tool()
    assert staged.profile_copy == _staged(expected_guest_path(source))
    assert _routes(runner) == [PROFILE_ACL, "scp", "certutil"]


def test_the_built_in_administrator_s_profile_printed_with_the_alias_la_is_trusted(tmp_path: Path) -> None:
    # The shipped default [ssh] user is the built-in Administrator (RID 500): Get-Acl prints its own
    # SID as the alias LA, as owner and in its ACE.
    source = _packed(tmp_path)
    admin = "S-1-5-21-1-2-3-500"
    sddl = "O:LAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LA)"
    runner = _pushing(source).on(PROFILE_ACL, profile_reply(sddl, user=admin))
    staged = _guest(runner, tmp_path).stage_tool()
    assert staged.profile_copy == _staged(expected_guest_path(source))
    assert _routes(runner) == [PROFILE_ACL, "scp", "certutil"]


def test_the_alias_la_is_refused_for_an_ssh_user_who_is_not_the_built_in_administrator(tmp_path: Path) -> None:
    sddl = "O:LAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LA)"
    runner = _pushing(_packed(tmp_path)).on(PROFILE_ACL, profile_reply(sddl))
    with pytest.raises(GuestPushError, match="the owner LA is not trusted"):
        _guest(runner, tmp_path).stage_tool()
    assert _routes(runner) == [PROFILE_ACL]


def test_the_probe_runs_an_encoded_script_reading_the_start_directory_descriptor(tmp_path: Path) -> None:
    source = _packed(tmp_path)
    runner = _pushing(source)
    _guest(runner, tmp_path).stage_tool()
    remote = _guest_remote(runner.calls[0])
    assert remote[:4] == [POWERSHELL[0], "-NoProfile", "-NonInteractive", "-EncodedCommand"]
    assert len(remote) == 5
    # No "=" padding: cmd.exe, the guest's ssh shell, treats "=" as an argument delimiter.
    assert re.fullmatch(r"[A-Za-z0-9+/]+", remote[4])
    script = base64.b64decode(remote[4], validate=True).decode("utf-16-le")
    assert "Get-Acl -LiteralPath ." in script
    assert "ConvertTo-Json -Compress" in script


PLANTED = "planted-value-7f3a"


@pytest.mark.parametrize(
    ("stdout", "field"),
    [
        (f"not json {PLANTED}\r\n", "answer"),
        (profile_reply().stdout * 2, "answer"),
        (f'["{PLANTED}"]\r\n', "answer"),
        (profile_reply(user=PLANTED).stdout, "user"),
        (profile_reply(path="C:\\" + PLANTED * 100).stdout, "path"),
        ('{"path":"C:\\\\Users\\\\x","user":"S-1-5-18"}\r\n', "sddl"),
    ],
    ids=["not-json", "two-objects", "not-an-object", "user-not-a-sid", "path-too-long", "no-sddl"],
)
def test_a_probe_answer_that_is_not_the_expected_object_refuses_naming_the_field(
    tmp_path: Path, stdout: str, field: str
) -> None:
    source = _packed(tmp_path)
    runner = _pushing(source).on(PROFILE_ACL, Reply(0, stdout))
    with pytest.raises(GuestPushError) as caught:
        _guest(runner, tmp_path).stage_tool()
    message = str(caught.value)
    assert f"{field}: " in message
    assert "nothing was copied" in message
    assert PLANTED not in message
    assert _routes(runner) == [PROFILE_ACL]


def test_a_probe_that_fails_refuses_before_the_copy(tmp_path: Path) -> None:
    source = _packed(tmp_path)
    runner = _pushing(source).on(PROFILE_ACL, Reply(1, "", "Get-Acl : Attempted to perform an unauthorized operation."))
    with pytest.raises(GuestPushError) as caught:
        _guest(runner, tmp_path).stage_tool()
    message = str(caught.value)
    assert message.startswith("reading the ssh user's profile security descriptor failed rc=1: Get-Acl")
    assert message.endswith("; nothing was copied")
    assert _routes(runner) == [PROFILE_ACL]


def test_a_probe_that_gets_no_answer_refuses_before_the_copy(tmp_path: Path) -> None:
    source = _packed(tmp_path)
    runner = _pushing(source).on(PROFILE_ACL, subprocess.TimeoutExpired("ssh", 60))
    with pytest.raises(GuestPushError, match=r"timed out after 60 s; nothing was copied$"):
        _guest(runner, tmp_path).stage_tool()
    assert _routes(runner) == [PROFILE_ACL]


def test_a_descriptor_it_cannot_parse_refuses_before_the_copy(tmp_path: Path) -> None:
    source = _packed(tmp_path)
    runner = _pushing(source).on(PROFILE_ACL, profile_reply("D:P(A;;ZZ;;;BU)"))
    with pytest.raises(GuestPushError, match="cannot be read: unknown rights code 'ZZ'; nothing was copied"):
        _guest(runner, tmp_path).stage_tool()
    assert _routes(runner) == [PROFILE_ACL]


def test_the_old_key_variable_is_not_read(monkeypatch: pytest.MonkeyPatch) -> None:
    # The key comes from the settings alone; a per-run override is PVE_WINREPAIR___SSH__KEY, which
    # the configuration loader reads into SshSettings.key.
    monkeypatch.setenv("WINREPAIR_SSH_KEY", "/old/key")
    monkeypatch.setenv("WINREPAIR_DIR", "/old/dir")
    runner = FakeRunner().on("hostname", Reply(0))
    guest = Guest(GUEST_IP, ssh_settings=SSH, runner=runner)
    guest.ssh("hostname", timeout=5.0)
    assert runner.calls[0][:3] == ["ssh", "-i", KEY]
    assert guest.tool_dir == guest_ssh.TOOL_DIR


def test_the_key_override_variable_reaches_the_ssh_argv(isolated_layers: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # End to end: the environment layer, the settings model, the node, the guest's argv.
    monkeypatch.setenv("PVE_WINREPAIR___SSH__KEY", "/env/guest.key")
    monkeypatch.setenv("PVE_WINREPAIR___SSH__USER", USER)
    runner = FakeRunner().on("hostname", Reply(0))
    node = Node(ssh=load_settings(get_config()).ssh, runner=runner)
    node.guest(GUEST_IP).ssh("hostname", timeout=5.0)
    assert runner.calls[0][:3] == ["ssh", "-i", "/env/guest.key"]
    assert f"{USER}@{GUEST_IP}" in runner.calls[0]


def test_the_tool_dir_is_the_guest_tool_shipped_in_the_package() -> None:
    assert guest_ssh.TOOL_DIR.name == "guest_tool"
    assert (guest_ssh.TOOL_DIR / guest_ssh.TOOL_NAME).is_file()


# --- the upgrade run's state: one reading shared by both drivers ------------------------------

DONE_OK_LINES = ("launching: setup.exe", "STATE=DONE-OK setup exit=0x00000000")
DONE_FAIL_LINES = ("launching: setup.exe", "STATE=DONE-FAIL setup exit=0xC1900200")


@pytest.mark.parametrize(
    ("alive", "log", "live", "marker"),
    [
        (False, state_log(present=False), False, None),
        (False, state_log(*DONE_OK_LINES), False, "STATE=DONE-OK"),
        (False, state_log(*DONE_FAIL_LINES), False, "STATE=DONE-FAIL"),
        (False, state_log("launching: setup.exe"), True, None),
        (True, state_log(*DONE_OK_LINES), True, "STATE=DONE-OK"),
        (True, state_log(present=False), True, None),
    ],
    ids=["no-log", "done-ok", "done-fail", "no-marker", "alive-over-done-ok", "alive-no-log"],
)
def test_run_state_reads_live_and_marker(alive: bool, log: object, live: bool, marker: str | None) -> None:
    runner = FakeRunner().on("setup-alive", answer("setup-alive", SetupReport(int(alive), alive)))
    runner.on("state", answer("state", log))
    state = read_run_state(_guest(runner), timeout=300)
    assert (state.live, state.marker, state.alive) == (live, marker, alive)
    assert state.log_path == r"C:\upgrade-state.log"


def test_run_state_with_an_unknown_marker_is_a_protocol_error() -> None:
    runner = FakeRunner().on("setup-alive", answer("setup-alive", SetupReport(0, False)))
    runner.on("state", answer("state", {"path": "C:\\x.log", "present": True, "verdict": "DONE-MAYBE"}))
    with pytest.raises(GuestProtocolError, match="DONE-MAYBE"):
        read_run_state(_guest(runner), timeout=300)


@pytest.mark.parametrize("reply", [Reply(255, "", "reset"), crashed("setup-alive", OSError("wmi"))])
def test_run_state_that_cannot_be_read_raises_instead_of_reading_as_idle(reply: Reply) -> None:
    runner = FakeRunner().on("setup-alive", reply)
    with pytest.raises((GuestNoAnswerError, GuestInternalError)):
        read_run_state(_guest(runner), timeout=300)


@pytest.mark.parametrize("error", [subprocess.TimeoutExpired(["scp"], 5400), OSError("no scp")])
def test_copy_to_that_times_out_or_cannot_start_is_a_failed_process(error: BaseException) -> None:
    runner = FakeRunner().on("scp", error)
    proc = _guest(runner).copy_to(["/media/setup.exe"], "D:\\upgrade\\", timeout=5400)
    assert proc.returncode == 255
    assert "media transfer" in proc.stderr


# --- the content address both deploy units agree on ------------------------------------------


def test_the_content_address_agrees_with_the_name_the_ssh_adapter_pushes(tmp_path: Path) -> None:
    # Two deploy units (the node pushes, the guest checks): the shape must agree on both sides.
    (tmp_path / "winrepair_guest.ps1").write_bytes(b"# v1\n")
    guest_path = guest_ssh.packed_tool(tmp_path).guest_path
    assert ntpath.dirname(guest_path) == guest_ssh.GUEST_TOOL_DIR == lockdown.TOOL_DIR
    assert lockdown.lock_scope_problem(guest_path, r"D:\upgrade") is None
    copy = tmp_path / ntpath.basename(guest_path)
    copy.write_bytes(b"# v1\n")
    assert lockdown.content_address(str(copy))[1] is None


def test_the_scope_check_takes_the_tool_alone_when_no_stage_root_is_named(tmp_path: Path) -> None:
    (tmp_path / "winrepair_guest.ps1").write_bytes(b"# v1\n")
    tool = guest_ssh.packed_tool(tmp_path).guest_path
    assert lockdown.lock_scope_problem(tool, None) is None
    assert lockdown.lock_scope_problem(r"C:\Windows\x.ps1", None) is not None


def test_ssh_options_keep_the_order_winrepair_shipped() -> None:
    # Literal on purpose: an expectation built from ssh_options() cannot see a reorder. IdentitiesOnly
    # joined after winrepair: without it ssh also offers every agent and default key before -i's.
    settings = SshSettings(key="/k", strict_host_key_checking=False, known_hosts_file="~/.ssh/kh")
    assert ssh_options(settings) == (
        "-o", "BatchMode=yes",
        "-o", "PreferredAuthentications=publickey",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=~/.ssh/kh",
        "-o", "ConnectTimeout=20",
        "-o", "ServerAliveInterval=30",
    )  # fmt: skip


def test_ssh_and_scp_argv_carry_the_options_in_that_order() -> None:
    # Driven through the public Guest calls, which build the argv a guest call really runs.
    settings = SshSettings(key="/k", user="admin", strict_host_key_checking=False, known_hosts_file="~/.ssh/kh")
    opts = list(ssh_options(settings))
    runner = FakeRunner().on("hostname", Reply(0, "GUEST\r\n")).on("scp", Reply(0))
    guest = Guest("192.0.2.10", ssh_settings=settings, tool_dir=TOOL_DIR, runner=runner)
    guest.ssh("hostname", timeout=5.0)
    guest.copy_to(["a"], "D:\\x\\", timeout=5.0)
    assert runner.calls == [
        ["ssh", "-i", "/k", *opts, "admin@192.0.2.10", "hostname"],
        ["scp", "-q", "-i", "/k", *opts, "-r", "a", "admin@192.0.2.10:D:\\x\\"],
    ]
