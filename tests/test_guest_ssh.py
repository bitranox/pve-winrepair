"""Tests for the guest ssh adapter: the argv it builds, the arguments it refuses, and how it reads an answer.

Every call goes through the injected runner (``guest_fakes.FakeRunner``); nothing reaches ssh.
The envelopes come from the guest tool's own ``envelope`` module and data models.
"""

from __future__ import annotations

import hashlib
import ntpath
import re
import subprocess
from typing import TYPE_CHECKING

import guest_fakes
import pytest
from guest_fakes import (
    GUEST_IP,
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
    state_log,
)

from pve_winrepair.adapters import guest_ssh
from pve_winrepair.adapters.config.loader import get_config
from pve_winrepair.adapters.config.settings import load_settings
from pve_winrepair.adapters.guest_ssh import (
    Guest,
    GuestInternalError,
    GuestNoAnswerError,
    GuestProtocolError,
    GuestPushError,
    UnsafeArgumentError,
    ssh_options,
)
from pve_winrepair.domain.settings import SshSettings
from pve_winrepair_guest import lockdown
from pve_winrepair_guest.probes import BuildInfo, SetupReport, StagedOs
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
    return _ssh(*guest_ssh.POWERSHELL, _staged(dest), "lock-dirs", "--tool", dest, "--json")


def _hash_call(path: str) -> list[str]:
    return _ssh(r"%SystemRoot%\System32\certutil.exe", "-hashfile", path, "SHA256")


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
    assert runner.calls[1:] == [
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
    assert _routes(runner) == ["scp", "certutil", "del"]


def test_push_tool_refuses_when_the_copy_in_place_does_not_hash_to_the_tool(tmp_path: Path) -> None:
    source = _packed(tmp_path)
    runner = _pushing(source)
    good = Reply(0, certutil_output(_sha(source)))
    runner.replies["certutil"] = [good, Reply(0, certutil_output(_other_digest(source)))]
    dest = expected_guest_path(source)
    with pytest.raises(GuestPushError, match=re.escape(dest)):
        _guest(runner, tmp_path).push_tool()
    assert _routes(runner) == ["scp", "certutil", "lock-dirs", "copy", "move", "certutil", "del"]


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
        ("scp", Reply(1, "", "Connection reset"), ["scp", "del"]),
        ("certutil", Reply(1, "", "Zugriff verweigert"), ["scp", "certutil", "del"]),
        ("lock-dirs", Reply(255, "", "Connection reset"), ["scp", "certutil", "lock-dirs", "del"]),
        ("copy", Reply(1, "", "Zugriff verweigert"), ["scp", "certutil", "lock-dirs", "copy", "del"]),
        ("move", Reply(1, "", "Zugriff verweigert"), ["scp", "certutil", "lock-dirs", "copy", "move", "del"]),
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
    assert guest_ssh.guest_stderr(caught.value) == ("Traceback ...",)
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
    assert runner.calls[1] == _hash_call(_staged(dest))
    assert runner.calls[-1][runner.calls[-1].index("-File") + 1] == _staged(dest)
    # Nothing is copied into C:\winrepair and nothing is deleted yet: the caller still runs it.
    assert _routes(runner) == ["scp", "certutil", "build"]
    assert staged.remove_profile_copy() is None
    assert runner.calls[-1] == _ssh("del", "/Q", _staged(dest))


def test_stage_tool_refuses_and_deletes_a_profile_copy_that_is_not_the_tool(tmp_path: Path) -> None:
    source = _packed(tmp_path)
    runner = _pushing(source)
    runner.replies["certutil"] = [Reply(0, certutil_output(_other_digest(source)))]
    with pytest.raises(GuestPushError, match="profile"):
        _guest(runner, tmp_path).stage_tool()
    assert _routes(runner) == ["scp", "certutil", "del"]


def test_remove_profile_copy_reports_a_failed_delete(tmp_path: Path) -> None:
    source = _packed(tmp_path)
    runner = _pushing(source)
    runner.replies["del"] = [subprocess.TimeoutExpired("ssh", 60)]
    staged = _guest(runner, tmp_path).stage_tool()
    left = staged.remove_profile_copy()
    assert left is not None
    assert "timed out" in left


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
    node = guest_ssh.Node(ssh=load_settings(get_config()).ssh, runner=runner)
    node.guest(GUEST_IP).ssh("hostname", timeout=5.0)
    assert runner.calls[0][:3] == ["ssh", "-i", "/env/guest.key"]
    assert f"{USER}@{GUEST_IP}" in runner.calls[0]


def test_the_tool_dir_is_the_guest_tool_shipped_in_the_package() -> None:
    assert guest_ssh.TOOL_DIR.name == "guest_tool"
    assert (guest_ssh.TOOL_DIR / guest_ssh.TOOL_NAME).is_file()


def test_a_node_reaches_its_guests_and_qm_through_one_runner() -> None:
    runner = FakeRunner().on("hostname", Reply(0)).on("qm", Reply(0, "status: running\n"))
    node = guest_ssh.Node(ssh=SSH, runner=runner)
    node.guest(GUEST_IP).ssh("hostname", timeout=5.0)
    node.qm("status", "100", timeout=30)
    assert runner.calls == [_ssh("hostname"), ["qm", "status", "100"]]
    assert runner.timeouts == [5.0, 30]


# --- argument refusal -----------------------------------------------------------------------

REFUSED = [
    *(f"D:\\up{c}grade" for c in '&|<>^"%!()'),
    "D:\\up\ngrade",
    "D:\\up\rgrade",
    "D:\\up grade",
    "D:\\up\tgrade",
    "D:\\up'grade",
    "D:\\up`grade",
    "D:\\up;grade",
    "D:\\up,grade",
    "D:\\up=grade",
    "D:\\up*grade",
    "D:\\up?grade",
    "D:\\up$grade",
    "D:\\up" + chr(0xE4) + "grade",
    "",
    "-PwshPyClean",
    "-pwshpyelevate",
    "-x:D",
    "--",
]


@pytest.mark.parametrize("bad", REFUSED)
def test_an_unsafe_argument_is_refused_before_ssh(bad: str) -> None:
    runner = FakeRunner()
    with pytest.raises(UnsafeArgumentError):
        _guest(runner).tool("prepare", "--stage-root", bad, timeout=60)
    assert runner.calls == []


def test_an_unsafe_subcommand_is_refused_before_ssh() -> None:
    runner = FakeRunner()
    with pytest.raises(UnsafeArgumentError):
        _guest(runner).tool("build&calc", timeout=60)
    assert runner.calls == []


@pytest.mark.parametrize("good", ["D:\\upgrade", "C:\\upgrade-state.log", "18", "--stage-root", "C:/x_y.z"])
def test_a_plain_argument_passes(good: str) -> None:
    runner = FakeRunner().on("state", answer("state", {"verdict": None}))
    _guest(runner).tool("state", "--log", good, timeout=60)
    assert runner.calls[0][-2] == good


# --- reading the answer ---------------------------------------------------------------------


def test_a_valid_envelope_is_returned_with_typed_fields() -> None:
    runner = FakeRunner().on("build", answer("build", BUILD))
    env = _guest(runner).tool("build", timeout=60)
    assert (env.ok, env.command, env.exit_code) == (True, "build", 0)
    assert env.data.text("current_build") == "26200"
    assert env.data.integer("ubr") == 8973


def test_a_refused_envelope_is_returned_not_raised() -> None:
    runner = FakeRunner().on("restore-wu", answer("restore-wu", {"verdict": "STILL_DISABLED"}, ok=False))
    env = _guest(runner).tool("restore-wu", timeout=60)
    assert (env.ok, env.exit_code) == (False, 1)
    assert env.data.text("verdict") == "STILL_DISABLED"


def test_bootstrap_noise_around_the_envelope_is_ignored() -> None:
    reply = answer("setup-alive", SetupReport(count=1, alive=True))
    noisy = Reply(0, "uv was not found; installing it ...\r\n" + reply.stdout + "\r\n")
    runner = FakeRunner().on("setup-alive", noisy)
    assert _guest(runner).probe("setup-alive", timeout=60).flag("alive") is True


@pytest.mark.parametrize(
    ("reply", "fragment"),
    [
        (Reply(0, ""), "no envelope"),
        (Reply(0, "\r\n  \r\n"), "no envelope"),
        (Reply(0, "Das System kann den angegebenen Pfad nicht finden.\r\n"), "no envelope"),
        (Reply(0, '{"ok": true, "command": "build", "data": {'), "no envelope"),
        (Reply(0, '{"ok": true}'), "no envelope"),
        (Reply(255, "", "ssh: connect to host 192.0.2.10 port 22: Connection timed out"), "exit 255"),
        (Reply(1, "", "Die Benennung powershell wurde nicht erkannt"), "exit 1"),
        (Reply(127, "", "uv is not installed"), "exit 127"),
    ],
)
def test_no_valid_envelope_raises_no_answer(reply: Reply, fragment: str) -> None:
    runner = FakeRunner().on("build", reply)
    with pytest.raises(GuestNoAnswerError, match=fragment):
        _guest(runner).tool("build", timeout=60)


def test_a_valid_envelope_under_a_foreign_exit_code_is_no_answer() -> None:
    reply = answer("build", BUILD)
    runner = FakeRunner().on("build", Reply(255, reply.stdout, "Connection reset"))
    with pytest.raises(GuestNoAnswerError, match="exit 255"):
        _guest(runner).tool("build", timeout=60)


def test_a_timeout_raises_no_answer() -> None:
    runner = FakeRunner().on("build", subprocess.TimeoutExpired(["ssh"], 60))
    with pytest.raises(GuestNoAnswerError, match="timed out"):
        _guest(runner).tool("build", timeout=60)


def test_ssh_that_cannot_start_raises_no_answer() -> None:
    runner = FakeRunner().on("build", FileNotFoundError(2, "No such file or directory", "ssh"))
    with pytest.raises(GuestNoAnswerError, match="could not run"):
        _guest(runner).tool("build", timeout=60)


def test_an_internal_error_envelope_raises_with_the_guest_error() -> None:
    runner = FakeRunner().on("staged-os", crashed("staged-os", PermissionError("Zugriff verweigert")))
    with pytest.raises(GuestInternalError, match="Zugriff verweigert") as caught:
        _guest(runner).tool("staged-os", timeout=60)
    assert caught.value.envelope.data.text("error_type") == "PermissionError"


def test_a_usage_error_envelope_raises_internal() -> None:
    # An older packed tool that does not know the command answers with command "" and exit 2.
    runner = FakeRunner().on("setup-alive", crashed("", ValueError("invalid choice: 'setup-alive'")))
    with pytest.raises(GuestInternalError, match="invalid choice"):
        _guest(runner).tool("setup-alive", timeout=60)


@pytest.mark.parametrize(
    "reply",
    [
        Reply(0, answer("build", BUILD).stdout * 2),
        Reply(0, answer("drives", BUILD).stdout),
        Reply(0, answer("build", BUILD, ok=False).stdout),
        Reply(1, answer("build", BUILD).stdout),
        Reply(0, '{"ok": "yes", "command": "build", "data": {}, "skipped": []}'),
        Reply(0, '{"ok": true, "command": "build", "data": [], "skipped": []}'),
    ],
)
def test_an_inconsistent_envelope_raises_protocol_error(reply: Reply) -> None:
    runner = FakeRunner().on("build", reply)
    with pytest.raises(GuestProtocolError):
        _guest(runner).tool("build", timeout=60)


def test_probe_treats_a_refusal_as_a_protocol_breach() -> None:
    runner = FakeRunner().on("staged-os", answer("staged-os", StagedOs("x", False, "RERUN"), ok=False))
    with pytest.raises(GuestProtocolError, match="refused"):
        _guest(runner).probe("staged-os", timeout=60)


# --- typed fields ---------------------------------------------------------------------------


def _fields(data: object) -> guest_ssh.Fields:
    runner = FakeRunner().on("build", answer("build", data))
    return _guest(runner).probe("build", timeout=60)


def test_a_missing_field_is_a_protocol_error_not_a_default() -> None:
    with pytest.raises(GuestProtocolError, match="schtasks_exit"):
        _fields({"registered": True}).integer("schtasks_exit")


@pytest.mark.parametrize(
    ("data", "getter"),
    [
        ({"x": True}, "integer"),
        ({"x": 1}, "flag"),
        ({"x": 1}, "text"),
        ({"x": "1"}, "number"),
        ({"x": None}, "text"),
        ({"x": [1]}, "section"),
    ],
)
def test_a_mistyped_field_is_a_protocol_error(data: object, getter: str) -> None:
    with pytest.raises(GuestProtocolError, match="'x'"):
        getattr(_fields(data), getter)("x")


def test_optional_getters_accept_null_and_nested_sections_read() -> None:
    fields = _fields({"a": None, "b": {"c": ["x", "y"], "d": [{"e": 1.5}]}, "n": 3})
    assert fields.text_or_none("a") is None
    assert fields.integer_or_none("a") is None
    assert fields.flag_or_none("a") is None
    assert fields.section("b").texts("c") == ("x", "y")
    assert fields.section("b").sections("d")[0].number("e") == 1.5
    assert fields.number("n") == 3.0


def test_gate_returns_the_field_and_checks_it_agrees_with_ok() -> None:
    runner = FakeRunner().on("restore-wu", answer("restore-wu", {"verdict": "RESTORED"}, ok=False))
    env = _guest(runner).tool("restore-wu", timeout=60)
    with pytest.raises(GuestProtocolError, match="RESTORED"):
        env.gate("verdict", "RESTORED")


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
    state = guest_ssh.read_run_state(_guest(runner), timeout=300)
    assert (state.live, state.marker, state.alive) == (live, marker, alive)
    assert state.log_path == r"C:\upgrade-state.log"


def test_run_state_with_an_unknown_marker_is_a_protocol_error() -> None:
    runner = FakeRunner().on("setup-alive", answer("setup-alive", SetupReport(0, False)))
    runner.on("state", answer("state", {"path": "C:\\x.log", "present": True, "verdict": "DONE-MAYBE"}))
    with pytest.raises(GuestProtocolError, match="DONE-MAYBE"):
        guest_ssh.read_run_state(_guest(runner), timeout=300)


@pytest.mark.parametrize("reply", [Reply(255, "", "reset"), crashed("setup-alive", OSError("wmi"))])
def test_run_state_that_cannot_be_read_raises_instead_of_reading_as_idle(reply: Reply) -> None:
    runner = FakeRunner().on("setup-alive", reply)
    with pytest.raises((GuestNoAnswerError, GuestInternalError)):
        guest_ssh.read_run_state(_guest(runner), timeout=300)


# --- shared helpers the drivers gate on -------------------------------------------------------


@pytest.mark.parametrize(
    ("verdict", "marker"), [(None, None), ("DONE-OK", "STATE=DONE-OK"), ("DONE-FAIL", "STATE=DONE-FAIL")]
)
def test_state_marker_maps_the_verdict_to_its_marker_line(verdict: str | None, marker: str | None) -> None:
    fields = guest_ssh.Fields({"verdict": verdict}, "state.data")
    assert guest_ssh.state_marker(fields) == marker


def test_state_marker_refuses_an_unknown_verdict() -> None:
    with pytest.raises(GuestProtocolError, match="DONE-MAYBE"):
        guest_ssh.state_marker(guest_ssh.Fields({"verdict": "DONE-MAYBE"}, "state.data"))


def test_a_crash_keeps_the_tail_of_the_guest_traceback() -> None:
    traceback = "\n".join(
        ["Traceback (most recent call last):", *(f'  File "x.py", line {i}' for i in range(30)),
         "PermissionError: [WinError 5] Zugriff verweigert"]
    )  # fmt: skip
    reply = Reply(2, crashed("quiesce-wu", PermissionError("denied")).stdout, traceback)
    runner = FakeRunner().on("quiesce-wu", reply)
    with pytest.raises(GuestInternalError) as caught:
        _guest(runner).tool("quiesce-wu", timeout=60)
    assert "PermissionError: [WinError 5] Zugriff verweigert" in str(caught.value)
    assert len(caught.value.stderr_tail) == guest_ssh.STDERR_TAIL_LINES
    assert caught.value.stderr_tail[-1] == "PermissionError: [WinError 5] Zugriff verweigert"
    assert guest_ssh.guest_stderr(RuntimeError("no guest call behind it")) is None


def test_guest_stderr_is_found_through_the_cause_chain() -> None:
    runner = FakeRunner().on("build", crashed("build", OSError("x")))
    try:
        _guest(runner).tool("build", timeout=60)
    except GuestInternalError as exc:
        try:
            raise RuntimeError("driver refusal") from exc
        except RuntimeError as wrapped:
            assert guest_ssh.guest_stderr(wrapped) == ("Traceback ...",)


@pytest.mark.parametrize("error", [subprocess.TimeoutExpired(["scp"], 5400), OSError("no scp")])
def test_copy_to_that_times_out_or_cannot_start_is_a_failed_process(error: BaseException) -> None:
    runner = FakeRunner().on("scp", error)
    proc = _guest(runner).copy_to(["/media/setup.exe"], "D:\\upgrade\\", timeout=5400)
    assert proc.returncode == 255
    assert "media transfer" in proc.stderr


# --- the content address both deploy units agree on (from the lockdown tests) ----------------


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
