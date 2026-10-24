"""Tests for the envelope contract: the arguments it refuses, how an answer is read, its typed fields.

The answers are driven through a real ``Guest`` over the injected runner
(``guest_fakes.FakeRunner``), so each test reads exactly what a guest call reads; nothing reaches ssh.
The envelopes come from the guest tool's own ``envelope`` module and data models.
"""

from __future__ import annotations

import subprocess

import pytest
from guest_fakes import GUEST_IP, TOOL_DIR, USER, FakeRunner, Reply, answer, crashed

from pve_winrepair.adapters.guest_ssh import Guest
from pve_winrepair.domain.envelope import (
    STDERR_TAIL_LINES,
    Fields,
    GuestInternalError,
    GuestNoAnswerError,
    GuestProtocolError,
    UnsafeArgumentError,
    guest_stderr,
    state_marker,
)
from pve_winrepair.domain.settings import SshSettings
from pve_winrepair_guest.probes import BuildInfo, SetupReport, StagedOs

SSH = SshSettings(key="/keys/test.key", user=USER)
BUILD = BuildInfo(current_build="26200", ubr=8973, build="26200.8973")


def _guest(runner: FakeRunner) -> Guest:
    return Guest(GUEST_IP, ssh_settings=SSH, tool_dir=TOOL_DIR, runner=runner)


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
    runner = FakeRunner().on(
        "staged-os", answer("staged-os", StagedOs(path="x", present=False, verdict="RERUN"), ok=False)
    )
    with pytest.raises(GuestProtocolError, match="refused"):
        _guest(runner).probe("staged-os", timeout=60)


def _fields(data: object) -> Fields:
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


@pytest.mark.parametrize(
    ("verdict", "marker"), [(None, None), ("DONE-OK", "STATE=DONE-OK"), ("DONE-FAIL", "STATE=DONE-FAIL")]
)
def test_state_marker_maps_the_verdict_to_its_marker_line(verdict: str | None, marker: str | None) -> None:
    fields = Fields({"verdict": verdict}, "state.data")
    assert state_marker(fields) == marker


def test_state_marker_refuses_an_unknown_verdict() -> None:
    with pytest.raises(GuestProtocolError, match="DONE-MAYBE"):
        state_marker(Fields({"verdict": "DONE-MAYBE"}, "state.data"))


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
    assert len(caught.value.stderr_tail) == STDERR_TAIL_LINES
    assert caught.value.stderr_tail[-1] == "PermissionError: [WinError 5] Zugriff verweigert"
    assert guest_stderr(RuntimeError("no guest call behind it")) is None


def test_guest_stderr_is_found_through_the_cause_chain() -> None:
    runner = FakeRunner().on("build", crashed("build", OSError("x")))
    try:
        _guest(runner).tool("build", timeout=60)
    except GuestInternalError as exc:
        try:
            raise RuntimeError("driver refusal") from exc
        except RuntimeError as wrapped:
            assert guest_stderr(wrapped) == ("Traceback ...",)
