"""Tests for the envelope contract: the arguments it refuses, how an answer is validated, every way a read fails.

The answers are driven through a real ``Guest`` over the injected runner
(``guest_fakes.FakeRunner``), so each test reads exactly what a guest call reads; nothing reaches ssh.
The envelopes come from the guest tool's own ``envelope`` module and data models, so the contract
tests below fail when a payload field is renamed, added or dropped on either side.
"""

from __future__ import annotations

import json
import re
import subprocess

import pytest
from guest_fakes import (
    BUILD_BEFORE,
    GUEST_IP,
    NIC_MACS,
    TOOL_DIR,
    TOOL_PATH,
    USER,
    FakeRunner,
    Reply,
    answer,
    crashed,
    drive_report,
    launch_report,
    locked,
    prepare_report,
    quiesce_report,
    restore_report,
    servicing_report,
    state_log,
)
from pwshpy import ServiceState, TaskState
from pydantic import BaseModel, ValidationError, field_validator

from pve_winrepair.adapters.guest_ssh import Guest
from pve_winrepair.domain import guest_answers as answers
from pve_winrepair.domain.envelope import (
    STDERR_TAIL_LINES,
    Fields,
    GuestInternalError,
    GuestNoAnswerError,
    GuestProtocolError,
    InternalErrorData,
    SkippedItem,
    UnsafeArgumentError,
    describe_validation_error,
    guest_stderr,
    state_marker,
)
from pve_winrepair.domain.guest_answers import GatedPayload, GuestCommand, ProbePayload
from pve_winrepair.domain.settings import SshSettings
from pve_winrepair_guest.envelope import Outcome, build, render
from pve_winrepair_guest.probes import (
    Container,
    LpDefectReport,
    LpVerdict,
    RunnerReport,
    RunnerVerdict,
    SetupReport,
    StagedOs,
    StagedVerdict,
    TaskReport,
)
from pve_winrepair_guest.upgrade import UpgradeRunReport
from pve_winrepair_guest.winrepair_guest import default_commands

SSH = SshSettings(key="/keys/test.key", user=USER)
BUILD = GuestCommand.BUILD


def _guest(runner: FakeRunner) -> Guest:
    return Guest(GUEST_IP, ssh_settings=SSH, tool_dir=TOOL_DIR, runner=runner)


def _build(runner: FakeRunner) -> answers.BuildAnswer:
    return _guest(runner).ask(BUILD, answers.BuildAnswer, timeout=60).data


def _envelope(command: str, data: object, *, ok: bool = True) -> str:
    """The guest's envelope line for ``data``, as a string to edit for a broken-contract case."""
    return render(build(command, Outcome(ok=ok, data=data)))


# --- arguments ------------------------------------------------------------------------------


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
        _guest(runner).ask(GuestCommand.PREPARE, answers.PrepareAnswer, "--stage-root", bad, timeout=60)
    assert runner.calls == []


@pytest.mark.parametrize("good", ["D:\\upgrade", "C:\\upgrade-state.log", "18", "--stage-root", "C:/x_y.z"])
def test_a_plain_argument_passes(good: str) -> None:
    runner = FakeRunner().on("state", answer("state", state_log()))
    _guest(runner).ask(GuestCommand.STATE, answers.StateAnswer, "--log", good, timeout=60)
    assert runner.calls[0][-2] == good


def test_the_subcommand_travels_as_its_value() -> None:
    runner = FakeRunner().on("build", answer("build", BUILD_BEFORE))
    _build(runner)
    assert runner.calls[0][-2:] == ["build", "--json"]


# --- a valid answer -------------------------------------------------------------------------


def test_a_valid_answer_is_returned_typed() -> None:
    runner = FakeRunner().on("build", answer("build", BUILD_BEFORE))
    got = _guest(runner).ask(BUILD, answers.BuildAnswer, timeout=60)
    assert (got.ok, got.command, got.skipped) == (True, GuestCommand.BUILD, ())
    assert got.data == answers.BuildAnswer(
        current_build="26200", ubr=7462, build="26200.7462", install_date=BUILD_BEFORE.install_date
    )


def test_a_refused_answer_is_returned_not_raised() -> None:
    runner = FakeRunner().on("restore-wu", answer("restore-wu", restore_report("STILL_DISABLED"), ok=False))
    got = _guest(runner).ask(GuestCommand.RESTORE_WU, answers.RestoreWuAnswer, timeout=60)
    assert (got.ok, got.data.verdict) == (False, answers.RestoreVerdict.STILL_DISABLED)


def test_bootstrap_noise_around_the_envelope_is_ignored() -> None:
    reply = answer("setup-alive", SetupReport(count=1, alive=True))
    noisy = Reply(0, 'uv was not found; installing it ...\r\n{"progress": 1}\r\n' + reply.stdout + "\r\n")
    runner = FakeRunner().on("setup-alive", noisy)
    assert _guest(runner).ask(GuestCommand.SETUP_ALIVE, answers.SetupAliveAnswer, timeout=60).data.alive is True


def test_skipped_items_are_read_typed() -> None:
    line = _envelope("drives", drive_report(C=1.0))
    assert '"skipped": []' in line
    runner = FakeRunner().on(
        "drives", Reply(0, line.replace('"skipped": []', '"skipped": [{"item": "D:", "reason": "x"}]'))
    )
    got = _guest(runner).ask(GuestCommand.DRIVES, answers.DrivesAnswer, timeout=60)
    assert got.skipped == (SkippedItem(item="D:", reason="x"),)


# --- no answer, a crash ---------------------------------------------------------------------


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
        _build(runner)


def test_a_valid_envelope_under_a_foreign_exit_code_is_no_answer() -> None:
    runner = FakeRunner().on("build", Reply(255, answer("build", BUILD_BEFORE).stdout, "Connection reset"))
    with pytest.raises(GuestNoAnswerError, match="exit 255"):
        _build(runner)


def test_a_timeout_raises_no_answer() -> None:
    runner = FakeRunner().on("build", subprocess.TimeoutExpired(["ssh"], 60))
    with pytest.raises(GuestNoAnswerError, match="timed out"):
        _build(runner)


def test_ssh_that_cannot_start_raises_no_answer() -> None:
    runner = FakeRunner().on("build", FileNotFoundError(2, "No such file or directory", "ssh"))
    with pytest.raises(GuestNoAnswerError, match="could not run"):
        _build(runner)


def test_an_internal_error_envelope_raises_with_the_guest_error() -> None:
    runner = FakeRunner().on("staged-os", crashed("staged-os", PermissionError("Zugriff verweigert")))
    with pytest.raises(GuestInternalError, match="guest tool staged-os failed: Zugriff verweigert") as caught:
        _guest(runner).ask(GuestCommand.STAGED_OS, answers.StagedOsAnswer, timeout=60)
    assert caught.value.answer.data == InternalErrorData(error="Zugriff verweigert", error_type="PermissionError")


def test_a_usage_error_envelope_raises_internal_naming_no_command() -> None:
    # An older packed tool that does not know the command answers with command "" and exit 2.
    runner = FakeRunner().on("setup-alive", crashed("", ValueError("invalid choice: 'setup-alive'")))
    with pytest.raises(GuestInternalError, match=re.escape("guest tool ? failed: invalid choice")):
        _guest(runner).ask(GuestCommand.SETUP_ALIVE, answers.SetupAliveAnswer, timeout=60)


def test_an_exit_2_envelope_without_the_error_payload_is_a_protocol_error() -> None:
    runner = FakeRunner().on("build", Reply(2, _envelope("build", BUILD_BEFORE, ok=False)))
    with pytest.raises(GuestProtocolError, match=re.escape("data.error: Field required")):
        _build(runner)


def test_a_crash_keeps_the_tail_of_the_guest_traceback() -> None:
    traceback = "\n".join(
        ["Traceback (most recent call last):", *(f'  File "x.py", line {i}' for i in range(30)),
         "PermissionError: [WinError 5] Zugriff verweigert"]
    )  # fmt: skip
    reply = Reply(2, crashed("quiesce-wu", PermissionError("denied")).stdout, traceback)
    runner = FakeRunner().on("quiesce-wu", reply)
    with pytest.raises(GuestInternalError) as caught:
        _guest(runner).ask(GuestCommand.QUIESCE_WU, answers.QuiesceWuAnswer, timeout=60)
    assert "PermissionError: [WinError 5] Zugriff verweigert" in str(caught.value)
    assert len(caught.value.stderr_tail) == STDERR_TAIL_LINES
    assert caught.value.stderr_tail[-1] == "PermissionError: [WinError 5] Zugriff verweigert"
    assert guest_stderr(RuntimeError("no guest call behind it")) is None


def test_guest_stderr_is_found_through_the_cause_chain() -> None:
    runner = FakeRunner().on("build", crashed("build", OSError("x")))
    try:
        _build(runner)
    except GuestInternalError as exc:
        try:
            raise RuntimeError("driver refusal") from exc
        except RuntimeError as wrapped:
            assert guest_stderr(wrapped) == ("Traceback ...",)


# --- a broken contract ----------------------------------------------------------------------

GOOD = _envelope("build", BUILD_BEFORE)


@pytest.mark.parametrize(
    ("line", "exit_code", "fragment"),
    [
        (GOOD + "\r\n" + GOOD, 0, "2 envelopes on stdout"),
        (_envelope("drives", drive_report(C=1.0)), 0, "asked 'build', the envelope answers 'drives'"),
        (_envelope("build", BUILD_BEFORE, ok=False), 0, "ok=False with exit 0"),
        (GOOD, 1, "ok=True with exit 1"),
        (GOOD.replace('"ok": true', '"ok": "yes"'), 0, "ok: Input should be a valid boolean"),
        (GOOD.replace('"command": "build"', '"command": "bild"'), 0, "command: Input should be"),
        ('{"ok": true, "command": "build", "data": [], "skipped": []}', 0, "data: Input should be an object"),
        (GOOD.replace('"skipped": []', '"skipped": [{"item": "x"}]'), 0, "skipped.0.reason: Field required"),
        (GOOD.replace('"skipped": []', '"skipped": [], "extra": 1'), 0, "extra: Extra inputs are not permitted"),
    ],
    ids=["two", "other-command", "ok-false-exit-0", "ok-true-exit-1", "ok-text", "unknown-command", "data-list",
         "skipped-item", "extra-key"],
)  # fmt: skip
def test_an_inconsistent_envelope_raises_protocol_error(line: str, exit_code: int, fragment: str) -> None:
    runner = FakeRunner().on("build", Reply(exit_code, line))
    with pytest.raises(GuestProtocolError, match=re.escape(fragment)):
        _build(runner)


@pytest.mark.parametrize(
    ("edit", "fragment"),
    [
        (('"ubr": 7462', '"ubr": true'), "data.ubr: Input should be a valid integer"),
        (('"ubr": 7462', '"ubr": "7462"'), "data.ubr: Input should be a valid integer"),
        (('"ubr": 7462, ', ""), "data.ubr: Field required"),
        (('"ubr": 7462', '"ubr": 7462, "renamed": 1'), "data.renamed: Extra inputs are not permitted"),
        (('"ubr": 7462', '"ubr": null'), "data.ubr: Input should be a valid integer"),
    ],
    ids=["bool-for-int", "text-for-int", "missing", "unknown-field", "null"],
)
def test_a_payload_field_that_breaks_the_model_is_a_protocol_error_naming_it(
    edit: tuple[str, str], fragment: str
) -> None:
    assert edit[0] in GOOD
    runner = FakeRunner().on("build", Reply(0, GOOD.replace(*edit)))
    with pytest.raises(
        GuestProtocolError, match=re.escape(f"guest tool build: the answer breaks the contract: {fragment}")
    ):
        _build(runner)


def test_an_unknown_verdict_is_refused_without_echoing_it_and_keeps_the_validation_error_as_cause() -> None:
    line = _envelope("lock-dirs", locked(present=True)).replace('"verdict": "OK"', '"verdict": "PLANTED-VERDICT"')
    runner = FakeRunner().on("lock-dirs", Reply(0, line))
    with pytest.raises(GuestProtocolError, match=re.escape("data.verdict: Input should be 'OK' or 'FAILED'")) as caught:
        _guest(runner).ask(GuestCommand.LOCK_DIRS, answers.LockDirsAnswer, timeout=60)
    assert "PLANTED-VERDICT" not in str(caught.value)
    assert isinstance(caught.value.__cause__, ValidationError)


def test_a_probe_that_refuses_is_a_protocol_breach() -> None:
    staged = StagedOs(path="x", present=False, verdict=StagedVerdict.RERUN)
    runner = FakeRunner().on("staged-os", answer("staged-os", staged, ok=False))
    with pytest.raises(GuestProtocolError, match=re.escape("probe staged-os refused (exit 1); it never should")):
        _guest(runner).ask(GuestCommand.STAGED_OS, answers.StagedOsAnswer, timeout=60)


def test_a_verdict_that_contradicts_ok_is_a_protocol_error() -> None:
    runner = FakeRunner().on("restore-wu", answer("restore-wu", restore_report("RESTORED"), ok=False))
    with pytest.raises(
        GuestProtocolError, match=re.escape("restore-wu: ok=False contradicts verdict='RESTORED' (pass is 'RESTORED')")
    ):
        _guest(runner).ask(GuestCommand.RESTORE_WU, answers.RestoreWuAnswer, timeout=60)


def test_a_failed_gate_reported_as_ok_is_a_protocol_error() -> None:
    runner = FakeRunner().on("prepare", answer("prepare", prepare_report("FAIL", "too old"), ok=True))
    with pytest.raises(
        GuestProtocolError, match=re.escape("prepare: ok=True contradicts gate='FAIL' (pass is 'PASS')")
    ):
        _guest(runner).ask(GuestCommand.PREPARE, answers.PrepareAnswer, timeout=60)


def test_a_verdict_with_two_passing_values_names_both() -> None:
    report = _lp_report(LpVerdict.CLEAN)
    runner = FakeRunner().on("detect-lp-defect", answer("detect-lp-defect", report, ok=False))
    with pytest.raises(GuestProtocolError, match=re.escape("(pass is 'AFFECTED' or 'CLEAN')")):
        _guest(runner).ask(GuestCommand.DETECT_LP_DEFECT, answers.DetectLpDefectAnswer, timeout=60)


# --- the contract with the guest's own models -----------------------------------------------


def _lp_report(verdict: LpVerdict) -> LpDefectReport:
    return LpDefectReport(
        host="GUEST",
        current_build="26200",
        ubr=7462,
        build="26200.7462",
        display_version="25H2",
        install_language="0407",
        lp_absent_events=0,
        events_read=600,
        events_unrendered=0,
        codes=("0x800736b3",),
        last=None,
        verdict=verdict,
        reason=None,
    )


RUNNERS = RunnerReport(
    tasks=(
        TaskReport(
            name="StartRunners",
            present=True,
            task_path="\\",
            state=TaskState.READY,
            enabled=True,
            last_run="2026-10-21T09:05:07",
            last_result=0,
        ),
    ),
    docker_service=ServiceState.RUNNING,
    dockerd_processes=1,
    containers=(Container(name="runner-1", status="Up 3 minutes"),),
    count=1,
    expected=1,
    verdict=RunnerVerdict.OK,
)
UPGRADE_RUN = UpgradeRunReport(
    state_log="C:\\upgrade-state.log",
    setup="D:\\upgrade\\setup.exe",
    argv=("/auto", "upgrade"),
    build_before="26200.7462",
    build_after="26200.7462",
    exit_code=0,
    exit_hex="0x00000000",
    seconds=3725.0,
    tree_wait="job",
    newos_staged=True,
    verdict="DONE-OK",
    reason=None,
)

#: One real reply per subcommand, built from the guest's own models, and the host model it validates into.
CONTRACT: dict[GuestCommand, tuple[object, type[ProbePayload | GatedPayload]]] = {
    GuestCommand.DETECT_LP_DEFECT: (_lp_report(LpVerdict.AFFECTED), answers.DetectLpDefectAnswer),
    GuestCommand.DRIVES: (drive_report(C=60.0, D=200.0), answers.DrivesAnswer),
    GuestCommand.VERIFY_RUNNERS: (RUNNERS, answers.VerifyRunnersAnswer),
    GuestCommand.BUILD: (BUILD_BEFORE, answers.BuildAnswer),
    GuestCommand.STAGED_OS: (StagedOs(path="x", present=True, verdict=StagedVerdict.REARMABLE), answers.StagedOsAnswer),
    GuestCommand.SERVICING_ACTIVE: (servicing_report(2), answers.ServicingActiveAnswer),
    GuestCommand.SETUP_ALIVE: (SetupReport(count=1, alive=True), answers.SetupAliveAnswer),
    GuestCommand.STATE: (state_log("launching: setup.exe", "STATE=DONE-OK setup exit=0x0"), answers.StateAnswer),
    GuestCommand.NIC_MACS: (None, answers.NicMacsAnswer),
    GuestCommand.QUIESCE_WU: (quiesce_report("OK"), answers.QuiesceWuAnswer),
    GuestCommand.RESTORE_WU: (restore_report("RESTORED"), answers.RestoreWuAnswer),
    GuestCommand.PREPARE: (prepare_report("PASS"), answers.PrepareAnswer),
    GuestCommand.LOCK_DIRS: (locked(present=True, stage_root="D:\\upgrade"), answers.LockDirsAnswer),
    GuestCommand.LAUNCH: (launch_report("OK"), answers.LaunchAnswer),
    GuestCommand.UPGRADE_RUN: (UPGRADE_RUN, answers.UpgradeRunAnswer),
}


def test_the_host_knows_exactly_the_guest_s_subcommands() -> None:
    assert {command.value for command in GuestCommand} == {command.name for command in default_commands()}
    assert set(CONTRACT) == set(GuestCommand)


@pytest.mark.parametrize("command", list(GuestCommand), ids=lambda command: command.value)
def test_every_guest_reply_validates_into_its_host_model_unchanged(command: GuestCommand) -> None:
    data, payload = CONTRACT[command]
    reply = NIC_MACS if data is None else answer(command.value, data)
    runner = FakeRunner().on(command.value, reply)
    got = _guest(runner).ask(command, payload, timeout=60)
    # Every field the guest sent is declared and re-serialises to the same JSON: nothing was read
    # into a looser type, renamed or dropped on the way in.
    sent = json.loads(reply.stdout)["data"]
    assert got.data.model_dump(mode="json") == sent


def test_a_new_field_on_the_guest_side_fails_the_contract() -> None:
    sent = BUILD_BEFORE.model_dump(mode="json") | {"edition_id": "Professional"}
    runner = FakeRunner().on("build", answer("build", sent))
    with pytest.raises(GuestProtocolError, match=re.escape("data.edition_id: Extra inputs are not permitted")):
        _build(runner)


# --- the validation message -----------------------------------------------------------------


class _Checked(BaseModel):
    count: int

    @field_validator("count")
    @classmethod
    def _positive(cls, value: int) -> int:
        if value < 1:
            raise ValueError("must be at least 1")
        return value


def test_a_validator_message_is_shown_without_pydantic_s_prefix() -> None:
    with pytest.raises(ValidationError) as caught:
        _Checked.model_validate_json('{"count": 0}')
    assert describe_validation_error(caught.value, root="doc") == "count: must be at least 1"


def test_a_problem_without_a_location_is_named_by_the_root() -> None:
    with pytest.raises(ValidationError) as caught:
        _Checked.model_validate_json("[]")
    assert describe_validation_error(caught.value, root="doc").startswith("doc: ")


# --- TEMPORARY(data-arch): the name-keyed read path, removed once repair.py/apply.py read typed answers


def test_the_name_keyed_path_refuses_an_unsafe_subcommand_before_ssh() -> None:
    runner = FakeRunner()
    with pytest.raises(UnsafeArgumentError):
        _guest(runner).tool("build&calc", timeout=60)
    assert runner.calls == []


def test_the_name_keyed_path_reads_fields_and_its_exit_code() -> None:
    runner = FakeRunner().on("build", answer("build", BUILD_BEFORE))
    env = _guest(runner).tool("build", timeout=60)
    assert (env.ok, env.command, env.exit_code) == (True, "build", 0)
    assert env.data.text("current_build") == "26200"
    assert env.data.integer("ubr") == 7462


def test_the_name_keyed_probe_treats_a_refusal_as_a_protocol_breach() -> None:
    staged = StagedOs(path="x", present=False, verdict=StagedVerdict.RERUN)
    runner = FakeRunner().on("staged-os", answer("staged-os", staged, ok=False))
    with pytest.raises(GuestProtocolError, match="refused"):
        _guest(runner).probe("staged-os", timeout=60)


def test_the_name_keyed_path_raises_internal_errors_typed() -> None:
    runner = FakeRunner().on("build", crashed("build", OSError("denied")))
    with pytest.raises(GuestInternalError) as caught:
        _guest(runner).tool("build", timeout=60)
    assert caught.value.answer.data.error_type == "OSError"


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


def test_the_tool_path_is_the_content_address() -> None:
    runner = FakeRunner().on("build", answer("build", BUILD_BEFORE))
    _build(runner)
    assert runner.calls[0][runner.calls[0].index("-File") + 1] == TOOL_PATH
