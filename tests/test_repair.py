"""Tests for the repair use case's guest-facing steps and its whole run, through the ssh runner seam.

Every answer is a real guest envelope built from the guest tool's own data models, so these tests
pin the field names the driver gates on. The PVE side (``qm``) is a ``FakePve`` that tracks the VM's
power state.
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from ipaddress import IPv4Address
from typing import TYPE_CHECKING

import pytest
from guest_fakes import (
    ALIVE,
    GONE,
    GUEST_IP,
    IMAGE,
    INSTALL_DATE,
    LAN_IP,
    MUTATING_QM,
    NIC_MACS,
    NO_LOG,
    TOOL_DIR,
    TOOL_PATH,
    USER,
    VM_MAC,
    Answer,
    FakeClock,
    FakePve,
    FakeRunner,
    Reply,
    agent_runner,
    answer,
    call_labels,
    crashed,
    drive_report,
    hashes_to,
    launch_report,
    lock_dirs_reply,
    locked,
    make_guest,
    make_node,
    prepare_report,
    quiesce_report,
    servicing_report,
    state_log,
    tool_on_the_guest,
)
from pydantic import ValidationError

from pve_winrepair.adapters.receipts import FileReceiptStore
from pve_winrepair.application import repair
from pve_winrepair.application.repair import RepairError, RepairRequest, run_repair
from pve_winrepair.domain.enums import DriveLetter
from pve_winrepair.domain.envelope import (
    WU_HELD_HINT,
    GuestInternalError,
    GuestProtocolError,
    InternalErrorAnswer,
    InternalErrorData,
)
from pve_winrepair.domain.receipt import RepairReceipt
from pve_winrepair.domain.report import Report, RunExit, RunResult, RunVerdict, Step, StepName
from pve_winrepair.domain.settings import GuestSettings, RepairSettings
from pve_winrepair_guest.probes import NicMacReport, SetupReport
from pve_winrepair_guest.upgrade import LaunchReport, LockDirsReport, TaskCleanup

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path


def _repair_settings(media: Path) -> RepairSettings:
    return RepairSettings(media_dir=str(media), snapshot_name="pre_kb_test", stage_free_gb=15.0, system_free_gb=25.0)


# The free-space floors the stage-root tests gate on (media_dir is not read there).
REPAIR = RepairSettings(snapshot_name="pre_kb_test", stage_free_gb=15.0, system_free_gb=25.0)
GUEST = GuestSettings(subnet="192.0.2.0/24")


def _wire(steps: Sequence[Step]) -> list[dict[str, object]]:
    """The steps as the --json envelope carries them."""
    return [step.model_dump() for step in steps]


def _step(rep: Report, name: str) -> dict[str, object]:
    return next(s for s in _wire(rep.steps) if s["step"] == name)


# --- the report ------------------------------------------------------------------------------


def test_on_step_receives_each_step_in_order() -> None:
    recorded: list[Step] = []
    rep = Report(vmid=1, on_step=recorded.append)
    rep.add(StepName.SHUTDOWN, ok=True, note="already stopped")
    rep.add(StepName.VTPM, ok=False, storage="local")
    assert _wire(recorded) == [
        {"step": "shutdown", "ok": True, "note": "already stopped"},
        {"step": "vtpm", "ok": False, "storage": "local"},
    ]
    assert recorded == rep.steps


def test_a_report_held_at_start_flags_the_hold_on_a_failure() -> None:
    rep = Report(vmid=1, held_at_start=True)
    assert rep.wu_held is True
    rep.failure(StepName.ERROR, "refused", RuntimeError("refused"))
    assert _wire(rep.steps)[-1]["wu_held"] is True
    assert "restore-wu" in str(_wire(rep.steps)[-1]["message"])


def test_a_report_without_a_quiesce_step_is_not_held() -> None:
    rep = Report(vmid=1)
    rep.add(StepName.QUIESCE_WU, ok=False)
    assert rep.wu_held is False


def test_a_step_keeps_the_order_its_keys_were_recorded_in_and_a_held_step_appends_the_new_ones() -> None:
    """The --json bytes follow recording order: a note recorded first stays first, a new one goes last."""
    rep = Report(vmid=1, held_at_start=True)
    rep.add(StepName.VTPM, ok=True, note="added v2.0", storage="local")
    rep.add(StepName.POLL, ok=False, verdict=RunVerdict.DONE_FAIL)
    rep.ended_held()
    assert list(rep.steps[0].model_dump()) == ["step", "ok", "note", "storage"]
    assert list(rep.steps[1].model_dump()) == ["step", "ok", "verdict", "wu_held", "note"]
    rep.add(StepName.POLL, ok=False, verdict=RunVerdict.WORKER_GONE, note="no verdict")
    rep.ended_held()
    assert list(rep.steps[2].model_dump()) == ["step", "ok", "verdict", "note", "wu_held"]
    assert rep.steps[2].note == f"no verdict - {WU_HELD_HINT}"


def test_a_failure_step_carries_message_hold_and_guest_traceback_in_that_order() -> None:
    rep = Report(vmid=1, held_at_start=True)
    crash = InternalErrorAnswer(
        ok=False, command="quiesce-wu", data=InternalErrorData(error="boom", error_type="OSError"), skipped=()
    )
    rep.failure(StepName.ERROR, "refused", GuestInternalError(crash, "line 1\nline 2\n"))
    assert list(rep.steps[0].model_dump()) == ["step", "ok", "message", "wu_held", "guest_stderr"]
    assert rep.steps[0].model_dump()["guest_stderr"] == ["line 1", "line 2"]


def test_an_enum_measurement_is_kept_as_its_plain_value() -> None:
    """A RunVerdict a step records is a plain str inside it, so no rendering can show the member name."""
    step = Step.record(StepName.POLL, ok=True, fields={"verdict": RunVerdict.DONE_OK})
    assert type(step.detail["verdict"]) is str
    assert f"{step.detail['verdict']}" == "STATE=DONE-OK"


def test_a_step_with_an_unknown_name_or_a_key_order_that_misses_a_key_is_refused() -> None:
    with pytest.raises(ValidationError, match="step"):
        Step.model_validate({"step": "no_such_step", "ok": True, "detail": {}, "key_order": ()})
    with pytest.raises(ValidationError, match="key_order"):
        Step.model_validate({"step": "poll", "ok": True, "detail": {"verdict": "TIMEOUT"}, "key_order": ()})
    with pytest.raises(ValidationError, match="key_order"):
        Step.model_validate({"step": "poll", "ok": True, "note": "x", "detail": {}, "key_order": ()})


# --- quiesce-wu -----------------------------------------------------------------------------


def test_quiesce_ok_records_the_previous_start_modes() -> None:
    runner = FakeRunner().on("quiesce-wu", answer("quiesce-wu", quiesce_report("OK")))
    rep = Report(vmid=1)
    repair.quiesce_windows_update(make_guest(runner), rep)
    step = _step(rep, "quiesce_wu")
    assert step["ok"] is True
    assert step["previous_start_modes"] == {"wuauserv": "Manual", "UsoSvc": "Auto"}
    assert step["verdict"] == "OK"


def test_quiesce_fail_refuses_naming_what_still_runs() -> None:
    reply = answer("quiesce-wu", quiesce_report("FAIL", running=("wuauserv",)), ok=False)
    runner = FakeRunner().on("quiesce-wu", reply)
    with pytest.raises(RepairError, match=r"not held: FAIL.*wuauserv"):
        repair.quiesce_windows_update(make_guest(runner), Report(vmid=1))


def test_quiesce_without_an_answer_refuses() -> None:
    runner = FakeRunner().on("quiesce-wu", Reply(255, "", "Connection reset"))
    with pytest.raises(RepairError, match="no verdict"):
        repair.quiesce_windows_update(make_guest(runner), Report(vmid=1))


def test_quiesce_ok_flag_contradicting_the_verdict_is_a_protocol_error() -> None:
    runner = FakeRunner().on("quiesce-wu", answer("quiesce-wu", quiesce_report("FAIL"), ok=True))
    with pytest.raises(GuestProtocolError):
        repair.quiesce_windows_update(make_guest(runner), Report(vmid=1))


# --- drives / stage root --------------------------------------------------------------------


def test_stage_root_prefers_a_non_system_drive_with_room() -> None:
    runner = FakeRunner().on("drives", answer("drives", drive_report(C=40.0, D=200.0)))
    rep = Report(vmid=1)
    assert repair.pick_stage_root(make_guest(runner), rep, None, repair=REPAIR) == "D:\\upgrade"
    assert _step(rep, "stage_root")["drives"] == {"C": 40.0, "D": 200.0}


def test_stage_root_gates_on_exact_bytes_not_the_rounded_figure() -> None:
    # 14.96 GiB rounds to 15.0 in free_gb but is below the 15 GB floor.
    runner = FakeRunner().on("drives", answer("drives", drive_report(C=40.0, D=14.96)))
    assert repair.pick_stage_root(make_guest(runner), Report(vmid=1), None, repair=REPAIR) == "C:\\upgrade"


def test_stage_root_refuses_a_full_system_drive() -> None:
    runner = FakeRunner().on("drives", answer("drives", drive_report(C=10.0, D=200.0)))
    with pytest.raises(RepairError, match=r"C: has 10.0 GB free"):
        repair.pick_stage_root(make_guest(runner), Report(vmid=1), None, repair=REPAIR)


def test_stage_root_refuses_a_drive_the_guest_does_not_have() -> None:
    runner = FakeRunner().on("drives", answer("drives", drive_report(C=80.0)))
    with pytest.raises(RepairError, match="E: which the guest does not have"):
        repair.pick_stage_root(make_guest(runner), Report(vmid=1), DriveLetter.DRIVE_E, repair=REPAIR)


def test_stage_root_gates_on_the_configured_system_floor() -> None:
    runner = FakeRunner().on("drives", answer("drives", drive_report(C=40.0, D=200.0)))
    floors = RepairSettings(system_free_gb=50.0)
    with pytest.raises(RepairError, match=r"^C: has 40.0 GB free, below the 50.0 GB an in-place upgrade needs"):
        repair.pick_stage_root(make_guest(runner), Report(vmid=1), None, repair=floors)


def test_stage_root_gates_on_the_configured_stage_floor() -> None:
    runner = FakeRunner().on("drives", answer("drives", drive_report(C=60.0, D=200.0)))
    floors = RepairSettings(stage_free_gb=250.0)
    with pytest.raises(RepairError, match=r"^D: has only 200.0 GB free, need 250.0$"):
        repair.pick_stage_root(make_guest(runner), Report(vmid=1), DriveLetter.DRIVE_D, repair=floors)


def test_drives_unreadable_refuses_naming_the_guest_error() -> None:
    runner = FakeRunner().on("drives", crashed("drives", RuntimeError("no fixed drive with a letter")))
    with pytest.raises(RepairError, match=r"could not read any drive.*no fixed drive"):
        repair.pick_stage_root(make_guest(runner), Report(vmid=1), None, repair=REPAIR)


# --- servicing idle -------------------------------------------------------------------------


def test_servicing_idle_retries_a_failed_read_instead_of_calling_it_idle() -> None:
    runner = FakeRunner().on(
        "servicing-active",
        Reply(255, "", "timeout"),
        answer("servicing-active", servicing_report(1)),
        answer("servicing-active", servicing_report(0)),
    )
    clock, rep = FakeClock(), Report(vmid=1)
    repair.wait_servicing_idle(make_guest(runner), rep, clock=clock.time, sleep=clock.sleep)
    assert _step(rep, "servicing_idle")["ok"] is True
    assert clock.slept == [20, 30]


def test_servicing_still_active_at_the_deadline_is_reported() -> None:
    runner = FakeRunner().on("servicing-active", answer("servicing-active", servicing_report(2)))
    clock, rep = FakeClock(), Report(vmid=1)
    repair.wait_servicing_idle(make_guest(runner), rep, minutes=1.0, clock=clock.time, sleep=clock.sleep)
    assert _step(rep, "servicing_idle")["ok"] is False


# --- no live run before launch --------------------------------------------------------------


def test_live_run_check_passes_a_guest_with_no_run() -> None:
    runner = FakeRunner().on("setup-alive", answer("setup-alive", SetupReport(count=0, alive=False)))
    runner.on("state", answer("state", state_log(present=False)))
    rep = Report(vmid=1)
    repair.refuse_live_run(make_guest(runner), rep)
    assert _step(rep, "no_live_run")["ok"] is True


def test_live_run_check_passes_a_finished_run() -> None:
    runner = FakeRunner().on("setup-alive", answer("setup-alive", SetupReport(count=0, alive=False)))
    runner.on("state", answer("state", state_log("launching: setup.exe", "STATE=DONE-FAIL setup exit=0xC1900200")))
    rep = Report(vmid=1)
    repair.refuse_live_run(make_guest(runner), rep)
    assert _step(rep, "no_live_run")["previous_verdict"] == "DONE-FAIL"


def test_live_run_check_refuses_while_setuphost_runs() -> None:
    runner = FakeRunner().on("setup-alive", answer("setup-alive", SetupReport(count=2, alive=True)))
    runner.on("state", answer("state", state_log(present=False)))
    with pytest.raises(RepairError, match="SetupHost is running"):
        repair.refuse_live_run(make_guest(runner), Report(vmid=1))


def test_live_run_check_refuses_a_started_run_without_a_marker() -> None:
    runner = FakeRunner().on("setup-alive", answer("setup-alive", SetupReport(count=0, alive=False)))
    runner.on("state", answer("state", state_log("=== start", "launching: setup.exe")))
    with pytest.raises(RepairError, match="no DONE marker"):
        repair.refuse_live_run(make_guest(runner), Report(vmid=1))


def test_live_run_check_refuses_when_it_cannot_ask() -> None:
    runner = FakeRunner().on("setup-alive", Reply(255, "", "Connection refused"))
    with pytest.raises(RepairError, match="cannot verify"):
        repair.refuse_live_run(make_guest(runner), Report(vmid=1))


# --- prepare --------------------------------------------------------------------------------


def test_prepare_pass_reports_the_image_and_the_waiver() -> None:
    runner = FakeRunner().on("prepare", answer("prepare", prepare_report("PASS")))
    rep = Report(vmid=1)
    repair.prepare(make_guest(runner), rep, "D:\\upgrade")
    step = _step(rep, "prepare")
    assert step["ok"] is True
    assert (step["image_spbuild"], step["running"], step["waiver_readback"], step["tpm_present"]) == (
        8973,
        "26200.7462",
        1,
        True,
    )
    assert runner.calls[0][-3:] == ["--stage-root", "D:\\upgrade", "--json"]


def test_prepare_fail_refuses_with_the_guest_reason() -> None:
    reply = answer("prepare", prepare_report("FAIL", "image 26200.8973 older than running 26200.9711"), ok=False)
    runner = FakeRunner().on("prepare", reply)
    with pytest.raises(RepairError, match=r"guest gate refused: image 26200\.8973 older than running 26200\.9711"):
        repair.prepare(make_guest(runner), Report(vmid=1), "D:\\upgrade")


def test_prepare_reports_an_absent_tpm_without_refusing() -> None:
    runner = FakeRunner().on("prepare", answer("prepare", prepare_report("PASS", tpm=False)))
    rep = Report(vmid=1)
    repair.prepare(make_guest(runner), rep, "D:\\upgrade")
    assert _step(rep, "prepare")["ok"] is True
    assert "no TPM" in str(_step(rep, "prepare")["warnings"])


# --- launch ---------------------------------------------------------------------------------

REMOVED = TaskCleanup(action="REMOVE", ended=True, disabled=False, deleted=True, error=None)


def test_launch_points_the_system_task_at_the_pushed_tool() -> None:
    runner = FakeRunner().on("launch", answer("launch", launch_report("OK")))
    repair.launch(make_guest(runner), Report(vmid=1), "D:\\upgrade")
    argv = runner.calls[0]
    assert argv[argv.index("-File") + 1] == TOOL_PATH
    # The task's action runs the file named here, so it must be the content address just pushed.
    assert argv[argv.index("--tool") + 1] == TOOL_PATH


def test_launch_ok_records_the_step() -> None:
    runner = FakeRunner().on("launch", answer("launch", launch_report("OK")))
    rep = Report(vmid=1)
    assert repair.launch(make_guest(runner), rep, "D:\\upgrade") is None
    step = _step(rep, "launch")
    assert (step["ok"], step["verdict"], step["setuphost"], step["task_cleanup"]) == (True, "OK", 1, "DISARM")


@pytest.mark.parametrize(
    ("report", "fragment"),
    [
        (launch_report("SUSPECT", "setup already gone, read the state verdict", setuphost=0), "SUSPECT"),
        (
            launch_report(
                "SUSPECT",
                "the run ended before launching setup",
                wait="ENDED",
                setuphost=None,
                cleanup=REMOVED,
            ),
            "SUSPECT",
        ),
        (
            launch_report(
                "NO_START",
                "no 'launching' line within 600 s",
                wait="TIMEOUT",
                setuphost=None,
                cleanup=REMOVED,
            ),
            "NO_START",
        ),
        (
            launch_report("FAILED", "the task could not be registered: x", wait=None, setuphost=None, cleanup=REMOVED),
            "FAILED",
        ),
    ],
)
def test_launch_without_a_running_setup_refuses(report: LaunchReport, fragment: str) -> None:
    runner = FakeRunner().on("launch", answer("launch", report, ok=False))
    with pytest.raises(RepairError, match=fragment):
        repair.launch(make_guest(runner), Report(vmid=1), "D:\\upgrade")


def test_launch_task_left_after_disarm_keeps_polling() -> None:
    left = TaskCleanup(action="DISARM", ended=None, disabled=True, deleted=False, error="delete: access denied")
    report = launch_report("TASK_LEFT", "OK; the task \\OVMRepairUpgrade could not be disarmed: x", cleanup=left)
    runner = FakeRunner().on("launch", answer("launch", report, ok=False))
    rep = Report(vmid=1)
    repair.launch(make_guest(runner), rep, "D:\\upgrade")  # no raise: setup IS running
    step = _step(rep, "launch")
    assert (step["ok"], step["verdict"]) == (False, "TASK_LEFT")
    assert "schtasks" in str(step["note"])


def test_launch_task_left_after_disarm_does_not_claim_setup_is_running() -> None:
    # _settle can find SetupHost gone (SUSPECT) after a DISARM, which _louder turns into TASK_LEFT.
    left = TaskCleanup(action="DISARM", ended=None, disabled=True, deleted=False, error="delete: access denied")
    reason = "SUSPECT: setup already gone, read the state verdict; the task could not be disarmed: x"
    report = launch_report("TASK_LEFT", reason, setuphost=0, cleanup=left)
    runner = FakeRunner().on("launch", answer("launch", report, ok=False))
    rep = Report(vmid=1)
    repair.launch(make_guest(runner), rep, "D:\\upgrade")
    note = str(_step(rep, "launch")["note"])
    assert "is running" not in note
    assert reason in note


def test_launch_task_left_after_remove_refuses_with_the_manual_cleanup() -> None:
    left = TaskCleanup(
        action="REMOVE",
        ended=False,
        disabled=True,
        deleted=False,
        error="end: still running 30 s after the end request",
    )
    report = launch_report("TASK_LEFT", "NO_START: no 'launching' line", wait="TIMEOUT", setuphost=None, cleanup=left)
    runner = FakeRunner().on("launch", answer("launch", report, ok=False))
    with pytest.raises(RepairError, match=r"TASK_LEFT.*schtasks /End"):
        repair.launch(make_guest(runner), Report(vmid=1), "D:\\upgrade")


def test_launch_with_no_answer_refuses_and_warns_against_a_relaunch() -> None:
    runner = FakeRunner().on("launch", Reply(255, "", "Connection reset"))
    with pytest.raises(RepairError, match=r"outcome unknown.*do not relaunch"):
        repair.launch(make_guest(runner), Report(vmid=1), "D:\\upgrade")


def test_launch_unknown_verdict_is_a_protocol_error() -> None:
    runner = FakeRunner().on("launch", answer("launch", launch_report("MAYBE"), ok=False))
    with pytest.raises(GuestProtocolError, match="MAYBE"):
        repair.launch(make_guest(runner), Report(vmid=1), "D:\\upgrade")


# --- poll -----------------------------------------------------------------------------------


def _poll(runner: FakeRunner, hours: float = 6.0) -> tuple[str, Report, FakeClock]:
    clock, rep = FakeClock(), Report(vmid=1)
    verdict = repair.poll(make_guest(runner), rep, hours, clock=clock.time, sleep=clock.sleep)
    return verdict, rep, clock


RUNNING_LOG = answer("state", state_log("launching: setup.exe"))


def test_poll_returns_the_marker_verdict() -> None:
    done = answer("state", state_log("launching: setup.exe", "STATE=DONE-OK setup exit=0x00000000"))
    runner = FakeRunner().on("state", RUNNING_LOG, done).on("setup-alive", ALIVE)
    verdict, rep, clock = _poll(runner)
    assert verdict == "STATE=DONE-OK"
    assert (_step(rep, "poll")["ok"], _step(rep, "poll")["verdict"]) == (True, "STATE=DONE-OK")
    assert clock.slept == [300]


def test_poll_done_fail_is_not_ok() -> None:
    runner = FakeRunner().on("state", answer("state", state_log("STATE=DONE-FAIL setup exit=0xC1900200")))
    verdict, rep, _clock = _poll(runner)
    assert verdict == "STATE=DONE-FAIL"
    assert _step(rep, "poll")["ok"] is False


def test_poll_failed_read_is_not_an_absent_marker() -> None:
    # Seven failed reads with SetupHost gone: read as "no marker", they would end in WORKER_GONE
    # after the 6-read grace window; read as failures, the poll keeps going until the marker.
    done = answer("state", state_log("STATE=DONE-OK"))
    failed = Reply(255, "", "reset")
    runner = FakeRunner().on("state", *([failed] * 7), done).on("setup-alive", GONE)
    verdict, rep, clock = _poll(runner)
    assert verdict == "STATE=DONE-OK"
    assert "note" not in _step(rep, "poll")
    assert clock.slept == [20] * 7


def test_poll_reads_a_late_marker_after_the_worker_exits() -> None:
    late = answer("state", state_log("launching: setup.exe", "STATE=DONE-OK"))
    runner = FakeRunner().on("state", RUNNING_LOG, RUNNING_LOG, late).on("setup-alive", GONE)
    verdict, rep, clock = _poll(runner)
    assert verdict == "STATE=DONE-OK"
    assert "40s after the worker exited" in str(_step(rep, "poll")["note"])
    assert clock.slept == [20, 20]


def test_poll_worker_gone_without_a_marker() -> None:
    runner = FakeRunner().on("state", RUNNING_LOG).on("setup-alive", GONE)
    verdict, _rep, clock = _poll(runner)
    assert verdict == "WORKER_GONE"
    assert clock.slept == [20] * 6


def test_poll_unreadable_setuphost_is_not_a_gone_worker() -> None:
    runner = FakeRunner().on("state", RUNNING_LOG).on("setup-alive", Reply(255, "", "reset"))
    verdict, _rep, clock = _poll(runner, hours=0.2)
    assert verdict == "TIMEOUT"
    assert set(clock.slept) == {300}


def test_poll_deadline_is_timeout() -> None:
    runner = FakeRunner().on("state", RUNNING_LOG).on("setup-alive", ALIVE)
    verdict, rep, _clock = _poll(runner, hours=0.5)
    assert verdict == "TIMEOUT"
    assert _step(rep, "poll")["ok"] is False


def test_poll_garbage_state_raises_rather_than_waiting() -> None:
    runner = FakeRunner().on("state", answer("state", {"present": True})).on("setup-alive", ALIVE)
    with pytest.raises(GuestProtocolError):
        _poll(runner)


# --- push and the media ---------------------------------------------------------------------


def test_push_tool_step() -> None:
    runner = (
        FakeRunner()
        .on("scp", Reply(0))
        .on("certutil", hashes_to(TOOL_DIR / "winrepair_guest.ps1"))
        .on("lock-dirs", answer("lock-dirs", locked(present=False)))
        .on("copy", Reply(0))
        .on("move", Reply(0))
        .on("del", Reply(0))
    )
    rep = Report(vmid=1)
    repair.push_tool(make_guest(runner), rep)
    assert (_step(rep, "push_tool")["dest"], _step(rep, "push_tool")["copied"]) == (TOOL_PATH, True)


def test_push_tool_step_reports_a_profile_copy_it_could_not_delete() -> None:
    runner = tool_on_the_guest(FakeRunner())
    runner.replies["del"] = [Reply(1, "", "Zugriff verweigert")]
    rep = Report(vmid=1)
    repair.push_tool(make_guest(runner), rep)
    step = _step(rep, "push_tool")
    assert step["ok"] is True
    assert "Zugriff verweigert" in str(step["staged_left"])


def test_push_tool_failure_refuses(tmp_path: Path) -> None:
    with pytest.raises(RepairError, match=r"winrepair_guest.ps1"):
        repair.push_tool(make_guest(FakeRunner(), tmp_path), Report(vmid=1))


def test_stage_media_copies_every_media_entry_into_the_root(tmp_path: Path) -> None:
    (tmp_path / "setup.exe").write_bytes(b"MZ")
    (tmp_path / "sources").mkdir()
    runner = FakeRunner().on("scp", Reply(0))
    rep = Report(vmid=1)
    repair.stage_media(make_guest(runner), rep, "D:\\upgrade", media=tmp_path)
    # lock-dirs created and locked the root before this; the transfer is the only call.
    assert len(runner.calls) == 1
    scp = runner.calls[0]
    assert scp[-3:] == [
        str(tmp_path / "setup.exe"),
        str(tmp_path / "sources"),
        f"{USER}@{GUEST_IP}:D:\\upgrade\\",
    ]
    assert "-r" in scp


def test_stage_media_refuses_a_root_that_is_not_a_drive_path(tmp_path: Path) -> None:
    with pytest.raises(RepairError, match="stage root"):
        repair.stage_media(make_guest(FakeRunner()), Report(vmid=1), "D:\\up&grade", media=tmp_path)


def test_stage_media_transfer_timeout_refuses_as_a_failed_transfer(tmp_path: Path) -> None:
    (tmp_path / "setup.exe").write_bytes(b"MZ")
    runner = FakeRunner().on("scp", subprocess.TimeoutExpired(["scp"], 5400))
    with pytest.raises(RepairError, match="media transfer failed rc=255"):
        repair.stage_media(make_guest(runner), Report(vmid=1), "D:\\upgrade", media=tmp_path)


def test_stage_media_failed_copy_refuses(tmp_path: Path) -> None:
    (tmp_path / "setup.exe").write_bytes(b"MZ")
    runner = FakeRunner().on("scp", Reply(1, "", "No space left"))
    with pytest.raises(RepairError, match="media transfer failed"):
        repair.stage_media(make_guest(runner), Report(vmid=1), "D:\\upgrade", media=tmp_path)


# --- orchestration: the live-run guard runs before anything can stop the guest -----------------


def _request(*, ip: str | None = None, stage_only: bool = True, hours: float = 1.0) -> RepairRequest:
    address = None if ip is None else IPv4Address(ip)
    return RepairRequest(vmid=1, snapshot_name="pre_kb_test", hours=hours, stage_only=stage_only, ip=address)


def _first_mutation(labels: list[str]) -> int:
    return next((i for i, label in enumerate(labels) if label.split()[-1] in MUTATING_QM), len(labels))


def _live_run_runner(pve: FakePve) -> FakeRunner:
    return (
        tool_on_the_guest(FakeRunner())
        .on("qm", pve)
        .on("hostname", Reply(0, "GUEST\r\n"))
        .on("nic-macs", NIC_MACS)
        .on("setup-alive", ALIVE)
        .on("state", answer("state", state_log("=== start", "launching: setup.exe")))
    )


@pytest.mark.parametrize("ip", [GUEST_IP, None], ids=["agentless", "agent"])
def test_a_rerun_over_a_live_run_refuses_before_anything_stops_the_guest(tmp_path: Path, ip: str | None) -> None:
    pve = FakePve()
    runner, clock = _live_run_runner(pve), FakeClock()
    with pytest.raises(RepairError, match="SetupHost is running"):
        repair.repair_sequence(
            _request(ip=ip),
            Report(vmid=1),
            make_node(runner, clock),
            repair=_repair_settings(tmp_path),
            guest=GUEST,
            receipts=FileReceiptStore(tmp_path / "state"),
        )
    labels = call_labels(runner.calls)
    assert [label for label in labels if label.split()[-1] in MUTATING_QM] == []
    assert pve.status == "running"
    assert "guest setup-alive" in labels


def test_an_agentless_run_clears_the_guard_before_its_offline_snapshot(tmp_path: Path) -> None:
    (tmp_path / "setup.exe").write_bytes(b"MZ")
    pve = FakePve()
    runner = (
        tool_on_the_guest(FakeRunner())
        .on("qm", pve)
        .on("hostname", Reply(0, "GUEST\r\n"))
        .on("nic-macs", NIC_MACS)
        .on("setup-alive", GONE)
        .on("state", answer("state", state_log(present=False)))
        .on("drives", answer("drives", drive_report(C=60.0)))
        .on("quiesce-wu", answer("quiesce-wu", quiesce_report("OK")))
    )
    rep = Report(vmid=1)
    verdict = repair.repair_sequence(
        _request(ip=GUEST_IP),
        rep,
        make_node(runner, FakeClock()),
        repair=_repair_settings(tmp_path),
        guest=GUEST,
        receipts=FileReceiptStore(tmp_path / "state"),
    )
    assert verdict == "STAGED"
    labels = call_labels(runner.calls)
    first_guard = labels.index("guest setup-alive")
    assert labels.index("guest lock-dirs") < first_guard < labels.index("qm shutdown")
    assert first_guard < _first_mutation(labels)
    steps = [s["step"] for s in _wire(rep.steps)]
    assert steps.index("no_live_run") < steps.index("shutdown") < steps.index("snapshot")


# --- the guest's LAN address -------------------------------------------------------------------


def _interfaces(*addresses: str) -> Reply:
    entries = [{"ip-address-type": "ipv4", "ip-address": address} for address in addresses]
    return Reply(0, json.dumps([{"name": "Ethernet", "ip-addresses": entries}]))


def test_guest_ip_takes_the_address_inside_the_subnet() -> None:
    runner = FakeRunner().on("qm", _interfaces("172.17.0.1", LAN_IP))
    assert repair.guest_ip(make_node(runner, FakeClock()), 1, GUEST.network()) == LAN_IP


def test_guest_ip_without_a_subnet_refuses_several_candidates_naming_them_and_the_setting() -> None:
    runner = FakeRunner().on("qm", _interfaces("172.17.0.1", LAN_IP))
    with pytest.raises(RepairError) as caught:
        repair.guest_ip(make_node(runner, FakeClock()), 1, None)
    assert str(caught.value) == (
        f"the guest agent on 1 reports several candidate LAN addresses (172.17.0.1, {LAN_IP}): "
        "set [guest] subnet to the LAN the node reaches"
    )


@pytest.mark.parametrize(
    "stdout",
    ['{"ip-addresses": []}', '[{"ip-addresses": "192.0.2.50"}]', '[{"ip-addresses": [{"ip-address": 7}]}]'],
    ids=["not-a-list", "addresses-not-a-list", "address-not-text"],
)
def test_an_agent_answer_that_is_not_the_interface_list_is_an_internal_error(tmp_path: Path, stdout: str) -> None:
    pve = FakePve()

    def qm(cmd: list[str]) -> Reply:
        return Reply(0, stdout) if cmd[1] == "guest" else pve(cmd)

    result, steps = _run(agent_runner(pve, qm=qm), _media(tmp_path))
    assert (result.exit, result.verdict, steps[-1]["step"]) == (RunExit.INTERNAL, "INTERNAL", "internal")
    assert "validation error for tuple[_AgentInterface, ...]" in str(steps[-1]["message"])


def test_guest_ip_with_no_address_in_the_subnet_retries_then_refuses() -> None:
    runner, clock = FakeRunner().on("qm", _interfaces("172.17.0.1", "198.51.100.7")), FakeClock()
    with pytest.raises(RepairError, match="no LAN address from the guest agent on 1 after 2 tries"):
        repair.guest_ip(make_node(runner, clock), 1, GUEST.network(), tries=2)
    assert clock.slept == [10, 10]


# --- run_repair: the result and the whole agent path ----------------------------------------------


def _run(
    runner: FakeRunner,
    media: Path,
    *,
    ip: str | None = None,
    hours: float = 6.0,
    stage_only: bool = False,
    receipts: FileReceiptStore | None = None,
) -> tuple[RunResult, list[dict[str, object]]]:
    """Run the whole repair (not stage-only by default) on a fake node; return the result and its steps.

    The receipts go to ``receipts``, by default a state directory beside ``media``.
    """
    address = None if ip is None else IPv4Address(ip)
    request = RepairRequest(vmid=1, snapshot_name="pre_kb_test", hours=hours, ip=address, stage_only=stage_only)
    result = run_repair(
        request,
        make_node(runner, FakeClock()),
        repair=_repair_settings(media),
        guest=GUEST,
        receipts=receipts or FileReceiptStore(media.parent / "state"),
        on_step=lambda _s: None,
    )
    return result, _wire(result.steps)


def _media(tmp_path: Path) -> Path:
    """A media directory holding only ``setup.exe``, apart from the state directory :func:`_run` uses."""
    media = tmp_path / "media"
    media.mkdir()
    (media / "setup.exe").write_bytes(b"MZ")
    return media


def test_main_runs_the_whole_agent_path_to_done_ok(tmp_path: Path) -> None:
    result, steps = _run(agent_runner(FakePve()), _media(tmp_path))
    assert (result.exit, result.verdict) == (RunExit.OK, "STATE=DONE-OK")
    assert [s["step"] for s in steps] == [
        "running", "push_tool", "no_live_run", "quiesce_wu", "servicing_idle", "vtpm", "running",
        "snapshot", "push_tool", "no_live_run", "stage_root", "lock_dirs", "stage_media", "quiesce_wu",
        "prepare", "build_before", "receipt", "launch", "poll",
    ]  # fmt: skip


def test_an_unconfigured_media_dir_is_refused_before_any_call(tmp_path: Path) -> None:
    runner = FakeRunner()
    result = run_repair(
        RepairRequest(vmid=1, snapshot_name="pre_kb_test"),
        make_node(runner, FakeClock()),
        repair=RepairSettings(media_dir=""),
        guest=GUEST,
        receipts=FileReceiptStore(tmp_path),
        on_step=lambda _s: None,
    )
    assert (result.exit, result.verdict) == (RunExit.REFUSED, "ERROR")
    assert _wire(result.steps)[-1]["step"] == "error"
    assert _wire(result.steps)[-1]["message"] == (
        "[repair] media_dir is not configured: set it to the directory holding the installation media"
    )
    assert runner.calls == []


def test_a_missing_media_dir_is_refused_naming_it(tmp_path: Path) -> None:
    runner = FakeRunner()
    result, steps = _run(runner, tmp_path / "absent")
    assert (result.exit, result.verdict) == (RunExit.REFUSED, "ERROR")
    assert steps[-1]["message"] == f"media directory missing: {tmp_path / 'absent'}"
    assert runner.calls == []


def test_main_refusal_after_the_wu_hold_says_wu_is_still_held(tmp_path: Path) -> None:
    refused = answer("prepare", prepare_report("FAIL", "image 26200.8973 older than running 26200.9711"), ok=False)
    result, steps = _run(agent_runner(FakePve(), prepare=refused), _media(tmp_path))
    error = steps[-1]
    assert (result.exit, result.verdict, error["step"], error["wu_held"]) == (RunExit.REFUSED, "ERROR", "error", True)
    assert "restore-wu" in str(error["message"])


def test_main_refusal_before_the_wu_hold_does_not_claim_a_hold(tmp_path: Path) -> None:
    runner = agent_runner(FakePve(), **{"setup-alive": ALIVE})
    result, steps = _run(runner, _media(tmp_path))
    assert (result.exit, steps[-1]["step"]) == (RunExit.REFUSED, "error")
    assert "wu_held" not in steps[-1]
    assert "restore-wu" not in str(steps[-1]["message"])


DONE_FAIL = answer("state", state_log("launching: setup.exe", "STATE=DONE-FAIL setup exit=0x00000001"))


@pytest.mark.parametrize(
    ("state", "hours", "verdict"),
    [
        ([NO_LOG, NO_LOG, DONE_FAIL], 6.0, "STATE=DONE-FAIL"),
        ([NO_LOG], 6.0, "WORKER_GONE"),
        ([NO_LOG], 0.0, "TIMEOUT"),
    ],
    ids=["done-fail", "worker-gone", "timeout"],
)
def test_main_failed_poll_after_the_wu_hold_says_wu_is_still_held(
    tmp_path: Path,
    state: list[Answer],
    hours: float,
    verdict: str,
) -> None:
    runner = agent_runner(FakePve())
    runner.replies["state"] = list(state)
    result, steps = _run(runner, _media(tmp_path), hours=hours)
    last = steps[-1]
    assert (result.exit, result.verdict, last["step"], last["wu_held"]) == (RunExit.REFUSED, verdict, "poll", True)
    assert "restore-wu" in str(last["note"])


def test_on_step_sees_the_hold_flagged_on_the_failed_poll_it_already_received(tmp_path: Path) -> None:
    runner = agent_runner(FakePve())
    runner.replies["state"] = [NO_LOG, NO_LOG, DONE_FAIL]
    recorded: list[Step] = []
    result = run_repair(
        RepairRequest(vmid=1, snapshot_name="pre_kb_test"),
        make_node(runner, FakeClock()),
        repair=_repair_settings(_media(tmp_path)),
        guest=GUEST,
        receipts=FileReceiptStore(tmp_path / "state"),
        on_step=recorded.append,
    )
    polls = [step for step in recorded if step.step is StepName.POLL]
    assert len(polls) == 2
    assert polls[0].wu_held is None
    assert recorded[-1] is polls[1]
    assert (polls[1].wu_held, polls[1].detail["verdict"]) == (True, "STATE=DONE-FAIL")
    assert "restore-wu" in str(polls[1].note)
    assert [step.step for step in recorded[:-1]] == [step.step for step in result.steps]


def test_main_done_ok_does_not_flag_the_hold_as_a_leftover(tmp_path: Path) -> None:
    _result, steps = _run(agent_runner(FakePve()), _media(tmp_path))
    assert "wu_held" not in steps[-1]


def test_main_carries_the_guest_traceback_into_the_error_step(tmp_path: Path) -> None:
    trace = "Traceback (most recent call last):\nOSError: [WinError 1060] Dienst nicht vorhanden"
    crash = Reply(2, crashed("quiesce-wu", OSError("wmi")).stdout, trace)
    runner = agent_runner(FakePve(), **{"quiesce-wu": crash})
    result, steps = _run(runner, _media(tmp_path))
    assert result.exit is RunExit.REFUSED
    assert steps[-1]["guest_stderr"] == trace.splitlines()
    assert "WinError 1060" in str(steps[-1]["message"])


def test_repair_refuses_a_vm_that_never_reaches_the_status(tmp_path: Path) -> None:
    runner = agent_runner(FakePve(status="stopped", stuck=True))
    result, steps = _run(runner, _media(tmp_path))
    assert (result.exit, result.verdict, steps[-1]["step"]) == (RunExit.REFUSED, "ERROR", "error")
    assert steps[-1]["message"] == "vm 1 did not reach status running"
    labels = call_labels(runner.calls)
    assert labels.count("qm start") == 1
    # The repair run's own bound: 48 reads 5 s apart after the start.
    assert labels[labels.index("qm start") + 1 :] == ["qm status"] * 48


def test_repair_refuses_at_once_a_status_qm_status_does_not_name(tmp_path: Path) -> None:
    """An unknown status word is never read as "not running": nothing stops or starts the VM on it."""
    runner = agent_runner(FakePve(status="suspended"))
    result, steps = _run(runner, _media(tmp_path))
    assert (result.exit, result.verdict, steps[-1]["step"]) == (RunExit.REFUSED, RunVerdict.ERROR, "error")
    assert steps[-1]["message"] == "qm status 1 reported no status running or stopped (rc=0): 'status: suspended'"
    assert call_labels(runner.calls) == ["qm status"]


def test_a_failed_qm_status_refuses_naming_its_stderr(tmp_path: Path) -> None:
    pve = FakePve()

    def missing_vm(cmd: list[str]) -> Reply:
        if cmd[1] == "status":
            return Reply(2, "", "Configuration file 'nodes/pve1/qemu-server/1.conf' does not exist\n")
        return pve(cmd)

    runner = agent_runner(pve)
    runner.replies["qm"] = [missing_vm]
    result, steps = _run(runner, _media(tmp_path))
    assert (result.exit, result.verdict) == (RunExit.REFUSED, RunVerdict.ERROR)
    assert steps[-1]["message"] == (
        "qm status 1 reported no status running or stopped (rc=2): "
        "\"Configuration file 'nodes/pve1/qemu-server/1.conf' does not exist\""
    )


def _status_fails_after_start(pve: FakePve, *, failures: int | None) -> Callable[[list[str]], Reply]:
    """``qm`` that fails ``qm status`` after ``qm start``: ``failures`` times, or for good when None."""
    seen = {"started": False, "failed": 0}

    def qm(cmd: list[str]) -> Reply:
        seen["started"] = seen["started"] or cmd[1] == "start"
        transient = failures is None or seen["failed"] < failures
        if cmd[1] == "status" and seen["started"] and transient:
            seen["failed"] += 1
            return Reply(255, "", "trying to acquire lock...\n")
        return pve(cmd)

    return qm


def test_a_wait_polls_through_a_status_read_that_fails_while_the_vm_starts(tmp_path: Path) -> None:
    """The wait spans the VM's own start, so a failed read means "not there yet", not a refusal."""
    pve = FakePve(status="stopped")
    runner = agent_runner(pve)
    runner.replies["qm"] = [_status_fails_after_start(pve, failures=2)]
    result, _steps = _run(runner, _media(tmp_path))
    assert result.exit is RunExit.OK
    labels = call_labels(runner.calls)
    assert labels[labels.index("qm start") + 1 : labels.index("qm start") + 4] == ["qm status"] * 3


def test_a_wait_whose_reads_never_recover_names_the_last_failure(tmp_path: Path) -> None:
    pve = FakePve(status="stopped")
    runner = agent_runner(pve)
    runner.replies["qm"] = [_status_fails_after_start(pve, failures=None)]
    result, steps = _run(runner, _media(tmp_path))
    assert (result.exit, result.verdict) == (RunExit.REFUSED, RunVerdict.ERROR)
    assert steps[-1]["message"] == (
        "vm 1 did not reach status running; the last read failed: "
        "qm status 1 reported no status running or stopped (rc=255): 'trying to acquire lock...'"
    )
    labels = call_labels(runner.calls)
    assert labels[labels.index("qm start") + 1 :] == ["qm status"] * 48


def test_main_driver_tool_mismatch_is_exit_2_internal(tmp_path: Path) -> None:
    runner = agent_runner(FakePve(), state=answer("state", {"present": True}))
    result, steps = _run(runner, _media(tmp_path))
    assert (result.exit, result.verdict, steps[-1]["step"]) == (RunExit.INTERNAL, "INTERNAL", "internal")


def test_main_agentless_guest_that_never_answers_ssh_is_refused_untouched(tmp_path: Path) -> None:
    pve = FakePve()
    runner = FakeRunner().on("qm", pve).on("hostname", Reply(255, "", "Connection timed out"))
    result, steps = _run(runner, _media(tmp_path), ip=GUEST_IP)
    assert (result.exit, result.verdict) == (RunExit.REFUSED, "ERROR")
    assert "never answered ssh" in str(steps[-1]["message"])
    assert [label for label in call_labels(runner.calls) if label.split()[-1] in MUTATING_QM] == []
    assert pve.status == "running"


# --- lock-dirs: the stage root is locked before the media goes in -------------------------------


def test_lock_dirs_step_locks_the_stage_root_with_the_pushed_tool() -> None:
    runner = FakeRunner().on("lock-dirs", lock_dirs_reply)
    rep = Report(vmid=1)
    repair.lock_dirs(make_guest(runner), rep, "D:\\upgrade")
    assert runner.calls[0][-6:] == ["lock-dirs", "--tool", TOOL_PATH, "--stage-root", "D:\\upgrade", "--json"]
    step = _step(rep, "lock_dirs")
    assert step["ok"] is True
    assert step["directories"] == {"C:\\winrepair": "ALREADY_LOCKED", "D:\\upgrade": "CREATED"}


def test_lock_dirs_refusal_stops_the_run_naming_the_guest_reason() -> None:
    reason = "D:\\upgrade held files before it was locked: remove it (rd /s /q D:\\upgrade) and rerun"
    refused = LockDirsReport(
        tool=TOOL_PATH, tool_present=True, tool_sha256=None, directories=(), verdict="FAILED", reason=reason
    )
    runner = FakeRunner().on("lock-dirs", answer("lock-dirs", refused, ok=False))
    with pytest.raises(RepairError, match=r"not staging.*rd /s /q D:\\upgrade"):
        repair.lock_dirs(make_guest(runner), Report(vmid=1), "D:\\upgrade")


def test_lock_dirs_without_an_answer_stops_the_run() -> None:
    runner = FakeRunner().on("lock-dirs", Reply(255, "", "Connection reset"))
    with pytest.raises(RepairError, match="lock-dirs returned no verdict"):
        repair.lock_dirs(make_guest(runner), Report(vmid=1), "D:\\upgrade")


def _media_scp(cmd: list[str]) -> bool:
    return cmd[0] == "scp" and cmd[-1].endswith(":D:\\upgrade\\")


def test_main_locks_each_directory_before_anything_is_copied_into_it(tmp_path: Path) -> None:
    pushing = answer("lock-dirs", locked(present=False))
    runner = agent_runner(FakePve(), copy=Reply(0), move=Reply(0))
    runner.replies["lock-dirs"] = [pushing, pushing, lock_dirs_reply]
    result, _steps = _run(runner, _media(tmp_path))
    assert result.exit is RunExit.OK
    labels = call_labels(runner.calls)
    # The tool goes into C:\\winrepair (copy) only after a lock-dirs, every time it is pushed ...
    copies = [i for i, label in enumerate(labels) if label == "guest copy"]
    locks = [i for i, label in enumerate(labels) if label == "guest lock-dirs"]
    assert copies and all(any(lock < copy for lock in locks) for copy in copies)
    assert all(labels[copy - 1] == "guest lock-dirs" for copy in copies)
    # ... and the media go into the stage root only after a lock-dirs that named it.
    media = next(i for i, cmd in enumerate(runner.calls) if _media_scp(cmd))
    stage_locks = [i for i in locks if "--stage-root" in runner.calls[i]]
    assert stage_locks and stage_locks[0] < media
    assert runner.calls[stage_locks[0]][runner.calls[stage_locks[0]].index("--stage-root") + 1] == "D:\\upgrade"


def test_main_lock_dirs_refusal_copies_no_media_and_says_wu_is_held(tmp_path: Path) -> None:
    refused = LockDirsReport(
        tool=TOOL_PATH,
        tool_present=True,
        tool_sha256=None,
        directories=(),
        verdict="FAILED",
        reason="D:\\upgrade is owned by S-1-5-21-9",
    )

    def lock_dirs(cmd: list[str]) -> Reply:
        return answer("lock-dirs", refused, ok=False) if "--stage-root" in cmd else lock_dirs_reply(cmd)

    runner = agent_runner(FakePve(), **{"lock-dirs": lock_dirs})
    result, steps = _run(runner, _media(tmp_path))
    assert (result.exit, result.verdict, steps[-1]["step"], steps[-1]["wu_held"]) == (
        RunExit.REFUSED,
        "ERROR",
        "error",
        True,
    )
    assert "S-1-5-21-9" in str(steps[-1]["message"])
    assert not any(_media_scp(cmd) for cmd in runner.calls)


# --- the repair receipt: the image build prepare measured, for apply to verify ---------------

OLD_RECEIPT = RepairReceipt(
    vmid=1,
    image_build=26200,
    image_spbuild=7462,
    build_before=(26100, 1),
    install_date_before=1,
    written_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
)


class _RecordingStore(FileReceiptStore):
    """A file store that notes how many runner calls (and what time) had passed when it was written."""

    def __init__(self, state_dir: Path, runner: FakeRunner, clock: FakeClock) -> None:
        super().__init__(state_dir)
        self._runner, self._clock = runner, clock
        self.calls_at_write: list[int] = []
        self.time_at_write: list[float] = []

    def write(self, receipt: RepairReceipt) -> Path:
        self.calls_at_write.append(len(self._runner.calls))
        self.time_at_write.append(self._clock.now)
        return super().write(receipt)


def _seeded(tmp_path: Path) -> FileReceiptStore:
    """A state directory holding an earlier repair's receipt for VM 1 and one for VM 2."""
    store = FileReceiptStore(tmp_path / "state")
    store.write(OLD_RECEIPT)
    store.write(OLD_RECEIPT.model_copy(update={"vmid": 2}))
    return store


def test_repair_writes_the_receipt_after_prepare_and_before_launch(tmp_path: Path) -> None:
    runner, clock = agent_runner(FakePve()), FakeClock()
    store = _RecordingStore(tmp_path / "state", runner, clock)
    store.write(OLD_RECEIPT)
    result = run_repair(
        RepairRequest(vmid=1, snapshot_name="pre_kb_test"),
        make_node(runner, clock),
        repair=_repair_settings(_media(tmp_path)),
        guest=GUEST,
        receipts=store,
        on_step=lambda _s: None,
    )
    assert (result.exit, result.verdict) == (RunExit.OK, "STATE=DONE-OK")
    labels = call_labels(runner.calls)
    assert len(store.calls_at_write) == 2  # the seeding write, then the run's own
    assert labels.index("guest prepare") < store.calls_at_write[1] <= labels.index("guest launch")
    written_at = datetime.fromtimestamp(store.time_at_write[1], tz=timezone.utc)
    assert store.read(1) == RepairReceipt(
        vmid=1,
        image_build=IMAGE.build,
        image_spbuild=IMAGE.spbuild,
        build_before=(26200, 7462),
        install_date_before=INSTALL_DATE,
        written_at=written_at,
    )
    assert labels.index("guest prepare") < labels.index("guest build") < store.calls_at_write[1]
    step = next(s for s in _wire(result.steps) if s["step"] == "receipt")
    assert step == {"step": "receipt", "ok": True, "path": str(store.path(1)), "expected_build": "26200.8973"}


def test_a_stage_only_repair_ends_held_on_a_staged_step(tmp_path: Path) -> None:
    recorded: list[Step] = []
    result = run_repair(
        RepairRequest(vmid=1, snapshot_name="pre_kb_test", stage_only=True),
        make_node(agent_runner(FakePve()), FakeClock()),
        repair=_repair_settings(_media(tmp_path)),
        guest=GUEST,
        receipts=FileReceiptStore(tmp_path / "state"),
        on_step=recorded.append,
    )
    assert (result.exit, result.verdict) == (RunExit.OK, "STAGED")
    last = _wire(result.steps)[-1]
    assert (last["step"], last["ok"], last["wu_held"], last["root"]) == ("staged", True, True, "D:\\upgrade")
    assert str(last["note"]).endswith(f" - {WU_HELD_HINT}")
    # Emitted once when recorded and once more with the hold flagged, as a failed poll is.
    assert [s.step for s in recorded[-2:]] == [StepName.STAGED, StepName.STAGED]
    assert recorded[-2].wu_held is None
    assert recorded[-1] == result.steps[-1]


def test_a_stage_only_repair_leaves_no_receipt(tmp_path: Path) -> None:
    store = _seeded(tmp_path)
    result, _steps = _run(agent_runner(FakePve()), _media(tmp_path), stage_only=True, receipts=store)
    assert (result.exit, result.verdict) == (RunExit.OK, "STAGED")
    assert store.read(1) is None
    assert store.read(2) == OLD_RECEIPT.model_copy(update={"vmid": 2})


def test_a_repair_refused_before_prepare_leaves_no_stale_receipt(tmp_path: Path) -> None:
    store = _seeded(tmp_path)
    runner = agent_runner(FakePve(), drives=answer("drives", drive_report(C=10.0)))
    result, steps = _run(runner, _media(tmp_path), receipts=store)
    assert (result.exit, result.verdict) == (RunExit.REFUSED, "ERROR")
    assert str(steps[-1]["message"]).startswith(
        "C: has 10.0 GB free, below the 25.0 GB an in-place upgrade needs - free space before retrying"
    )
    assert "guest prepare" not in call_labels(runner.calls)
    assert store.read(1) is None


@pytest.mark.parametrize("status", ["running", "stopped"])
def test_a_repair_refused_by_the_live_run_guard_keeps_the_receipt(tmp_path: Path, status: str) -> None:
    store = _seeded(tmp_path)
    runner = agent_runner(FakePve(status=status), **{"setup-alive": ALIVE})
    result, steps = _run(runner, _media(tmp_path), receipts=store)
    assert (result.exit, result.verdict) == (RunExit.REFUSED, "ERROR")
    assert steps[-1]["message"] == "SetupHost is running - an upgrade is live; poll it instead of relaunching"
    assert store.read(1) == OLD_RECEIPT


def test_a_receipt_that_cannot_be_removed_refuses_the_repair_before_staging(tmp_path: Path) -> None:
    store = FileReceiptStore(tmp_path / "state")
    store.path(1).mkdir(parents=True)  # a directory where the receipt file goes: unlink fails
    runner = agent_runner(FakePve())
    result, steps = _run(runner, _media(tmp_path), receipts=store)
    assert (result.exit, result.verdict) == (RunExit.REFUSED, "ERROR")
    assert str(steps[-1]["message"]).startswith(f"cannot remove the repair receipt {store.path(1)}: ")
    assert "guest drives" not in call_labels(runner.calls)


def test_a_receipt_that_cannot_be_written_refuses_the_repair_before_launch(tmp_path: Path) -> None:
    blocker = tmp_path / "state"
    blocker.write_text("", encoding="utf-8")  # a file where the state directory goes
    store = FileReceiptStore(blocker)
    runner = agent_runner(FakePve())
    result, steps = _run(runner, _media(tmp_path), receipts=store)
    assert (result.exit, result.verdict) == (RunExit.REFUSED, "ERROR")
    assert str(steps[-1]["message"]).startswith(f"cannot write the repair receipt {store.path(1)}: ")
    labels = call_labels(runner.calls)
    assert "guest prepare" in labels
    assert "guest launch" not in labels


def test_a_build_that_cannot_be_read_before_launch_refuses_without_a_receipt(tmp_path: Path) -> None:
    store = FileReceiptStore(tmp_path / "state")
    runner = agent_runner(FakePve(), build=Reply(255, "", "Connection reset"))
    result, steps = _run(runner, _media(tmp_path), receipts=store)
    assert (result.exit, result.verdict) == (RunExit.REFUSED, "ERROR")
    assert str(steps[-1]["message"]).startswith("cannot read the guest's build and InstallDate for the receipt")
    assert steps[-1]["wu_held"] is True
    assert "guest launch" not in call_labels(runner.calls)
    assert store.read(1) is None


def test_the_build_before_step_reports_the_build_and_install_date(tmp_path: Path) -> None:
    _result, steps = _run(agent_runner(FakePve()), _media(tmp_path))
    step = next(s for s in steps if s["step"] == "build_before")
    assert step == {"step": "build_before", "ok": True, "build": "26200.7462", "install_date": INSTALL_DATE}


# --- --ip: the guest at the address must be the VM --vmid names (a MAC of its config) -----------

OTHER_MACS = answer("nic-macs", NicMacReport(macs=("BC:24:11:FF:FF:01", "BC:24:11:FF:FF:02")))
UP = Reply(0, "GUEST\r\n")


def _agentless(pve: FakePve, **overrides: Answer) -> FakeRunner:
    """A guest without an agent, reached at :data:`GUEST_IP`, that answers ssh."""
    return agent_runner(pve, hostname=UP, **overrides)


def test_an_agentless_repair_of_a_guest_that_is_not_the_vm_refuses_before_any_qm_action(tmp_path: Path) -> None:
    pve = FakePve()
    runner = _agentless(pve, **{"nic-macs": OTHER_MACS})
    result, steps = _run(runner, _media(tmp_path), ip=GUEST_IP, stage_only=True)
    assert (result.exit, result.verdict) == (RunExit.REFUSED, "ERROR")
    labels = call_labels(runner.calls)
    assert [label for label in labels if label.split()[-1] in MUTATING_QM] == []
    assert pve.status == "running"
    check = next(s for s in steps if s["step"] == "guest_identity")
    assert check == {
        "step": "guest_identity",
        "ok": False,
        "ip": GUEST_IP,
        "vm_macs": [VM_MAC],
        "guest_macs": ["BC:24:11:FF:FF:01", "BC:24:11:FF:FF:02"],
    }
    assert steps[-1]["message"] == (
        f"the guest at {GUEST_IP} is not VM 1: none of its NIC MACs (BC:24:11:FF:FF:01, BC:24:11:FF:FF:02) "
        f"is a MAC of VM 1 in qm config ({VM_MAC}) - check --ip"
    )
    # Refused before the live-run guard and before WU was held: nothing to restore.
    assert "wu_held" not in steps[-1]
    assert "guest setup-alive" not in labels


def test_an_agentless_repair_of_the_vm_s_own_guest_proceeds(tmp_path: Path) -> None:
    runner = _agentless(FakePve())
    result, steps = _run(runner, _media(tmp_path), ip=GUEST_IP, stage_only=True)
    assert (result.exit, result.verdict) == (RunExit.OK, "STAGED")
    labels = call_labels(runner.calls)
    checks = [i for i, label in enumerate(labels) if label == "guest nic-macs"]
    # Once before anything acts on the VM, once after its boot before anything is staged.
    assert len(checks) == 2
    assert checks[0] < _first_mutation(labels)
    assert labels.index("qm start") < checks[1] < next(i for i, c in enumerate(runner.calls) if _media_scp(c))
    identity = [s for s in steps if s["step"] == "guest_identity"]
    assert identity == [{"step": "guest_identity", "ok": True, "ip": GUEST_IP, "macs": [VM_MAC]}] * 2


def test_a_stopped_vm_reached_by_ip_is_checked_after_its_boot_before_anything_is_staged(tmp_path: Path) -> None:
    runner = _agentless(FakePve(status="stopped"), **{"nic-macs": OTHER_MACS})
    result, steps = _run(runner, _media(tmp_path), ip=GUEST_IP, stage_only=True)
    assert (result.exit, result.verdict) == (RunExit.REFUSED, "ERROR")
    assert str(steps[-1]["message"]).startswith(f"the guest at {GUEST_IP} is not VM 1")
    labels = call_labels(runner.calls)
    assert labels.index("qm start") < labels.index("guest nic-macs")
    assert not any(_media_scp(cmd) for cmd in runner.calls)
    assert "guest drives" not in labels


def test_the_agent_path_never_asks_for_the_guest_s_macs(tmp_path: Path) -> None:
    runner = agent_runner(FakePve())
    result, steps = _run(runner, _media(tmp_path))
    assert result.exit is RunExit.OK
    assert "guest nic-macs" not in call_labels(runner.calls)
    assert "guest_identity" not in [s["step"] for s in steps]


def test_a_vm_without_a_network_device_cannot_be_bound_to_the_guest_and_is_refused(tmp_path: Path) -> None:
    pve = FakePve()
    pve.config = "scsi0: local-zfs:vm-1-disk-0,size=64G\ntpmstate0: local-zfs:vm-1-disk-1,size=4M\n"
    runner = _agentless(pve)
    result, steps = _run(runner, _media(tmp_path), ip=GUEST_IP, stage_only=True)
    assert (result.exit, result.verdict) == (RunExit.REFUSED, "ERROR")
    assert steps[-1]["message"] == (
        f"VM 1 has no network device with a MAC in qm config, so the guest at {GUEST_IP} cannot be bound to it"
    )
    assert [label for label in call_labels(runner.calls) if label.split()[-1] in MUTATING_QM] == []


@pytest.mark.parametrize(
    "reply",
    [crashed("nic-macs", RuntimeError("no network adapter with a MAC address")), Reply(255, "", "reset")],
    ids=["no-mac", "no-answer"],
)
def test_a_guest_whose_macs_cannot_be_read_is_refused(tmp_path: Path, reply: Reply) -> None:
    pve = FakePve()
    runner = _agentless(pve, **{"nic-macs": reply})
    result, steps = _run(runner, _media(tmp_path), ip=GUEST_IP, stage_only=True)
    assert (result.exit, result.verdict) == (RunExit.REFUSED, "ERROR")
    assert str(steps[-1]["message"]).startswith(f"cannot read the NIC MACs of the guest at {GUEST_IP}: ")
    assert pve.status == "running"


def test_a_qm_config_that_cannot_be_read_is_refused(tmp_path: Path) -> None:
    pve = FakePve()

    def qm(cmd: list[str]) -> Reply:
        return Reply(2, "", "no such VM") if cmd[1] == "config" else pve(cmd)

    runner = _agentless(pve, qm=qm)
    result, steps = _run(runner, _media(tmp_path), ip=GUEST_IP, stage_only=True)
    assert (result.exit, result.verdict) == (RunExit.REFUSED, "ERROR")
    assert steps[-1]["message"] == "cannot read qm config 1 to bind the guest at 192.0.2.10 to it: rc=2: no such VM"


def test_a_mac_the_guest_reports_that_is_not_a_mac_is_a_protocol_error(tmp_path: Path) -> None:
    bad = answer("nic-macs", NicMacReport(macs=("not-a-mac",)))
    result, _steps = _run(_agentless(FakePve(), **{"nic-macs": bad}), _media(tmp_path), ip=GUEST_IP)
    assert (result.exit, result.verdict) == (RunExit.INTERNAL, "INTERNAL")
