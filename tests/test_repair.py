"""Tests for the repair use case's guest-facing steps and its whole run, through the ssh runner seam.

Every answer is a real guest envelope built from the guest tool's own data models, so these tests
pin the field names the driver gates on. The PVE side (``qm``) is a ``FakePve`` that tracks the VM's
power state.
"""

from __future__ import annotations

import json
import subprocess
from typing import TYPE_CHECKING

import pytest
from guest_fakes import (
    GUEST_IP,
    LAN_IP,
    MUTATING_QM,
    SSH,
    TOOL_DIR,
    TOOL_PATH,
    USER,
    Answer,
    FakeClock,
    FakePve,
    FakeRunner,
    Reply,
    answer,
    call_labels,
    crashed,
    hashes_to,
    lock_dirs_reply,
    locked,
    make_guest,
    state_log,
    tool_on_the_guest,
)

from pve_winrepair.adapters.node import Node
from pve_winrepair.application import repair
from pve_winrepair.application.repair import RepairError, RepairRequest, RunResult, run_repair
from pve_winrepair.domain.envelope import GuestProtocolError
from pve_winrepair.domain.report import Report, RunExit, Step
from pve_winrepair.domain.settings import GuestSettings, RepairSettings
from pve_winrepair_guest.probes import BuildInfo, Drive, DriveReport, ServicingReport, SetupReport
from pve_winrepair_guest.upgrade import LaunchReport, LaunchWait, LockDirsReport, PrepareReport, TaskCleanup
from pve_winrepair_guest.wim import WimImage
from pve_winrepair_guest.wu import QuiesceReport, ServiceRow, StartWrite, StopIssued, StopWait

if TYPE_CHECKING:
    from pathlib import Path

GIB = 1024**3


def _repair_settings(media: Path) -> RepairSettings:
    return RepairSettings(media_dir=str(media), snapshot_name="pre_kb_test", stage_free_gb=15.0, system_free_gb=25.0)


# The free-space floors the stage-root tests gate on (media_dir is not read there).
REPAIR = RepairSettings(snapshot_name="pre_kb_test", stage_free_gb=15.0, system_free_gb=25.0)
GUEST = GuestSettings(subnet="192.0.2.0/24")


def _step(rep: Report, name: str) -> dict[str, object]:
    return next(s for s in rep.steps if s["step"] == name)


# --- the report ------------------------------------------------------------------------------


def test_on_step_receives_each_step_in_order() -> None:
    recorded: list[Step] = []
    rep = Report(vmid=1, on_step=recorded.append)
    rep.add("shutdown", ok=True, note="already stopped")
    rep.add("vtpm", ok=False, storage="local")
    assert recorded == [
        {"step": "shutdown", "ok": True, "note": "already stopped"},
        {"step": "vtpm", "ok": False, "storage": "local"},
    ]
    assert recorded == rep.steps


def test_a_report_held_at_start_flags_the_hold_on_a_failure() -> None:
    rep = Report(vmid=1, held_at_start=True)
    assert rep.wu_held is True
    rep.failure("error", "refused", RuntimeError("refused"))
    assert rep.steps[-1]["wu_held"] is True
    assert "restore-wu" in str(rep.steps[-1]["message"])


def test_a_report_without_a_quiesce_step_is_not_held() -> None:
    rep = Report(vmid=1)
    rep.add("quiesce_wu", ok=False)
    assert rep.wu_held is False


# --- quiesce-wu -----------------------------------------------------------------------------


def _quiesce(verdict: str, *, running: tuple[str, ...] = ()) -> QuiesceReport:
    rows = (ServiceRow("wuauserv", "Disabled", "Running" if running else "Stopped"),)
    return QuiesceReport(
        previous_start_modes={"wuauserv": "Manual", "UsoSvc": "Auto"},
        writes=(StartWrite("wuauserv", 4, "WRITTEN", None),),
        stops=(StopIssued("wuauserv", 0, None),),
        wait=StopWait(10.0, False, running),
        services=rows,
        not_disabled=(),
        still_running=running,
        verdict=verdict,
    )


def test_quiesce_ok_records_the_previous_start_modes() -> None:
    runner = FakeRunner().on("quiesce-wu", answer("quiesce-wu", _quiesce("OK")))
    rep = Report(vmid=1)
    repair.quiesce_windows_update(make_guest(runner), rep)
    step = _step(rep, "quiesce_wu")
    assert step["ok"] is True
    assert step["previous_start_modes"] == {"wuauserv": "Manual", "UsoSvc": "Auto"}
    assert step["verdict"] == "OK"


def test_quiesce_fail_refuses_naming_what_still_runs() -> None:
    reply = answer("quiesce-wu", _quiesce("FAIL", running=("wuauserv",)), ok=False)
    runner = FakeRunner().on("quiesce-wu", reply)
    with pytest.raises(RepairError, match=r"not held: FAIL.*wuauserv"):
        repair.quiesce_windows_update(make_guest(runner), Report(vmid=1))


def test_quiesce_without_an_answer_refuses() -> None:
    runner = FakeRunner().on("quiesce-wu", Reply(255, "", "Connection reset"))
    with pytest.raises(RepairError, match="no verdict"):
        repair.quiesce_windows_update(make_guest(runner), Report(vmid=1))


def test_quiesce_ok_flag_contradicting_the_verdict_is_a_protocol_error() -> None:
    runner = FakeRunner().on("quiesce-wu", answer("quiesce-wu", _quiesce("FAIL"), ok=True))
    with pytest.raises(GuestProtocolError):
        repair.quiesce_windows_update(make_guest(runner), Report(vmid=1))


# --- drives / stage root --------------------------------------------------------------------


def _drives(**free_gib: float) -> DriveReport:
    return DriveReport(
        drives=tuple(
            Drive(letter, int(gib * GIB), int(gib * GIB) * 2, round(gib, 1)) for letter, gib in sorted(free_gib.items())
        )
    )


def test_stage_root_prefers_a_non_system_drive_with_room() -> None:
    runner = FakeRunner().on("drives", answer("drives", _drives(C=40.0, D=200.0)))
    rep = Report(vmid=1)
    assert repair.pick_stage_root(make_guest(runner), rep, None, repair=REPAIR) == "D:\\upgrade"
    assert _step(rep, "stage_root")["drives"] == {"C": 40.0, "D": 200.0}


def test_stage_root_gates_on_exact_bytes_not_the_rounded_figure() -> None:
    # 14.96 GiB rounds to 15.0 in free_gb but is below the 15 GB floor.
    runner = FakeRunner().on("drives", answer("drives", _drives(C=40.0, D=14.96)))
    assert repair.pick_stage_root(make_guest(runner), Report(vmid=1), None, repair=REPAIR) == "C:\\upgrade"


def test_stage_root_refuses_a_full_system_drive() -> None:
    runner = FakeRunner().on("drives", answer("drives", _drives(C=10.0, D=200.0)))
    with pytest.raises(RepairError, match=r"C: has 10.0 GB free"):
        repair.pick_stage_root(make_guest(runner), Report(vmid=1), None, repair=REPAIR)


def test_stage_root_refuses_a_drive_the_guest_does_not_have() -> None:
    runner = FakeRunner().on("drives", answer("drives", _drives(C=80.0)))
    with pytest.raises(RepairError, match="E: which the guest does not have"):
        repair.pick_stage_root(make_guest(runner), Report(vmid=1), "E:", repair=REPAIR)


def test_stage_root_gates_on_the_configured_system_floor() -> None:
    runner = FakeRunner().on("drives", answer("drives", _drives(C=40.0, D=200.0)))
    floors = RepairSettings(system_free_gb=50.0)
    with pytest.raises(RepairError, match=r"^C: has 40.0 GB free, below the 50.0 GB an in-place upgrade needs"):
        repair.pick_stage_root(make_guest(runner), Report(vmid=1), None, repair=floors)


def test_stage_root_gates_on_the_configured_stage_floor() -> None:
    runner = FakeRunner().on("drives", answer("drives", _drives(C=60.0, D=200.0)))
    floors = RepairSettings(stage_free_gb=250.0)
    with pytest.raises(RepairError, match=r"^D: has only 200.0 GB free, need 250.0$"):
        repair.pick_stage_root(make_guest(runner), Report(vmid=1), "D:", repair=floors)


def test_drives_unreadable_refuses_naming_the_guest_error() -> None:
    runner = FakeRunner().on("drives", crashed("drives", RuntimeError("no fixed drive with a letter")))
    with pytest.raises(RepairError, match=r"could not read any drive.*no fixed drive"):
        repair.pick_stage_root(make_guest(runner), Report(vmid=1), None, repair=REPAIR)


# --- servicing idle -------------------------------------------------------------------------


def _servicing(total: int) -> ServicingReport:
    return ServicingReport(counts={"TiWorker": total, "TrustedInstaller": 0}, total=total, active=total > 0)


def test_servicing_idle_retries_a_failed_read_instead_of_calling_it_idle() -> None:
    runner = FakeRunner().on(
        "servicing-active",
        Reply(255, "", "timeout"),
        answer("servicing-active", _servicing(1)),
        answer("servicing-active", _servicing(0)),
    )
    clock, rep = FakeClock(), Report(vmid=1)
    repair.wait_servicing_idle(make_guest(runner), rep, clock=clock.time, sleep=clock.sleep)
    assert _step(rep, "servicing_idle")["ok"] is True
    assert clock.slept == [20, 30]


def test_servicing_still_active_at_the_deadline_is_reported() -> None:
    runner = FakeRunner().on("servicing-active", answer("servicing-active", _servicing(2)))
    clock, rep = FakeClock(), Report(vmid=1)
    repair.wait_servicing_idle(make_guest(runner), rep, minutes=1.0, clock=clock.time, sleep=clock.sleep)
    assert _step(rep, "servicing_idle")["ok"] is False


# --- no live run before launch --------------------------------------------------------------


def test_live_run_check_passes_a_guest_with_no_run() -> None:
    runner = FakeRunner().on("setup-alive", answer("setup-alive", SetupReport(0, False)))
    runner.on("state", answer("state", state_log(present=False)))
    rep = Report(vmid=1)
    repair.refuse_live_run(make_guest(runner), rep)
    assert _step(rep, "no_live_run")["ok"] is True


def test_live_run_check_passes_a_finished_run() -> None:
    runner = FakeRunner().on("setup-alive", answer("setup-alive", SetupReport(0, False)))
    runner.on("state", answer("state", state_log("launching: setup.exe", "STATE=DONE-FAIL setup exit=0xC1900200")))
    rep = Report(vmid=1)
    repair.refuse_live_run(make_guest(runner), rep)
    assert _step(rep, "no_live_run")["previous_verdict"] == "DONE-FAIL"


def test_live_run_check_refuses_while_setuphost_runs() -> None:
    runner = FakeRunner().on("setup-alive", answer("setup-alive", SetupReport(2, True)))
    runner.on("state", answer("state", state_log(present=False)))
    with pytest.raises(RepairError, match="SetupHost is running"):
        repair.refuse_live_run(make_guest(runner), Report(vmid=1))


def test_live_run_check_refuses_a_started_run_without_a_marker() -> None:
    runner = FakeRunner().on("setup-alive", answer("setup-alive", SetupReport(0, False)))
    runner.on("state", answer("state", state_log("=== start", "launching: setup.exe")))
    with pytest.raises(RepairError, match="no DONE marker"):
        repair.refuse_live_run(make_guest(runner), Report(vmid=1))


def test_live_run_check_refuses_when_it_cannot_ask() -> None:
    runner = FakeRunner().on("setup-alive", Reply(255, "", "Connection refused"))
    with pytest.raises(RepairError, match="cannot verify"):
        repair.refuse_live_run(make_guest(runner), Report(vmid=1))


# --- prepare --------------------------------------------------------------------------------

IMAGE = WimImage(1, "Windows 11 Pro", "Professional", 26200, 8973, ("de-DE",), "de-DE")
RUNNING = BuildInfo("26200", 7462, "26200.7462")


def _prepare(gate: str, reason: str | None = None, *, tpm: bool | None = True) -> PrepareReport:
    passed = gate == "PASS"
    return PrepareReport(
        "D:\\upgrade",
        12,
        0,
        "D:\\upgrade\\sources\\install.wim",
        gate,
        reason,
        IMAGE,
        RUNNING,
        1 if passed else None,
        tpm if passed else None,
        (),
    )


def test_prepare_pass_reports_the_image_and_the_waiver() -> None:
    runner = FakeRunner().on("prepare", answer("prepare", _prepare("PASS")))
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
    reply = answer("prepare", _prepare("FAIL", "image SPBuild 8973 older than running 9711"), ok=False)
    runner = FakeRunner().on("prepare", reply)
    with pytest.raises(RepairError, match="guest gate refused: image SPBuild 8973 older than running 9711"):
        repair.prepare(make_guest(runner), Report(vmid=1), "D:\\upgrade")


def test_prepare_reports_an_absent_tpm_without_refusing() -> None:
    runner = FakeRunner().on("prepare", answer("prepare", _prepare("PASS", tpm=False)))
    rep = Report(vmid=1)
    repair.prepare(make_guest(runner), rep, "D:\\upgrade")
    assert _step(rep, "prepare")["ok"] is True
    assert "no TPM" in str(_step(rep, "prepare")["warnings"])


# --- launch ---------------------------------------------------------------------------------

DISARMED = TaskCleanup("DISARM", None, False, True, None)
REMOVED = TaskCleanup("REMOVE", True, False, True, None)


def _launch(
    verdict: str,
    reason: str | None = None,
    *,
    wait: str | None = "LAUNCHED",
    setuphost: int | None = 1,
    cleanup: TaskCleanup = DISARMED,
) -> LaunchReport:
    return LaunchReport(
        "OVMRepairUpgrade",
        f"powershell -File {TOOL_PATH} upgrade-run",
        False,
        True,
        None if wait is None else LaunchWait(wait, 42.0, None),
        setuphost,
        state_log("launching: setup.exe"),
        cleanup,
        verdict,
        reason,
    )


def test_launch_points_the_system_task_at_the_pushed_tool() -> None:
    runner = FakeRunner().on("launch", answer("launch", _launch("OK")))
    repair.launch(make_guest(runner), Report(vmid=1), "D:\\upgrade")
    argv = runner.calls[0]
    assert argv[argv.index("-File") + 1] == TOOL_PATH
    # The task's action runs the file named here, so it must be the content address just pushed.
    assert argv[argv.index("--tool") + 1] == TOOL_PATH


def test_launch_ok_records_the_step() -> None:
    runner = FakeRunner().on("launch", answer("launch", _launch("OK")))
    rep = Report(vmid=1)
    assert repair.launch(make_guest(runner), rep, "D:\\upgrade") is None
    step = _step(rep, "launch")
    assert (step["ok"], step["verdict"], step["setuphost"], step["task_cleanup"]) == (True, "OK", 1, "DISARM")


@pytest.mark.parametrize(
    ("report", "fragment"),
    [
        (_launch("SUSPECT", "setup already gone, read the state verdict", setuphost=0), "SUSPECT"),
        (
            _launch(
                "SUSPECT",
                "the run ended before launching setup",
                wait="ENDED",
                setuphost=None,
                cleanup=REMOVED,
            ),
            "SUSPECT",
        ),
        (
            _launch(
                "NO_START",
                "no 'launching' line within 600 s",
                wait="TIMEOUT",
                setuphost=None,
                cleanup=REMOVED,
            ),
            "NO_START",
        ),
        (
            _launch("FAILED", "the task could not be registered: x", wait=None, setuphost=None, cleanup=REMOVED),
            "FAILED",
        ),
    ],
)
def test_launch_without_a_running_setup_refuses(report: LaunchReport, fragment: str) -> None:
    runner = FakeRunner().on("launch", answer("launch", report, ok=False))
    with pytest.raises(RepairError, match=fragment):
        repair.launch(make_guest(runner), Report(vmid=1), "D:\\upgrade")


def test_launch_task_left_after_disarm_keeps_polling() -> None:
    left = TaskCleanup("DISARM", None, True, False, "delete: access denied")
    report = _launch("TASK_LEFT", "OK; the task \\OVMRepairUpgrade could not be disarmed: x", cleanup=left)
    runner = FakeRunner().on("launch", answer("launch", report, ok=False))
    rep = Report(vmid=1)
    repair.launch(make_guest(runner), rep, "D:\\upgrade")  # no raise: setup IS running
    step = _step(rep, "launch")
    assert (step["ok"], step["verdict"]) == (False, "TASK_LEFT")
    assert "schtasks" in str(step["note"])


def test_launch_task_left_after_disarm_does_not_claim_setup_is_running() -> None:
    # _settle can find SetupHost gone (SUSPECT) after a DISARM, which _louder turns into TASK_LEFT.
    left = TaskCleanup("DISARM", None, True, False, "delete: access denied")
    reason = "SUSPECT: setup already gone, read the state verdict; the task could not be disarmed: x"
    report = _launch("TASK_LEFT", reason, setuphost=0, cleanup=left)
    runner = FakeRunner().on("launch", answer("launch", report, ok=False))
    rep = Report(vmid=1)
    repair.launch(make_guest(runner), rep, "D:\\upgrade")
    note = str(_step(rep, "launch")["note"])
    assert "is running" not in note
    assert reason in note


def test_launch_task_left_after_remove_refuses_with_the_manual_cleanup() -> None:
    left = TaskCleanup("REMOVE", False, True, False, "end: still running 30 s after the end request")
    report = _launch("TASK_LEFT", "NO_START: no 'launching' line", wait="TIMEOUT", setuphost=None, cleanup=left)
    runner = FakeRunner().on("launch", answer("launch", report, ok=False))
    with pytest.raises(RepairError, match=r"TASK_LEFT.*schtasks /End"):
        repair.launch(make_guest(runner), Report(vmid=1), "D:\\upgrade")


def test_launch_with_no_answer_refuses_and_warns_against_a_relaunch() -> None:
    runner = FakeRunner().on("launch", Reply(255, "", "Connection reset"))
    with pytest.raises(RepairError, match=r"outcome unknown.*do not relaunch"):
        repair.launch(make_guest(runner), Report(vmid=1), "D:\\upgrade")


def test_launch_unknown_verdict_is_a_protocol_error() -> None:
    runner = FakeRunner().on("launch", answer("launch", _launch("MAYBE"), ok=False))
    with pytest.raises(GuestProtocolError, match="MAYBE"):
        repair.launch(make_guest(runner), Report(vmid=1), "D:\\upgrade")


# --- poll -----------------------------------------------------------------------------------


def _poll(runner: FakeRunner, hours: float = 6.0) -> tuple[str, Report, FakeClock]:
    clock, rep = FakeClock(), Report(vmid=1)
    verdict = repair.poll(make_guest(runner), rep, hours, clock=clock.time, sleep=clock.sleep)
    return verdict, rep, clock


ALIVE = answer("setup-alive", SetupReport(1, True))
GONE = answer("setup-alive", SetupReport(0, False))
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
    return RepairRequest(vmid=1, snapshot_name="pre_kb_test", hours=hours, stage_only=stage_only, ip=ip)


def _node(runner: FakeRunner, clock: FakeClock) -> Node:
    return Node(ssh=SSH, runner=runner, clock=clock.time, sleep=clock.sleep, tool_dir=TOOL_DIR)


def _first_mutation(labels: list[str]) -> int:
    return next((i for i, label in enumerate(labels) if label.split()[-1] in MUTATING_QM), len(labels))


def _live_run_runner(pve: FakePve) -> FakeRunner:
    return (
        tool_on_the_guest(FakeRunner())
        .on("qm", pve)
        .on("hostname", Reply(0, "GUEST\r\n"))
        .on("setup-alive", ALIVE)
        .on("state", answer("state", state_log("=== start", "launching: setup.exe")))
    )


@pytest.mark.parametrize("ip", [GUEST_IP, None], ids=["agentless", "agent"])
def test_a_rerun_over_a_live_run_refuses_before_anything_stops_the_guest(tmp_path: Path, ip: str | None) -> None:
    pve = FakePve()
    runner, clock = _live_run_runner(pve), FakeClock()
    with pytest.raises(RepairError, match="SetupHost is running"):
        repair.repair_sequence(
            _request(ip=ip), Report(vmid=1), _node(runner, clock), repair=_repair_settings(tmp_path), guest=GUEST
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
        .on("setup-alive", GONE)
        .on("state", answer("state", state_log(present=False)))
        .on("drives", answer("drives", _drives(C=60.0)))
        .on("quiesce-wu", answer("quiesce-wu", _quiesce("OK")))
    )
    rep = Report(vmid=1)
    verdict = repair.repair_sequence(
        _request(ip=GUEST_IP), rep, _node(runner, FakeClock()), repair=_repair_settings(tmp_path), guest=GUEST
    )
    assert verdict == "STAGED"
    labels = call_labels(runner.calls)
    first_guard = labels.index("guest setup-alive")
    assert labels.index("guest lock-dirs") < first_guard < labels.index("qm shutdown")
    assert first_guard < _first_mutation(labels)
    steps = [s["step"] for s in rep.steps]
    assert steps.index("no_live_run") < steps.index("shutdown") < steps.index("snapshot")


# --- the guest's LAN address -------------------------------------------------------------------


def _interfaces(*addresses: str) -> Reply:
    entries = [{"ip-address-type": "ipv4", "ip-address": address} for address in addresses]
    return Reply(0, json.dumps([{"name": "Ethernet", "ip-addresses": entries}]))


def test_guest_ip_takes_the_address_inside_the_subnet() -> None:
    runner = FakeRunner().on("qm", _interfaces("172.17.0.1", LAN_IP))
    assert repair.guest_ip(_node(runner, FakeClock()), 1, GUEST.network()) == LAN_IP


def test_guest_ip_without_a_subnet_refuses_several_candidates_naming_them_and_the_setting() -> None:
    runner = FakeRunner().on("qm", _interfaces("172.17.0.1", LAN_IP))
    with pytest.raises(RepairError) as caught:
        repair.guest_ip(_node(runner, FakeClock()), 1, None)
    assert str(caught.value) == (
        f"the guest agent on 1 reports several candidate LAN addresses (172.17.0.1, {LAN_IP}): "
        "set [guest] subnet to the LAN the node reaches"
    )


def test_guest_ip_with_no_address_in_the_subnet_retries_then_refuses() -> None:
    runner, clock = FakeRunner().on("qm", _interfaces("172.17.0.1", "198.51.100.7")), FakeClock()
    with pytest.raises(RepairError, match="no LAN address from the guest agent on 1 after 2 tries"):
        repair.guest_ip(_node(runner, clock), 1, GUEST.network(), tries=2)
    assert clock.slept == [10, 10]


# --- run_repair: the result and the whole agent path ----------------------------------------------

NO_LOG = answer("state", state_log(present=False))
DONE_OK = answer("state", state_log("launching: setup.exe", "STATE=DONE-OK setup exit=0x00000000"))


def _agent_runner(pve: FakePve, **overrides: Answer) -> FakeRunner:
    """A healthy agent guest with no run on it: every step of a full repair answers OK."""
    answers: dict[str, list[Answer]] = {
        "qm": [pve],
        "lock-dirs": [lock_dirs_reply],
        "certutil": [hashes_to(TOOL_DIR / "winrepair_guest.ps1")],
        "del": [Reply(0)],
        "setup-alive": [GONE],
        "state": [NO_LOG, NO_LOG, DONE_OK],
        "quiesce-wu": [answer("quiesce-wu", _quiesce("OK"))],
        "servicing-active": [answer("servicing-active", _servicing(0))],
        "drives": [answer("drives", _drives(C=60.0, D=200.0))],
        "scp": [Reply(0)],
        "prepare": [answer("prepare", _prepare("PASS"))],
        "launch": [answer("launch", _launch("OK"))],
    }
    answers.update({key: [value] for key, value in overrides.items()})
    runner = FakeRunner()
    for key, replies in answers.items():
        runner.on(key, *replies)
    return runner


def _run(
    runner: FakeRunner, media: Path, *, ip: str | None = None, hours: float = 6.0
) -> tuple[RunResult, list[dict[str, object]]]:
    """Run the whole repair (not stage-only) on a fake node; return the result and its steps."""
    request = RepairRequest(vmid=1, snapshot_name="pre_kb_test", hours=hours, ip=ip)
    result = run_repair(
        request,
        _node(runner, FakeClock()),
        repair=_repair_settings(media),
        guest=GUEST,
        on_step=lambda _s: None,
    )
    return result, list(result.steps)


def _media(tmp_path: Path) -> Path:
    (tmp_path / "setup.exe").write_bytes(b"MZ")
    return tmp_path


def test_main_runs_the_whole_agent_path_to_done_ok(tmp_path: Path) -> None:
    result, steps = _run(_agent_runner(FakePve()), _media(tmp_path))
    assert (result.exit, result.verdict) == (RunExit.OK, "STATE=DONE-OK")
    assert [s["step"] for s in steps] == [
        "running", "push_tool", "no_live_run", "quiesce_wu", "servicing_idle", "vtpm", "running",
        "snapshot", "push_tool", "no_live_run", "stage_root", "lock_dirs", "stage_media", "quiesce_wu",
        "prepare", "launch", "poll",
    ]  # fmt: skip


def test_an_unconfigured_media_dir_is_refused_before_any_call() -> None:
    runner = FakeRunner()
    result = run_repair(
        RepairRequest(vmid=1, snapshot_name="pre_kb_test"),
        _node(runner, FakeClock()),
        repair=RepairSettings(media_dir=""),
        guest=GUEST,
        on_step=lambda _s: None,
    )
    assert (result.exit, result.verdict) == (RunExit.REFUSED, "ERROR")
    assert result.steps[-1]["step"] == "error"
    assert result.steps[-1]["message"] == (
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
    refused = answer("prepare", _prepare("FAIL", "image SPBuild 8973 older than running 9711"), ok=False)
    result, steps = _run(_agent_runner(FakePve(), prepare=refused), _media(tmp_path))
    error = steps[-1]
    assert (result.exit, result.verdict, error["step"], error["wu_held"]) == (RunExit.REFUSED, "ERROR", "error", True)
    assert "restore-wu" in str(error["message"])


def test_main_refusal_before_the_wu_hold_does_not_claim_a_hold(tmp_path: Path) -> None:
    runner = _agent_runner(FakePve(), **{"setup-alive": ALIVE})
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
    runner = _agent_runner(FakePve())
    runner.replies["state"] = list(state)
    result, steps = _run(runner, _media(tmp_path), hours=hours)
    last = steps[-1]
    assert (result.exit, result.verdict, last["step"], last["wu_held"]) == (RunExit.REFUSED, verdict, "poll", True)
    assert "restore-wu" in str(last["note"])


def test_on_step_sees_the_hold_flagged_on_the_failed_poll_it_already_received(tmp_path: Path) -> None:
    runner = _agent_runner(FakePve())
    runner.replies["state"] = [NO_LOG, NO_LOG, DONE_FAIL]
    recorded: list[Step] = []
    result = run_repair(
        RepairRequest(vmid=1, snapshot_name="pre_kb_test"),
        _node(runner, FakeClock()),
        repair=_repair_settings(_media(tmp_path)),
        guest=GUEST,
        on_step=recorded.append,
    )
    polls = [step for step in recorded if step["step"] == "poll"]
    assert len(polls) == 2
    assert "wu_held" not in polls[0]
    assert recorded[-1] is polls[1]
    assert (polls[1]["wu_held"], polls[1]["verdict"]) == (True, "STATE=DONE-FAIL")
    assert "restore-wu" in str(polls[1]["note"])
    assert [step["step"] for step in recorded[:-1]] == [step["step"] for step in result.steps]


def test_main_done_ok_does_not_flag_the_hold_as_a_leftover(tmp_path: Path) -> None:
    _result, steps = _run(_agent_runner(FakePve()), _media(tmp_path))
    assert "wu_held" not in steps[-1]


def test_main_carries_the_guest_traceback_into_the_error_step(tmp_path: Path) -> None:
    trace = "Traceback (most recent call last):\nOSError: [WinError 1060] Dienst nicht vorhanden"
    crash = Reply(2, crashed("quiesce-wu", OSError("wmi")).stdout, trace)
    runner = _agent_runner(FakePve(), **{"quiesce-wu": crash})
    result, steps = _run(runner, _media(tmp_path))
    assert result.exit is RunExit.REFUSED
    assert steps[-1]["guest_stderr"] == trace.splitlines()
    assert "WinError 1060" in str(steps[-1]["message"])


def test_main_driver_tool_mismatch_is_exit_2_internal(tmp_path: Path) -> None:
    runner = _agent_runner(FakePve(), state=answer("state", {"present": True}))
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
    refused = LockDirsReport(TOOL_PATH, True, None, (), "FAILED", reason)
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
    runner = _agent_runner(FakePve(), copy=Reply(0), move=Reply(0))
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
    refused = LockDirsReport(TOOL_PATH, True, None, (), "FAILED", "D:\\upgrade is owned by S-1-5-21-9")

    def lock_dirs(cmd: list[str]) -> Reply:
        return answer("lock-dirs", refused, ok=False) if "--stage-root" in cmd else lock_dirs_reply(cmd)

    runner = _agent_runner(FakePve(), **{"lock-dirs": lock_dirs})
    result, steps = _run(runner, _media(tmp_path))
    assert (result.exit, result.verdict, steps[-1]["step"], steps[-1]["wu_held"]) == (
        RunExit.REFUSED,
        "ERROR",
        "error",
        True,
    )
    assert "S-1-5-21-9" in str(steps[-1]["message"])
    assert not any(_media_scp(cmd) for cmd in runner.calls)
