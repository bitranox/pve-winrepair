"""Tests for the apply-and-verify use case's guest-facing gates and its whole run, through the ssh runner seam.

The answers are real guest envelopes over the guest tool's own data models.
"""

from __future__ import annotations

import ntpath
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest
from guest_fakes import (
    ALIVE,
    DONE_OK,
    GONE,
    GUEST_IP,
    MUTATING_QM,
    NEWOS,
    NO_LOG,
    TOOL_DIR,
    TOOL_PATH,
    Answer,
    FakeClock,
    FakePve,
    FakeRunner,
    Reply,
    answer,
    apply_runner,
    call_labels,
    certutil_output,
    crashed,
    hashes_to,
    lock_dirs_reply,
    make_guest,
    make_node,
    restore_report,
    route,
    state_log,
    tool_on_the_guest,
)

from pve_winrepair.adapters.receipts import FileReceiptStore
from pve_winrepair.application import apply
from pve_winrepair.application.apply import ApplyError, ApplyRequest, run_apply
from pve_winrepair.domain.envelope import WU_HELD_HINT, GuestProtocolError
from pve_winrepair.domain.receipt import RepairReceipt
from pve_winrepair.domain.report import Report, RunExit, Step
from pve_winrepair_guest.probes import BuildInfo, StagedOs
from pve_winrepair_guest.upgrade import LockDirsReport
from pve_winrepair_guest.wu import SearchProbe

if TYPE_CHECKING:
    from pathlib import Path


# --- build ----------------------------------------------------------------------------------


def test_read_build_returns_build_and_decimal_ubr() -> None:
    runner = FakeRunner().on("build", answer("build", BuildInfo("26200", 8973, "26200.8973")))
    assert apply.read_build(make_guest(runner)) == ("26200", 8973)


@pytest.mark.parametrize(
    "reply",
    [Reply(255, "", "Connection timed out"), Reply(0, ""), crashed("build", RuntimeError("UBR is missing"))],
)
def test_read_build_cannot_read_is_none_not_a_wrong_build(reply: Reply) -> None:
    runner = FakeRunner().on("build", reply)
    assert apply.read_build(make_guest(runner)) is None


def test_read_build_with_a_renamed_field_is_a_protocol_error() -> None:
    runner = FakeRunner().on("build", answer("build", {"CurrentBuild": "26200", "UBR": 8973}))
    with pytest.raises(GuestProtocolError):
        apply.read_build(make_guest(runner))


# --- staged NewOS ---------------------------------------------------------------------------


def test_gate_staged_present_is_rearmable() -> None:
    runner = FakeRunner().on("staged-os", answer("staged-os", StagedOs(NEWOS, True, "REARMABLE")))
    rep = Report(vmid=1)
    apply.gate_staged(make_guest(runner), rep)
    assert rep.steps == [{"step": "gate_staged", "ok": True, "verdict": "REARMABLE"}]


def test_gate_staged_absent_refuses_to_reboot() -> None:
    runner = FakeRunner().on("staged-os", answer("staged-os", StagedOs(NEWOS, False, "RERUN")))
    rep = Report(vmid=1)
    with pytest.raises(ApplyError, match="NewOS is absent"):
        apply.gate_staged(make_guest(runner), rep)
    assert rep.steps == [{"step": "gate_staged", "ok": False, "verdict": "RERUN"}]


@pytest.mark.parametrize("reply", [Reply(255, "", "reset"), crashed("staged-os", PermissionError("denied"))])
def test_gate_staged_unreadable_refuses_to_reboot_on_an_unknown_state(reply: Reply) -> None:
    runner = FakeRunner().on("staged-os", reply)
    with pytest.raises(ApplyError, match="could not read the staged-OS state"):
        apply.gate_staged(make_guest(runner), Report(vmid=1))


def test_gate_staged_present_flag_contradicting_the_verdict_is_a_protocol_error() -> None:
    runner = FakeRunner().on("staged-os", answer("staged-os", StagedOs(NEWOS, False, "REARMABLE")))
    with pytest.raises(GuestProtocolError):
        apply.gate_staged(make_guest(runner), Report(vmid=1))


# --- restore-wu -----------------------------------------------------------------------------


def test_restore_wu_restored_is_ok() -> None:
    runner = FakeRunner().on("restore-wu", answer("restore-wu", restore_report("RESTORED")))
    rep = Report(vmid=1)
    apply.restore_windows_update(make_guest(runner), rep)
    assert rep.steps[0]["ok"] is True
    assert rep.steps[0]["note"] == "all restored"
    assert rep.steps[0]["search"] == "TIMEOUT"


def test_restore_wu_search_timeout_is_explained_as_no_verdict() -> None:
    runner = FakeRunner().on("restore-wu", answer("restore-wu", restore_report("RESTORED")))
    rep = Report(vmid=1)
    apply.restore_windows_update(make_guest(runner), rep)
    assert rep.steps[0]["ok"] is True
    note = str(rep.steps[0]["search_note"])
    assert "not a verdict" in note.lower()
    assert "180 s" in note
    assert "re-run restore-wu" in note


def test_restore_wu_search_ok_records_the_pending_count() -> None:
    found = SearchProbe("OK", 2, ("KB1", "KB2"), None, 180.0)
    runner = FakeRunner().on("restore-wu", answer("restore-wu", restore_report("RESTORED", search=found)))
    rep = Report(vmid=1)
    apply.restore_windows_update(make_guest(runner), rep)
    assert (rep.steps[0]["ok"], rep.steps[0]["search"], rep.steps[0]["search_pending"]) == (True, "OK", 2)
    assert "search_note" not in rep.steps[0]


def test_restore_wu_search_failure_is_recorded_and_still_ok() -> None:
    failed = SearchProbe("FAILED", None, (), "com_error: 0x8024401c", 180.0)
    runner = FakeRunner().on("restore-wu", answer("restore-wu", restore_report("RESTORED", search=failed)))
    rep = Report(vmid=1)
    apply.restore_windows_update(make_guest(runner), rep)
    assert (rep.steps[0]["ok"], rep.steps[0]["search_error"]) == (True, "com_error: 0x8024401c")


def test_restore_wu_still_disabled_refuses_naming_the_services() -> None:
    reply = answer("restore-wu", restore_report("STILL_DISABLED", ("UsoSvc",)), ok=False)
    runner = FakeRunner().on("restore-wu", reply)
    rep = Report(vmid=1)
    with pytest.raises(ApplyError, match="Windows Update left disabled: UsoSvc"):
        apply.restore_windows_update(make_guest(runner), rep)
    assert rep.steps[0]["ok"] is False


def test_restore_wu_unknown_refuses_rather_than_reading_as_restored() -> None:
    runner = FakeRunner().on("restore-wu", answer("restore-wu", restore_report("UNKNOWN"), ok=False))
    with pytest.raises(ApplyError, match="could not be verified"):
        apply.restore_windows_update(make_guest(runner), Report(vmid=1))


def test_restore_wu_without_an_answer_refuses() -> None:
    runner = FakeRunner().on("restore-wu", Reply(255, "", "reset"))
    rep = Report(vmid=1)
    with pytest.raises(ApplyError, match="could not run the Windows Update restore"):
        apply.restore_windows_update(make_guest(runner), rep)
    assert rep.steps[0]["ok"] is False


# --- ssh readiness --------------------------------------------------------------------------


def test_wait_ssh_returns_once_the_guest_answers() -> None:
    runner = FakeRunner().on("hostname", Reply(255), Reply(0, "GUEST\r\n"))
    clock = FakeClock()
    assert apply.wait_ssh(make_guest(runner), 25.0, clock=clock.time, sleep=clock.sleep) is True
    assert clock.slept == [15]


def test_wait_ssh_gives_up_at_the_deadline() -> None:
    runner = FakeRunner().on("hostname", Reply(255))
    clock = FakeClock()
    assert apply.wait_ssh(make_guest(runner), 1.0, clock=clock.time, sleep=clock.sleep) is False


def test_push_tool_step_records_the_content_address_and_whether_it_copied() -> None:
    runner = tool_on_the_guest(FakeRunner())
    rep = Report(vmid=1)
    apply.push_tool(make_guest(runner), rep)
    assert (rep.steps[0]["dest"], rep.steps[0]["copied"]) == (TOOL_PATH, False)


def test_push_tool_step_reports_a_profile_copy_it_could_not_delete() -> None:
    runner = tool_on_the_guest(FakeRunner())
    runner.replies["del"] = [Reply(1, "", "Zugriff verweigert")]
    rep = Report(vmid=1)
    apply.push_tool(make_guest(runner), rep)
    assert "Zugriff verweigert" in str(rep.steps[0]["staged_left"])


# --- orchestration: nothing stops the guest until its upgrade run has finished OK -----------

DONE_FAIL = answer("state", state_log("launching: setup.exe", "STATE=DONE-FAIL setup exit=0xC1900200"))
NO_MARKER = answer("state", state_log("=== start", "launching: setup.exe"))
REQUEST = ApplyRequest(vmid=1, ip=GUEST_IP)
# What the repair run's prepare step measured for VM 1: the build the apply must reach.
RECEIPT = RepairReceipt(
    vmid=1, image_build=26200, image_spbuild=8973, written_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
)


@pytest.fixture
def receipts(tmp_path: Path) -> FileReceiptStore:
    """A state directory holding :data:`RECEIPT`, the receipt a repair of VM 1 left behind."""
    store = FileReceiptStore(tmp_path / "state")
    store.write(RECEIPT)
    return store


@pytest.mark.parametrize(
    ("alive", "state", "verdict", "reason"),
    [
        (ALIVE, NO_MARKER, "RUN_LIVE", "SetupHost is running"),
        (ALIVE, DONE_OK, "RUN_LIVE", "SetupHost is running"),
        (GONE, NO_MARKER, "RUN_UNFINISHED", "no DONE marker"),
        (GONE, DONE_FAIL, "RUN_FAILED", "STATE=DONE-FAIL"),
        (GONE, NO_LOG, "NO_RUN", "no state log"),
        (Reply(255, "", "Connection refused"), DONE_OK, "ERROR", "cannot verify"),
        (GONE, crashed("state", PermissionError("denied")), "ERROR", "cannot verify"),
    ],
    ids=[
        "alive",
        "alive-over-done-ok",
        "unfinished",
        "done-fail",
        "no-log",
        "alive-unreadable",
        "state-unreadable",
    ],
)
def test_apply_refuses_before_anything_stops_a_guest_whose_run_did_not_finish_ok(
    alive: Reply, state: Reply, verdict: str, reason: str
) -> None:
    pve = FakePve()
    runner = apply_runner(pve, alive, state)
    rep = Report(vmid=1)
    refusal: ApplyError | None = None
    try:
        apply.apply_sequence(REQUEST, make_node(runner), rep, receipt=RECEIPT)
    except ApplyError as exc:
        refusal = exc
    labels = call_labels(runner.calls)
    assert [label for label in labels if label.split()[-1] in MUTATING_QM] == []
    assert pve.status == "running"
    assert "guest setup-alive" in labels
    assert refusal is not None
    assert (refusal.verdict, reason in str(refusal)) == (verdict, True)


def test_apply_reads_a_finished_run_before_the_apply_reboot() -> None:
    pve = FakePve()
    runner = apply_runner(pve, GONE, DONE_OK)
    rep = Report(vmid=1)
    assert apply.apply_sequence(REQUEST, make_node(runner), rep, receipt=RECEIPT) == "VERIFIED"
    labels = call_labels(runner.calls)
    assert "guest setup-alive" in labels
    assert "guest state" in labels
    shutdown = labels.index("qm shutdown")
    assert labels.index("guest setup-alive") < shutdown
    assert labels.index("guest state") < shutdown
    names = [s["step"] for s in rep.steps]
    assert names.index("run_finished") < names.index("clean_stop")
    assert next(s for s in rep.steps if s["step"] == "run_finished") == {
        "step": "run_finished",
        "ok": True,
        "marker": "STATE=DONE-OK",
    }


def test_run_result_names_a_live_run_and_is_refused(receipts: FileReceiptStore) -> None:
    runner = apply_runner(FakePve(), ALIVE, NO_MARKER)
    result = run_apply(REQUEST, make_node(runner), receipts=receipts, on_step=lambda _s: None)
    assert (result.exit, result.verdict) == (RunExit.REFUSED, "RUN_LIVE")
    assert [s["step"] for s in result.steps][-2:] == ["run_finished", "error"]
    assert result.steps[-2]["ok"] is False


def test_run_result_names_a_failed_run(receipts: FileReceiptStore) -> None:
    runner = apply_runner(FakePve(), GONE, DONE_FAIL)
    result = run_apply(REQUEST, make_node(runner), receipts=receipts, on_step=lambda _s: None)
    assert (result.exit, result.verdict) == (RunExit.REFUSED, "RUN_FAILED")


def test_run_result_of_a_refusal_says_windows_update_is_still_held(receipts: FileReceiptStore) -> None:
    runner = apply_runner(FakePve(), GONE, DONE_FAIL)
    result = run_apply(REQUEST, make_node(runner), receipts=receipts, on_step=lambda _s: None)
    error = result.steps[-1]
    assert (result.exit, error["step"], error["wu_held"]) == (RunExit.REFUSED, "error", True)
    assert "restore-wu" in str(error["message"])


def test_apply_refuses_a_vm_that_never_reaches_the_status(receipts: FileReceiptStore) -> None:
    runner = apply_runner(FakePve(stuck=True), GONE, DONE_OK)
    result = run_apply(REQUEST, make_node(runner), receipts=receipts, on_step=lambda _s: None)
    assert (result.exit, result.verdict, result.steps[-1]["step"]) == (RunExit.REFUSED, "ERROR", "error")
    assert "vm 1 did not reach status stopped" in str(result.steps[-1]["message"])
    assert result.steps[-1]["wu_held"] is True
    labels = call_labels(runner.calls)
    # The apply run's own bound: 60 reads 5 s apart after the shutdown.
    assert labels[labels.index("qm shutdown") + 1 :] == ["qm status"] * 60


# --- after the apply reboot: run from the verified profile copy, never from C:\winrepair ------

STAGED = ntpath.basename(TOOL_PATH)


def _after_reboot(runner: FakeRunner) -> list[list[str]]:
    """The calls after the guest came back on ssh."""
    last = max(i for i, call in enumerate(runner.calls) if route(call) == "hostname")
    return runner.calls[last + 1 :]


def _runs(call: list[str]) -> str:
    return call[call.index("-File") + 1]


def _applied(runner: FakeRunner) -> tuple[str | None, list[dict[str, object]]]:
    rep = Report(vmid=1)
    try:
        return apply.apply_sequence(REQUEST, make_node(runner), rep, receipt=RECEIPT), rep.steps
    except ApplyError:
        return None, rep.steps


def test_after_the_apply_reboot_build_and_restore_wu_run_from_the_verified_profile_copy() -> None:
    runner = apply_runner(FakePve(), GONE, DONE_OK)
    verdict, steps = _applied(runner)
    after = _after_reboot(runner)
    assert verdict == "VERIFIED"
    assert [route(call) for call in after] == ["scp", "certutil", "lock-dirs", "build", "restore-wu", "del"]
    # The profile copy is hashed before it runs anything; nothing is copied into C:\winrepair.
    assert after[1][-2] == STAGED
    assert {_runs(call) for call in after if "-File" in call} == {STAGED}
    lock = next(s for s in steps if s["step"] == "winrepair_lock")
    assert (lock["ok"], lock["action"]) == (True, "ALREADY_LOCKED")
    assert next(s for s in steps if s["step"] == "remove_profile_copy")["ok"] is True


def test_a_changed_winrepair_lock_after_the_upgrade_is_reported_and_still_lifts_the_wu_hold() -> None:
    runner = apply_runner(FakePve(), GONE, DONE_OK)
    reason = r"C:\winrepair existed before lock-dirs and is not locked as lock-dirs creates it (owner)"
    changed = answer("lock-dirs", LockDirsReport(TOOL_PATH, True, None, (), "FAILED", reason), ok=False)
    runner.replies["lock-dirs"] = [lock_dirs_reply, changed]
    verdict, steps = _applied(runner)
    assert verdict == "VERIFIED"
    lock = next(s for s in steps if s["step"] == "winrepair_lock")
    assert lock["ok"] is False
    assert reason in str(lock["reason"])
    assert r"rd /s /q C:\winrepair" in str(lock["note"])
    assert [route(call) for call in _after_reboot(runner)][-2:] == ["restore-wu", "del"]
    assert next(s for s in steps if s["step"] == "restore_wu")["ok"] is True


def test_a_profile_copy_that_is_not_the_tool_after_the_reboot_runs_nothing_and_is_deleted() -> None:
    runner = apply_runner(FakePve(), GONE, DONE_OK)
    wrong = Reply(0, certutil_output("0" * 64))
    replies: list[Answer] = [hashes_to(TOOL_DIR / "winrepair_guest.ps1")] * 2
    runner.replies["certutil"] = [*replies, wrong]
    verdict, _steps = _applied(runner)
    assert verdict is None
    assert [route(call) for call in _after_reboot(runner)] == ["scp", "certutil", "del"]


def test_a_failure_after_the_reboot_still_deletes_the_profile_copy() -> None:
    runner = apply_runner(FakePve(), GONE, DONE_OK)
    runner.replies["build"] = [
        answer("build", BuildInfo("26200", 7462, "26200.7462")),
        answer("build", BuildInfo("26200", 7462, "26200.7462")),
    ]
    verdict, steps = _applied(runner)
    assert verdict is None
    assert [route(call) for call in _after_reboot(runner)][-2:] == ["build", "del"]
    assert next(s for s in steps if s["step"] == "remove_profile_copy")["ok"] is True


def test_a_profile_copy_left_behind_after_the_reboot_is_reported() -> None:
    runner = apply_runner(FakePve(), GONE, DONE_OK)
    runner.replies["del"] = [Reply(0), Reply(1, "", "Zugriff verweigert")]
    verdict, steps = _applied(runner)
    assert verdict == "VERIFIED"
    left = next(s for s in steps if s["step"] == "remove_profile_copy")
    assert left["ok"] is False
    assert "Zugriff verweigert" in str(left["error"])


def test_the_wu_held_hint_names_a_verified_copy_never_the_tool_directory(receipts: FileReceiptStore) -> None:
    runner = apply_runner(FakePve(), GONE, DONE_FAIL)
    result = run_apply(REQUEST, make_node(runner), receipts=receipts, on_step=lambda _s: None)
    message = str(result.steps[-1]["message"])
    assert "certutil -hashfile" in message
    assert "ssh user's profile" in message
    assert "restore-wu" in message


# --- the repair receipt: apply verifies the build the repair's prepare step measured ----------


def test_apply_without_a_receipt_refuses_before_any_call(tmp_path: Path) -> None:
    runner = apply_runner(FakePve(), GONE, DONE_OK)
    store = FileReceiptStore(tmp_path / "state")
    result = run_apply(REQUEST, make_node(runner), receipts=store, on_step=lambda _s: None)
    assert runner.calls == []
    assert (result.exit, result.verdict) == (RunExit.REFUSED, "ERROR")
    assert [s["step"] for s in result.steps] == ["error"]
    assert result.steps[-1]["message"] == (
        f"no repair receipt for VM 1 at {store.path(1)} - run `pve-winrepair repair` for this VM first: "
        f"apply verifies the build its prepare step measured - {WU_HELD_HINT}"
    )


def test_apply_with_an_unreadable_receipt_refuses_naming_the_file_before_any_call(tmp_path: Path) -> None:
    runner = apply_runner(FakePve(), GONE, DONE_OK)
    store = FileReceiptStore(tmp_path)
    store.path(1).write_text("{not json", encoding="utf-8")
    result = run_apply(REQUEST, make_node(runner), receipts=store, on_step=lambda _s: None)
    assert runner.calls == []
    assert (result.exit, result.verdict) == (RunExit.REFUSED, "ERROR")
    assert str(result.steps[-1]["message"]).startswith(f"the repair receipt {store.path(1)} is not valid: ")


@pytest.mark.parametrize(
    ("spbuild", "exit_", "verdict"),
    [(8973, RunExit.OK, "VERIFIED"), (9000, RunExit.REFUSED, "REVERTED_OR_UNCHANGED")],
    ids=["build-reached", "build-short-of-the-receipt"],
)
def test_apply_verifies_the_build_the_receipt_recorded(
    tmp_path: Path, spbuild: int, exit_: RunExit, verdict: str
) -> None:
    store = FileReceiptStore(tmp_path)
    store.write(RECEIPT.model_copy(update={"image_spbuild": spbuild}))
    runner = apply_runner(FakePve(), GONE, DONE_OK)  # BUILD_AFTER is 26200.8973
    recorded: list[Step] = []
    result = run_apply(REQUEST, make_node(runner), receipts=store, on_step=recorded.append)
    assert (result.exit, result.verdict) == (exit_, verdict)
    assert recorded == list(result.steps)
    receipt = next(s for s in result.steps if s["step"] == "receipt")
    assert (receipt["path"], receipt["want"]) == (str(store.path(1)), f"26200.{spbuild}")
    check = next(s for s in result.steps if s["step"] == "verify_build")
    if verdict == "VERIFIED":
        assert check == {"step": "verify_build", "ok": True, "build": "26200.8973"}
        assert result.steps[-1]["step"] == "remove_profile_copy"
    else:
        assert (check["ok"], check["got"], check["want"]) == (False, "26200.8973", "26200.9000")
        assert str(result.steps[-1]["message"]).startswith("build is 26200.8973, wanted 26200.9000")


def test_run_apply_maps_an_unexpected_error_to_internal(receipts: FileReceiptStore) -> None:
    runner = apply_runner(FakePve(), GONE, DONE_OK)
    runner.replies["build"] = [ValueError("a driver and tool that disagree")]
    result = run_apply(REQUEST, make_node(runner), receipts=receipts, on_step=lambda _s: None)
    assert (result.exit, result.verdict) == (RunExit.INTERNAL, "INTERNAL")
    last = result.steps[-1]
    assert (last["step"], last["ok"], last["wu_held"]) == ("internal", False, True)
    assert str(last["message"]).startswith("ValueError('a driver and tool that disagree')")
