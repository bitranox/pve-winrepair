r"""Apply a staged in-place repair upgrade and prove it landed.

The down-level runs with /noreboot, which arms a ONE-SHOT BCD bootsequence pointing at the
staged NewOS. This use case performs that reboot the only way that is safe on a hypervisor, then
verifies the result and lifts the Windows Update hold.

Every in-guest read runs the packed guest tool through the :class:`GuestPort` and gates on typed
fields of its JSON envelope.

Nothing stops the guest before the run gate: SetupHost gone AND the state log ending
``STATE=DONE-OK``, then the NewOS gate. Otherwise the verdict is RUN_LIVE (SetupHost runs),
RUN_UNFINISHED (the run started, SetupHost is gone, and no DONE marker was written: it was cut off,
for instance by a hard power-off - check the guest), RUN_FAILED (``STATE=DONE-FAIL``) or NO_RUN
(no state log).

After the apply reboot the tool runs only from a fresh copy in the ssh user's profile whose bytes
were checked against the node's digest (``stage_tool``), never from ``C:\winrepair``: the upgrade
may have changed that directory's lock, and no SYSTEM task starts from it again. Its lock state is
reported as the informational ``winrepair_lock`` step and never repaired; a changed lock does not
stop the restore of Windows Update. The profile copy is deleted at the end on every path
(``remove_profile_copy``).

The build it verifies is the one the repair run's prepare step measured from the staged image and
recorded in the VM's receipt (:class:`ReceiptStore`). The receipt is read first, before any node or
guest call: without one there is nothing to verify against, and the run is refused untouched.

Every refusal leaves Windows Update held (the repair run held it, and only this use case's last
step lifts it); the ``error`` step says so with ``wu_held: true``.

Verdicts: VERIFIED, RUN_LIVE, RUN_UNFINISHED, RUN_FAILED, NO_RUN, REVERTED_OR_UNCHANGED, ERROR,
INTERNAL.
"""

from __future__ import annotations

import ntpath
from dataclasses import dataclass
from typing import TYPE_CHECKING

from pve_winrepair.application.guest_state import read_run_state
from pve_winrepair.application.vm import VmStatusTimeoutError, wait_status
from pve_winrepair.domain.envelope import (
    PROBE_TIMEOUT,
    READ_FAILURES,
    GuestCallError,
    GuestProtocolError,
)
from pve_winrepair.domain.receipt import ReceiptError
from pve_winrepair.domain.report import Report, RunExit, RunResult, Step

if TYPE_CHECKING:
    from collections.abc import Callable

    from pve_winrepair.application.ports import GuestPort, NodePort, ReceiptStore
    from pve_winrepair.domain.envelope import Fields, RunState
    from pve_winrepair.domain.receipt import RepairReceipt

__all__ = [
    "ApplyError",
    "ApplyRequest",
    "run_apply",
]

# How many ``qm status`` reads, 5 s apart, the apply reboot's stop or start may take (5 min).
_STATUS_TRIES = 60


class ApplyError(RuntimeError):
    """A gate refused. The message names what was measured.

    Attributes:
        verdict: The run's verdict for this refusal (ERROR unless a gate names its own).
    """

    def __init__(self, message: str, *, verdict: str = "ERROR") -> None:
        """Keep ``message`` and the verdict the run reports for it."""
        super().__init__(message)
        self.verdict = verdict


@dataclass(frozen=True)
class ApplyRequest:
    """One apply run: the guest and how long its apply phase may take.

    Attributes:
        vmid: The guest's VMID on this node.
        ip: The guest's address.
        apply_minutes: How long the apply phase may take before it is reported as overrun.
    """

    vmid: int
    ip: str
    apply_minutes: float = 90.0


def push_tool(guest: GuestPort, rep: Report) -> None:
    r"""Copy the packed guest tool to its content address in ``C:\winrepair`` before the first read.

    Only before the apply reboot. After it the tool runs from a verified profile copy
    (:func:`stage_tool`): the in-place upgrade migrates the system drive and may change the lock of
    ``C:\winrepair``, which nothing there runs from again.
    """
    try:
        pushed = guest.push_tool()
    except GuestCallError as exc:
        raise ApplyError(str(exc)) from exc
    left = {} if pushed.staged_left is None else {"staged_left": pushed.staged_left}
    rep.add("push_tool", ok=True, dest=pushed.path, copied=pushed.copied, **left)


def stage_tool(guest: GuestPort, rep: Report) -> GuestPort:
    """Copy the tool to the ssh user's profile, verify its bytes, and return the guest that runs that copy."""
    try:
        staged = guest.stage_tool()
    except GuestCallError as exc:
        raise ApplyError(str(exc)) from exc
    rep.add("stage_tool", ok=True, path=staged.tool_path, sha256=staged.packed.sha256)
    return staged


def report_tool_dir_lock(staged: GuestPort, rep: Report) -> None:
    r"""Report ``C:\winrepair``'s lock after the upgrade (lock-dirs from the verified copy); never stops.

    lock-dirs writes no DACL onto a directory that exists: it reuses one that is exactly locked and
    refuses any other. A refusal here means the upgrade changed the lock; nothing runs from that
    directory any more in this run, and the next repair run would refuse it, so the step says to
    remove it. ``--no-create`` keeps this report read-only: a directory the upgrade removed comes
    back ABSENT instead of being created (and reported CREATED, which would hide that it was gone);
    the next repair creates it locked. Whatever the answer, Windows Update is still restored.
    """
    # The directory of the tool's content address: the one the ssh adapter pushes into.
    tool_dir = ntpath.dirname(staged.packed.guest_path)
    try:
        envelope = staged.tool("lock-dirs", "--tool", staged.packed.guest_path, "--no-create", timeout=PROBE_TIMEOUT)
        verdict = envelope.gate("verdict", "OK")
    except GuestCallError as exc:
        rep.add("winrepair_lock", ok=False, note=f"could not read the lock (informational): {exc}")
        return
    if verdict == "OK":
        actions = [d.text("action") for d in envelope.data.sections("directories")]
        action = actions[0] if actions else None
        gone = {"note": f"{tool_dir} is gone after the upgrade; the next repair creates it locked"}
        rep.add("winrepair_lock", ok=True, action=action, **(gone if action == "ABSENT" else {}))
        return
    rep.add(
        "winrepair_lock",
        ok=False,
        reason=envelope.data.text_or_none("reason"),
        note=f"{tool_dir} changed during the upgrade; nothing was relocked and nothing runs "
        f"from it - remove it (rd /s /q {tool_dir}, as an administrator) before the next "
        f"repair run, which refuses it otherwise",
    )


def remove_profile_copy(staged: GuestPort, rep: Report) -> None:
    """Delete the verified profile copy; a copy left behind is reported, never raised."""
    left = staged.remove_profile_copy()
    rep.add("remove_profile_copy", ok=left is None, **({} if left is None else {"error": left}))


def read_build(guest: GuestPort) -> tuple[str, int] | None:
    """CurrentBuild and UBR, or None if the guest could not be read.

    None means CANNOT READ, which is not the same as a wrong build - collapsing the two makes
    an unreachable guest look like a clean negative. The guest reports UBR as a decimal
    integer, so there is no hex to parse here.
    """
    try:
        build = guest.probe("build", timeout=PROBE_TIMEOUT)
    except READ_FAILURES:
        return None
    return build.text("current_build"), build.integer("ubr")


def wait_ssh(
    guest: GuestPort,
    minutes: float = 25.0,
    *,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
) -> bool:
    """Wait until the guest answers ssh; False when ``minutes`` pass first."""
    deadline = clock() + minutes * 60
    while clock() < deadline:
        if guest.ssh("hostname", timeout=30).returncode == 0:
            return True
        sleep(15)
    return False


def _unfinished(state: RunState) -> ApplyError | None:
    """Why ``state`` is no finished, successful run (with its verdict), or None when it is."""
    if state.alive:
        return ApplyError("SetupHost is running - the upgrade is still live; let it finish", verdict="RUN_LIVE")
    if state.live:
        return ApplyError(
            f"{state.log_path} shows a run that started, has no DONE marker, and SetupHost is gone - "
            f"it was cut off; check the guest before applying anything",
            verdict="RUN_UNFINISHED",
        )
    if not state.log_present:
        return ApplyError(f"no state log at {state.log_path} - no upgrade run to apply", verdict="NO_RUN")
    if state.marker != "STATE=DONE-OK":
        return ApplyError(
            f"the run ended {state.marker} - re-diagnose it rather than applying it", verdict="RUN_FAILED"
        )
    return None


def gate_run_finished(guest: GuestPort, rep: Report) -> None:
    """Refuse the apply reboot unless the upgrade run is over AND ended ``STATE=DONE-OK``.

    setup fills NewOS during its down-level, long before it writes the marker, so the NewOS gate
    alone passes a live run, and the apply reboot would then ACPI-stop setup mid-run. This is the
    same reading the repair run takes before it stops a guest (:func:`read_run_state`), held to the
    stricter bar: a DONE-FAIL run is not one to apply either. A guest that cannot be asked is
    refused: an unknown state is not a finished one.
    """
    try:
        state = read_run_state(guest, timeout=PROBE_TIMEOUT)
    except READ_FAILURES as exc:
        raise ApplyError(f"cannot verify that the upgrade run finished: {exc}") from exc
    refusal = _unfinished(state)
    if refusal is not None:
        rep.add("run_finished", ok=False, verdict=refusal.verdict, alive=state.alive, marker=state.marker)
        raise refusal
    rep.add("run_finished", ok=True, marker=state.marker)


def gate_staged(guest: GuestPort, rep: Report) -> None:
    """A rollback DELETES NewOS, so re-arming the boot entry would boot into nothing.

    This is the decision, not a formality: present means apply, absent means the whole
    down-level has to be re-run from setup.exe.
    """
    try:
        staged = guest.probe("staged-os", timeout=PROBE_TIMEOUT)
    except READ_FAILURES as exc:
        raise ApplyError(
            f"could not read the staged-OS state from the guest - refusing to reboot on an unknown state: {exc}"
        ) from exc
    present, verdict = staged.flag("present"), staged.text("verdict")
    if verdict != ("REARMABLE" if present else "RERUN"):
        raise GuestProtocolError(f"staged-os: present={present} contradicts verdict {verdict!r}")
    rep.add("gate_staged", ok=present, verdict=verdict)
    if not present:
        raise ApplyError(
            "NewOS is absent - the upgrade rolled back; re-run the down-level rather than re-arming the boot entry"
        )


def _search_detail(search: Fields) -> dict[str, object]:
    """The bounded Windows Update search as step fields: informational, never part of the verdict.

    A TIMEOUT is normal on the first boot after the apply, while servicing still runs; bare, it
    reads like a failure, so it carries the sentence that says what it is.
    """
    status = search.text("status")
    detail: dict[str, object] = {"search": status}
    if status == "OK":
        detail["search_pending"] = search.integer("pending")
    elif status == "TIMEOUT":
        detail["search_note"] = (
            f"Windows Update search abandoned after {search.number('timeout_s'):g} s - informational, "
            f"NOT a verdict; normal on the first boot after the apply while servicing runs; "
            f"re-run restore-wu later to list pending updates"
        )
    else:
        detail["search_error"] = search.text_or_none("error")
    return detail


def restore_windows_update(guest: GuestPort, rep: Report) -> None:
    """Lift the Windows Update hold and VERIFY it lifted (guest tool ``restore-wu``).

    Leaving a start type Disabled survives into the repaired OS and silently stops the machine
    ever patching again, so only a verified RESTORED passes; a state that could not be read
    (UNKNOWN, or no answer) is a failure, not "all restored".
    """
    try:
        envelope = guest.tool("restore-wu", timeout=900)
    except READ_FAILURES as exc:
        rep.add("restore_wu", ok=False, note="no answer")
        raise ApplyError(f"could not run the Windows Update restore: {exc}") from exc
    verdict = envelope.gate("verdict", "RESTORED")
    data = envelope.data
    still = data.texts("still_disabled")
    search = _search_detail(data.section("search"))
    if verdict == "RESTORED":
        rep.add("restore_wu", ok=True, note="all restored", **search)
        return
    rep.add("restore_wu", ok=False, verdict=verdict, still_disabled=list(still), **search)
    if verdict == "STILL_DISABLED":
        raise ApplyError("Windows Update left disabled: " + ", ".join(still))
    raise ApplyError(f"Windows Update state could not be verified: {verdict}")


def apply_reboot(node: NodePort, vmid: int, rep: Report) -> None:
    """Clean ACPI stop, then a fresh start.

    Never a hard stop: cutting the guest off mid-write is the documented way component stores
    get damaged, and the store is the thing under repair. The one-shot boot entry lives in BCD
    ON DISK, so it survives a clean stop and start.
    """
    node.qm("shutdown", str(vmid), "--timeout", "300", timeout=400)
    wait_status(node, vmid, "stopped", tries=_STATUS_TRIES)
    rep.add("clean_stop", ok=True, note="qm shutdown (ACPI)")
    if node.qm("start", str(vmid), timeout=300).returncode != 0:
        raise ApplyError("start failed")
    wait_status(node, vmid, "running", tries=_STATUS_TRIES)
    rep.add("start", ok=True, note="one-shot bootsequence honoured from BCD on disk")


def _reboot_into_newos(node: NodePort, request: ApplyRequest, guest: GuestPort, rep: Report) -> None:
    """Gate, then the apply reboot, then wait for the guest to come back on ssh.

    Both gates run before the reboot: it stops the guest, which must never happen to a live run.
    """
    gate_run_finished(guest, rep)
    gate_staged(guest, rep)
    apply_reboot(node, request.vmid, rep)
    # The apply phase runs before the OS is reachable; SSH returning IS the signal that it
    # finished, one way or the other.
    if not wait_ssh(guest, request.apply_minutes, clock=node.clock, sleep=node.sleep):
        raise ApplyError(
            f"guest did not answer ssh within {request.apply_minutes} min - check the console for 'undoing changes'"
        )
    rep.add("guest_back", ok=True)


def read_receipt(receipts: ReceiptStore, vmid: int, rep: Report) -> RepairReceipt:
    """The build the VM's repair run measured; refused when there is no usable receipt."""
    try:
        receipt = receipts.read(vmid)
    except ReceiptError as exc:
        raise ApplyError(str(exc)) from exc
    if receipt is None:
        raise ApplyError(
            f"no repair receipt for VM {vmid} at {receipts.path(vmid)} - run `pve-winrepair repair` for this VM "
            f"first: apply verifies the build its prepare step measured"
        )
    rep.add("receipt", ok=True, path=str(receipts.path(vmid)), want=receipt.expected_build())
    return receipt


def _verify_build(after: tuple[str, int], receipt: RepairReceipt, rep: Report) -> None:
    """Refuse a build other than the one the receipt recorded (verdict REVERTED_OR_UNCHANGED)."""
    if after != (str(receipt.image_build), receipt.image_spbuild):
        # A revert carrying a successful down-level means the APPLY was cut off.
        rep.add(
            "verify_build",
            ok=False,
            got=f"{after[0]}.{after[1]}",
            want=receipt.expected_build(),
            note="did not reach the target - check Panther for Setup360Result before re-diagnosing the upgrade",
        )
        raise ApplyError(
            f"build is {after[0]}.{after[1]}, wanted {receipt.expected_build()}",
            verdict="REVERTED_OR_UNCHANGED",
        )
    rep.add("verify_build", ok=True, build=f"{after[0]}.{after[1]}")


def apply_sequence(request: ApplyRequest, node: NodePort, rep: Report, *, receipt: RepairReceipt) -> str:
    """The whole sequence; returns VERIFIED or raises :class:`ApplyError` naming its verdict.

    ``receipt`` holds the build the guest must reach.
    """
    guest = node.guest(request.ip)
    push_tool(guest, rep)
    before = read_build(guest)
    if before is None:
        raise ApplyError(
            "cannot read the build from the guest - it is unreachable, which is not the same as a wrong build"
        )
    rep.add("build_before", ok=True, build=f"{before[0]}.{before[1]}")

    _reboot_into_newos(node, request, guest, rep)

    staged = stage_tool(guest, rep)
    try:
        _verify_and_restore(staged, receipt, rep)
    finally:
        remove_profile_copy(staged, rep)
    return "VERIFIED"


def _verify_and_restore(staged: GuestPort, receipt: RepairReceipt, rep: Report) -> None:
    """After the apply reboot, from the verified profile copy: the lock report, the build, then restore-wu."""
    report_tool_dir_lock(staged, rep)
    after = read_build(staged)
    if after is None:
        raise ApplyError("guest answered ssh but its build could not be read")
    rep.add("build_after", ok=True, build=f"{after[0]}.{after[1]}")
    _verify_build(after, receipt, rep)

    # Lift the WU hold LAST: only a verified build is worth patching again.
    restore_windows_update(staged, rep)


def run_apply(
    request: ApplyRequest, node: NodePort, *, receipts: ReceiptStore, on_step: Callable[[Step], None]
) -> RunResult:
    """Apply and verify, and map how it ended to an exit and a verdict.

    VERIFIED is OK. An :class:`ApplyError` is REFUSED with the error's own verdict, a VM that never
    reached the status the reboot waits for (:class:`VmStatusTimeoutError`) REFUSED with verdict
    ``ERROR``; anything else (a driver/tool mismatch) is INTERNAL.

    Args:
        request: The guest and how long its apply phase may take.
        node: The PVE node the guest runs on.
        receipts: Where the repair run recorded the build its prepare step measured; read first,
            and a missing or unusable receipt is REFUSED (verdict ``ERROR``) before any call.
        on_step: Called with each step as it is recorded (see :class:`Report`).

    Returns:
        The exit, the verdict and every step, the failure step included.
    """
    # Every refusal leaves Windows Update held: the repair run held it, and only a verified
    # restore, the last step of a successful run, lifts it.
    rep = Report(request.vmid, on_step=on_step, held_at_start=True)
    try:
        receipt = read_receipt(receipts, request.vmid, rep)
        verdict = apply_sequence(request, node, rep, receipt=receipt)
    except ApplyError as exc:
        rep.failure("error", str(exc), exc)
        return RunResult(RunExit.REFUSED, exc.verdict, tuple(rep.steps))
    except VmStatusTimeoutError as exc:
        rep.failure("error", str(exc), exc)
        return RunResult(RunExit.REFUSED, "ERROR", tuple(rep.steps))
    except Exception as exc:  # anything unexpected (a driver/tool mismatch) is an internal error
        rep.failure("internal", repr(exc), exc)
        return RunResult(RunExit.INTERNAL, "INTERNAL", tuple(rep.steps))
    return RunResult(RunExit.OK, verdict, tuple(rep.steps))
