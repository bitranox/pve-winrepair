r"""Repair one Windows guest whose cumulative update fails, by an in-place repair upgrade.

Runs ON the PVE node that hosts the guest - any of them. Drives the whole sequence:
snapshot -> ensure vTPM -> lock the stage root -> stage the installation media as a DIRECTORY ->
gate the WIM -> waive the compat block -> launch setup from a SYSTEM task -> poll to a verdict.

What SYSTEM executes is locked to SYSTEM and Administrators before it is copied in: the tool's
directory by every push (the ssh adapter's ``push_tool``), the stage root by :func:`lock_dirs`
before the media transfer. :func:`launch` then only verifies those locks and the tree below them.

The vTPM storage and the staging drive are MEASURED from the guest, not assumed: a storage or a
drive letter named here would hold on one node or one guest and fail on the next.

Every in-guest step runs the packed guest tool through the :class:`GuestPort` and gates on typed
fields of its JSON envelope.

Once prepare has measured the staged image, its build is recorded in the VM's receipt
(:class:`ReceiptStore`) before setup is launched; apply verifies against it. The previous receipt
is removed once the last live-run guard passed, so a run that stops before prepare leaves none.

Once this run has held Windows Update, a refusal, a crash or a poll ending DONE-FAIL, WORKER_GONE
or TIMEOUT leaves the hold in place (only the apply step lifts it, after a verified build); the
last step then says so with ``wu_held: true``.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from pve_winrepair.application.guest_state import read_run_state
from pve_winrepair.application.vm import VmStatusTimeoutError, vm_status, wait_status
from pve_winrepair.domain.addresses import AmbiguousAddressError, lan_address
from pve_winrepair.domain.envelope import (
    PROBE_TIMEOUT,
    READ_FAILURES,
    Envelope,
    Fields,
    GuestCallError,
    GuestProtocolError,
    state_marker,
)
from pve_winrepair.domain.receipt import ReceiptError, RepairReceipt
from pve_winrepair.domain.report import Report, RunExit, RunResult, Step

if TYPE_CHECKING:
    from collections.abc import Callable
    from ipaddress import IPv4Network

    from pve_winrepair.application.ports import GuestPort, NodePort, ReceiptStore
    from pve_winrepair.domain.settings import GuestSettings, RepairSettings

# Progress between steps (still waiting, a read that failed and is retried) is for the operator
# only; the steps themselves go to ``on_step``.
_log = logging.getLogger(__name__)

__all__ = [
    "RepairError",
    "RepairRequest",
    "run_repair",
]


# How many ``qm status`` reads, 5 s apart, a stop or start may take (4 min).
_STATUS_TRIES = 48


class RepairError(RuntimeError):
    """A step refused to proceed. The message names what was measured, not what was assumed."""


@dataclass(frozen=True)
class RepairRequest:
    """One repair run: the guest, its snapshot, the poll deadline and the operator's overrides.

    Attributes:
        vmid: The guest's VMID on this node.
        snapshot_name: The snapshot taken before anything changes on the guest.
        hours: The poll deadline.
        stage_only: Stage and verify the media but do not launch setup.
        ip: The guest's address, for a guest with no QEMU agent; implies the offline snapshot.
        stage_root: The drive to stage the media on (``C:``, ``D:``); default: measured.
        tpm_storage: The PVE storage for a new vTPM volume; default: the storage of the guest's disk.
    """

    vmid: int
    snapshot_name: str
    hours: float = 6.0
    stage_only: bool = False
    ip: str | None = None
    stage_root: str | None = None
    tpm_storage: str | None = None


class _AgentAddress(BaseModel):
    """One address of ``qm guest cmd <vmid> network-get-interfaces``; other keys are ignored."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    ip_address_type: str = Field(default="", alias="ip-address-type")
    ip_address: str = Field(default="", alias="ip-address")


class _AgentInterface(BaseModel):
    """One interface of that output: an interface without addresses has no ``ip-addresses`` key."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    ip_addresses: tuple[_AgentAddress, ...] = Field(default=(), alias="ip-addresses")


_AGENT_INTERFACES = TypeAdapter(tuple[_AgentInterface, ...])


def _agent_ipv4(stdout: str) -> list[str]:
    """Every IPv4 address in ``network-get-interfaces`` output, in order.

    Raises:
        pydantic.ValidationError: The output is not the agent's interface list (a driver/agent mismatch).
    """
    interfaces = _AGENT_INTERFACES.validate_json(stdout)
    return [a.ip_address for i in interfaces for a in i.ip_addresses if a.ip_address_type == "ipv4"]


def guest_ip(node: NodePort, vmid: int, network: IPv4Network | None, tries: int = 30) -> str:
    """Resolve the guest's LAN address from the agent (see :func:`lan_address`).

    Never the first address: docker guests also carry a Hyper-V/NAT switch address (172.x) that is
    unreachable from the node. Without a configured subnet, several candidates are refused.
    """
    for _ in range(tries):
        proc = node.qm("guest", "cmd", str(vmid), "network-get-interfaces", timeout=60)
        if proc.returncode == 0 and proc.stdout.strip():
            try:
                ip = lan_address(_agent_ipv4(proc.stdout), network)
            except AmbiguousAddressError as exc:
                raise RepairError(
                    f"the guest agent on {vmid} reports several candidate LAN addresses "
                    f"({', '.join(exc.candidates)}): set [guest] subnet to the LAN the node reaches"
                ) from exc
            if ip is not None:
                return ip
        node.sleep(10)
    raise RepairError(f"no LAN address from the guest agent on {vmid} after {tries} tries")


def ensure_stopped(node: NodePort, vmid: int, rep: Report) -> None:
    """Stop the guest cleanly (ACPI) unless it is stopped already."""
    if vm_status(node, vmid) == "stopped":
        rep.add("shutdown", ok=True, note="already stopped")
        return
    node.qm("shutdown", str(vmid), "--timeout", "240", timeout=300)
    # Never force-stop: hard-stopping a guest mid-servicing is how component stores get damaged,
    # and the store is the thing under repair.
    wait_status(node, vmid, "stopped", tries=_STATUS_TRIES)
    rep.add("shutdown", ok=True, note="clean via qm shutdown (ACPI; agent-assisted only when the guest has one)")


def vm_storage(node: NodePort, vmid: int) -> str:
    """The storage the guest's own disks live on.

    Never one node's pool by name: another node can have that pool DISABLED, so `qm set` fails
    with a storage error that reads like a permissions problem. Reading the guest's existing disk
    keeps the vTPM on whatever storage the VM is already using, on any node.
    """
    cfg = node.qm("config", str(vmid), timeout=60).stdout
    # Match a real disk entry only. `description:` can quote other volumes, and matching that
    # would put the vTPM on a pool this node cannot see.
    for line in cfg.splitlines():
        match = re.match(r"^(?:scsi|virtio|sata|ide)\d+:\s*([^:,]+):", line)
        if match and "media=cdrom" not in line:
            return match.group(1).strip()
    raise RepairError(f"cannot determine storage for vm {vmid} - no disk entry in qm config")


def ensure_vtpm(node: NodePort, vmid: int, rep: Report, storage: str | None = None) -> bool:
    """setup.exe hard-blocks on TpmVersion when no TPM exists at all.

    The MoSetup waiver covers an UNSUPPORTED TPM, not an ABSENT one, so a guest without
    tpmstate0 needs real vTPM hardware before the upgrade can start.
    """
    cfg = node.qm("config", str(vmid), timeout=60).stdout
    if re.search(r"^tpmstate0:", cfg, re.M):
        rep.add("vtpm", ok=True, note="already present")
        return False
    # An openvmm guest gets its TPM from the launcher (`args: ... --tpm`), not from a PVE
    # tpmstate0 volume. Looking only for tpmstate0 would bolt redundant hardware onto a guest
    # that already has a working TPM.
    if re.search(r"^args:.*--tpm\b", cfg, re.M):
        rep.add("vtpm", ok=True, note="provided by openvmm --tpm")
        return False
    target = storage or vm_storage(node, vmid)
    ensure_stopped(node, vmid, rep)
    proc = node.qm("set", str(vmid), "-tpmstate0", f"{target}:1,version=v2.0", timeout=300)
    if proc.returncode != 0:
        raise RepairError(f"adding vTPM failed: {proc.stderr.strip()}")
    rep.add("vtpm", ok=True, note="added v2.0", storage=target)
    return True


def ensure_running(node: NodePort, vmid: int, rep: Report, network: IPv4Network | None) -> str:
    """Start the guest if needed, wait for its agent, and return its LAN address."""
    if vm_status(node, vmid) != "running":
        proc = node.qm("start", str(vmid), timeout=300)
        if proc.returncode != 0:
            raise RepairError(f"start failed: {proc.stderr.strip()}")
        wait_status(node, vmid, "running", tries=_STATUS_TRIES)
    for _ in range(60):
        if node.qm("agent", str(vmid), "ping", timeout=30).returncode == 0:
            break
        node.sleep(5)
    ip = guest_ip(node, vmid, network)
    rep.add("running", ok=True, ip=ip)
    return ip


def existing_snapshots(node: NodePort, vmid: int) -> set[str]:
    """Names currently present in ``qm listsnapshot``.

    Each line looks like ``` `-> name   <date>   <description> ```, so take the token after the
    arrow. ``current`` is PVE's you-are-here marker, not a snapshot.
    """
    out = node.qm("listsnapshot", str(vmid), timeout=60).stdout
    names: set[str] = set()
    for line in out.splitlines():
        match = re.match(r"^[\s`|+\\>-]*->\s*(\S+)", line)
        if match:
            names.add(match.group(1))
    names.discard("current")
    return names


def wait_ssh(guest: GuestPort, tries: int = 60, *, sleep: Callable[[float], None]) -> None:
    """Wait until the guest answers SSH.

    For a guest with no QEMU agent (an openvmm one, for instance) this is the only readiness
    signal there is - "the VM is running" says nothing about whether Windows has finished booting.
    """
    for _ in range(tries):
        if guest.ssh("hostname", timeout=30).returncode == 0:
            return
        sleep(10)
    raise RepairError(f"guest {guest.ip} never answered ssh")


def wait_servicing_idle(
    guest: GuestPort,
    rep: Report,
    minutes: float = 20.0,
    *,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
) -> None:
    """Let an in-flight CBS transaction finish before the guest is stopped.

    A clean ACPI stop does not corrupt a store, but stopping while TrustedInstaller is mid
    transaction means the next boot spends its first minutes rolling that work back; a guest
    whose CU keeps failing often has TiWorker, TrustedInstaller and MoUsoCoreWorker live with a
    CBS reboot already pending. Bounded, and it REPORTS a timeout rather than proceeding silently.
    """
    deadline = clock() + minutes * 60
    while clock() < deadline:
        try:
            servicing = guest.probe("servicing-active", timeout=PROBE_TIMEOUT)
        except READ_FAILURES:
            # A failed read is not an idle guest. Retry rather than count it as zero.
            sleep(20)
            continue
        if not servicing.flag("active"):
            rep.add("servicing_idle", ok=True, note="TiWorker/TrustedInstaller not running")
            return
        _log.info("servicing still active (%s processes), waiting", servicing.integer("total"))
        sleep(30)
    rep.add(
        "servicing_idle",
        ok=False,
        note=f"still active after {minutes} min - proceeding with a "
        f"CLEAN stop, which is safe, but the next boot may roll back",
    )


def snapshot_offline(node: NodePort, vmid: int, name: str, rep: Report) -> None:
    """Snapshot a STOPPED guest.

    The agent-based path fsfreezes a running guest; with no agent that is impossible, and a
    crash-consistent snapshot of a running Windows box can be one that never boots again. A
    powered-off guest has no dirty state at all, so this is strictly the safer of the two - it
    just costs a shutdown and a boot.
    """
    if name in existing_snapshots(node, vmid):
        rep.add("snapshot", ok=True, name=name, note="exists")
        return
    if vm_status(node, vmid) != "stopped":
        raise RepairError("refusing an agentless snapshot of a running guest - stop it first")
    proc = node.qm(
        "snapshot",
        str(vmid),
        name,
        "--description",
        "before an in-place repair upgrade (offline)",
        timeout=900,
    )
    if proc.returncode != 0:
        raise RepairError(f"snapshot failed: {proc.stderr.strip()}")
    rep.add("snapshot", ok=True, name=name, note="created offline (guest powered off)")


def snapshot(node: NodePort, vmid: int, name: str, rep: Report) -> None:
    """Snapshot only a guest whose agent answers, so PVE can freeze the filesystem.

    With the agent up, PVE fsfreezes before snapshotting and the image is consistent. Without
    it the snapshot is crash-consistent at whatever instant it lands, and if that instant is
    mid-boot the result is unbootable in a way that looks like a hung VM: a black console,
    byte-identical screendumps, the cores busy, and an agent that never appears.
    """
    if not wait_agent(node, vmid):
        raise RepairError(
            "guest agent still not responding after 5 min - refusing to snapshot a possibly mid-boot guest"
        )
    # Ask the snapshot LIST whether the name is taken, never a phrase in stderr: PVE says
    # "snapshot name 'X' already used", a text free to change and to be localised, and a re-run
    # must continue past an existing snapshot rather than abort on it.
    if name in existing_snapshots(node, vmid):
        rep.add("snapshot", ok=True, name=name, note="exists")
        return
    proc = node.qm(
        "snapshot",
        str(vmid),
        name,
        "--description",
        "before an in-place repair upgrade",
        timeout=900,
    )
    if proc.returncode != 0:
        raise RepairError(f"snapshot failed: {proc.stderr.strip()}")
    # PVE prints this only when it actually froze the guest fs. Report it either way rather
    # than assume: a snapshot that silently skipped the freeze is the dangerous one.
    froze = "freeze guest filesystem" in (proc.stdout + proc.stderr)
    rep.add("snapshot", ok=True, name=name, note="created", fs_frozen=froze)


def wait_agent(node: NodePort, vmid: int, minutes: float = 5.0) -> bool:
    """Poll the guest agent until it answers, rather than sampling it once.

    A single `qm agent ping` right after a boot answers about a TRANSITIONAL state: the agent
    service may simply not have finished starting, so a ping that fails now passes a minute later.
    One sample would turn a healthy guest into a refused snapshot and abort the run after the
    vTPM had already been added.
    """
    deadline = node.clock() + minutes * 60
    while node.clock() < deadline:
        if node.qm("agent", str(vmid), "ping", timeout=30).returncode == 0:
            return True
        node.sleep(10)
    return False


_GIB = 1024**3
_DRIVE_LETTER = re.compile(r"[A-Z]")
# The stage root as this driver builds it (a letter plus \upgrade); it is also a raw ssh argument
# to cmd.exe below, so anything else is refused rather than quoted.
_STAGE_ROOT = re.compile(r"[A-Z]:\\upgrade")
LAUNCH_VERDICTS = frozenset({"OK", "SUSPECT", "NO_START", "FAILED", "TASK_LEFT"})
MANUAL_TASK_CLEANUP = "schtasks /End /TN OVMRepairUpgrade, then schtasks /Delete /F /TN OVMRepairUpgrade"


def push_tool(guest: GuestPort, rep: Report) -> None:
    r"""Put the packed guest tool at its content address on the guest (the ssh adapter's ``push_tool``).

    Pushed again at every point a reboot or a restore may have replaced the guest's copy, so a
    resumed run never talks to a stale tool. Safe before the live-run guard: a push never writes
    a file that exists, so it cannot touch the copy a live SYSTEM run is executing, and its
    lock-dirs leaves a ``C:\winrepair`` that is already locked as it found it.
    """
    try:
        pushed = guest.push_tool()
    except GuestCallError as exc:
        raise RepairError(str(exc)) from exc
    left = {} if pushed.staged_left is None else {"staged_left": pushed.staged_left}
    rep.add("push_tool", ok=True, dest=pushed.path, copied=pushed.copied, **left)


def guest_drives(guest: GuestPort) -> dict[str, float]:
    """Free space per fixed drive letter in GiB, measured in the guest from exact byte counts."""
    try:
        report = guest.probe("drives", timeout=PROBE_TIMEOUT)
    except READ_FAILURES as exc:
        raise RepairError(f"could not read any drive from the guest: {exc}") from exc
    drives: dict[str, float] = {}
    for drive in report.sections("drives"):
        letter = drive.text("letter")
        if not _DRIVE_LETTER.fullmatch(letter):
            raise GuestProtocolError(f"drives: {letter!r} is not a drive letter")
        drives[letter] = drive.integer("free_bytes") / _GIB
    if not drives:
        raise RepairError("could not read any drive from the guest: it reported none")
    return drives


def pick_stage_root(guest: GuestPort, rep: Report, override: str | None, *, repair: RepairSettings) -> str:
    r"""Choose where the media goes, and gate on headroom BEFORE spending an hour on it.

    The drive is measured, never assumed: a guest with only C: cannot even create
    `D:\upgrade`, and the transfer then fails with a remote mkdir error that says nothing about a
    missing drive. Gated on exact bytes, so 14.96 GiB (shown as 15.0) is below a 15 GB floor.

    The staging drive needs ``repair.stage_free_gb`` for the media; C: additionally needs
    ``repair.system_free_gb`` for the upgrade's expansion and rollback copy - a shortfall there
    surfaces as ERROR_DISK_FULL hours later.
    """
    stage_free_gb, system_free_gb = repair.stage_free_gb, repair.system_free_gb
    drives = guest_drives(guest)
    shown = {letter: round(free, 1) for letter, free in drives.items()}
    if drives.get("C", 0.0) < system_free_gb:
        raise RepairError(
            f"C: has {shown.get('C', 0.0)} GB free, below the {system_free_gb} GB "
            f"an in-place upgrade needs - free space before retrying"
        )
    if override:
        letter = override.rstrip(":\\").upper()
        if letter not in drives:
            raise RepairError(f"--stage-root names {letter}: which the guest does not have: {shown}")
        if drives[letter] < stage_free_gb:
            raise RepairError(f"{letter}: has only {shown[letter]} GB free, need {stage_free_gb}")
        root = f"{letter}:\\upgrade"
        rep.add("stage_root", ok=True, root=root, note="explicit", drives=shown)
        return root
    # Prefer a non-system drive so the media does not compete with the upgrade's own working
    # set, but fall back to C: rather than refusing a guest that simply has one disk.
    for letter in sorted(k for k in drives if k != "C"):
        if drives[letter] >= stage_free_gb:
            root = f"{letter}:\\upgrade"
            rep.add("stage_root", ok=True, root=root, note="non-system drive", drives=shown)
            return root
    if drives["C"] < system_free_gb + stage_free_gb:
        raise RepairError(
            f"only C: is usable and its {shown['C']} GB cannot hold both the media "
            f"and the upgrade ({system_free_gb + stage_free_gb} GB needed)"
        )
    rep.add("stage_root", ok=True, root="C:\\upgrade", note="no non-system drive; using C:", drives=shown)
    return "C:\\upgrade"


def lock_dirs(guest: GuestPort, rep: Report, root: str) -> None:
    r"""Create and lock the stage root (and re-check ``C:\winrepair``) before the media go in.

    setup.exe runs as SYSTEM and loads what lies beside it; a stage root still open to local users
    while the media arrive lets one of them plant a DLL there, and no later lock can tell. The
    guest tool's ``lock-dirs`` creates the root with the lock already in place (a missing drive is
    refused here, not after an hour of transfer) and refuses an existing root that is not exactly
    locked.
    """
    if not _STAGE_ROOT.fullmatch(root):
        raise RepairError(f"refusing stage root {root!r}: not a <letter>:\\upgrade path")
    try:
        envelope = guest.tool("lock-dirs", "--tool", guest.tool_path, "--stage-root", root, timeout=PROBE_TIMEOUT)
    except READ_FAILURES as exc:
        raise RepairError(f"lock-dirs returned no verdict: {exc}") from exc
    if envelope.gate("verdict", "OK") != "OK":
        raise RepairError(f"not staging into {root}: {envelope.data.text_or_none('reason')}")
    locked = {d.text("path"): d.text("action") for d in envelope.data.sections("directories")}
    rep.add("lock_dirs", ok=True, directories=locked)


def stage_media(guest: GuestPort, rep: Report, root: str, *, media: Path) -> None:
    """Copy the media directory into ``root`` on the guest; :func:`lock_dirs` created and locked it."""
    if not _STAGE_ROOT.fullmatch(root):
        raise RepairError(f"refusing stage root {root!r}: not a <letter>:\\upgrade path")
    started = time.time()
    proc = guest.copy_to([str(p) for p in sorted(media.iterdir())], f"{root}\\", timeout=5400)
    if proc.returncode != 0:
        raise RepairError(f"media transfer failed rc={proc.returncode}: {proc.stderr.strip()[:400]}")
    rep.add("stage_media", ok=True, seconds=round(time.time() - started), root=root)


def refuse_live_run(guest: GuestPort, rep: Report) -> None:
    """Refuse to go on while an earlier upgrade run is still live on the guest.

    A second launch deletes the state log and restarts the task under the live run, which can
    end it; restaging copies media over files setup is reading. Live means SetupHost is running,
    or the state log shows a run that started and never wrote its DONE marker. A guest that
    cannot be asked is refused too: an unknown state is not an idle one.
    """
    try:
        state = read_run_state(guest, timeout=PROBE_TIMEOUT)
    except READ_FAILURES as exc:
        raise RepairError(f"cannot verify that no upgrade run is live on the guest: {exc}") from exc
    if state.alive:
        raise RepairError("SetupHost is running - an upgrade is live; poll it instead of relaunching")
    if state.live:
        raise RepairError(
            f"{state.log_path} shows a run that started and has no DONE marker - "
            f"it may still be running; check the guest before relaunching"
        )
    rep.add("no_live_run", ok=True, previous_verdict=state.verdict)


def quiesce_windows_update(guest: GuestPort, rep: Report) -> None:
    """Keep Windows Update out of the servicing stack for the duration of the upgrade.

    Stopping the services is NOT enough: they are trigger-started and come back. A WU that
    restarts mid-upgrade runs the next LCU against the still-broken store, fails, and can leave a
    store-corruption repair holding the stack - time lost and a live CBS transaction blocking the
    apply reboot. Disabling the start type is what actually holds.

    The start types are RESTORED by the guest tool's restore-wu after the apply reboot; they are
    recorded in the report so the pre-change state is recoverable from the run's own output.
    """
    try:
        envelope = guest.tool("quiesce-wu", timeout=900)
    except READ_FAILURES as exc:
        raise RepairError(f"quiesce step returned no verdict: {exc}") from exc
    # Gate on the VERIFIED state, never on the step having run: a step that only ran can report
    # ok while wuauserv is still Manual and Running.
    verdict = envelope.gate("verdict", "OK")
    data = envelope.data
    if verdict != "OK":
        raise RepairError(
            f"Windows Update not held: {verdict} "
            f"not_disabled={list(data.texts('not_disabled'))} "
            f"still_running={list(data.texts('still_running'))}"
        )
    previous = data.section("previous_start_modes")
    rep.add(
        "quiesce_wu",
        ok=True,
        previous_start_modes={k: previous.text(k) for k in previous.values},
        verdict=verdict,
    )


def _prepare_warnings(data: Fields) -> list[str]:
    """What prepare reported but does not gate on: setup itself refuses on these later."""
    warnings: list[str] = []
    if data.integer_or_none("waiver_readback") != 1:
        warnings.append("the MoSetup waiver did not read back as 1")
    tpm = data.flag_or_none("tpm_present")
    if tpm is not True:
        warnings.append("no TPM visible" if tpm is False else "TPM presence unknown")
    return warnings


def prepare(guest: GuestPort, rep: Report, root: str) -> tuple[int, int]:
    """Clear read-only, gate hard on the WIM, write the compat waiver (guest tool ``prepare``).

    Only the WIM gate refuses: the vTPM is ensured on the host earlier, and the TPM and waiver
    readback are reported so a later setup refusal can be read against them.

    Returns:
        The staged image's build and servicing build: the build the upgrade installs.
    """
    try:
        envelope = guest.tool("prepare", "--stage-root", root, timeout=900)
    except READ_FAILURES as exc:
        raise RepairError(f"prepare returned no gate: {exc}") from exc
    data = envelope.data
    if envelope.gate("gate", "PASS") != "PASS":
        raise RepairError(f"guest gate refused: {data.text_or_none('reason')}")
    image, running = data.section("image"), data.section("running")
    image_build, image_spbuild = image.integer("build"), image.integer("spbuild")
    rep.add(
        "prepare",
        ok=True,
        gate="PASS",
        image_build=image_build,
        image_spbuild=image_spbuild,
        running=running.text("build"),
        readonly_cleared=data.integer("readonly_cleared"),
        waiver_readback=data.integer_or_none("waiver_readback"),
        tpm_present=data.flag_or_none("tpm_present"),
        warnings=_prepare_warnings(data),
    )
    return image_build, image_spbuild


def forget_receipt(receipts: ReceiptStore, vmid: int) -> None:
    """Remove the VM's previous receipt: from here on it no longer describes what is staged.

    Only after the live-run guard: a run still in flight is refused there, and removing its receipt
    earlier would make its later apply refuse for want of one.
    """
    try:
        receipts.delete(vmid)
    except ReceiptError as exc:
        raise RepairError(str(exc)) from exc


def record_receipt(receipts: ReceiptStore, receipt: RepairReceipt, rep: Report) -> None:
    """Record the build prepare measured, for apply to verify; refused before setup is launched."""
    try:
        path = receipts.write(receipt)
    except ReceiptError as exc:
        raise RepairError(f"{exc} - not launching setup: apply could not verify the build it installs") from exc
    rep.add("receipt", ok=True, path=str(path), expected_build=receipt.expected_build())


def _launch_detail(envelope: Envelope) -> dict[str, object]:
    data = envelope.data
    wait = data.section_or_none("wait")
    return {
        "verdict": envelope.gate("verdict", "OK"),
        "reason": data.text_or_none("reason"),
        "setuphost": data.integer_or_none("setuphost"),
        "wait": None if wait is None else wait.text("status"),
        "waited_s": None if wait is None else wait.number("waited_s"),
        "task_cleanup": data.section("task_cleanup").text("action"),
    }


def launch(guest: GuestPort, rep: Report, root: str) -> None:
    """Start setup as a SYSTEM task (guest tool ``launch``) and map its verdict.

    Returns normally when setup is running, so the caller polls: OK, and TASK_LEFT after a
    DISARM (the run launched setup; only deleting its task definition failed - relaunching
    would end the live run). Every other verdict raises: SUSPECT (setup already gone), NO_START,
    FAILED, and TASK_LEFT after a REMOVE (setup never started, but the task is still there).
    """
    try:
        # --tool names the exact copy just pushed: the SYSTEM task's action runs that file.
        envelope = guest.tool("launch", "--stage-root", root, "--tool", guest.tool_path, timeout=1800)
    except READ_FAILURES as exc:
        raise RepairError(
            f"launch outcome unknown ({exc}); setup may be running - check "
            f"setup-alive and the state log, do not relaunch"
        ) from exc
    detail = _launch_detail(envelope)
    verdict = str(detail["verdict"])
    if verdict not in LAUNCH_VERDICTS:
        raise GuestProtocolError(f"launch: unknown verdict {verdict!r}")
    if verdict == "OK":
        rep.add("launch", ok=True, **detail)
        return
    if verdict == "TASK_LEFT" and detail["task_cleanup"] == "DISARM":
        rep.add(
            "launch",
            ok=False,
            **detail,
            note=f"setup was launched ({detail['reason']}); its task is still defined - "
            f"after the run: {MANUAL_TASK_CLEANUP}",
        )
        return
    _log.warning("launch did not leave setup running: %s", json.dumps(detail))
    hint = f"; remove the task by hand: {MANUAL_TASK_CLEANUP}" if verdict == "TASK_LEFT" else ""
    raise RepairError(f"launch did not leave setup running: {verdict}: {detail['reason']}{hint}")


def read_marker(guest: GuestPort) -> str | None:
    """The state log's completion marker (``STATE=DONE-OK`` / ``STATE=DONE-FAIL``), or None.

    Raises:
        GuestNoAnswerError, GuestInternalError: The log could not be read - NOT an absent marker.
        GuestProtocolError: The log carries a verdict this driver does not know.
    """
    return state_marker(guest.probe("state", timeout=PROBE_TIMEOUT))


def setup_alive(guest: GuestPort) -> bool | None:
    """Whether SetupHost runs; None when the guest could not be asked (never read as gone)."""
    try:
        return guest.probe("setup-alive", timeout=PROBE_TIMEOUT).flag("alive")
    except READ_FAILURES:
        return None


def _late_marker(guest: GuestPort, rep: Report, sleep: Callable[[float], None]) -> str:
    """Re-read the marker over a grace window after SetupHost vanished.

    The worker vanishing is NOT a verdict. The guest appends its marker only AFTER setup.exe
    returns, so the marker can already be in the file while a poll that stops at the vanished
    worker still returns WORKER_GONE - failing a down-level that in fact succeeded (rc 0x0). So
    re-read over a grace window before calling it a failure.
    """
    for attempt in range(6):
        sleep(20)
        try:
            marker = read_marker(guest)
        except READ_FAILURES:
            continue
        if marker:
            rep.add(
                "poll",
                ok=marker == "STATE=DONE-OK",
                verdict=marker,
                note=f"verdict read {(attempt + 1) * 20}s after the worker exited",
            )
            return marker
    rep.add(
        "poll",
        ok=False,
        verdict="WORKER_GONE",
        note="SetupHost exited and no verdict appeared within 120s of grace",
    )
    return "WORKER_GONE"


def poll(
    guest: GuestPort,
    rep: Report,
    hours: float,
    *,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
) -> str:
    """Wait on the task's OWN completion marker.

    A derived signal (percent, disk, log size) cannot tell finished from aborted, and this
    upgrade's mid down-level phase legitimately flatlines both disk and log for long stretches.
    """
    deadline = clock() + hours * 3600
    while clock() < deadline:
        try:
            marker, read_failed = read_marker(guest), False
        except READ_FAILURES as exc:
            marker, read_failed = None, True
            _log.info("marker read failed (%s), not treating as absent", exc)
        if marker:
            rep.add("poll", ok=marker == "STATE=DONE-OK", verdict=marker)
            return marker
        # Progress is logged for the operator only. It is deliberately NOT a completion test:
        # a percentage that stops moving reads identically for finished and for aborted.
        alive = setup_alive(guest)
        _log.info("waiting, SetupHost running=%s", alive)
        if read_failed:
            sleep(20)
            continue
        if alive is False:
            return _late_marker(guest, rep, sleep)
        sleep(300)
    rep.add("poll", ok=False, verdict="TIMEOUT", note=f"no verdict within {hours} h - investigate")
    return "TIMEOUT"


def _clear_live_run(node: NodePort, request: RepairRequest, rep: Report, network: IPv4Network | None) -> GuestPort:
    r"""Refuse a live upgrade run on a running guest BEFORE anything can stop or change it.

    Runs first on both paths. Without an agent (``ip``) the next step is a shutdown for the
    offline snapshot, and with one the vTPM step can stop the guest; a re-run over a setup still in
    its down-level would end that setup and only then refuse. A guest that cannot be asked is
    refused too (:func:`refuse_live_run`; an agentless guest that never answers ssh: :func:`wait_ssh`).
    Pushing first is safe: a push never writes a tool file that exists and rewrites no DACL of an
    already locked ``C:\winrepair`` (see the ssh adapter).

    Its one boundary: it runs only on a RUNNING VM. On a stopped one :func:`ensure_vtpm` and, with
    ``ip``, the offline snapshot plus ``qm start`` come before any guard - inherent, since a
    stopped guest cannot be asked; the guard then runs again before staging and launch.
    """
    if request.ip:
        guest = node.guest(request.ip)
        wait_ssh(guest, sleep=node.sleep)
    else:
        guest = node.guest(ensure_running(node, request.vmid, rep, network))
    push_tool(guest, rep)
    refuse_live_run(guest, rep)
    return guest


def _early_hold(node: NodePort, guest: GuestPort, rep: Report) -> None:
    """Hold Windows Update BEFORE anything stops the guest.

    A guest that needs a vTPM is stopped by :func:`ensure_vtpm`, and letting WU push another LCU
    into the broken store across that boot costs the time the hold exists to save.
    """
    quiesce_windows_update(guest, rep)
    wait_servicing_idle(guest, rep, clock=node.clock, sleep=node.sleep)


def _agentless_running(node: NodePort, request: RepairRequest, ip: str, rep: Report) -> GuestPort:
    """No agent to fsfreeze with, so snapshot the guest POWERED OFF, then boot and wait for ssh.

    Powered off is more consistent than the agent path, not less; ssh is the only readiness
    signal such a guest has.
    """
    guest = node.guest(ip)
    ensure_stopped(node, request.vmid, rep)
    snapshot_offline(node, request.vmid, request.snapshot_name, rep)
    if vm_status(node, request.vmid) != "running":
        if node.qm("start", str(request.vmid), timeout=300).returncode != 0:
            raise RepairError("start failed")
        wait_status(node, request.vmid, "running", tries=_STATUS_TRIES)
    wait_ssh(guest, sleep=node.sleep)
    rep.add("running", ok=True, ip=ip, note="agentless (ssh-verified)")
    return guest


def _media_dir(repair: RepairSettings) -> Path:
    """The configured media directory; refused when ``[repair] media_dir`` is empty or missing.

    An empty setting is refused by name, never read as a path: ``Path("")`` is the working
    directory, which exists, so the run would stage whatever directory it was started from.
    """
    if not repair.media_dir:
        raise RepairError(
            "[repair] media_dir is not configured: set it to the directory holding the installation media"
        )
    media = Path(repair.media_dir)
    if not media.is_dir():
        raise RepairError(f"media directory missing: {media}")
    return media


def repair_sequence(
    request: RepairRequest,
    rep: Report,
    node: NodePort,
    *,
    repair: RepairSettings,
    guest: GuestSettings,
    receipts: ReceiptStore,
) -> str:
    """The whole sequence; returns the verdict (STATE=DONE-OK, STAGED, ...).

    The VM's previous receipt is removed once the live-run guard passed for the last time, so a
    run refused after that, or a stage-only run, leaves none for apply to trust; the new one is
    written once prepare has measured the image, before setup is launched.
    """
    media = _media_dir(repair)
    network = guest.network()
    if vm_status(node, request.vmid) == "running":
        live = _clear_live_run(node, request, rep, network)
        if not request.ip:
            _early_hold(node, live, rep)
    ensure_vtpm(node, request.vmid, rep, request.tpm_storage)
    if request.ip:
        target = _agentless_running(node, request, request.ip, rep)
    else:
        target = node.guest(ensure_running(node, request.vmid, rep, network))
        snapshot(node, request.vmid, request.snapshot_name, rep)
    # Pushed again after the vTPM reboot and the snapshot, so the steps below never meet a
    # stale copy; the live-run check guards the restaging as well as the launch.
    push_tool(target, rep)
    refuse_live_run(target, rep)
    forget_receipt(receipts, request.vmid)
    stage_root = pick_stage_root(target, rep, request.stage_root, repair=repair)
    lock_dirs(target, rep, stage_root)
    stage_media(target, rep, stage_root, media=media)
    # Idempotent, and it re-VERIFIES the hold across the vTPM reboot rather than assuming
    # the earlier pass survived it.
    quiesce_windows_update(target, rep)
    if request.stage_only:
        return "STAGED"
    image_build, image_spbuild = prepare(target, rep, stage_root)
    written_at = datetime.fromtimestamp(node.clock(), tz=timezone.utc)
    receipt = RepairReceipt(
        vmid=request.vmid, image_build=image_build, image_spbuild=image_spbuild, written_at=written_at
    )
    record_receipt(receipts, receipt, rep)
    launch(target, rep, stage_root)
    return poll(target, rep, request.hours, clock=node.clock, sleep=node.sleep)


def run_repair(
    request: RepairRequest,
    node: NodePort,
    *,
    repair: RepairSettings,
    guest: GuestSettings,
    receipts: ReceiptStore,
    on_step: Callable[[Step], None],
) -> RunResult:
    """Run the repair and map how it ended to an exit and a verdict.

    ``STATE=DONE-OK`` and ``STAGED`` are OK. Any other verdict the run returns (the poll's
    ``STATE=DONE-FAIL``, ``WORKER_GONE``, ``TIMEOUT``: answers, not exceptions) is REFUSED with
    that verdict, its last step flagged when Windows Update is still held. A :class:`RepairError`
    or a VM that never reached the status a stop or start waits for (:class:`VmStatusTimeoutError`)
    is REFUSED with verdict ``ERROR``; anything else (a driver/tool mismatch) is INTERNAL.

    Args:
        request: The guest and the operator's choices for this run.
        node: The PVE node the guest runs on.
        repair: ``[repair]``: the media directory and the free-space floors.
        guest: ``[guest]``: the subnet the guest's LAN address is picked from.
        receipts: Where the build prepare measured is recorded for apply (one receipt per VM).
        on_step: Called with each step as it is recorded (see :class:`Report`).

    Returns:
        The exit, the verdict and every step, the failure step included.
    """
    rep = Report(vmid=request.vmid, on_step=on_step)
    try:
        verdict = repair_sequence(request, rep, node, repair=repair, guest=guest, receipts=receipts)
    except (RepairError, VmStatusTimeoutError) as exc:
        rep.failure("error", str(exc), exc)
        return RunResult(RunExit.REFUSED, "ERROR", tuple(rep.steps))
    except Exception as exc:  # anything unexpected (a driver/tool mismatch) is an internal error
        rep.failure("internal", repr(exc), exc)
        return RunResult(RunExit.INTERNAL, "INTERNAL", tuple(rep.steps))
    if verdict in ("STATE=DONE-OK", "STAGED"):
        return RunResult(RunExit.OK, verdict, tuple(rep.steps))
    rep.ended_held()
    return RunResult(RunExit.REFUSED, verdict, tuple(rep.steps))
