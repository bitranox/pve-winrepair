"""Read-only guest probes: is the guest affected, what build is it, is setup or servicing running.

Each probe reads Windows only through the :class:`ProbeHost` port; :class:`PwshpyHost` is the
real adapter, and the decision logic between the two is plain Python that runs on Linux.

Exit semantics (see ``envelope.py``): a probe that only REPORTS a reading (build, drives,
staged-os, servicing-active, setup-alive, state) is ok whenever the reading succeeded. A probe
that carries a VERDICT (detect-lp-defect, verify-runners) is refused (exit 1) when the verdict
is UNKNOWN or, for verify-runners, SHORT. A failed read raises, which the entry turns into exit 2:
a read that could not happen must never look like an empty answer.

Contents:
    * :func:`commands` - the probe subcommands for the entry's command table.
    * :class:`ProbeHost`, :class:`PwshpyHost` - the OS port and its pwshpy adapter.
    * the pure decision helpers and their result records.
"""

from __future__ import annotations

import argparse
import codecs
import importlib
import itertools
import json
import os
import re
import socket
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, cast

from pwshpy import (
    CimInstance,
    EventLogEntry,
    ProcessInfo,
    ProcessResult,
    PwshPyError,
    RegistryValue,
    ScheduledTaskInfo,
    ServiceInfo,
    ps,
)

from pve_winrepair_guest.envelope import Command, Outcome, Skip
from pve_winrepair_guest.evtlog import EvtApi, iter_events

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping, Sequence

__all__ = [
    "CURRENT_VERSION_KEY",
    "DEFAULT_STATE_LOG",
    "NEWOS_WINLOAD",
    "BuildInfo",
    "Drive",
    "ProbeError",
    "ProbeHost",
    "PwshpyHost",
    "StagedOs",
    "StateLog",
    "TaskRunInfo",
    "build_info",
    "commands",
    "drive_from_cim",
    "fixed_drives",
    "read_state",
    "staged_os",
    "state_verdict",
    "task_time",
]

CURRENT_VERSION_KEY = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
NLS_LANGUAGE_KEY = r"HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language"
# Where the upgrade run writes its append-only log and its STATE=DONE-OK|DONE-FAIL marker.
DEFAULT_STATE_LOG = r"C:\upgrade-state.log"
# setup.exe stages the new OS here; a rollback deletes it, so its winload decides re-arm vs re-run.
NEWOS_WINLOAD = r"C:\$WINDOWS.~BT\NewOS\Windows\System32\winload.efi"
# The newest 600 Setup events: enough to span the failed CU attempts on every affected guest seen.
SETUP_LOG_EVENTS = 600
# docker ps answers in seconds on a healthy runner host; 120 s bounds a wedged daemon.
DOCKER_PS_TIMEOUT = 120.0
SERVICING_PROCESSES = ("TiWorker", "TrustedInstaller")
SETUP_PROCESSES = ("SetupHost",)
STATE_MARKERS = ("STATE=DONE-OK", "STATE=DONE-FAIL")
STATE_TAIL_LINES = 200
_HRESULT = re.compile(r"(0x[0-9a-f]{8})", re.IGNORECASE)
_GB = 1024**3


class ProbeError(RuntimeError):
    """A probe could not read what it needs; the entry reports it as an internal error."""


@dataclass(frozen=True)
class TaskRunInfo:
    """When a scheduled task last ran and what it returned (Get-ScheduledTaskInfo).

    Attributes:
        last_run: LastRunTime as local wall-clock ISO text (no offset), or None when it never ran.
        last_result: LastTaskResult (0 = success, 267009 = still running).
    """

    last_run: str | None
    last_result: int | None


# Task Scheduler's "never": LastRunTime of a task that never ran is 1999-11-30, NextRunTime of a
# task with no next run 1899-12-30 (both read on a test guest); no real run predates 2000.
_TASK_TIME_FLOOR = 2000


def task_time(value: object) -> str | None:
    """Render a Task Scheduler COM time as local wall-clock ISO text, or None for "never".

    pywin32 labels these times UTC, but they are the guest's local wall time (the never-run date
    reads 00:00 both through pywin32 and in PowerShell's local view on a test guest), so the false offset
    is dropped rather than converted.

    Args:
        value: ``LastRunTime`` / ``NextRunTime`` as pywin32 returns it.

    Returns:
        For example ``2026-10-21T19:57:06``; None for the never sentinels or a missing value.
    """
    if not isinstance(value, datetime) or value.year < _TASK_TIME_FLOOR:
        return None
    return value.replace(tzinfo=None).isoformat(timespec="seconds")


class ProbeHost(Protocol):
    """The Windows reads the probes need. Every method raises when it cannot read."""

    def registry(self, key: str) -> Iterable[RegistryValue]:
        """Return the values under a registry key (Get-ItemProperty)."""
        ...

    def win_events(self, log_name: str) -> Iterable[EventLogEntry]:
        """Return the events of a log, newest first, read lazily (Get-WinEvent).

        ``message`` is the provider-rendered text, or None when it could not be rendered;
        never an error string in its place.
        """
        ...

    def cim(self, class_name: str, *, where: str | None = None) -> Iterable[CimInstance]:
        """CIM instances of a class (Get-CimInstance)."""
        ...

    def processes(self) -> Iterable[ProcessInfo]:
        """Return the running processes, names without ``.exe`` (Get-Process)."""
        ...

    def services(self) -> Iterable[ServiceInfo]:
        """Installed services (Get-Service)."""
        ...

    def scheduled_tasks(self) -> Iterable[ScheduledTaskInfo]:
        """Every scheduled task in every folder (Get-ScheduledTask)."""
        ...

    def task_run_info(self, task: ScheduledTaskInfo) -> TaskRunInfo:
        """Last run time and result of one task (Get-ScheduledTaskInfo)."""
        ...

    def exec(self, argv: Sequence[str], *, timeout: float) -> ProcessResult:
        """Run a program without a shell; raises on timeout or a missing executable."""
        ...

    def computer_name(self) -> str:
        """Return the machine name ($env:COMPUTERNAME)."""
        ...


class PwshpyHost:
    """The real :class:`ProbeHost`: pwshpy's native Windows bindings."""

    def __init__(self, event_api: EvtApi | None = None) -> None:
        """Bind the host; ``event_api`` replaces pywin32's event-log binding (tests only).

        Args:
            event_api: The event-log binding, or None for the real one (loaded on first read).
        """
        self._event_api = event_api

    def registry(self, key: str) -> Iterable[RegistryValue]:
        """See :meth:`ProbeHost.registry`."""
        return ps.get_item_property(key)

    def win_events(self, log_name: str) -> Iterable[EventLogEntry]:
        """See :meth:`ProbeHost.win_events`.

        Not ``ps.get_win_event``: pwshpy 1.5.0 formats messages without the provider's metadata
        and swallows the failure, so every Setup message came back as a Win32 error string and
        detect-lp-defect could never match (see ``evtlog.py``).
        """
        return iter_events(log_name, api=self._event_api)

    def cim(self, class_name: str, *, where: str | None = None) -> Iterable[CimInstance]:
        """See :meth:`ProbeHost.cim`."""
        return ps.get_cim_instance(class_name, where=where)

    def processes(self) -> Iterable[ProcessInfo]:
        """See :meth:`ProbeHost.processes`."""
        return ps.get_process()

    def services(self) -> Iterable[ServiceInfo]:
        """See :meth:`ProbeHost.services`."""
        return ps.get_service()

    def scheduled_tasks(self) -> Iterable[ScheduledTaskInfo]:
        """See :meth:`ProbeHost.scheduled_tasks`."""
        return ps.get_scheduled_task()

    def task_run_info(self, task: ScheduledTaskInfo) -> TaskRunInfo:
        """See :meth:`ProbeHost.task_run_info`.

        pwshpy 1.5.0's ScheduledTaskInfo has no LastRunTime / LastTaskResult (filed in pwshpy's
        OPEN-WORK.md), so this asks the Task Scheduler COM API directly, as pwshpy itself does.
        """
        # import_module, not an import statement: pywin32 is a Windows-only dependency of pwshpy
        # that the Linux dev host does not install, and this line only ever runs on the guest.
        client: Any = importlib.import_module("win32com.client")
        scheduler = client.Dispatch("Schedule.Service")
        scheduler.Connect()
        folder = scheduler.GetFolder(task.task_path.rstrip("\\") or "\\")
        registered = folder.GetTask(task.task_name)
        return TaskRunInfo(last_run=task_time(registered.LastRunTime), last_result=int(registered.LastTaskResult))

    def exec(self, argv: Sequence[str], *, timeout: float) -> ProcessResult:
        """See :meth:`ProbeHost.exec`."""
        return ps.exec(list(argv), timeout=timeout)

    def computer_name(self) -> str:
        """See :meth:`ProbeHost.computer_name`."""
        return os.environ.get("COMPUTERNAME") or socket.gethostname()


# --- registry and build ---------------------------------------------------------------------


@dataclass(frozen=True)
class BuildInfo:
    """The guest's OS build.

    Attributes:
        current_build: CurrentBuild (REG_SZ, e.g. "26200").
        ubr: UBR as a decimal integer (``reg query`` prints it as hex, which a decimal comparison misreads).
        build: "<current_build>.<ubr>".
    """

    current_build: str
    ubr: int
    build: str


def _values(host: ProbeHost, key: str) -> dict[str, object]:
    """All values under ``key`` as name -> data."""
    return {value.name: value.data for value in host.registry(key)}


def build_info(values: Mapping[str, object]) -> BuildInfo:
    """Extract CurrentBuild and UBR from the CurrentVersion values.

    Raises:
        ProbeError: Either value is missing or has the wrong type.
    """
    current, ubr = values.get("CurrentBuild"), values.get("UBR")
    if not isinstance(current, str) or not current.strip():
        raise ProbeError(f"CurrentBuild is missing or not text: {current!r}")
    if not isinstance(ubr, int) or isinstance(ubr, bool):
        raise ProbeError(f"UBR is missing or not a DWORD: {ubr!r}")
    return BuildInfo(current_build=current.strip(), ubr=ubr, build=f"{current.strip()}.{ubr}")


def _run_build(host: ProbeHost) -> Outcome:
    return Outcome(ok=True, data=build_info(_values(host, CURRENT_VERSION_KEY)))


# --- detect-lp-defect -----------------------------------------------------------------------


@dataclass(frozen=True)
class LpDefectReport:
    r"""The orphaned-language-pack verdict for one guest.

    Attributes:
        host: Computer name.
        current_build: CurrentBuild.
        ubr: UBR, or None when absent.
        build: "<current_build>.<ubr>", or None when either is missing.
        display_version: DisplayVersion (e.g. "25H2"), or None.
        install_language: Nls\Language InstallLanguage (e.g. "0407"), or None if unreadable.
        lp_absent_events: Matching Setup events among the newest 600, or None when the verdict
            is UNKNOWN (a count there would read like an answer).
        events_read: Setup events read (at most 600), or None if the log was unreadable.
        events_unrendered: Of those, events whose message could not be rendered, or None.
        codes: The distinct HRESULTs in those events, first seen first.
        last: The newest matching event's time (ISO), or None.
        verdict: AFFECTED, CLEAN, or UNKNOWN (log unreadable, empty, or messages unrendered).
        reason: Why the verdict is UNKNOWN, else None.
    """

    host: str
    current_build: str | None
    ubr: int | None
    build: str | None
    display_version: str | None
    install_language: str | None
    lp_absent_events: int | None
    events_read: int | None
    events_unrendered: int | None
    codes: tuple[str, ...]
    last: str | None
    verdict: str
    reason: str | None


@dataclass(frozen=True)
class SetupScan:
    """What the newest Setup events showed.

    Attributes:
        read: Events read.
        unrendered: Events whose message was None or blank (could not be rendered).
        hits: The language-pack-to-Absent events, newest first.
    """

    read: int
    unrendered: int
    hits: tuple[EventLogEntry, ...]


def is_lp_absent_event(message: str | None) -> bool:
    """Tell whether a Setup event is about a language pack failing its transition to Absent.

    Keyed on the failing OPERATION, never an error code: the same defect reads 0x800736B3 at
    Execute and 0x80071A2D at Resolve, so a code filter calls affected machines healthy. The
    match is case-insensitive, like PowerShell's ``-match``.
    """
    text = (message or "").casefold()
    return "language pack" in text and "absent" in text


def scan_setup_events(events: Iterable[EventLogEntry], limit: int = SETUP_LOG_EVENTS) -> SetupScan:
    """Scan the newest ``limit`` events (the stream is newest first) for the defect.

    An event without a rendered message is counted, not silently treated as "no match": an
    unrendered message hides whether it was a hit.
    """
    read, unrendered, hits = 0, 0, list[EventLogEntry]()
    for event in itertools.islice(events, limit):
        read += 1
        if not event.message or not event.message.strip():
            unrendered += 1
        elif is_lp_absent_event(event.message):
            hits.append(event)
    return SetupScan(read=read, unrendered=unrendered, hits=tuple(hits))


def hresults(hits: Iterable[EventLogEntry]) -> tuple[str, ...]:
    """Return the first HRESULT of each hit, de-duplicated in first-seen order."""
    found = (_HRESULT.search(hit.message or "") for hit in hits)
    return tuple(dict.fromkeys(match.group(1) for match in found if match))


def newest_time(hits: Iterable[EventLogEntry]) -> str | None:
    """Return the newest TimeCreated among the hits, as ISO text."""
    times = [hit.time_created for hit in hits if hit.time_created is not None]
    newest: datetime | None = max(times, default=None)
    return newest.isoformat() if newest else None


def _scan_setup_log(host: ProbeHost, skipped: list[Skip]) -> SetupScan | None:
    """Scan the Setup log, or return None (with a Skip) when the log cannot be read."""
    try:
        return scan_setup_events(host.win_events("Setup"))
    except PwshPyError as exc:
        # An unreadable log is never "0 events": that would report it as clean.
        skipped.append(Skip("Setup event log", str(exc)))
        return None


def _install_language(host: ProbeHost, skipped: list[Skip]) -> str | None:
    try:
        language = _values(host, NLS_LANGUAGE_KEY).get("InstallLanguage")
    except PwshPyError as exc:
        skipped.append(Skip(NLS_LANGUAGE_KEY, str(exc)))
        return None
    return language if isinstance(language, str) else None


def lp_verdict(scan: SetupScan | None) -> tuple[str, str | None]:
    """Return the verdict and, for UNKNOWN, the reason.

    AFFECTED when any event matched, even if others were unrendered (a hit is a hit). CLEAN only
    when at least one event was read, every event read had a rendered message, and none matched.
    UNKNOWN when the log was unreadable, held no events, or any message was unrendered: counting
    an unrendered message as a non-match would read an unrendered log as a confident CLEAN, and an
    in-place upgrade starts a fresh, empty Setup log, where CLEAN would be an absence, not evidence.

    A Win32 error string in place of a message cannot be told from event text here (pwshpy
    1.5.0 produced three different ones on one guest), so keeping those out is the adapter's
    job: ``evtlog`` reports a message it cannot format as None.
    """
    if scan is None:
        return "UNKNOWN", "the Setup event log could not be read"
    if scan.hits:
        return "AFFECTED", None
    if scan.read == 0:
        return "UNKNOWN", "the Setup log holds no events (fresh after an upgrade): no evidence either way"
    if scan.unrendered:
        return "UNKNOWN", f"{scan.unrendered} of {scan.read} Setup event messages could not be rendered"
    return "CLEAN", None


def _run_detect_lp_defect(host: ProbeHost) -> Outcome:
    values = _values(host, CURRENT_VERSION_KEY)
    skipped: list[Skip] = []
    language = _install_language(host, skipped)
    scan = _scan_setup_log(host, skipped)
    verdict, reason = lp_verdict(scan)
    hits = scan.hits if scan else ()
    current, ubr, display = values.get("CurrentBuild"), values.get("UBR"), values.get("DisplayVersion")
    current_build = current if isinstance(current, str) else None
    ubr_value = ubr if isinstance(ubr, int) else None
    report = LpDefectReport(
        host=host.computer_name(),
        current_build=current_build,
        ubr=ubr_value,
        build=f"{current_build}.{ubr_value}" if current_build and ubr_value is not None else None,
        display_version=display if isinstance(display, str) else None,
        install_language=language,
        lp_absent_events=None if verdict == "UNKNOWN" else len(hits),
        events_read=scan.read if scan else None,
        events_unrendered=scan.unrendered if scan else None,
        codes=hresults(hits),
        last=newest_time(hits),
        verdict=verdict,
        reason=reason,
    )
    return Outcome(ok=report.verdict != "UNKNOWN", data=report, skipped=tuple(skipped))


# --- drives ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class Drive:
    """A fixed drive with a letter.

    Attributes:
        letter: The drive letter without a colon.
        free_bytes: Free space in bytes (exact; gate on this).
        size_bytes: Capacity in bytes.
        free_gb: Free space in GiB rounded to one decimal, for reading only (gate on free_bytes).
    """

    letter: str
    free_bytes: int
    size_bytes: int
    free_gb: float


def _byte_count(value: object) -> int | None:
    """A WMI uint64 (reported as a string) as an int; None when it is absent or not a number."""
    text = str(value) if value is not None else ""
    return int(text) if re.fullmatch(r"[0-9]{1,20}", text) else None


def drive_from_cim(disk: CimInstance) -> Drive | None:
    """One Win32_LogicalDisk as a Drive, or None without a letter or a numeric free-space figure.

    A size that is not a number reads as 0: it is informational, the free bytes are the gate.
    """
    device, free, size = (disk.properties.get(name) for name in ("DeviceID", "FreeSpace", "Size"))
    free_bytes = _byte_count(free)
    if not isinstance(device, str) or free_bytes is None:
        return None
    return Drive(
        letter=device.rstrip(":").upper(),
        free_bytes=free_bytes,
        size_bytes=_byte_count(size) or 0,
        free_gb=round(free_bytes / _GB, 1),
    )


def fixed_drives(disks: Iterable[CimInstance]) -> tuple[tuple[Drive, ...], tuple[Skip, ...]]:
    """Every disk parsed once: the drives sorted by letter, and a Skip per disk that is not one.

    One odd volume (no letter, a free-space figure that is not a number) is skipped, never a
    reason to fail the whole reading.
    """
    drives: list[Drive] = []
    skips: list[Skip] = []
    for disk in disks:
        drive = drive_from_cim(disk)
        if drive is None:
            skips.append(Skip(str(disk.properties.get("DeviceID")), "no letter or no numeric free-space figure"))
        else:
            drives.append(drive)
    return tuple(sorted(drives, key=lambda d: d.letter)), tuple(skips)


@dataclass(frozen=True)
class DriveReport:
    """Every fixed drive, sorted by letter."""

    drives: tuple[Drive, ...]


def _run_drives(host: ProbeHost) -> Outcome:
    disks = list(host.cim("Win32_LogicalDisk", where="DriveType=3"))
    drives, skipped = fixed_drives(disks)
    if not drives:
        raise ProbeError(f"no fixed drive with a letter and a free-space figure ({len(disks)} disks seen)")
    return Outcome(ok=True, data=DriveReport(drives=drives), skipped=skipped)


# --- verify-runners -------------------------------------------------------------------------


@dataclass(frozen=True)
class TaskReport:
    """One boot task the runners depend on."""

    name: str
    present: bool
    task_path: str | None
    state: str | None
    enabled: bool | None
    last_run: str | None
    last_result: int | None


@dataclass(frozen=True)
class Container:
    """One running container from ``docker ps``."""

    name: str
    status: str


@dataclass(frozen=True)
class RunnerReport:
    """Did the runner containers and their boot tasks come back after a reboot.

    Attributes:
        tasks: The boot tasks named on the command line, in that order (empty when none were named).
        docker_service: The docker service status, or None when it is not installed.
        dockerd_processes: Running dockerd processes.
        containers: The running containers, or None when they could not be enumerated.
        count: len(containers), or None when they could not be enumerated (never 0 then).
        expected: The count that means OK.
        verdict: OK, SHORT or UNKNOWN.
    """

    tasks: tuple[TaskReport, ...]
    docker_service: str | None
    dockerd_processes: int
    containers: tuple[Container, ...] | None
    count: int | None
    expected: int
    verdict: str


def runner_verdict(count: int | None, expected: int) -> str:
    """OK at or above ``expected``, SHORT below it, UNKNOWN when the count is unknown."""
    if count is None:
        return "UNKNOWN"
    return "OK" if count >= expected else "SHORT"


def parse_containers(stdout: str) -> tuple[Container, ...]:
    """Containers from ``docker ps --format "{{json .}}"``, one JSON object per line.

    A line that is not a JSON object (a warning, a blank) is not a container.
    """
    containers: list[Container] = []
    for line in stdout.splitlines():
        try:
            row: object = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            fields = cast("dict[str, object]", row)  # json.loads gives str keys
            containers.append(Container(name=str(fields.get("Names", "")), status=str(fields.get("Status", ""))))
    return tuple(containers)


def _containers(host: ProbeHost, skipped: list[Skip]) -> tuple[Container, ...] | None:
    """Return the running containers, or None (with a Skip) when docker could not be asked."""
    try:
        result = host.exec(["docker", "ps", "--format", "{{json .}}"], timeout=DOCKER_PS_TIMEOUT)
    except PwshPyError as exc:  # timeout or no docker CLI: cannot count, which is not zero
        skipped.append(Skip("docker ps", str(exc)))
        return None
    if result.exit_code != 0:
        skipped.append(Skip("docker ps", f"exit {result.exit_code}: {result.stderr.strip()[:300]}"))
        return None
    return parse_containers(result.stdout)


def _task_report(host: ProbeHost, name: str, tasks: Sequence[ScheduledTaskInfo], skipped: list[Skip]) -> TaskReport:
    task = next((t for t in tasks if t.task_name.casefold() == name.casefold()), None)
    if task is None:
        return TaskReport(
            name=name, present=False, task_path=None, state=None, enabled=None, last_run=None, last_result=None
        )
    try:
        run = host.task_run_info(task)
    except Exception as exc:  # diagnostics only (pywin32 COM raises its own com_error), never the gate
        skipped.append(Skip(f"{name} run info", str(exc)))
        run = TaskRunInfo(None, None)
    return TaskReport(
        name=name,
        present=True,
        task_path=task.task_path,
        state=str(task.state.value),
        enabled=task.enabled,
        last_run=run.last_run,
        last_result=run.last_result,
    )


def count_processes(processes: Iterable[ProcessInfo], names: Sequence[str]) -> dict[str, int]:
    """How many processes run under each name, matched case-insensitively like Get-Process."""
    wanted = {name.casefold(): name for name in names}
    counts = dict.fromkeys(names, 0)
    for process in processes:
        name = wanted.get(process.name.casefold())
        if name is not None:
            counts[name] += 1
    return counts


def _docker_service(host: ProbeHost) -> str | None:
    service = next((s for s in host.services() if s.name.casefold() == "docker"), None)
    return str(service.status.value) if service else None


def _run_verify_runners(host: ProbeHost, expected: int, names: Sequence[str]) -> Outcome:
    skipped: list[Skip] = []
    tasks = list(host.scheduled_tasks())
    containers = _containers(host, skipped)
    count = None if containers is None else len(containers)
    report = RunnerReport(
        tasks=tuple(_task_report(host, name, tasks, skipped) for name in names),
        docker_service=_docker_service(host),
        dockerd_processes=count_processes(host.processes(), ("dockerd",))["dockerd"],
        containers=containers,
        count=count,
        expected=expected,
        verdict=runner_verdict(count, expected),
    )
    return Outcome(ok=report.verdict == "OK", data=report, skipped=tuple(skipped))


def _non_negative_int(text: str) -> int:
    """Argparse type for a count: ASCII digits only."""
    if not re.fullmatch(r"[0-9]{1,6}", text):
        raise argparse.ArgumentTypeError(f"not a non-negative count: {text!r}")
    return int(text)


def _task_name(text: str) -> str:
    """Argparse type for a scheduled task name: letters, digits and ``_ . -`` only."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", text):
        raise argparse.ArgumentTypeError(f"not a task name: {text!r}")
    return text


def _configure_verify_runners(parser: argparse.ArgumentParser) -> None:
    # default None, not []: argparse appends into a list default and would share it across parses.
    parser.add_argument(
        "--task",
        dest="tasks",
        type=_task_name,
        action="append",
        default=None,
        help="a boot task to check (repeatable; none = no task check)",
    )
    parser.add_argument(
        "--expected",
        type=_non_negative_int,
        default=0,
        help="containers that mean OK (default 0: any readable count)",
    )


# --- servicing-active / setup-alive ---------------------------------------------------------


@dataclass(frozen=True)
class ServicingReport:
    """Is a CBS transaction in flight (TiWorker / TrustedInstaller running)."""

    counts: Mapping[str, int]
    total: int
    active: bool


@dataclass(frozen=True)
class SetupReport:
    """Is the down-level setup still running (SetupHost)."""

    count: int
    alive: bool


def _run_servicing_active(host: ProbeHost) -> Outcome:
    counts = count_processes(host.processes(), SERVICING_PROCESSES)
    total = sum(counts.values())
    return Outcome(ok=True, data=ServicingReport(counts=counts, total=total, active=total > 0))


def _run_setup_alive(host: ProbeHost) -> Outcome:
    count = sum(count_processes(host.processes(), SETUP_PROCESSES).values())
    return Outcome(ok=True, data=SetupReport(count=count, alive=count > 0))


# --- staged-os ------------------------------------------------------------------------------


@dataclass(frozen=True)
class StagedOs:
    """Is the staged NewOS still there (REARMABLE) or did a rollback delete it (RERUN)."""

    path: str
    present: bool
    verdict: str


def staged_os(path: str | os.PathLike[str]) -> StagedOs:
    """Check for the staged NewOS boot loader.

    Raises:
        OSError: The path exists but cannot be examined; an unknown state is not "absent".
    """
    try:
        Path(path).stat()
    except (FileNotFoundError, NotADirectoryError):
        return StagedOs(path=os.fspath(path), present=False, verdict="RERUN")
    return StagedOs(path=os.fspath(path), present=True, verdict="REARMABLE")


# --- state ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class StateLog:
    """The upgrade run's state log and the completion marker it carries.

    Attributes:
        path: The log path.
        present: False when the file does not exist yet.
        verdict: DONE-OK or DONE-FAIL from the LAST marker line, or None while running.
        marker: That marker line, or None.
        line_count: Non-blank lines in the log.
        tail: The last 200 lines.
    """

    path: str
    present: bool
    verdict: str | None
    marker: str | None
    line_count: int
    tail: tuple[str, ...]


def decode_state(raw: bytes) -> str:
    """Decode the state log, tolerating a BOM and a UTF-16 tail after an ASCII header.

    A log appended through PowerShell's ``Tee-Object`` has exactly that mix, which reads as
    "D O N E"; dropping the NUL bytes recovers the ASCII marker either way.
    """
    if raw.startswith(codecs.BOM_UTF16_LE):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace").replace("\x00", "")


def state_verdict(lines: Sequence[str]) -> tuple[str | None, str | None]:
    """Return the verdict and line of the LAST marker; (None, None) while still running."""
    for line in reversed(lines):
        for marker in STATE_MARKERS:
            if marker in line:
                return marker.removeprefix("STATE="), line
    return None, None


def read_state(path: str | os.PathLike[str]) -> StateLog:
    """Read the state log.

    Raises:
        OSError: The file exists but cannot be read; a failed read is not an absent marker.
    """
    try:
        raw = Path(path).read_bytes()
    except FileNotFoundError:
        return StateLog(path=os.fspath(path), present=False, verdict=None, marker=None, line_count=0, tail=())
    lines = [line.rstrip("\r") for line in decode_state(raw).split("\n") if line.strip()]
    verdict, marker = state_verdict(lines)
    return StateLog(
        path=os.fspath(path),
        present=True,
        verdict=verdict,
        marker=marker,
        line_count=len(lines),
        tail=tuple(lines[-STATE_TAIL_LINES:]),
    )


def _configure_state(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--log", default=DEFAULT_STATE_LOG, help=f"the state log to read (default {DEFAULT_STATE_LOG})")


# --- registration ---------------------------------------------------------------------------


def commands(
    host_factory: Callable[[], ProbeHost] = PwshpyHost, *, staged_os_path: str = NEWOS_WINLOAD
) -> tuple[Command, ...]:
    """Build the probe subcommands; each builds its host only when it runs.

    Args:
        host_factory: Builds the :class:`ProbeHost`; tests pass a fake.
        staged_os_path: The file ``staged-os`` checks; tests pass one under a temporary dir.

    Returns:
        The commands for the entry's command table.
    """
    return (
        Command(
            "detect-lp-defect",
            "is this guest affected by the orphaned language pack",
            lambda _a: _run_detect_lp_defect(host_factory()),
        ),
        Command("drives", "free space per fixed drive", lambda _a: _run_drives(host_factory())),
        Command(
            "verify-runners",
            "did the runner containers and their boot tasks come back after a reboot",
            lambda a: _run_verify_runners(host_factory(), a.expected, tuple(a.tasks or ())),
            _configure_verify_runners,
        ),
        Command("build", "CurrentBuild and UBR", lambda _a: _run_build(host_factory())),
        Command(
            "staged-os",
            "is the staged NewOS still present",
            lambda _a: Outcome(ok=True, data=staged_os(staged_os_path)),
        ),
        Command(
            "servicing-active",
            "is TiWorker / TrustedInstaller running",
            lambda _a: _run_servicing_active(host_factory()),
        ),
        Command("setup-alive", "is SetupHost running", lambda _a: _run_setup_alive(host_factory())),
        Command(
            "state",
            "the upgrade state log and its completion marker",
            lambda a: Outcome(ok=True, data=read_state(a.log)),
            _configure_state,
        ),
    )
