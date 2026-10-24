"""Hold Windows Update out of the servicing stack during the upgrade, and let it back in after.

Each step reaches Windows only through the :class:`WuHost` port; :class:`PwshpyHost` is the real
adapter. The verdicts are plain functions.

Why the quiesce works the way it does (all measured on test guests):

* Stopping is not enough: UsoSvc and BITS start Automatic, so the service control manager brings
  them straight back. On one guest Windows Update restarted 35 minutes into the upgrade, ran
  KB5101650 against the still broken store and blocked the apply reboot.
* Set-Service is not enough either: wuauserv refuses it (one guest reported success and stayed
  Manual/Running), and WaaSMedicSvc exists to revert Windows Update changes. So the Start value is
  written in the REGISTRY.
* Nothing may block: on one guest ``Stop-Service -Force`` never returned because wuauserv sat in Stop
  Pending, and the driver killed the step at its 600 s timeout. So: registry first (cannot hang),
  then ``ps.stop_service(wait=False)``, which only ISSUES the stop (one ControlService; a service
  already in Stop Pending gets none) and returns the state right after it, then a BOUNDED poll.

Contents:
    * :func:`commands` - quiesce-wu and restore-wu for the entry's command table.
    * :class:`WuHost`, :class:`PwshpyHost` - the OS port and its adapter.
    * :func:`search_probe` - the abandonable Windows Update search (pwshpy's ``get_windows_update``).
    * the pure verdict helpers and their records.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from enum import Enum, IntEnum
from typing import TYPE_CHECKING, Protocol

from pwshpy import (
    CimInstance,
    OperationTimeoutError,
    PwshPyError,
    RegistryValue,
    RegistryValueType,
    ServiceState,
    ps,
)

from pve_winrepair_guest.envelope import Command, Outcome, Report

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence

    from pwshpy import ServiceInfo, WindowsUpdate

__all__ = [
    "RESTORE_START",
    "TARGETS",
    "PwshpyHost",
    "QuiesceReport",
    "QuiesceVerdict",
    "RestoreReport",
    "RestoreVerdict",
    "SearchProbe",
    "SearchStatus",
    "ServiceRow",
    "ServiceStart",
    "StartMode",
    "StartWrite",
    "StopIssued",
    "StopWait",
    "WmiServiceState",
    "WriteResult",
    "WuHost",
    "commands",
    "quiesce_verdict",
    "read_services",
    "restore_verdict",
    "search_probe",
    "wait_until_stopped",
]


class ServiceStart(IntEnum):
    """A service's registry ``Start`` value (the DWORD the service control manager reads)."""

    AUTOMATIC = 2
    MANUAL = 3
    DISABLED = 4


TARGETS = ("wuauserv", "UsoSvc", "BITS", "WaaSMedicSvc")
# The modes measured on test guests BEFORE quiescing (wuauserv Manual, UsoSvc Auto, BITS Auto);
# WaaSMedicSvc ships Manual.
RESTORE_START = (
    ("wuauserv", ServiceStart.MANUAL),
    ("UsoSvc", ServiceStart.AUTOMATIC),
    ("BITS", ServiceStart.AUTOMATIC),
    ("WaaSMedicSvc", ServiceStart.MANUAL),
)
SERVICES_KEY = r"HKLM\SYSTEM\CurrentControlSet\Services"
STOP_WAIT = 180.0
STOP_POLL = 10.0
SEARCH_TIMEOUT = 180.0
SEARCH_CRITERIA = "IsInstalled=0 and Type='Software'"
_WHERE = " OR ".join(f"Name='{name}'" for name in TARGETS)


# --- port and adapter -----------------------------------------------------------------------


class SearchStatus(str, Enum):
    """How the bounded Windows Update search ended."""

    OK = "OK"
    FAILED = "FAILED"
    # Abandoned after its bound: says nothing about Windows Update either way.
    TIMEOUT = "TIMEOUT"


class SearchProbe(Report):
    """Can Windows Update search again (informational; never part of a verdict).

    Attributes:
        status: OK (the search finished), FAILED (it raised or its worker died), or TIMEOUT
            (abandoned after ``timeout_s``: NOT a verdict either way).
        pending: Updates the search found, or None unless OK.
        titles: Their titles.
        error: Why it FAILED, else None.
        timeout_s: The bound the search ran under.
    """

    status: SearchStatus
    pending: int | None
    titles: tuple[str, ...]
    error: str | None
    timeout_s: float


class WuHost(Protocol):
    """The Windows calls quiesce-wu and restore-wu need."""

    def cim(self, class_name: str, *, where: str | None = None) -> Iterable[CimInstance]:
        """CIM instances of a class (Get-CimInstance); raises when WMI cannot be asked."""
        ...

    def registry(self, key: str) -> Iterable[RegistryValue]:
        """Return the values under a key; raises when the key cannot be read (or does not exist)."""
        ...

    def set_dword(self, key: str, name: str, value: int) -> None:
        """Write a REG_DWORD value; raises when it cannot be written."""
        ...

    def stop_service(self, name: str) -> ServiceInfo:
        """Issue a stop and return the service's state right after it, without waiting for Stopped.

        Raises a pwshpy error when the service cannot be opened or refuses the control.
        """
        ...

    def monotonic(self) -> float:
        """Return a monotonic clock reading in seconds."""
        ...

    def sleep(self, seconds: float) -> None:
        """Wait ``seconds``."""
        ...

    def search_updates(self, timeout: float) -> SearchProbe:
        """Run the Windows Update search, abandoned after ``timeout`` seconds."""
        ...


class PwshpyHost:
    """The real :class:`WuHost`: pwshpy's native bindings."""

    def cim(self, class_name: str, *, where: str | None = None) -> Iterable[CimInstance]:
        """See :meth:`WuHost.cim`."""
        return ps.get_cim_instance(class_name, where=where)

    def registry(self, key: str) -> Iterable[RegistryValue]:
        """See :meth:`WuHost.registry`."""
        return ps.get_item_property(key)

    def set_dword(self, key: str, name: str, value: int) -> None:
        """See :meth:`WuHost.set_dword`."""
        ps.set_item_property(key, name, value, RegistryValueType.REG_DWORD)

    def stop_service(self, name: str) -> ServiceInfo:
        """See :meth:`WuHost.stop_service`.

        ControlService itself returns once the service acknowledged the control; the service
        control manager bounds a handler that never answers (ERROR_SERVICE_REQUEST_TIMEOUT).
        """
        return ps.stop_service(name, wait=False)

    def monotonic(self) -> float:
        """See :meth:`WuHost.monotonic`."""
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        """See :meth:`WuHost.sleep`."""
        time.sleep(seconds)

    def search_updates(self, timeout: float) -> SearchProbe:
        """See :meth:`WuHost.search_updates`.

        pwshpy runs the search in a ``spawn`` child it kills after ``timeout``, so the entry
        script needs its ``if __name__ == "__main__":`` guard (the child re-imports it).
        """
        return search_probe(
            lambda: ps.get_windows_update(criteria=SEARCH_CRITERIA, timeout=timeout).to_list(), timeout=timeout
        )


# --- the bounded search ---------------------------------------------------------------------


def search_probe(search: Callable[[], Iterable[WindowsUpdate]], *, timeout: float) -> SearchProbe:
    """Run a Windows Update search and map how it ended to a :class:`SearchProbe`.

    Why a killable child process and not a thread (pwshpy's ``get_windows_update`` does this): the
    search is one synchronous COM call that cannot be interrupted in-process, and after an
    in-place upgrade it runs against an EMPTY datastore (measured on a freshly upgraded guest: 25+
    minutes, worker CPU flat, which hung the calling unit long after the repair was proven).

    A TIMEOUT stays a TIMEOUT: it says nothing about Windows Update either way, so it must never
    be reported as success or as a failure of Windows Update.

    Args:
        search: Runs the search and returns its updates; raises a pwshpy error when it cannot.
        timeout: The bound the search runs under, reported in the probe.

    Returns:
        OK with the count and titles, TIMEOUT (abandoned), or FAILED with the error.
    """
    try:
        updates = list(search())
    except OperationTimeoutError:  # a NativeCallError subclass, so it must be caught first
        return SearchProbe(status=SearchStatus.TIMEOUT, pending=None, titles=(), error=None, timeout_s=timeout)
    except PwshPyError as exc:
        return SearchProbe(status=SearchStatus.FAILED, pending=None, titles=(), error=str(exc), timeout_s=timeout)
    titles = tuple(update.title for update in updates)
    return SearchProbe(status=SearchStatus.OK, pending=len(updates), titles=titles, error=None, timeout_s=timeout)


# --- service state and verdicts -------------------------------------------------------------


class StartMode(str, Enum):
    """Win32_Service.StartMode, English in every locale."""

    BOOT = "Boot"
    SYSTEM = "System"
    AUTO = "Auto"
    MANUAL = "Manual"
    DISABLED = "Disabled"
    # WMI reported no StartMode; the envelope has always carried that as the text "None".
    NOT_REPORTED = "None"


class WmiServiceState(str, Enum):
    """Win32_Service.State, English in every locale (spelt apart, unlike Get-Service's ServiceState)."""

    STOPPED = "Stopped"
    START_PENDING = "Start Pending"
    STOP_PENDING = "Stop Pending"
    RUNNING = "Running"
    CONTINUE_PENDING = "Continue Pending"
    PAUSE_PENDING = "Pause Pending"
    PAUSED = "Paused"
    UNKNOWN = "Unknown"
    # WMI reported no State; the envelope has always carried that as the text "None".
    NOT_REPORTED = "None"


class ServiceRow(Report):
    """One target service as WMI reports it."""

    name: str
    start_mode: StartMode
    state: WmiServiceState


class WriteResult(str, Enum):
    """How one registry Start write ended."""

    WRITTEN = "WRITTEN"
    # The service key could not be read (the service is not installed): nothing was written.
    ABSENT = "ABSENT"
    FAILED = "FAILED"


class StartWrite(Report):
    """The registry Start write for one service.

    Attributes:
        service: The service name.
        value: The Start value written (2 Automatic, 3 Manual, 4 Disabled).
        result: WRITTEN, ABSENT (its key could not be read, so nothing was written), or FAILED.
        error: The error for ABSENT / FAILED, else None.
    """

    service: str
    value: ServiceStart
    result: WriteResult
    error: str | None


class StopIssued(Report):
    """One issued stop: the service's state right after it, or the error when it was refused.

    Attributes:
        service: The service name.
        state: Get-Service's Status right after the control (typically StopPending; Stopped when it
            was not running), or None when the stop could not be issued.
        error: Why the stop could not be issued, else None.
    """

    service: str
    state: ServiceState | None
    error: str | None


class StopWait(Report):
    """The bounded wait for the services to leave the Running state."""

    waited_s: float
    timed_out: bool
    still_running: tuple[str, ...]


def _service_row(instance: CimInstance) -> ServiceRow:
    """One Win32_Service instance as a row; a missing property reads as its NOT_REPORTED member.

    Raises:
        ValueError: StartMode or State holds a value Win32_Service does not document.
    """
    properties = instance.properties
    # str() of an absent property is "None", the value of each enum's NOT_REPORTED member.
    return ServiceRow(
        name=str(properties.get("Name")),
        start_mode=StartMode(str(properties.get("StartMode"))),
        state=WmiServiceState(str(properties.get("State"))),
    )


def read_services(host: WuHost) -> tuple[ServiceRow, ...]:
    """The target services WMI knows, in :data:`TARGETS` order.

    Raises:
        PwshPyError: WMI cannot be asked.
        ValueError: A service reports a StartMode or State Win32_Service does not document.
    """
    rows = {row.name: row for row in map(_service_row, host.cim("Win32_Service", where=_WHERE))}
    return tuple(rows[name] for name in TARGETS if name in rows)


class QuiesceVerdict(str, Enum):
    """quiesce-wu's verdict."""

    OK = "OK"
    FAIL = "FAIL"
    # No target service could be read: an empty reading is not a held state.
    UNKNOWN = "UNKNOWN"


class RestoreVerdict(str, Enum):
    """restore-wu's verdict."""

    RESTORED = "RESTORED"
    STILL_DISABLED = "STILL_DISABLED"
    # No target service could be read.
    UNKNOWN = "UNKNOWN"


def quiesce_verdict(rows: Sequence[ServiceRow]) -> tuple[QuiesceVerdict, tuple[str, ...], tuple[str, ...]]:
    """Judge the held state: (verdict, not_disabled, still_running).

    OK when every service read is Disabled and none is Running; Stop Pending counts as not
    running (it is shutting down and cannot take new work, which is what this step guarantees).
    UNKNOWN when no target service could be read at all: an empty reading is not a held state.
    """
    not_disabled = tuple(r.name for r in rows if r.start_mode is not StartMode.DISABLED)
    still_running = tuple(r.name for r in rows if r.state is WmiServiceState.RUNNING)
    if not rows:
        return QuiesceVerdict.UNKNOWN, not_disabled, still_running
    verdict = QuiesceVerdict.FAIL if not_disabled or still_running else QuiesceVerdict.OK
    return verdict, not_disabled, still_running


def restore_verdict(rows: Sequence[ServiceRow]) -> tuple[RestoreVerdict, tuple[str, ...]]:
    """Judge the restore: (verdict, still_disabled); none may still read Disabled.

    A start type left Disabled survives into the repaired OS and silently stops the machine
    ever patching again.
    """
    still_disabled = tuple(r.name for r in rows if r.start_mode is StartMode.DISABLED)
    if not rows:
        return RestoreVerdict.UNKNOWN, still_disabled
    return (RestoreVerdict.STILL_DISABLED if still_disabled else RestoreVerdict.RESTORED), still_disabled


def wait_until_stopped(
    running: Callable[[], tuple[str, ...]],
    *,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
    limit: float = STOP_WAIT,
    interval: float = STOP_POLL,
) -> StopWait:
    """Poll ``running`` until it is empty or ``limit`` seconds have passed.

    Args:
        running: Returns the services still in the Running state.
        clock: A monotonic clock.
        sleep: Waits between polls.
        limit: The bound: Stop Pending normally clears within it, and a hung stop must not block.
        interval: Seconds between polls.
    """
    started = clock()
    names = running()
    while names and clock() - started < limit:
        sleep(interval)
        names = running()
    return StopWait(waited_s=clock() - started, timed_out=bool(names), still_running=names)


# --- quiesce-wu -----------------------------------------------------------------------------


class QuiesceReport(Report):
    """quiesce-wu's answer.

    Attributes:
        previous_start_modes: StartMode per service BEFORE the change, for restoring by hand.
        writes: The registry Start=4 writes.
        stops: The issued stops.
        wait: The bounded wait for the services to leave Running.
        services: The verified state afterwards.
        not_disabled: Services whose StartMode is not Disabled.
        still_running: Services still Running.
        verdict: OK, FAIL, or UNKNOWN (no target service readable).
    """

    previous_start_modes: Mapping[str, StartMode]
    writes: tuple[StartWrite, ...]
    stops: tuple[StopIssued, ...]
    wait: StopWait
    services: tuple[ServiceRow, ...]
    not_disabled: tuple[str, ...]
    still_running: tuple[str, ...]
    verdict: QuiesceVerdict


def _service_key(service: str) -> str:
    return f"{SERVICES_KEY}\\{service}"


def write_start(host: WuHost, service: str, value: ServiceStart) -> StartWrite:
    """Write one service's Start value; a missing key is ABSENT, a refused write FAILED."""
    try:
        list(host.registry(_service_key(service)))
    except PwshPyError as exc:  # no service key: the service is not installed, nothing to write
        return StartWrite(service=service, value=value, result=WriteResult.ABSENT, error=str(exc))
    try:
        host.set_dword(_service_key(service), "Start", value.value)
    except PwshPyError as exc:
        return StartWrite(service=service, value=value, result=WriteResult.FAILED, error=str(exc))
    return StartWrite(service=service, value=value, result=WriteResult.WRITTEN, error=None)


def issue_stop(host: WuHost, service: str) -> StopIssued:
    """Issue a stop without waiting for Stopped, so it cannot block on Stop Pending."""
    try:
        info = host.stop_service(service)
    except PwshPyError as exc:
        return StopIssued(service=service, state=None, error=str(exc))
    return StopIssued(service=service, state=info.status, error=None)


def _running(host: WuHost) -> tuple[str, ...]:
    return tuple(r.name for r in read_services(host) if r.state is WmiServiceState.RUNNING)


def run_quiesce(host: WuHost) -> Outcome:
    """Disable, stop, wait (bounded), then verify the state - not the fact that commands ran."""
    previous = {r.name: r.start_mode for r in read_services(host)}  # raises before any change
    writes = tuple(write_start(host, name, ServiceStart.DISABLED) for name in TARGETS)
    stops = tuple(issue_stop(host, name) for name in TARGETS)
    wait = wait_until_stopped(lambda: _running(host), clock=host.monotonic, sleep=host.sleep)
    rows = read_services(host)
    verdict, not_disabled, still_running = quiesce_verdict(rows)
    report = QuiesceReport(
        previous_start_modes=previous,
        writes=writes,
        stops=stops,
        wait=wait,
        services=rows,
        not_disabled=not_disabled,
        still_running=still_running,
        verdict=verdict,
    )
    return Outcome(ok=verdict is QuiesceVerdict.OK, data=report)


# --- restore-wu -----------------------------------------------------------------------------


class RestoreReport(Report):
    """restore-wu's answer.

    Attributes:
        writes: The registry Start writes back to the modes in :data:`RESTORE_START`.
        services: The verified state afterwards.
        still_disabled: Services still Disabled (this machine would never patch again).
        verdict: RESTORED, STILL_DISABLED, or UNKNOWN (no target service readable).
        search: The bounded Windows Update search; informational, never part of the verdict.
    """

    writes: tuple[StartWrite, ...]
    services: tuple[ServiceRow, ...]
    still_disabled: tuple[str, ...]
    verdict: RestoreVerdict
    search: SearchProbe


def run_restore(host: WuHost) -> Outcome:
    """Write the defaults back, verify StartMode, then run the bounded search probe."""
    writes = tuple(write_start(host, name, value) for name, value in RESTORE_START)
    rows = read_services(host)
    verdict, still_disabled = restore_verdict(rows)
    search = host.search_updates(SEARCH_TIMEOUT)
    report = RestoreReport(writes=writes, services=rows, still_disabled=still_disabled, verdict=verdict, search=search)
    return Outcome(ok=verdict is RestoreVerdict.RESTORED, data=report)


# --- registration ---------------------------------------------------------------------------


def commands(host_factory: Callable[[], WuHost] = PwshpyHost) -> tuple[Command, ...]:
    """Build quiesce-wu and restore-wu; each builds its host only when it runs.

    Args:
        host_factory: Builds the :class:`WuHost`; tests pass a fake.

    Returns:
        The commands for the entry's command table.
    """
    return (
        Command(
            name="quiesce-wu",
            help="hold Windows Update (Start=4, issue stops, bounded wait) and verify",
            run=lambda _a: run_quiesce(host_factory()),
        ),
        Command(
            name="restore-wu",
            help="restore the Windows Update start modes and probe a bounded search",
            run=lambda _a: run_restore(host_factory()),
        ),
    )
