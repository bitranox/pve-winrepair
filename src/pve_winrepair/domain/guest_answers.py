r"""The guest tool's answers as typed models: one per subcommand, mirroring what the guest serialises.

The guest tool (``pve_winrepair_guest``) puts one payload into the ``data`` of each envelope. Every
model here declares every field of that payload, with the guest's own names and JSON types, and
forbids unknown ones: a field renamed, added or dropped on the guest side then fails validation
(and the contract tests, which build their replies from the guest's real models) instead of
travelling unread or reading as absent. A verdict, status or action the guest reports from a closed
set is an enum here, so an unknown value is refused at the boundary and never compared as text.

Each payload is either a :class:`ProbePayload` (the command never refuses: ``ok`` is always true)
or a :class:`GatedPayload` (its verdict decides ``ok``); :func:`~pve_winrepair.domain.envelope.parse_answer`
checks the envelope's ``ok`` against that rule. Names, paths and error messages stay ``str``, and
so do the task and Get-Service states the guest copies from pwshpy's vocabularies, which the host
never judges and which may grow with pwshpy.

Contents:
    * :class:`GuestCommand` - every subcommand name.
    * the verdict, status and action enums (:class:`StateVerdict` and the rest).
    * :class:`Gate` - the verdict a gated payload's ``ok`` must agree with.
    * the payload models, one ``<Command>Answer`` per subcommand, with their nested parts.
"""

from __future__ import annotations

from abc import abstractmethod
from enum import Enum, IntEnum
from typing import NamedTuple

from pydantic import BaseModel, ConfigDict, model_validator

from pve_winrepair.domain.addresses import MacAddress
from pve_winrepair.domain.enums import DriveLetter

__all__ = [
    "BuildAnswer",
    "ContainerRow",
    "DetectLpDefectAnswer",
    "DirectoryAction",
    "DirectoryLock",
    "DriveSpace",
    "DrivesAnswer",
    "Gate",
    "GatedPayload",
    "GuestCommand",
    "GuestPayload",
    "LaunchAnswer",
    "LaunchVerdict",
    "LaunchWait",
    "LaunchWaitStatus",
    "LockDirsAnswer",
    "LockDirsVerdict",
    "LpVerdict",
    "NicMacsAnswer",
    "PrepareAnswer",
    "PrepareGate",
    "ProbePayload",
    "QuiesceVerdict",
    "QuiesceWuAnswer",
    "RestoreVerdict",
    "RestoreWuAnswer",
    "RunnerVerdict",
    "RunningBuild",
    "ScheduledTaskState",
    "SearchStatus",
    "ServiceRow",
    "ServiceStart",
    "ServicingActiveAnswer",
    "SetupAliveAnswer",
    "StagedOsAnswer",
    "StagedOsVerdict",
    "StartMode",
    "StartWrite",
    "StartWriteResult",
    "StateAnswer",
    "StateVerdict",
    "StopIssued",
    "StopWait",
    "TaskCleanup",
    "TaskCleanupAction",
    "TreeWait",
    "UpdateSearch",
    "UpgradeRunAnswer",
    "VerifyRunnersAnswer",
    "WimImage",
    "WmiServiceState",
]


class GuestCommand(str, Enum):
    """Every subcommand of the guest tool; the value is the name on its command line and in its envelope."""

    DETECT_LP_DEFECT = "detect-lp-defect"
    DRIVES = "drives"
    VERIFY_RUNNERS = "verify-runners"
    BUILD = "build"
    STAGED_OS = "staged-os"
    SERVICING_ACTIVE = "servicing-active"
    SETUP_ALIVE = "setup-alive"
    STATE = "state"
    NIC_MACS = "nic-macs"
    QUIESCE_WU = "quiesce-wu"
    RESTORE_WU = "restore-wu"
    PREPARE = "prepare"
    LOCK_DIRS = "lock-dirs"
    LAUNCH = "launch"
    UPGRADE_RUN = "upgrade-run"


# --- verdicts, statuses and actions -----------------------------------------------------------


class StateVerdict(str, Enum):
    """How an upgrade run ended, from the last marker line of its state log.

    Example:
        >>> StateVerdict.DONE_OK.marker
        'STATE=DONE-OK'
    """

    DONE_OK = "DONE-OK"
    DONE_FAIL = "DONE-FAIL"

    @property
    def marker(self) -> str:
        """The marker line text the guest writes for this verdict; every log reader matches on it."""
        return f"STATE={self.value}"


class LpVerdict(str, Enum):
    """detect-lp-defect: the orphaned language pack's verdict."""

    AFFECTED = "AFFECTED"
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"


class RunnerVerdict(str, Enum):
    """verify-runners: enough runner containers came back, too few, or the count is unknown."""

    OK = "OK"
    SHORT = "SHORT"
    UNKNOWN = "UNKNOWN"


class StagedOsVerdict(str, Enum):
    """staged-os: the staged NewOS is still there (REARMABLE) or a rollback deleted it (RERUN)."""

    REARMABLE = "REARMABLE"
    RERUN = "RERUN"


class QuiesceVerdict(str, Enum):
    """quiesce-wu: Windows Update held, not held, or no target service could be read."""

    OK = "OK"
    FAILED = "FAIL"
    UNKNOWN = "UNKNOWN"


class RestoreVerdict(str, Enum):
    """restore-wu: every start mode restored, some still Disabled, or no target service could be read."""

    RESTORED = "RESTORED"
    STILL_DISABLED = "STILL_DISABLED"
    UNKNOWN = "UNKNOWN"


class StartMode(str, Enum):
    """A service's StartMode as WMI's Win32_Service reports it (English in every locale)."""

    BOOT = "Boot"
    SYSTEM = "System"
    AUTO = "Auto"
    MANUAL = "Manual"
    DISABLED = "Disabled"
    # WMI reported no StartMode for the service.
    NOT_REPORTED = "None"


class WmiServiceState(str, Enum):
    """A service's State as WMI's Win32_Service reports it (English in every locale)."""

    STOPPED = "Stopped"
    START_PENDING = "Start Pending"
    STOP_PENDING = "Stop Pending"
    RUNNING = "Running"
    CONTINUE_PENDING = "Continue Pending"
    PAUSE_PENDING = "Pause Pending"
    PAUSED = "Paused"
    UNKNOWN = "Unknown"
    # WMI reported no State for the service.
    NOT_REPORTED = "None"


class ServiceStart(IntEnum):
    """A registry Start value the guest writes."""

    AUTOMATIC = 2
    MANUAL = 3
    DISABLED = 4


class StartWriteResult(str, Enum):
    """One registry Start write: written, its key absent (nothing written), or refused."""

    WRITTEN = "WRITTEN"
    ABSENT = "ABSENT"
    FAILED = "FAILED"


class SearchStatus(str, Enum):
    """The bounded Windows Update search: finished, failed, or abandoned (not a verdict either way)."""

    OK = "OK"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"


class PrepareGate(str, Enum):
    """prepare: the WIM gate passed or failed."""

    PASSED = "PASS"
    FAILED = "FAIL"


class TreeWait(str, Enum):
    """upgrade-run: how it waited for setup.exe's whole process tree to end."""

    JOB = "job"


class LaunchWaitStatus(str, Enum):
    """launch: the run started setup, ended before it, or the wait timed out."""

    LAUNCHED = "LAUNCHED"
    ENDED = "ENDED"
    TIMEOUT = "TIMEOUT"


class TaskCleanupAction(str, Enum):
    """launch: what was done to the SYSTEM task once launch had its verdict."""

    DISARM = "DISARM"
    REMOVE = "REMOVE"
    NONE = "NONE"


class LaunchVerdict(str, Enum):
    """launch: setup runs, is already gone, never started, failed to start, or its task was left behind."""

    OK = "OK"
    SUSPECT = "SUSPECT"
    NO_START = "NO_START"
    FAILED = "FAILED"
    TASK_LEFT = "TASK_LEFT"


class DirectoryAction(str, Enum):
    """lock-dirs: what was done to one directory."""

    CREATED = "CREATED"
    ALREADY_LOCKED = "ALREADY_LOCKED"
    ABSENT = "ABSENT"


class LockDirsVerdict(str, Enum):
    """lock-dirs: every directory locked (and the tool in place checked), or refused."""

    OK = "OK"
    FAILED = "FAILED"


# --- payload bases --------------------------------------------------------------------------


class Gate(NamedTuple):
    """The verdict field a gated payload's ``ok`` must agree with.

    Attributes:
        field: The field's name in the payload (``verdict``, ``gate``), for messages.
        value: The verdict the payload carries.
        passing: The verdicts that mean ``ok``.
    """

    field: str
    value: Enum
    passing: frozenset[Enum]

    @property
    def passed(self) -> bool:
        """The payload's verdict is a passing one."""
        return self.value in self.passing


class GuestPayload(BaseModel):
    """Base of every guest answer payload: frozen, and closed to fields the guest does not send."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class ProbePayload(GuestPayload):
    """The payload of a command that never refuses: its envelope's ``ok`` is always true."""


class GatedPayload(GuestPayload):
    """The payload of a command whose verdict decides its envelope's ``ok``."""

    # Not named gate: prepare's payload has a field of that name.
    @abstractmethod
    def ok_gate(self) -> Gate:
        """The verdict ``ok`` must agree with; every gated payload names its own."""


# --- probes ---------------------------------------------------------------------------------


class RunningBuild(GuestPayload):
    """The guest's OS build (prepare's ``running``): CurrentBuild as the registry text, UBR, both joined."""

    current_build: str
    ubr: int
    build: str


class BuildAnswer(ProbePayload):
    """build: the running build and InstallDate (Unix epoch seconds)."""

    current_build: str
    ubr: int
    build: str
    install_date: int


class DetectLpDefectAnswer(GatedPayload):
    """detect-lp-defect: the orphaned-language-pack verdict; ok unless it is UNKNOWN."""

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
    verdict: LpVerdict
    reason: str | None

    def ok_gate(self) -> Gate:
        """ok unless the verdict is UNKNOWN."""
        return Gate("verdict", self.verdict, frozenset({LpVerdict.AFFECTED, LpVerdict.CLEAN}))


class DriveSpace(GuestPayload):
    """One fixed drive with a letter: free and total bytes, and free GiB rounded to one place."""

    letter: DriveLetter
    free_bytes: int
    size_bytes: int
    free_gb: float


class DrivesAnswer(ProbePayload):
    """drives: free space per fixed drive."""

    drives: tuple[DriveSpace, ...]


class NicMacsAnswer(ProbePayload):
    """nic-macs: the MAC address of every network adapter, each in the host's normal form.

    The guest normalises them too; a value that is no MAC breaks the contract here, like any other
    malformed field, rather than after the answer was accepted.
    """

    macs: tuple[MacAddress, ...]


class ScheduledTaskState(GuestPayload):
    """One boot task verify-runners checked; ``state`` stays text (pwshpy's ``TaskState``, never judged here)."""

    name: str
    present: bool
    task_path: str | None
    state: str | None
    enabled: bool | None
    last_run: str | None
    last_result: int | None


class ContainerRow(GuestPayload):
    """One running container from ``docker ps``."""

    name: str
    status: str


class VerifyRunnersAnswer(GatedPayload):
    """verify-runners: did the runner containers and their boot tasks come back.

    ``docker_service`` stays text: pwshpy's ``ServiceState`` vocabulary, never judged here.
    """

    tasks: tuple[ScheduledTaskState, ...]
    docker_service: str | None
    dockerd_processes: int
    containers: tuple[ContainerRow, ...] | None
    count: int | None
    expected: int
    verdict: RunnerVerdict

    def ok_gate(self) -> Gate:
        """ok when the verdict is OK."""
        return Gate("verdict", self.verdict, frozenset({RunnerVerdict.OK}))


class ServicingActiveAnswer(ProbePayload):
    """servicing-active: running processes per servicing process name, their total, and whether any runs."""

    counts: dict[str, int]
    total: int
    active: bool


class SetupAliveAnswer(ProbePayload):
    """setup-alive: SetupHost processes running, and whether any is."""

    count: int
    alive: bool


class StagedOsAnswer(ProbePayload):
    """staged-os: is the staged NewOS boot loader still there."""

    path: str
    present: bool
    verdict: StagedOsVerdict


class StateAnswer(ProbePayload):
    """state: the upgrade run's state log and the verdict of its last marker line (None while running)."""

    path: str
    present: bool
    verdict: StateVerdict | None
    marker: str | None
    line_count: int
    tail: tuple[str, ...]


# --- Windows Update -------------------------------------------------------------------------


class ServiceRow(GuestPayload):
    """One target service as WMI reports it."""

    name: str
    start_mode: StartMode
    state: WmiServiceState


class StartWrite(GuestPayload):
    """The registry Start write for one service."""

    service: str
    value: ServiceStart
    result: StartWriteResult
    error: str | None


class StopIssued(GuestPayload):
    """One issued service stop: Get-Service's Status right after it, or why it could not be issued.

    ``state`` stays text: it is pwshpy's ``ServiceState`` vocabulary, which the host never judges.
    """

    service: str
    state: str | None
    error: str | None


class StopWait(GuestPayload):
    """The bounded wait for the services to leave the Running state."""

    waited_s: float
    timed_out: bool
    still_running: tuple[str, ...]


class QuiesceWuAnswer(GatedPayload):
    """quiesce-wu: Windows Update held (start modes before, the writes, stops, wait and verified state)."""

    previous_start_modes: dict[str, StartMode]
    writes: tuple[StartWrite, ...]
    stops: tuple[StopIssued, ...]
    wait: StopWait
    services: tuple[ServiceRow, ...]
    not_disabled: tuple[str, ...]
    still_running: tuple[str, ...]
    verdict: QuiesceVerdict

    def ok_gate(self) -> Gate:
        """ok when the verdict is OK."""
        return Gate("verdict", self.verdict, frozenset({QuiesceVerdict.OK}))


class UpdateSearch(GuestPayload):
    """restore-wu's bounded Windows Update search; informational, never part of its verdict."""

    status: SearchStatus
    pending: int | None
    titles: tuple[str, ...]
    error: str | None
    timeout_s: float

    @model_validator(mode="after")
    def _pending_only_when_found(self) -> UpdateSearch:
        """The guest counts pending updates exactly when the search answered; anything else breaks the contract."""
        if (self.status is SearchStatus.OK) != (self.pending is not None):
            raise ValueError(f"search status {self.status.value} carries pending={self.pending!r}")
        return self


class RestoreWuAnswer(GatedPayload):
    """restore-wu: the start modes written back, the verified state, and the search probe."""

    writes: tuple[StartWrite, ...]
    services: tuple[ServiceRow, ...]
    still_disabled: tuple[str, ...]
    verdict: RestoreVerdict
    search: UpdateSearch

    def ok_gate(self) -> Gate:
        """ok when the verdict is RESTORED."""
        return Gate("verdict", self.verdict, frozenset({RestoreVerdict.RESTORED}))


# --- upgrade --------------------------------------------------------------------------------


class WimImage(GuestPayload):
    """Image index 1 of the staged WIM; ``build`` and ``spbuild`` go into the repair receipt."""

    index: int
    name: str
    edition: str
    build: int
    spbuild: int
    languages: tuple[str, ...]
    default_language: str


class PrepareAnswer(GatedPayload):
    """prepare: read-only cleared, the WIM gate, and on PASS the waiver read back, the TPM and the drives."""

    stage_root: str
    readonly_cleared: int
    readonly_failed: int
    wim: str
    gate: PrepareGate
    reason: str | None
    image: WimImage | None
    running: RunningBuild
    waiver_readback: int | None
    tpm_present: bool | None
    drives: tuple[DriveSpace, ...]

    @model_validator(mode="after")
    def _image_when_passed(self) -> PrepareAnswer:
        """A WIM gate can only pass on an image it read, so a PASS without one breaks the contract."""
        if self.gate is PrepareGate.PASSED and self.image is None:
            raise ValueError("gate PASS carries no image")
        return self

    @property
    def passed_image(self) -> WimImage:
        """The image a passed gate read; only meaningful once the gate is PASS.

        Raises:
            RuntimeError: Read on a gate that did not pass (a caller bug: validation guarantees an
                image on every PASS).
        """
        if self.image is None:
            raise RuntimeError(f"prepare: no image on a {self.gate.value} gate")
        return self.image

    def ok_gate(self) -> Gate:
        """ok when the gate is PASS."""
        return Gate("gate", self.gate, frozenset({PrepareGate.PASSED}))


class LaunchWait(GuestPayload):
    """launch's bounded wait for the SYSTEM run to start setup."""

    status: LaunchWaitStatus
    waited_s: float
    last_error: str | None


class TaskCleanup(GuestPayload):
    """What launch did to the SYSTEM task once it had its verdict."""

    action: TaskCleanupAction
    ended: bool | None
    disabled: bool
    deleted: bool
    error: str | None


class LaunchAnswer(GatedPayload):
    """launch: the SYSTEM task, the wait for setup, SetupHost afterwards, the state log, the task cleanup."""

    task: str
    command: str
    stale_log_removed: bool
    registered: bool
    wait: LaunchWait | None
    setuphost: int | None
    state: StateAnswer | None
    task_cleanup: TaskCleanup
    verdict: LaunchVerdict
    reason: str | None
    locked: tuple[str, ...]
    tool_sha256: str | None

    def ok_gate(self) -> Gate:
        """ok when the verdict is OK."""
        return Gate("verdict", self.verdict, frozenset({LaunchVerdict.OK}))


class DirectoryLock(GuestPayload):
    """One directory lock-dirs secured, and how."""

    path: str
    action: DirectoryAction


class LockDirsAnswer(GatedPayload):
    """lock-dirs: the directories it locked or found locked, and the tool already in place, if any."""

    tool: str
    tool_present: bool
    tool_sha256: str | None
    directories: tuple[DirectoryLock, ...]
    verdict: LockDirsVerdict
    reason: str | None

    def ok_gate(self) -> Gate:
        """ok when the verdict is OK."""
        return Gate("verdict", self.verdict, frozenset({LockDirsVerdict.OK}))


class UpgradeRunAnswer(GatedPayload):
    """upgrade-run: setup's run as the SYSTEM task's command; the state log carries the same facts."""

    state_log: str
    setup: str
    argv: tuple[str, ...]
    build_before: str | None
    build_after: str | None
    exit_code: int | None
    exit_hex: str | None
    seconds: float | None
    tree_wait: TreeWait | None
    newos_staged: bool | None
    verdict: StateVerdict
    reason: str | None

    def ok_gate(self) -> Gate:
        """ok when the run ended DONE-OK."""
        return Gate("verdict", self.verdict, frozenset({StateVerdict.DONE_OK}))
