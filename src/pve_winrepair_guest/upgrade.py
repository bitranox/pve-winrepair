r"""The in-place repair upgrade itself: gate the media, launch setup as SYSTEM, run it, mark the end.

Windows is reached through the :class:`UpgradeHost` port; :class:`PwshpyHost` is the real adapter.
The filesystem work (read-only bits on the media, ``setup.exe``, the state log) is plain Python,
and the WIM is read by pwshpy's portable ``get_windows_image`` (header and XML only, no DISM), so
both run for real in the tests too.

* ``prepare --stage-root D:\upgrade``: clear read-only (inherited from the source medium), gate
  hard on the WIM (a bad WIM or one older than the running build must stop the run, not surface
  hours later), write the MoSetup waiver, report TPM and free space.
* ``lock-dirs --tool C:\winrepair\winrepair_guest-<sha16>.ps1 [--stage-root D:\upgrade]
  [--no-create]``: create both directories with a DACL restricted to SYSTEM and Administrators already in place
  (``lockdown``; read back), before the driver copies the tool or the media in; accept an existing
  one only when it is exactly locked with nothing below it a non-admin can change, and a tool
  already there only when it matches its name. ``--no-create`` reports an absent directory as
  ABSENT instead of creating it (the node's report after the upgrade).
* ``launch --stage-root D:\upgrade``: first a preflight that changes nothing: the tool must be the
  content-addressed copy in ``C:\winrepair`` and the stage root ``<letter>:\upgrade``, the tool,
  ``setup.exe`` and powershell.exe must exist, the tool's bytes must match its content address,
  both directories must still carry exactly the DACL lock-dirs wrote, and nothing below them may
  be a reparse point or be owned or writable by a non-admin - SYSTEM is about to execute both
  files and whatever setup.exe loads. Then a SYSTEM scheduled task runs ``upgrade-run``, because
  Windows OpenSSH kills the process tree when the connection drops and setup runs for hours. The
  task has NO trigger (registered through the Task Scheduler COM API; ``schtasks /Create`` insists
  on one): launch starts it on demand, so a definition left behind by a launch that was killed
  mid-wait can never start setup again by itself. Then a bounded wait for the run's own
  "launching" line, and only after it the 150 s SetupHost check: both compat aborts seen on test
  guests died inside 90 s, and a first SYSTEM run of the packed tool may spend minutes
  bootstrapping uv and Python before setup even starts. The task is not left behind either: once
  the run is launching its definition is deleted (the instance keeps running), and on every other
  outcome the instance is ended and the task deleted.
* ``upgrade-run --stage-root D:\upgrade`` (the task's command): setup.exe with the fixed argv,
  an append-only UTF-8 state log, and the unchanged markers ``STATE=DONE-OK`` / ``STATE=DONE-FAIL``.

Contents:
    * :func:`commands` - prepare, lock-dirs, launch and upgrade-run for the entry's command table.
    * :class:`UpgradeHost`, :class:`PwshpyHost` - the OS port and its adapter.
    * :func:`register_on_demand` - the trigger-less SYSTEM task definition, over an injected
      Task Scheduler COM connection.
    * the pure helpers (:func:`wim_gate`, :func:`wait_for_launch`, :func:`task_spec`, the
      exit-code formatting) and their records.
"""

from __future__ import annotations

import contextlib
import importlib
import ntpath
import os
import re
import stat
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, cast

from pwshpy import (
    CimInstance,
    NativeCallError,
    ProcessInfo,
    PwshPyError,
    RegistryValue,
    RegistryValueType,
    TaskState,
    ps,
)

from pve_winrepair_guest.envelope import Command, Outcome, Skip
from pve_winrepair_guest.lockdown import (
    LOCK_SIDS,
    AclReading,
    LockTarget,
    TreeEntry,
    Win32Api,
    Win32File,
    Win32Security,
    acl_problems,
    content_address,
    create_locked_dir,
    exact_lock_problems,
    inspect_lock_target,
    lock_scope_problem,
    lock_target_problems,
    read_acl,
    token_user_sid,
    walk_tree,
)
from pve_winrepair_guest.probes import (
    CURRENT_VERSION_KEY,
    DEFAULT_STATE_LOG,
    BuildInfo,
    Drive,
    StateLog,
    build_info,
    drive_from_cim,
    fixed_drives,
    read_state,
    state_verdict,
)

if TYPE_CHECKING:
    import argparse
    from collections.abc import Callable, Iterable, Sequence

    from pwshpy import WindowsImage

__all__ = [
    "SETUP_FLAGS",
    "SUCCESS_CODES",
    "TASK_NAME",
    "TREE_LIMIT",
    "DirectoryLock",
    "LaunchReport",
    "LaunchWait",
    "LockDirsReport",
    "Preflight",
    "PrepareReport",
    "PwshpyHost",
    "SetupRun",
    "TaskCleanup",
    "TaskSpec",
    "UpgradeHost",
    "UpgradeRunReport",
    "WimImage",
    "commands",
    "elapsed_text",
    "exit_hex",
    "media_image",
    "powershell_path",
    "preflight",
    "register_on_demand",
    "run_lock_dirs",
    "setup_arguments",
    "signed32",
    "state_line",
    "task_spec",
    "token_account",
    "wait_for_launch",
    "wim_gate",
]

TASK_NAME = "OVMRepairUpgrade"
TASK_PATH = "\\" + TASK_NAME
MOSETUP_KEY = r"HKLM\SYSTEM\Setup\MoSetup"
# Waives an unsupported TPM VERSION or CPU, not an absent TPM (that needs a vTPM on the VM).
WAIVER = "AllowUpgradesWithUnsupportedTPMOrCPU"
TPM_NAMESPACE = "root/cimv2/Security/MicrosoftTpm"
NEWOS_DIR = r"C:\$WINDOWS.~BT\NewOS"
SETUP_PROCESS = "SetupHost"
# The task's program, below %SystemRoot%: by absolute path, never resolved through PATH (on a test
# guest four directories precede System32 in the machine PATH, and a SYSTEM task inherits it).
POWERSHELL_UNDER_ROOT = r"System32\WindowsPowerShell\v1.0\powershell.exe"
# SYSTEM by SID: Task Scheduler accepts the SID string as the principal, and unlike an account
# name it reads the same on every display language.
SYSTEM_SID = "S-1-5-18"
# Task Scheduler 2.0 COM constants (taskschd.h).
TASK_ACTION_EXEC = 0
TASK_CREATE_OR_UPDATE = 6  # replaces a definition an earlier launch left behind
TASK_LOGON_SERVICE_ACCOUNT = 5
TASK_RUNLEVEL_HIGHEST = 1
TASK_INSTANCES_IGNORE_NEW = 2
# The Task Scheduler's own default (a schtasks /Create task reads back PT72H on a test guest), set
# explicitly so it cannot drift: setup's down-level phase runs for hours, far inside it, and a hung
# run is still ended some day instead of never.
TASK_TIME_LIMIT = "PT72H"
LAUNCH_WAIT = 600.0
LAUNCH_POLL = 5.0
SETUP_SETTLE = 150.0
# Ending a task kills its process tree within a few seconds (measured on a test guest: 5 s later the
# action's cmd.exe and its ping.exe child were both gone); 30 s bounds a slow one.
TASK_END_WAIT = 30.0
TASK_END_POLL = 1.0
TREE_POLL = 10.0
# launch walks both locked trees; the 26200 media hold about a thousand entries. A tree past this
# is not the media the driver stages, and an unbounded walk would let it stall launch.
TREE_LIMIT = 20_000
TREE_PROBLEMS_SHOWN = 5
# /eula accept is REQUIRED with /quiet: without it setup runs ~30 s and exits 0xC190010E while the
# log says "User did not accept EULA at downlevel OS". /dynamicupdate disable keeps the run
# reproducible (no mid-run payload fetch). /noreboot so the driver controls the apply phase.
SETUP_FLAGS = (
    "/auto", "upgrade", "/quiet", "/eula", "accept", "/noreboot",
    "/compat", "ignorewarning", "/dynamicupdate", "disable",
)  # fmt: skip
# 3010 is ERROR_SUCCESS_REBOOT_REQUIRED. 0x3010 counts as success too: the existing state logs
# judged it so, and a reader must keep reading those logs the same way.
SUCCESS_CODES = frozenset({0, 3010, 0x3010})
_LAUNCHING = re.compile(r"(?:^|\s)launching: ")
# CurrentBuild is REG_SZ; ASCII digits only, so int() can neither raise nor read a non-ASCII digit.
_BUILD_NUMBER = re.compile(r"[0-9]{1,9}")
# The action's Arguments line is split by powershell's own command-line parser, not by a shell: a
# space or quote in a path would cut an argument, so a path that cannot ride in it unquoted is
# refused up front. Absolute with a drive letter: the task starts in System32, where a relative
# path names a different file; no trailing backslash (setup's /copylogs appends "-logs").
_ABSOLUTE_PATH = re.compile(r"[A-Za-z]:(?:\\[A-Za-z0-9_.-]+)+")
_GB = 1024**3


# --- port and adapter -----------------------------------------------------------------------


@dataclass(frozen=True)
class SetupRun:
    """How setup.exe ended.

    Attributes:
        exit_code: Its exit code as the unsigned DWORD Windows returns (0xC1900200 = 3247440384).
        tree_wait: How the wait covered setup's child processes: "job", or the fallback used.
    """

    exit_code: int
    tree_wait: str


@dataclass(frozen=True)
class TaskSpec:
    r"""A scheduled task to register: one exec action, a principal, settings, and NO trigger.

    There is deliberately no trigger field: the only way this task runs is an explicit start, so
    a definition that outlives its launch (killed driver, dropped ssh, a crash) stays inert.

    Attributes:
        path: ``\Name`` (root folder) or ``\Folder\Name``.
        program: The executable, by absolute path (never looked up through PATH).
        arguments: Its command line after the program.
        user_id: The principal, here SYSTEM by SID.
        logon_type: TASK_LOGON_SERVICE_ACCOUNT for SYSTEM (no password).
        run_level: TASK_RUNLEVEL_HIGHEST (HighestAvailable in the task XML, as ``/RL HIGHEST``).
        execution_time_limit: ISO 8601 duration after which the scheduler ends the instance.
        multiple_instances: What a second start does while one runs (IGNORE_NEW: nothing).
        disallow_start_on_batteries: Whether a host on battery refuses the start.
        stop_on_batteries: Whether the scheduler ends the instance when the host goes on battery.
    """

    path: str
    program: str
    arguments: str
    user_id: str = SYSTEM_SID
    logon_type: int = TASK_LOGON_SERVICE_ACCOUNT
    run_level: int = TASK_RUNLEVEL_HIGHEST
    execution_time_limit: str = TASK_TIME_LIMIT
    multiple_instances: int = TASK_INSTANCES_IGNORE_NEW
    # The scheduler defaults both to True (read back on a test guest); a setup run must neither be
    # refused nor killed by a host that reports a battery (a VM with an emulated one).
    disallow_start_on_batteries: bool = False
    stop_on_batteries: bool = False

    @property
    def command_line(self) -> str:
        """The program and its arguments as one line, for the report."""
        return f"{self.program} {self.arguments}"


class UpgradeHost(Protocol):
    """The Windows calls prepare, launch and upgrade-run need."""

    def registry(self, key: str) -> Iterable[RegistryValue]:
        """Return the values under a registry key; raises when it cannot be read."""
        ...

    def create_key(self, key: str) -> None:
        """Create a registry key (and its parents); an existing key is fine."""
        ...

    def set_dword(self, key: str, name: str, value: int) -> None:
        """Write a REG_DWORD value; raises when it cannot be written."""
        ...

    def cim(self, class_name: str, *, where: str | None = None, namespace: str = "root/cimv2") -> Iterable[CimInstance]:
        """CIM instances of a class; raises when WMI cannot be asked."""
        ...

    def register_task(self, spec: TaskSpec) -> None:
        """Create or replace a trigger-less task; raises a PwshPyError when it cannot."""
        ...

    def start_task(self, task_path: str) -> None:
        """Start a scheduled task now; raises when it cannot."""
        ...

    def task_state(self, task_path: str) -> TaskState | None:
        """Return a task's state (RUNNING while an instance runs), or None when there is no such task."""
        ...

    def stop_task(self, task_path: str) -> None:
        """End a task's running instance (its whole process tree); raises when it cannot."""
        ...

    def disable_task(self, task_path: str) -> None:
        """Disable a task so it refuses any start; a running instance keeps running."""
        ...

    def delete_task(self, task_path: str) -> None:
        """Delete a task's definition; a running instance keeps running. Raises when it cannot."""
        ...

    def processes(self) -> Iterable[ProcessInfo]:
        """Return the running processes, names without ``.exe``."""
        ...

    def monotonic(self) -> float:
        """Return a monotonic clock reading in seconds."""
        ...

    def sleep(self, seconds: float) -> None:
        """Wait ``seconds``."""
        ...

    def now(self) -> datetime:
        """Return the local wall-clock time for the state log."""
        ...

    def whoami(self) -> str:
        r"""Return ``DOMAIN\name (SID)`` of this run's account (SYSTEM: ``... (S-1-5-18)``).

        Raises on failure; upgrade-run logs that as unknown and carries on.
        """
        ...

    def user_sid(self) -> str:
        """Return the SID of the account running this process; raises OSError when unreadable."""
        ...

    def system_root(self) -> str:
        r"""Return %SystemRoot% (``C:\Windows``); raises OSError when it is not set."""
        ...

    def create_locked_dir(self, path: str) -> bool:
        """Create a directory already restricted to SYSTEM and Administrators (``lockdown``).

        Returns False when something already has that name; raises OSError when it cannot be made.
        """
        ...

    def name_taken(self, path: str) -> bool:
        """Return whether anything has that name (a directory, a file, a link even when dangling).

        The same question :meth:`create_locked_dir` answers with False, asked without creating:
        only a name nothing has reads as absent. Raises OSError when the name cannot be looked up.
        """
        ...

    def read_acl(self, path: str) -> AclReading:
        """Return a file's or directory's owner and DACL; raises OSError when unreadable."""
        ...

    def inspect_lock_target(self, path: str) -> LockTarget:
        """Read a directory and its path without following a reparse point; raises OSError."""
        ...

    def tree(self, root: str) -> Iterable[TreeEntry]:
        """Every entry below ``root``, not entering a reparse point (``lockdown.walk_tree``); OSError."""
        ...

    def test_path(self, path: str) -> bool:
        """Return whether a path exists."""
        ...

    def run_setup(self, argv: Sequence[str]) -> SetupRun:
        """Run setup.exe and wait for it AND every process it started; raises if it cannot start."""
        ...


class PwshpyHost:
    """The real :class:`UpgradeHost`: pwshpy's native bindings plus a Win32 job object."""

    def registry(self, key: str) -> Iterable[RegistryValue]:
        """See :meth:`UpgradeHost.registry`."""
        return ps.get_item_property(key)

    def create_key(self, key: str) -> None:
        """See :meth:`UpgradeHost.create_key`."""
        ps.new_registry_key(key)

    def set_dword(self, key: str, name: str, value: int) -> None:
        """See :meth:`UpgradeHost.set_dword`."""
        ps.set_item_property(key, name, value, RegistryValueType.REG_DWORD)

    def cim(self, class_name: str, *, where: str | None = None, namespace: str = "root/cimv2") -> Iterable[CimInstance]:
        """See :meth:`UpgradeHost.cim`."""
        return ps.get_cim_instance(class_name, where=where, namespace=namespace)

    def register_task(self, spec: TaskSpec) -> None:
        """See :meth:`UpgradeHost.register_task`.

        pwshpy 1.5.0's register_scheduled_task registers with the caller's interactive token only
        (no SYSTEM principal, no run level, no settings; filed in pwshpy's OPEN-WORK.md), so this
        drives the Task Scheduler COM API directly, as pwshpy itself does.
        """
        register_on_demand(_connect_scheduler, spec)

    def start_task(self, task_path: str) -> None:
        """See :meth:`UpgradeHost.start_task`."""
        ps.start_scheduled_task(task_path)

    def task_state(self, task_path: str) -> TaskState | None:
        """See :meth:`UpgradeHost.task_state`."""
        folder, _, name = task_path.rpartition("\\")
        folder += "\\"
        # get_scheduled_task recurses the folder tree, so the folder must match too.
        task = ps.get_scheduled_task(folder).first(lambda t: t.task_name == name and t.task_path == folder)
        return None if task is None else task.state

    def stop_task(self, task_path: str) -> None:
        """See :meth:`UpgradeHost.stop_task`."""
        ps.stop_scheduled_task(task_path)

    def disable_task(self, task_path: str) -> None:
        """See :meth:`UpgradeHost.disable_task`."""
        ps.disable_scheduled_task(task_path)

    def delete_task(self, task_path: str) -> None:
        """See :meth:`UpgradeHost.delete_task`."""
        ps.unregister_scheduled_task(task_path)

    def processes(self) -> Iterable[ProcessInfo]:
        """See :meth:`UpgradeHost.processes`."""
        return ps.get_process()

    def monotonic(self) -> float:
        """See :meth:`UpgradeHost.monotonic`."""
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        """See :meth:`UpgradeHost.sleep`."""
        time.sleep(seconds)

    def now(self) -> datetime:
        """See :meth:`UpgradeHost.now`."""
        return datetime.now()

    def whoami(self) -> str:
        """See :meth:`UpgradeHost.whoami`.

        Raises:
            OSError: pywin32 cannot be imported, or the token cannot be read.
        """
        return token_account(*_win32())

    def user_sid(self) -> str:
        """See :meth:`UpgradeHost.user_sid`."""
        return token_user_sid(*_win32())

    def system_root(self) -> str:
        """See :meth:`UpgradeHost.system_root`."""
        root = os.environ.get("SYSTEMROOT")
        if not root:
            raise OSError("SystemRoot is not set in this process's environment")
        return root

    def create_locked_dir(self, path: str) -> bool:
        """See :meth:`UpgradeHost.create_locked_dir`."""
        return create_locked_dir(_win32()[0], _win32file(), path)

    def name_taken(self, path: str) -> bool:
        """See :meth:`UpgradeHost.name_taken`.

        lstat, not ``os.path.lexists``: lexists answers False on every OSError, so a name that
        cannot be looked up (access denied on a parent) would read as absent.
        """
        try:
            os.lstat(path)
        except (FileNotFoundError, NotADirectoryError):  # a file as a parent: the name cannot exist
            return False
        return True

    def inspect_lock_target(self, path: str) -> LockTarget:
        """See :meth:`UpgradeHost.inspect_lock_target`."""
        return inspect_lock_target(_win32()[0], _win32file(), path)

    def tree(self, root: str) -> Iterable[TreeEntry]:
        """See :meth:`UpgradeHost.tree`."""
        return walk_tree(root)

    def read_acl(self, path: str) -> AclReading:
        """See :meth:`UpgradeHost.read_acl`."""
        return read_acl(_win32()[0], path)

    def test_path(self, path: str) -> bool:
        """See :meth:`UpgradeHost.test_path`."""
        return ps.test_path(path)

    def run_setup(self, argv: Sequence[str]) -> SetupRun:
        """See :meth:`UpgradeHost.run_setup`.

        The wait must cover setup.exe AND its descendants: the completion marker must not appear
        while SetupHost still works (PowerShell's ``Start-Process -Wait`` does wait for them,
        measured on a test guest: a ``cmd /c start /b ping -n 7`` that exits at once was waited for 8 s).
        ``ps.exec`` waits for setup.exe alone, so this process first joins a fresh job object,
        which every child it starts inherits, and then waits until it is the job's only process.
        If the job cannot be joined, it falls back to waiting until no SetupHost process is left.
        """
        job, why = _join_new_job()
        result = ps.exec(list(argv))  # no timeout: the down-level phase runs for hours
        if job is not None:
            _wait_job_drained(job)
            return SetupRun(exit_code=result.exit_code, tree_wait="job")
        while any(p.name.casefold() == SETUP_PROCESS.casefold() for p in ps.get_process()):
            time.sleep(TREE_POLL)
        return SetupRun(exit_code=result.exit_code, tree_wait=f"SetupHost by name (no job: {why})")


def _win32() -> tuple[Win32Security, Win32Api]:
    """pywin32's win32security and win32api, typed by the members this tool uses.

    Raises:
        OSError: pywin32 is not installed (it is Windows-only, absent on the Linux dev host).
    """
    try:
        security, api = importlib.import_module("win32security"), importlib.import_module("win32api")
    except ImportError as exc:
        raise OSError(f"pywin32 unavailable: {exc}") from exc
    return cast("Win32Security", security), cast("Win32Api", api)


def _win32file() -> Win32File:
    """pywin32's win32file, typed by the members this tool uses; OSError when pywin32 is missing."""
    try:
        return cast("Win32File", importlib.import_module("win32file"))
    except ImportError as exc:
        raise OSError(f"pywin32 unavailable: {exc}") from exc


def token_account(security: Win32Security, api: Win32Api) -> str:
    r"""Return ``DOMAIN\name (SID)`` of the account this process runs as, read from its own token.

    Not ``GetUserNameEx(NameSamCompatible)``: under the SYSTEM task on a domain member that names
    the computer account (``EXAMPLE\WIN-HOST$``, measured on a test guest), so the state log never
    showed that the run is SYSTEM. The name is localised (a German-language Windows says
    NT-AUTORITAET with an umlaut), so the SID is added as the part a reader can match on.

    Args:
        security: The ``win32security`` module (injected: pywin32 exists only on Windows).
        api: The ``win32api`` module.

    Returns:
        For example ``NT AUTHORITY\SYSTEM (S-1-5-18)``.

    Raises:
        OSError: A token call failed. pywin32 raises its own ``pywintypes.error`` (exposed as the
            module's ``error``), which derives from Exception, not OSError; re-raised as OSError so
            a caller that treats the account as informational catches it without a bare except.
    """
    try:
        token = security.OpenProcessToken(api.GetCurrentProcess(), security.TOKEN_QUERY)
        sid = security.GetTokenInformation(token, security.TokenUser)[0]
        name, domain, _kind = security.LookupAccountSid(None, sid)
        sid_text = security.ConvertSidToStringSid(sid)
    except security.error as exc:
        raise OSError(f"cannot read this run's account: {exc}") from exc
    return f"{domain}\\{name} ({sid_text})"


def _connect_scheduler() -> Any:
    """A connected Task Scheduler 2.0 service object."""
    # import_module: pywin32 is a Windows-only pwshpy dependency without stubs on the dev host.
    client: Any = importlib.import_module("win32com.client")
    service = client.Dispatch("Schedule.Service")
    service.Connect()
    return service


def _join_new_job() -> tuple[Any, str | None]:
    """Put this process into a new job object, so every process it starts joins it too."""
    try:
        win32job: Any = importlib.import_module("win32job")
        win32api: Any = importlib.import_module("win32api")
        job = win32job.CreateJobObject(None, "")
        win32job.AssignProcessToJobObject(job, win32api.GetCurrentProcess())
    except Exception as exc:  # pywin32 raises its own pywintypes.error; any failure means fall back
        return None, f"{type(exc).__name__}: {exc}"
    return job, None


def _wait_job_drained(job: Any) -> None:
    """Wait until this process is the only one left in ``job``."""
    win32job: Any = importlib.import_module("win32job")
    info = win32job.JobObjectBasicAccountingInformation
    while int(win32job.QueryInformationJobObject(job, info)["ActiveProcesses"]) > 1:
        time.sleep(TREE_POLL)


# --- prepare --------------------------------------------------------------------------------


@dataclass(frozen=True)
class PrepareReport:
    """prepare's answer.

    Attributes:
        stage_root: The staged media.
        readonly_cleared: Files whose read-only bit was cleared.
        readonly_failed: Files whose bit could not be cleared (each one is in ``skipped``).
        wim: The WIM path that was gated.
        gate: PASS or FAIL.
        reason: Why the gate failed, else None.
        image: Image index 1 of the WIM, or None when it could not be read.
        running: The guest's running build.
        waiver_readback: The MoSetup waiver value read back, or None (not written on FAIL).
        tpm_present: Whether a TPM is visible, or None when it could not be asked.
        drives: Free space per fixed drive.
    """

    stage_root: str
    readonly_cleared: int
    readonly_failed: int
    wim: str
    gate: str
    reason: str | None
    image: WimImage | None
    running: BuildInfo
    waiver_readback: int | None
    tpm_present: bool | None
    drives: tuple[Drive, ...]


def clear_read_only(root: str) -> tuple[int, list[Skip]]:
    """Clear the read-only bit on every file below ``root`` (copied media inherit it).

    Returns:
        The number of files cleared, and a Skip per file or directory that could not be handled.
    """
    failed: list[Skip] = []
    cleared = 0
    for folder, _dirs, files in os.walk(root, onerror=lambda e: failed.append(Skip(str(e.filename), str(e)))):
        for name in files:
            path = Path(folder, name)
            try:
                mode = path.stat().st_mode
                if not mode & stat.S_IWRITE:
                    path.chmod(mode | stat.S_IWRITE)
                    cleared += 1
            except OSError as exc:
                failed.append(Skip(os.fspath(path), str(exc)))
    return cleared, failed


@dataclass(frozen=True)
class WimImage:
    """One image of the staged media, as prepare reports it (the envelope's ``image``).

    The node reads ``build`` and ``spbuild`` from it into the repair receipt, so the field names
    are the envelope's contract, not pwshpy's (``WindowsImage.sp_build``).

    Attributes:
        index: The image's 1-based index.
        name: The image name, or "" when absent.
        edition: WINDOWS/EDITIONID, or "" when absent.
        build: WINDOWS/VERSION/BUILD (e.g. 26200); 0 when the XML holds no numeric one.
        spbuild: WINDOWS/VERSION/SPBUILD, the servicing build compared against a guest's UBR.
        languages: Every WINDOWS/LANGUAGES/LANGUAGE, in document order.
        default_language: WINDOWS/LANGUAGES/DEFAULT, or "" when absent.
    """

    index: int
    name: str
    edition: str
    build: int
    spbuild: int
    languages: tuple[str, ...]
    default_language: str


def media_image(record: WindowsImage) -> WimImage:
    """The envelope's view of one image pwshpy read from the WIM's header and XML."""
    return WimImage(
        index=record.index,
        name=record.name,
        edition=record.edition_id,
        build=record.build,
        spbuild=record.sp_build,
        languages=record.languages,
        default_language=record.default_language,
    )


def wim_gate(images: Sequence[WimImage], running: BuildInfo) -> tuple[str, str | None, WimImage | None]:
    """Gate the media: image index 1 must not be older than the running build.

    ``(BUILD, SPBUILD)`` is compared against ``(CurrentBuild, UBR)`` as a tuple: SPBuild alone
    would pass an older build whose servicing number happens to be higher than the guest's UBR
    (19045.9000 on a 26200.7462 guest), and setup would downgrade it.

    Returns:
        (PASS or FAIL, the reason for FAIL, image index 1 or None when absent).
    """
    image = next((i for i in images if i.index == 1), None)
    if image is None:
        return "FAIL", "the WIM has no image index 1", None
    if image.build == 0:
        # pwshpy reads a BUILD that is missing or not a number as 0. The tuple compare below would
        # FAIL it too, but with a reason naming a build "0" the media never carried.
        return "FAIL", "image index 1 names no build (WINDOWS/VERSION/BUILD missing or not a number)", image
    if not _BUILD_NUMBER.fullmatch(running.current_build):
        return "FAIL", f"running CurrentBuild {running.current_build!r} is not a number", image
    if (image.build, image.spbuild) < (int(running.current_build), running.ubr):
        return "FAIL", f"image {image.build}.{image.spbuild} older than running {running.build}", image
    return "PASS", None, image


def _read_wim(path: str) -> tuple[tuple[WimImage, ...] | None, str | None]:
    """Read the WIM's images from its header and XML; return (images, None) or (None, reason).

    pwshpy's reader never trusts the file's byte size: it refuses a truncated or oversized XML
    resource, a compressed one (resource flag 0x04), a DTD and malformed XML.
    """
    if not _exists(path):
        return None, "install.wim missing"
    try:
        return tuple(media_image(record) for record in ps.get_windows_image(path)), None
    except PwshPyError as exc:
        return None, f"the WIM reader refused the image: {exc}"


def _values(host: UpgradeHost, key: str) -> dict[str, object]:
    return {value.name: value.data for value in host.registry(key)}


def _write_waiver(host: UpgradeHost, skipped: list[Skip]) -> int | None:
    """Write the MoSetup waiver and return what reads back (None when absent or unreadable)."""
    item = f"{MOSETUP_KEY}\\{WAIVER}"
    try:
        host.create_key(MOSETUP_KEY)
        host.set_dword(MOSETUP_KEY, WAIVER, 1)
    except PwshPyError as exc:
        skipped.append(Skip(item, str(exc)))
    try:
        value = _values(host, MOSETUP_KEY).get(WAIVER)
    except PwshPyError as exc:
        skipped.append(Skip(f"{item} readback", str(exc)))
        return None
    return value if isinstance(value, int) else None


def _tpm_present(host: UpgradeHost, skipped: list[Skip]) -> bool | None:
    """A Win32_Tpm instance exists exactly when a TPM is present (Get-Tpm's TpmPresent)."""
    try:
        return bool(list(host.cim("Win32_Tpm", namespace=TPM_NAMESPACE)))
    except PwshPyError as exc:
        skipped.append(Skip("Win32_Tpm", str(exc)))
        return None


def _drives(host: UpgradeHost, skipped: list[Skip]) -> tuple[Drive, ...]:
    try:
        disks = list(host.cim("Win32_LogicalDisk", where="DriveType=3"))
    except PwshPyError as exc:
        skipped.append(Skip("Win32_LogicalDisk", str(exc)))
        return ()
    drives, skips = fixed_drives(disks)
    skipped.extend(skips)
    return drives


def run_prepare(host: UpgradeHost, stage_root: str) -> Outcome:
    """Clear read-only, gate on the WIM; on PASS write the waiver and report TPM and free space."""
    cleared, skipped = clear_read_only(stage_root)
    failed = len(skipped)
    running = build_info(_values(host, CURRENT_VERSION_KEY))
    wim_path = os.fspath(Path(stage_root, "sources", "install.wim"))
    images, reason = _read_wim(wim_path)
    gate, image = "FAIL", None
    if images is not None:
        gate, reason, image = wim_gate(images, running)
    report = PrepareReport(stage_root, cleared, failed, wim_path, gate, reason, image, running, None, None, ())
    if gate != "PASS":
        return Outcome(ok=False, data=report, skipped=tuple(skipped))
    waiver = _write_waiver(host, skipped)
    tpm = _tpm_present(host, skipped)
    drives = _drives(host, skipped)
    report = PrepareReport(stage_root, cleared, failed, wim_path, gate, reason, image, running, waiver, tpm, drives)
    return Outcome(ok=True, data=report, skipped=tuple(skipped))


# --- launch ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class LaunchWait:
    """The bounded wait for the SYSTEM run to start setup.

    Attributes:
        status: LAUNCHED (its "launching" line appeared), ENDED (a completion marker appeared
            first: the run gave up before setup started), or TIMEOUT.
        waited_s: Seconds waited.
        last_error: The last error reading the state log, or None.
    """

    status: str
    waited_s: float
    last_error: str | None


def wait_for_launch(
    read_lines: Callable[[], Sequence[str]],
    *,
    clock: Callable[[], float],
    sleep: Callable[[float], None],
    limit: float = LAUNCH_WAIT,
    interval: float = LAUNCH_POLL,
) -> LaunchWait:
    """Poll the state log until the run logs "launching", logs a marker, or ``limit`` passes.

    A failed read is not "no line yet" forever, but neither is it a verdict: the log is being
    appended by another process, so a read error is retried and the last one is reported.
    """
    started, last_error = clock(), None
    while True:
        try:
            lines = read_lines()
        except OSError as exc:
            lines, last_error = (), str(exc)
        if any(_LAUNCHING.search(line) for line in lines):
            return LaunchWait("LAUNCHED", clock() - started, last_error)
        if state_verdict(lines)[0] is not None:
            return LaunchWait("ENDED", clock() - started, last_error)
        if clock() - started >= limit:
            return LaunchWait("TIMEOUT", clock() - started, last_error)
        sleep(interval)


def _absolute(path: str) -> bool:
    r"""An ``X:\a\b`` path of plain segments, none of them ``.`` or ``..``."""
    segments = path.split("\\")[1:]
    return bool(_ABSOLUTE_PATH.fullmatch(path)) and not any(set(s) <= {"."} for s in segments)


def powershell_path(system_root: str) -> str:
    r"""Windows PowerShell under ``system_root`` (``C:\Windows\System32\...\powershell.exe``)."""
    return ntpath.join(system_root, POWERSHELL_UNDER_ROOT)


def task_spec(tool: str, stage_root: str, state_log: str, program: str) -> TaskSpec:
    r"""The SYSTEM task that runs upgrade-run.

    Raises:
        ValueError: A path is not an absolute ``X:\dir\...`` path of plain segments (no spaces,
            quotes, shell characters, ``..`` or trailing backslash); powershell's command-line split
            would cut or mangle it, and the task's System32 working directory would misread it.
    """
    if not _absolute(stage_root):
        raise ValueError(f"not a usable stage root (X:\\dir, no spaces, quotes or ..): {stage_root!r}")
    for path in (tool, state_log, program):
        if not _absolute(path):
            raise ValueError(f"not an absolute X:\\ path that can ride unquoted in a task command: {path!r}")
    arguments = (
        f"-NoProfile -ExecutionPolicy Bypass -File {tool} upgrade-run --stage-root {stage_root} --state-log {state_log}"
    )
    return TaskSpec(path=TASK_PATH, program=program, arguments=arguments)


def _apply_settings(settings: Any, spec: TaskSpec) -> None:
    """Set every ITaskSettings field launch depends on, defaults included, so none can drift."""
    settings.Enabled = True
    settings.AllowDemandStart = True  # the only way it runs
    settings.AllowHardTerminate = True  # launch's REMOVE ends it
    settings.ExecutionTimeLimit = spec.execution_time_limit
    settings.MultipleInstances = spec.multiple_instances
    settings.DisallowStartIfOnBatteries = spec.disallow_start_on_batteries
    settings.StopIfGoingOnBatteries = spec.stop_on_batteries


def _define(service: Any, spec: TaskSpec) -> None:
    """Fill a fresh COM task definition from ``spec`` and register it; no trigger is ever created."""
    definition = service.NewTask(0)
    principal = definition.Principal
    principal.UserId = spec.user_id
    principal.LogonType = spec.logon_type
    principal.RunLevel = spec.run_level
    _apply_settings(definition.Settings, spec)
    action = definition.Actions.Create(TASK_ACTION_EXEC)
    action.Path = spec.program
    action.Arguments = spec.arguments
    folder_path, _, name = spec.path.rpartition("\\")
    folder = service.GetFolder(folder_path or "\\")
    # The principal goes to RegisterTaskDefinition as well; SYSTEM takes no password.
    folder.RegisterTaskDefinition(name, definition, TASK_CREATE_OR_UPDATE, spec.user_id, None, spec.logon_type)


def _com_errors() -> tuple[type[BaseException], ...]:
    """pywintypes.com_error, or nothing where pywin32 is absent (then connecting fails with ImportError)."""
    try:
        pywintypes = importlib.import_module("pywintypes")
    except ImportError:
        return ()
    return (cast("type[BaseException]", pywintypes.com_error),)


def register_on_demand(
    connect: Callable[[], Any],
    spec: TaskSpec,
    *,
    com_errors: tuple[type[BaseException], ...] | None = None,
) -> None:
    """Register ``spec`` as a trigger-less task over a Task Scheduler COM connection.

    Args:
        connect: Returns a connected ``Schedule.Service`` object (injected: the tests hand in a
            recording stand-in, the guest a real COM connection).
        spec: The task.
        com_errors: The COM error types to wrap; pywintypes.com_error when None.

    Raises:
        NativeCallError: Connecting or registering failed (a COM error, an OSError, or pywin32
            missing), wrapped as pwshpy does, so the caller's ``except PwshPyError`` sees it. Any
            other exception is a bug here and propagates (the entry reports it as exit 2).
    """
    errors = (OSError, ImportError, *(_com_errors() if com_errors is None else com_errors))
    try:
        _define(connect(), spec)
    except errors as exc:
        raise NativeCallError(str(exc) or f"cannot register task {spec.path!r}") from exc


@dataclass(frozen=True)
class TaskCleanup:
    """What launch did to the SYSTEM task once it had its verdict.

    The task has no trigger, so a definition left behind cannot start by itself; it is removed
    anyway, because a start by name (by hand: ``schtasks /Run``, Task Scheduler's UI) would run
    upgrade-run, and with it setup, with nobody watching. A second launch does not need it gone:
    it re-registers the definition with CREATE_OR_UPDATE.

    Attributes:
        action: DISARM (the run is launching: delete the definition, leave the instance running,
            measured on a test guest to survive the delete), REMOVE (it never launched setup: end the
            instance, its whole process tree, then delete the definition), or NONE (the preflight
            refused, so launch never touched the task).
        ended: REMOVE: no instance runs any more (read back); False when it could not be ended,
            None when the task state could not be read. Always None for DISARM (not ended on purpose).
        disabled: The fallback when the task could not be deleted: it refuses any start. A REMOVE
            that could not end the instance only disables, so the task can still be ended by name.
        deleted: The definition is gone (read back).
        error: Why the cleanup did not reach its goal, else None.
    """

    action: str
    ended: bool | None
    disabled: bool
    deleted: bool
    error: str | None


def _attempt(errors: list[str], what: str, call: Callable[[], object]) -> bool:
    """Run one task call; record its error under ``what`` instead of raising."""
    try:
        call()
    except PwshPyError as exc:
        errors.append(f"{what}: {exc}")
        return False
    return True


def _deleted(host: UpgradeHost, errors: list[str]) -> bool:
    """Delete the task and read back that it is gone (a delete that reported success is not proof)."""
    _attempt(errors, "delete", lambda: host.delete_task(TASK_PATH))
    try:
        return host.task_state(TASK_PATH) is None
    except PwshPyError as exc:
        errors.append(f"read back: {exc}")
        return False


def _disarm(host: UpgradeHost) -> TaskCleanup:
    """Delete the definition of a task whose run is launching setup; the instance keeps running."""
    errors: list[str] = []
    if _deleted(host, errors):
        return TaskCleanup(action="DISARM", ended=None, disabled=False, deleted=True, error=None)
    disabled = _attempt(errors, "disable", lambda: host.disable_task(TASK_PATH))
    return TaskCleanup(action="DISARM", ended=None, disabled=disabled, deleted=False, error="; ".join(errors))


def _ended(host: UpgradeHost, errors: list[str]) -> bool:
    """End the running instance and wait, bounded, until the task no longer reports RUNNING."""
    if not _attempt(errors, "end", lambda: host.stop_task(TASK_PATH)):
        return False
    deadline = host.monotonic() + TASK_END_WAIT
    while True:
        try:
            if host.task_state(TASK_PATH) is not TaskState.RUNNING:
                return True
        except PwshPyError as exc:
            errors.append(f"read back: {exc}")
            return False
        if host.monotonic() >= deadline:
            errors.append(f"end: still running {TASK_END_WAIT:g} s after the end request")
            return False
        host.sleep(TASK_END_POLL)


def _remove(host: UpgradeHost) -> TaskCleanup:
    """End the instance of a task that never launched setup, then delete the task."""
    try:
        state = host.task_state(TASK_PATH)
    except PwshPyError as exc:
        return TaskCleanup(action="REMOVE", ended=None, disabled=False, deleted=False, error=f"read: {exc}")
    if state is None:
        return TaskCleanup(action="REMOVE", ended=True, disabled=False, deleted=True, error=None)
    errors: list[str] = []
    if state is TaskState.RUNNING and not _ended(host, errors):
        # Keep the definition: deleting it would leave a live instance that nothing can end by name.
        disabled = _attempt(errors, "disable", lambda: host.disable_task(TASK_PATH))
        return TaskCleanup(action="REMOVE", ended=False, disabled=disabled, deleted=False, error="; ".join(errors))
    if _deleted(host, errors):
        return TaskCleanup(action="REMOVE", ended=True, disabled=False, deleted=True, error=None)
    return TaskCleanup(action="REMOVE", ended=True, disabled=False, deleted=False, error="; ".join(errors))


def _louder(verdict: str, reason: str | None, cleanup: TaskCleanup) -> tuple[str, str | None]:
    """A task cleanup that failed overrides the verdict: the task is still there, armed or live."""
    if cleanup.error is None:
        return verdict, reason
    what = "disarmed" if cleanup.action == "DISARM" else "ended and removed"
    before = f"{verdict}: {reason}" if reason else verdict
    return "TASK_LEFT", f"{before}; the task {TASK_PATH} could not be {what}: {cleanup.error}"


@dataclass(frozen=True)
class LaunchReport:
    """launch's answer.

    Attributes:
        task: The scheduled task name.
        command: The command it runs.
        stale_log_removed: Whether an old state log was removed first.
        registered: Whether the trigger-less task was registered.
        wait: The wait for the "launching" line, or None when the task never started.
        setuphost: SetupHost processes 150 s after launching, or None when not checked.
        state: The state log at the end, or None when it could not be read.
        task_cleanup: What was done to the task afterwards.
        verdict: OK, SUSPECT (setup already gone), NO_START (no "launching" within 10 min),
            FAILED (the preflight refused, or the task could not be created or started), or
            TASK_LEFT: whatever the run
            did (``reason`` starts with that verdict), the task could not be cleaned up and is
            still defined, possibly with a live instance; end and delete it by hand
            (``schtasks /End`` then ``/Delete /F /TN OVMRepairUpgrade``). It has no trigger,
            so a task left behind does not run again by itself.
        reason: Why the verdict is not OK, else None.
        locked: The directories found still locked as lock-dirs locked them (read back); launch
            writes no DACL itself.
        tool_sha256: The tool's sha256, checked against its content address, or None.
    """

    task: str
    command: str
    stale_log_removed: bool
    registered: bool
    wait: LaunchWait | None
    setuphost: int | None
    state: StateLog | None
    task_cleanup: TaskCleanup
    verdict: str
    reason: str | None
    locked: tuple[str, ...] = ()
    tool_sha256: str | None = None


@dataclass(frozen=True)
class Preflight:
    """What launch checked before it touched the task.

    Attributes:
        locked: The directories found locked as lock-dirs locks them, with nothing below them a
            non-admin can change; () when launch refused.
        tool_sha256: The tool's sha256, or None when it was not read.
        problem: Why launch must not register the task, or None.
    """

    locked: tuple[str, ...]
    tool_sha256: str | None
    problem: str | None


def _exists(path: str) -> bool:
    """``os.path.exists``'s answer through pathlib: an error on the way reads as absent.

    Before Python 3.14 ``Path.exists`` re-raises a PermissionError where ``os.path.exists`` says
    False, and the guest's interpreter may be older than that.
    """
    try:
        return Path(path).exists()
    except OSError:
        return False


def _is_file(path: str) -> bool:
    """``os.path.isfile``'s answer through pathlib: an error on the way reads as no file (see ``_exists``)."""
    try:
        return Path(path).is_file()
    except OSError:
        return False


def _missing(paths: Sequence[str]) -> str | None:
    gone = [path for path in paths if not _is_file(path)]
    return f"not on the guest: {', '.join(gone)}" if gone else None


def _trusted(host: UpgradeHost) -> frozenset[str]:
    """Who may own and write what SYSTEM runs: SYSTEM, Administrators, and the admin running this."""
    return frozenset({*LOCK_SIDS, host.user_sid()})


def _acl_check(host: UpgradeHost, directories: Sequence[str], files: Sequence[str]) -> str | None:
    """Read every lock back; the account running launch (an admin over ssh) is trusted too."""
    trusted = _trusted(host)
    targets = [(path, True) for path in directories] + [(path, False) for path in files]
    problems: list[str] = []
    for path, container in targets:
        problems += acl_problems(host.read_acl(path), trusted=trusted, container=container)
    return "; ".join(problems) or None


def _unsafe_lock_targets(host: UpgradeHost, directories: Sequence[str]) -> str | None:
    """Why any of ``directories`` cannot be trusted: each read without following a reparse point."""
    problems: list[str] = []
    try:
        for directory in directories:
            problems += lock_target_problems(host.inspect_lock_target(directory))
    except (OSError, PwshPyError) as exc:
        return str(exc)
    return "; ".join(problems) or None


def _named_and_hashed(host: UpgradeHost, tool: str, stage_root: str, program: str) -> Preflight | None:
    """The checks before any ACL is read: the names, the files, the tool's bytes, the directories."""
    setup = ntpath.join(stage_root, "setup.exe")
    problem = lock_scope_problem(tool, stage_root) or _missing((tool, setup, program))
    if problem is not None:
        return Preflight((), None, problem)
    try:
        digest, mismatch = content_address(tool)
    except OSError as exc:
        return Preflight((), None, f"cannot read the tool: {exc}")
    problem = mismatch or _unsafe_lock_targets(host, (ntpath.dirname(tool), stage_root))
    return None if problem is None else Preflight((), digest, problem)


def _locks_held(host: UpgradeHost, directories: Sequence[str]) -> str | None:
    """Why a directory is not still exactly as lock-dirs locked it, or None."""
    problems: list[str] = []
    for directory in directories:
        found = exact_lock_problems(host.read_acl(directory))
        if found:
            problems.append(
                f"{directory} is not locked as lock-dirs creates it ({'; '.join(found)}): it must be "
                f"created locked by lock-dirs before anything is copied into it"
            )
    return "; ".join(problems) or None


def _summary(problems: Sequence[str]) -> str | None:
    if not problems:
        return None
    shown = "; ".join(problems[:TREE_PROBLEMS_SHOWN])
    more = len(problems) - TREE_PROBLEMS_SHOWN
    return f"{shown}; and {more} more" if more > 0 else shown


def _tree_problems(host: UpgradeHost, root: str, trusted: frozenset[str]) -> list[str]:
    """Why something below ``root`` could have been changed by a non-admin since the lock."""
    problems: list[str] = []
    for count, entry in enumerate(host.tree(root), start=1):
        if count > TREE_LIMIT:
            return [f"{root} holds more than {TREE_LIMIT} entries, more than any installation media"]
        if entry.reparse:
            problems.append(f"{entry.path} is a reparse point (a junction or link) the lock does not cover")
            continue
        problems += acl_problems(host.read_acl(entry.path), trusted=trusted, container=False)
    return problems


def _trees(host: UpgradeHost, directories: Sequence[str]) -> str | None:
    trusted = _trusted(host)
    return _summary([problem for root in directories for problem in _tree_problems(host, root, trusted)])


def preflight(host: UpgradeHost, tool: str, stage_root: str, program: str) -> Preflight:
    r"""Check what the SYSTEM task will execute, before anything registers it; changes nothing.

    SYSTEM runs the tool and ``<stage_root>\setup.exe``, and setup.exe loads what lies beside it
    (``sources\``). The tool must sit at its content address in ``C:\winrepair`` and the stage root
    be ``<letter>:\upgrade``, both files must exist (a missing one would otherwise cost a 10-minute
    NO_START with a misleading reason), the tool's bytes must match its name, and neither directory
    may be a reparse point, lie below one, or be owned by anyone but SYSTEM or Administrators.

    Then both directories must still carry exactly the DACL lock-dirs wrote. lock-dirs locks a
    directory before anything is copied into it, so this says no non-admin could write there
    since; launch never locks one itself, because a lock written now would bless whatever a local
    user put there while it was open. Below them, every entry is walked (bounded by
    :data:`TREE_LIMIT`): no reparse point, and no file or directory a non-admin owns or may write.
    That covers what the locked parent cannot: an explicit grant on a child, a child another
    account created through a handle it opened before the lock, and a file moved in on the same
    volume, which keeps its old ACEs. Last, the tool's and setup.exe's ACLs are read once more and
    the tool is hashed again.
    """
    refused = _named_and_hashed(host, tool, stage_root, program)
    if refused is not None:
        return refused
    directories = (ntpath.dirname(tool), stage_root)
    setup = ntpath.join(stage_root, "setup.exe")
    try:
        problem = (
            _locks_held(host, directories) or _trees(host, directories) or _acl_check(host, directories, (tool, setup))
        )
        digest, mismatch = content_address(tool)
    except (OSError, PwshPyError) as exc:
        return Preflight((), None, f"cannot verify the lock-down: {exc}")
    problem = problem or mismatch
    return Preflight((), digest, problem) if problem else Preflight(directories, digest, None)


def _refused(spec: TaskSpec, check: Preflight) -> Outcome:
    """The FAILED answer of a launch whose preflight refused: no task, no stale-log removal."""
    report = LaunchReport(
        task=TASK_NAME,
        command=spec.command_line,
        stale_log_removed=False,
        registered=False,
        wait=None,
        setuphost=None,
        state=None,
        task_cleanup=TaskCleanup(action="NONE", ended=None, disabled=False, deleted=False, error=None),
        verdict="FAILED",
        reason=f"refused before the task was registered: {check.problem}",
        locked=check.locked,
        tool_sha256=check.tool_sha256,
    )
    return Outcome(ok=False, data=report)


def _remove_stale(path: str) -> bool:
    """Delete an old state log; one that cannot be deleted raises (its marker would mislead)."""
    try:
        Path(path).unlink()
    except FileNotFoundError:
        return False
    return True


def _start_task(host: UpgradeHost, spec: TaskSpec) -> tuple[bool, str | None]:
    """Register and start the task; return (registered, failure reason or None)."""
    try:
        host.register_task(spec)
    except PwshPyError as exc:
        return False, f"the task could not be registered: {exc}"
    try:
        host.start_task(spec.path)
    except PwshPyError as exc:
        return True, f"the task could not be started: {exc}"
    return True, None


def _setuphost_count(host: UpgradeHost) -> int:
    return sum(1 for p in host.processes() if p.name.casefold() == SETUP_PROCESS.casefold())


def _settle(host: UpgradeHost, wait: LaunchWait) -> tuple[int | None, str, str | None]:
    """After the wait: (SetupHost count, verdict, reason)."""
    if wait.status == "TIMEOUT":
        return None, "NO_START", f"no 'launching' line within {LAUNCH_WAIT:g} s"
    if wait.status == "ENDED":
        return None, "SUSPECT", "the run ended before launching setup, read the state verdict"
    host.sleep(SETUP_SETTLE)
    count = _setuphost_count(host)
    if count == 0:
        return 0, "SUSPECT", "setup already gone, read the state verdict"
    return count, "OK", None


def _final_state(state_log: str, skipped: list[Skip]) -> StateLog | None:
    try:
        return read_state(state_log)
    except OSError as exc:
        skipped.append(Skip(state_log, str(exc)))
        return None


def run_launch(host: UpgradeHost, stage_root: str, state_log: str, tool: str) -> Outcome:
    """Start upgrade-run as a SYSTEM task, wait for it to launch setup, clean the task up, check SetupHost.

    The preflight comes first and a refusal there touches nothing (no task, the old state log
    kept). The cleanup comes right after the wait, before the 150 s check: once the run is
    launching its task has no further use, and a run that never launched must be stopped before
    it does.
    """
    spec = task_spec(tool, stage_root, state_log, powershell_path(host.system_root()))
    check = preflight(host, tool, stage_root, spec.program)
    if check.problem is not None:
        return _refused(spec, check)
    removed = _remove_stale(state_log)
    registered, failure = _start_task(host, spec)
    skipped: list[Skip] = []
    wait, count, verdict, reason = None, None, "FAILED", failure
    if failure is None:
        wait = wait_for_launch(lambda: read_state(state_log).tail, clock=host.monotonic, sleep=host.sleep)
    cleanup = _disarm(host) if wait is not None and wait.status == "LAUNCHED" else _remove(host)
    if wait is not None:
        count, verdict, reason = _settle(host, wait)
    verdict, reason = _louder(verdict, reason, cleanup)
    state = _final_state(state_log, skipped)
    report = LaunchReport(
        TASK_NAME, spec.command_line, removed, registered, wait, count, state, cleanup, verdict, reason,
        check.locked, check.tool_sha256,
    )  # fmt: skip
    return Outcome(ok=verdict == "OK", data=report, skipped=tuple(skipped))


# --- lock-dirs ------------------------------------------------------------------------------


@dataclass(frozen=True)
class DirectoryLock:
    """One directory lock-dirs secured.

    Attributes:
        path: The directory.
        action: CREATED (made with the lock in place), ALREADY_LOCKED (existed, exactly locked,
            nothing below it a non-admin can change; nothing written, content kept) or ABSENT
            (``--no-create`` only: nothing has that name, and nothing was created).
    """

    path: str
    action: str


@dataclass(frozen=True)
class LockDirsReport:
    """lock-dirs' answer.

    Attributes:
        tool: The tool path named with --tool (its directory is always secured).
        tool_present: A file is already at that path.
        tool_sha256: Its sha256 when present and checked, else None.
        directories: What was done to each directory, in order, up to a refusal.
        verdict: OK, or FAILED (``reason`` says why; nothing after the refusal was touched).
        reason: Why the verdict is not OK, else None.
    """

    tool: str
    tool_present: bool
    tool_sha256: str | None
    directories: tuple[DirectoryLock, ...]
    verdict: str
    reason: str | None


def _not_locked(directory: str, problems: Sequence[str], *, created: bool) -> str:
    if created:
        return f"{directory} did not read back as locked after it was created: {'; '.join(problems)}"
    # Locking it now would not help: a local user who opened it while it was open keeps that
    # access through the handle, and anything already in it was theirs to change.
    return (
        f"{directory} existed before lock-dirs and is not locked as lock-dirs creates it "
        f"({'; '.join(problems)}): remove it (rd /s /q {directory}, as an administrator) and run again"
    )


def _secure(host: UpgradeHost, directory: str, *, created: bool) -> tuple[str, str | None]:
    """(action, problem) for a directory just created locked, or one that already existed.

    The same three checks either way: what the name leads to (no reparse point, a directory, an
    allowed owner), exactly the lock's DACL, and nothing below it a non-admin owns or may write.
    """
    problems = lock_target_problems(host.inspect_lock_target(directory))
    if problems:
        return "", "; ".join(problems)
    problems = exact_lock_problems(host.read_acl(directory))
    if problems:
        return "", _not_locked(directory, problems, created=created)
    below = _summary(_tree_problems(host, directory, _trusted(host)))
    if below is not None:
        return "", below
    return ("CREATED" if created else "ALREADY_LOCKED"), None


def _judge_directory(host: UpgradeHost, directory: str, *, create: bool) -> tuple[str, str | None]:
    """(action, problem): create an absent directory locked, or with ``create`` off report it ABSENT.

    An existing directory is judged by :func:`_secure` either way, so ``create`` never changes the
    verdict on one; with it off nothing is written at all.
    """
    try:
        if create:
            created = host.create_locked_dir(directory)
        elif host.name_taken(directory):
            created = False
        else:
            return "ABSENT", None
        return _secure(host, directory, created=created)
    except (OSError, PwshPyError) as exc:
        return "", str(exc)


def _tool_in_place(host: UpgradeHost, tool: str) -> tuple[bool, str | None, str | None]:
    """(present, sha256, problem) for a tool already at its content address."""
    if not _is_file(tool):
        return False, None, None
    try:
        digest, mismatch = content_address(tool)
        problems = acl_problems(host.read_acl(tool), trusted=_trusted(host), container=False)
    except (OSError, PwshPyError) as exc:
        return True, None, f"cannot check the tool already at {tool}: {exc}"
    return True, digest, mismatch or ("; ".join(problems) or None)


def _lock_refused(tool: str, done: Sequence[DirectoryLock], reason: str, *, present: bool = False) -> Outcome:
    return Outcome(ok=False, data=LockDirsReport(tool, present, None, tuple(done), "FAILED", reason))


def run_lock_dirs(host: UpgradeHost, tool: str, stage_root: str | None, *, create: bool = True) -> Outcome:
    r"""Create and lock ``C:\winrepair`` (and ``stage_root``) before anything is copied into them.

    Each directory absent is created with the lock already in place (``lockdown.create_locked_dir``:
    a protected SYSTEM-and-Administrators DACL in the CreateDirectory call), so it is never open to
    a local user, not even for the moment between a mkdir and a lock, in which a handle opened by
    one would keep its access after the lock. Then, for a created and an existing directory alike:
    no reparse point on or above it, a directory, owned by SYSTEM or Administrators
    (``lockdown.lock_target_problems``); exactly the lock's DACL, read back; and nothing below it
    that a non-admin owns or may write, or that is a reparse point (the walk launch does too).

    An existing directory is never locked here, only accepted or refused. One that is not exactly
    locked was open to local users, and locking it now would neither revoke a handle opened then
    nor vouch for what is in it: refused, naming ``rd /s /q``. One that is exactly locked is reused
    with its content: only an administrator can have written there since it was locked, which is
    what lets a re-run, or a live SYSTEM run, keep its tool (the walk still refuses a child a
    non-admin owns). If a tool is already at ``tool``, its bytes must match its name and only
    trusted accounts may own or write it: the driver then runs that copy as an elevated admin
    instead of pushing its own.

    With ``create`` off (``--no-create``, the node's report after the upgrade) an absent directory
    is reported ABSENT and nothing is created: making one there would be a side effect of a
    read-only report, and its CREATED would hide that the upgrade removed it. An existing one is
    judged exactly as above.
    """
    scope = lock_scope_problem(tool, stage_root)
    if scope is not None:
        return _lock_refused(tool, (), scope)
    done: list[DirectoryLock] = []
    for directory in (ntpath.dirname(tool), *(() if stage_root is None else (stage_root,))):
        action, problem = _judge_directory(host, directory, create=create)
        if problem is not None:
            return _lock_refused(tool, done, problem)
        done.append(DirectoryLock(directory, action))
    present, digest, problem = _tool_in_place(host, tool)
    if problem is not None:
        return _lock_refused(tool, done, problem, present=present)
    return Outcome(ok=True, data=LockDirsReport(tool, present, digest, tuple(done), "OK", None))


# --- upgrade-run ----------------------------------------------------------------------------


@dataclass(frozen=True)
class UpgradeRunReport:
    r"""upgrade-run's answer; the state log carries the same facts for the host's poll.

    Attributes:
        state_log: The log written.
        setup: setup.exe's path.
        argv: Its arguments.
        build_before: The build before setup ran, or None when unreadable.
        build_after: The build after the down-level phase (unchanged until the apply reboot).
        exit_code: setup's exit code as an unsigned DWORD, or None when it did not run.
        exit_hex: The same as ``0x%08X``, or None.
        seconds: How long setup and its child processes ran, or None.
        tree_wait: How the wait covered setup's child processes, or None.
        newos_staged: Whether ``C:\$WINDOWS.~BT\NewOS`` exists afterwards, or None.
        verdict: DONE-OK or DONE-FAIL, as in the marker.
        reason: Why DONE-FAIL, else None.
    """

    state_log: str
    setup: str
    argv: tuple[str, ...]
    build_before: str | None
    build_after: str | None
    exit_code: int | None
    exit_hex: str | None
    seconds: float | None
    tree_wait: str | None
    newos_staged: bool | None
    verdict: str
    reason: str | None


def state_line(when: datetime, message: str) -> str:
    """One state-log line: local time, two spaces, the message (what every log reader expects).

    Example:
        >>> state_line(datetime(2026, 10, 21, 9, 5, 7), "STATE=DONE-OK")
        '2026-10-21 09:05:07  STATE=DONE-OK'
    """
    return f"{when:%Y-%m-%d %H:%M:%S}  {message}"


def signed32(code: int) -> int:
    """The exit code as PowerShell's signed Int32 ``ExitCode`` printed it."""
    code &= 0xFFFFFFFF
    return code - (1 << 32) if code >= 1 << 31 else code


def exit_hex(code: int) -> str:
    """The exit code as ``0x%08X`` (an HRESULT such as 0xC1900200).

    Example:
        >>> exit_hex(-1047526912)
        '0xC1900200'
    """
    return f"0x{code & 0xFFFFFFFF:08X}"


def elapsed_text(seconds: float) -> str:
    """Seconds as ``hh:mm:ss``.

    Example:
        >>> elapsed_text(3725.4)
        '01:02:05'
    """
    whole = int(seconds)
    return f"{whole // 3600:02d}:{whole % 3600 // 60:02d}:{whole % 60:02d}"


def setup_arguments(stage_root: str) -> tuple[str, ...]:
    """setup.exe's arguments; setup copies its logs to ``<stage_root>-logs``."""
    return (*SETUP_FLAGS, "/copylogs", f"{stage_root}-logs")


class _StateLog:
    """The append-only state log. UTF-8 written by Python, one open per line like Add-Content.

    Never Tee-Object: it appended UTF-16 after an ASCII header, and the mixed file read back as
    "D O N E", so a marker match silently failed and a waiter timed out on a SUCCESSFUL run.
    """

    def __init__(self, path: str, now: Callable[[], datetime]) -> None:
        self._path, self._now = path, now

    def say(self, message: str) -> None:
        with Path(self._path).open("a", encoding="utf-8", newline="") as handle:
            handle.write(state_line(self._now(), message) + "\r\n")


def _info(read: Callable[[], str]) -> tuple[str | None, str]:
    """Read one informational value; a failure is logged as unknown, never a reason to stop."""
    try:
        value = read()
    # Any exception, deliberately: these reads only fill log lines inside the run whose one purpose
    # is to start setup, and a pywin32 shape change (TypeError, KeyError) must not abort it.
    except Exception as exc:
        return None, f"unknown ({type(exc).__name__}: {exc})"
    return value, value


def _build(host: UpgradeHost) -> str:
    return build_info(_values(host, CURRENT_VERSION_KEY)).build


def _free_c_gb(host: UpgradeHost) -> str:
    disks = list(host.cim("Win32_LogicalDisk", where="DeviceID='C:'"))
    drive = drive_from_cim(disks[0]) if disks else None
    if drive is None:
        raise ValueError("no C: drive")
    # str(float) always writes a dot, whatever the guest locale; a decimal comma (as a German locale
    # renders one) would break a host-side parse of a number like this one.
    return str(drive.free_gb)


def _verdict(code: int) -> tuple[str, str]:
    """(verdict, marker message) for setup's exit code."""
    if (code & 0xFFFFFFFF) in SUCCESS_CODES:
        return "DONE-OK", "STATE=DONE-OK reboot required to apply"
    return "DONE-FAIL", f"STATE=DONE-FAIL rc={exit_hex(code)}"


def _upgrade(host: UpgradeHost, stage_root: str, log: _StateLog, state_log: str) -> Outcome:
    log.say("=== upgrade_run start ===")
    log.say("whoami=" + _info(host.whoami)[1])
    before, before_text = _info(lambda: _build(host))
    log.say(f"build_before={before_text}")
    log.say("free_C_GB=" + _info(lambda: _free_c_gb(host))[1])
    setup, argv = os.fspath(Path(stage_root, "setup.exe")), setup_arguments(stage_root)
    if not _is_file(setup):
        log.say("STATE=DONE-FAIL setup.exe missing")
        failed = UpgradeRunReport(
            state_log,
            setup,
            argv,
            before,
            None,
            None,
            None,
            None,
            None,
            None,
            "DONE-FAIL",
            "setup.exe missing",
        )
        return Outcome(ok=False, data=failed)
    log.say(f"launching: {setup} {' '.join(argv)}")
    started = host.monotonic()
    try:
        run = host.run_setup([setup, *argv])
    except PwshPyError as exc:
        log.say(f"STATE=DONE-FAIL setup.exe could not run: {exc}")
        log.say("=== upgrade_run end ===")
        failed = UpgradeRunReport(
            state_log, setup, argv, before, None, None, None, None, None, None, "DONE-FAIL", str(exc)
        )
        return Outcome(ok=False, data=failed)
    return _finish(host, log, UpgradeRunReport(
        state_log, setup, argv, before, None, run.exit_code, exit_hex(run.exit_code),
        host.monotonic() - started, run.tree_wait, None, "", None,
    ))  # fmt: skip


def _finish(host: UpgradeHost, log: _StateLog, ran: UpgradeRunReport) -> Outcome:
    """Log setup's result, the build and NewOS, then the marker."""
    code, seconds = ran.exit_code or 0, ran.seconds or 0.0
    log.say(f"setup exit={exit_hex(code)} ({signed32(code)}) after {elapsed_text(seconds)}")
    log.say(f"setup tree wait={ran.tree_wait}")
    after, after_text = _info(lambda: _build(host))
    log.say(f"build_after_downlevel={after_text} (unchanged until the apply reboot)")
    newos, newos_text = _info(lambda: str(host.test_path(NEWOS_DIR)))
    log.say(f"NewOS_staged={newos_text}")
    verdict, marker = _verdict(code)
    log.say(marker)
    log.say("=== upgrade_run end ===")
    reason = None if verdict == "DONE-OK" else marker.removeprefix("STATE=DONE-FAIL ")
    report = UpgradeRunReport(
        ran.state_log, ran.setup, ran.argv, ran.build_before, after, ran.exit_code, ran.exit_hex,
        ran.seconds, ran.tree_wait, None if newos is None else newos == "True", verdict, reason,
    )  # fmt: skip
    return Outcome(ok=verdict == "DONE-OK", data=report)


def run_upgrade(host: UpgradeHost, stage_root: str, state_log: str) -> Outcome:
    """Run setup.exe as the task's command, logging every step and ending with a marker.

    An unexpected error still leaves a ``STATE=DONE-FAIL`` marker (best effort), so the host's
    poll ends on a verdict instead of waiting out its deadline on a run that already died.
    """
    log = _StateLog(state_log, host.now)
    try:
        return _upgrade(host, stage_root, log, state_log)
    except Exception as exc:
        # If the log itself is what failed, the envelope still reports the error.
        with contextlib.suppress(OSError):
            log.say(f"STATE=DONE-FAIL internal error: {type(exc).__name__}: {exc}")
        raise


# --- registration ---------------------------------------------------------------------------


def _stage_root(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--stage-root", required=True, help=r"the staged media, e.g. D:\upgrade")


def _state_log(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--state-log", default=DEFAULT_STATE_LOG, help=f"the run's state log (default {DEFAULT_STATE_LOG})"
    )


def _configure_launch(parser: argparse.ArgumentParser) -> None:
    _stage_root(parser)
    _state_log(parser)
    # Required, no default: the driver pushes the tool under a content address
    # (C:\winrepair\winrepair_guest-<sha>.ps1) that only it knows, and a default path would register
    # a task whose action runs a file that is not there.
    parser.add_argument(
        "--tool",
        required=True,
        help=r"this tool's packed .ps1 as pushed, e.g. C:\winrepair\winrepair_guest-<sha>.ps1",
    )


def _configure_lock_dirs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--tool",
        required=True,
        help=r"the content address the driver pushes to, e.g. C:\winrepair\winrepair_guest-<sha>.ps1",
    )
    parser.add_argument("--stage-root", default=None, help=r"the stage root to lock as well, e.g. D:\upgrade")
    parser.add_argument(
        "--no-create",
        dest="create",
        action="store_false",
        help="report an absent directory as ABSENT instead of creating it; an existing one is judged as without it",
    )


def _configure_run(parser: argparse.ArgumentParser) -> None:
    _stage_root(parser)
    _state_log(parser)


def commands(host_factory: Callable[[], UpgradeHost] = PwshpyHost) -> tuple[Command, ...]:
    """Build prepare, lock-dirs, launch and upgrade-run; each builds its host only when it runs.

    Args:
        host_factory: Builds the :class:`UpgradeHost`; tests pass a fake.

    Returns:
        The commands for the entry's command table.
    """
    return (
        Command(
            "prepare",
            "clear read-only, gate on the WIM, write the compat waiver",
            lambda a: run_prepare(host_factory(), a.stage_root),
            _stage_root,
        ),
        Command(
            "lock-dirs",
            r"create C:\winrepair (and the stage root) already locked, before anything is copied into them",
            lambda a: run_lock_dirs(host_factory(), a.tool, a.stage_root, create=a.create),
            _configure_lock_dirs,
        ),
        Command(
            "launch",
            "start upgrade-run as a SYSTEM task and check setup stays up",
            lambda a: run_launch(host_factory(), a.stage_root, a.state_log, a.tool),
            _configure_launch,
        ),
        Command(
            "upgrade-run",
            "run setup.exe (the SYSTEM task's command), write the state log and marker",
            lambda a: run_upgrade(host_factory(), a.stage_root, a.state_log),
            _configure_run,
        ),
    )
