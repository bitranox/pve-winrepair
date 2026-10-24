"""Tests for prepare / launch / upgrade-run.

The commands reach Windows through the ``UpgradeHost`` port; ``FakeUpgradeHost`` answers from
real pwshpy records and a fake clock. Everything the old scripts did on the FILESYSTEM is done for
real here, under ``tmp_path``: the read-only media files, the WIM (the real header and XML of the
25H2 de-DE media, see ``FIXTURE``), ``setup.exe``'s presence and the append-only state log.
The scheduled task is simulated by ``task_lines``: lines the SYSTEM run appends to the state log
once the fake clock passes their time, so the launch wait is exercised against the real reader.
``task`` models the task definition's state as Task Scheduler reports it (None = no such task);
ending it kills the instance and deleting it leaves the instance running, as measured on a test guest.
"""

from __future__ import annotations

import codecs
import hashlib
import io
import json
import ntpath
import os
import shutil
import stat
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest
from json_paths import at, items, obj
from pwshpy import (
    CimInstance,
    CurrentIdentity,
    NativeCallError,
    Pipeline,
    ProcessInfo,
    RegistryHive,
    RegistryValue,
    RegistryValueType,
    ScheduledTaskInfo,
    TaskState,
    ps,
)
from pydantic import BaseModel, ValidationError
from win32_fakes import Descriptor, FakeFiles, FakeSecurity, Node, Sid

from pve_winrepair_guest import lockdown, probes, upgrade, winrepair_guest
from pve_winrepair_guest.lockdown import Ace, AclReading, LockTarget
from pve_winrepair_guest.upgrade import WimImage

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Sequence

# The real 208-byte header plus the real XML resource of a Windows 11 Pro 25H2 (de-DE, 26200.8973)
# ``sources/install.wim``, with only the XML offset (bytes 80-87) rewritten to 208 so it points into
# the small file, and the image NAME replaced by a same-length generic one (``build_wim_fixture.py``).
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "install_wim_header_xml.bin"
WIM_HEADER = 208
# The XML resource header: a 7-byte size at 72, its flag byte at 79 (0x04 = compressed).
WIM_XML_SIZE = 72
WIM_XML_FLAGS = 79
CURRENT_VERSION = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
MOSETUP = r"HKLM\SYSTEM\Setup\MoSetup"
WAIVER = "AllowUpgradesWithUnsupportedTPMOrCPU"
BASE = datetime(2026, 10, 21, 10, 0, 0)
# The driver pushes the tool under a content address (the first 16 hex of its sha256) and names
# it with --tool; launch checks the bytes against that name.
TOOL_BYTES = b"# the packed winrepair guest tool\r\n"
TOOL = rf"C:\winrepair\winrepair_guest-{hashlib.sha256(TOOL_BYTES).hexdigest()[:16]}.ps1"
STATE_LOG = r"C:\upgrade-state.log"
SETUP = r"D:\upgrade\setup.exe"
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
TASK_ARGS = (
    rf"-NoProfile -ExecutionPolicy Bypass -File {TOOL} upgrade-run "
    rf"--stage-root D:\upgrade --state-log {STATE_LOG}"
)
SYSTEM_SID, ADMINS_SID, RUNNER_SID, USERS_SID = "S-1-5-18", "S-1-5-32-544", "S-1-5-21-7-7-7-1001", "S-1-5-11"
# A local non-admin account: what owns a directory it created itself.
PLANTER_SID = "S-1-5-21-7-7-7-1002"
MODIFY, FULL = 0x1301BF, 0x1F01FF
LOCK_DIRS = [r"C:\winrepair", r"D:\upgrade"]


def _reg(name: str, data: str | int) -> RegistryValue:
    kind = RegistryValueType.REG_DWORD if isinstance(data, int) else RegistryValueType.REG_SZ
    return RegistryValue(hive=RegistryHive.HKLM, key="x", name=name, type=kind, data=data)


def _disk(letter: str, free: int) -> CimInstance:
    return CimInstance(
        class_name="Win32_LogicalDisk", properties={"DeviceID": letter, "FreeSpace": str(free), "Size": "999"}
    )


@dataclass
class FakeUpgradeHost:
    """An UpgradeHost over fixed records, a fake clock and a simulated SYSTEM task."""

    state_log: Path
    current_build: str = "26200"
    ubr: int = 8875
    mosetup: dict[str, int] = field(default_factory=dict[str, int])
    waiver_fails: bool = False
    tpm: list[CimInstance] | None = field(default_factory=lambda: [CimInstance(class_name="Win32_Tpm", properties={})])
    disks: list[CimInstance] = field(default_factory=lambda: [_disk("C:", 50 * 1024**3), _disk("D:", 9 * 1024**3)])
    register_fails: bool = False
    registered: list[upgrade.TaskSpec] = field(default_factory=list[upgrade.TaskSpec])
    start_fails: bool = False
    task_lines: list[tuple[float, str]] = field(default_factory=list[tuple[float, str]])
    setuphost: int = 1
    setup_exit: int = 0
    setup_seconds: float = 3725.0
    setup_fails: bool = False
    setup_crash: bool = False
    registry_fails: bool = False
    newos: bool = True
    now_s: float = 0.0
    calls: list[str] = field(default_factory=list[str])
    setup_argv: list[str] = field(default_factory=list[str])
    started_at: float | None = None
    task: TaskState | None = None
    disabled: bool = False
    stop_fails: bool = False
    stop_ignored: bool = False
    delete_fails: bool = False
    disable_fails: bool = False
    state_fails: bool = False
    task_events: list[tuple[float, str]] = field(default_factory=list[tuple[float, str]])
    locked: list[str] = field(default_factory=list[str])
    acl_overrides: dict[str, AclReading] = field(default_factory=dict[str, AclReading])
    lock_targets: dict[str, LockTarget] = field(default_factory=dict[str, LockTarget])
    inspect_fails: bool = False
    # The guest's filesystem as the lock and the tree walk see it: the directories that exist and
    # every path below them, with the ones that are reparse points.
    existing: set[str] = field(default_factory=set[str])
    entries: list[str] = field(default_factory=list[str])
    reparse: set[str] = field(default_factory=set[str])
    create_fails: bool = False
    walk_fails: bool = False

    def system_root(self) -> str:
        return r"C:\Windows"

    def user_sid(self) -> str:
        return RUNNER_SID

    def create_locked_dir(self, path: str) -> bool:
        """Windows' CreateDirectory with the lock's descriptor: the new directory is locked from birth."""
        self.calls.append(f"create {path}")
        if self.create_fails:
            raise OSError(f"cannot create {path}: (3, 'CreateDirectory', 'Der Pfad wurde nicht gefunden.')")
        if path in self.existing:
            return False
        self.existing.add(path)
        self.locked.append(path)
        return True

    def name_taken(self, path: str) -> bool:
        return path in self.existing

    def tree(self, root: str) -> Iterable[lockdown.TreeEntry]:
        if self.walk_fails:
            raise OSError(f"[WinError 5] Zugriff verweigert: '{root}'")
        below = [path for path in self.entries if path.startswith(root + "\\")]
        dirs = {ntpath.dirname(path) for path in self.entries}
        return [lockdown.TreeEntry(path=path, reparse=path in self.reparse, directory=path in dirs) for path in below]

    def inspect_lock_target(self, path: str) -> LockTarget:
        """Windows' answer for a real directory an elevated admin created: owned by Administrators."""
        if self.inspect_fails:
            raise OSError(f"cannot inspect {path} before locking it: (5, 'Zugriff verweigert')")
        return self.lock_targets.get(path, LockTarget(path=path, reparse_points=(), directory=True, owner=ADMINS_SID))

    def read_acl(self, path: str) -> AclReading:
        """Windows' answer: a locked dir and everything below it carry only the two lock ACEs."""
        if path in self.acl_overrides:
            return self.acl_overrides[path]
        system, admins = (
            Ace(sid=SYSTEM_SID, kind=0, flags=0x3, mask=FULL),
            Ace(sid=ADMINS_SID, kind=0, flags=0x3, mask=FULL),
        )
        if path in self.locked:
            return AclReading(path=path, owner=ADMINS_SID, protected=True, aces=(system, admins))
        if any(path.startswith(d + "\\") for d in self.locked):
            return AclReading(
                path=path,
                owner=RUNNER_SID,
                protected=False,
                aces=(
                    Ace(sid=SYSTEM_SID, kind=0, flags=0x10, mask=FULL),
                    Ace(sid=ADMINS_SID, kind=0, flags=0x10, mask=FULL),
                ),
            )
        # Not locked: what a directory under a drive root inherits by default.
        return AclReading(
            path=path,
            owner=ADMINS_SID,
            protected=False,
            aces=(system, admins, Ace(sid=USERS_SID, kind=0, flags=0x1B, mask=MODIFY)),
        )

    def registry(self, key: str) -> Iterable[RegistryValue]:
        if key == CURRENT_VERSION:
            if self.registry_fails:
                raise NativeCallError("registry unavailable")
            return [_reg("CurrentBuild", self.current_build), _reg("UBR", self.ubr)]
        assert key == MOSETUP
        return [_reg(name, value) for name, value in self.mosetup.items()]

    def create_key(self, key: str) -> None:
        assert key == MOSETUP
        self.calls.append("create MoSetup")

    def set_dword(self, key: str, name: str, value: int) -> None:
        assert (key, name) == (MOSETUP, WAIVER)
        self.calls.append(f"set {name}={value}")
        if self.waiver_fails:
            raise NativeCallError("Zugriff verweigert")
        self.mosetup[name] = value

    def cim(self, class_name: str, *, where: str | None = None, namespace: str = "root/cimv2") -> Iterable[CimInstance]:
        if class_name == "Win32_Tpm":
            assert namespace == "root/cimv2/Security/MicrosoftTpm"
            if self.tpm is None:
                raise NativeCallError("Zugriff verweigert")
            return self.tpm
        assert class_name == "Win32_LogicalDisk"
        if where == "DeviceID='C:'":
            return [d for d in self.disks if d.properties["DeviceID"] == "C:"]
        assert where == "DriveType=3"
        return self.disks

    def register_task(self, spec: upgrade.TaskSpec) -> None:
        self.calls.append("register")
        assert self.state_log.exists() is False, "the stale state log must be gone before the task exists"
        if self.register_fails:
            raise NativeCallError("Zugriff verweigert")
        self.registered.append(spec)
        self.task = TaskState.READY

    def start_task(self, task_path: str) -> None:
        self.calls.append(f"start {task_path}")
        if self.start_fails:
            raise NativeCallError("task not found")
        self.started_at = self.now_s
        self.task = TaskState.RUNNING

    def task_state(self, task_path: str) -> TaskState | None:
        assert task_path == "\\OVMRepairUpgrade"
        if self.state_fails:
            raise NativeCallError("Task Scheduler unavailable")
        return self.task

    def stop_task(self, task_path: str) -> None:
        self._task_call("end", task_path)
        if self.stop_fails:
            raise NativeCallError("Zugriff verweigert")
        if not self.stop_ignored and self.task is TaskState.RUNNING:
            self.task = TaskState.READY

    def disable_task(self, task_path: str) -> None:
        self._task_call("disable", task_path)
        if self.disable_fails:
            raise NativeCallError("Zugriff verweigert")
        self.disabled = True

    def delete_task(self, task_path: str) -> None:
        self._task_call("delete", task_path)
        if self.delete_fails or self.task is None:
            raise NativeCallError("Zugriff verweigert" if self.delete_fails else "not found")
        self.task = None  # a running instance keeps running (measured on a test guest)

    def _task_call(self, what: str, task_path: str) -> None:
        assert task_path == "\\OVMRepairUpgrade"
        self.calls.append(what)
        self.task_events.append((self.now_s, what))

    def processes(self) -> Iterable[ProcessInfo]:
        return [ProcessInfo(pid=10 + i, name="SetupHost") for i in range(self.setuphost)]

    def monotonic(self) -> float:
        return self.now_s

    def sleep(self, seconds: float) -> None:
        self.now_s += seconds
        if self.started_at is None:
            return
        due = [line for at, line in self.task_lines if at <= self.now_s - self.started_at]
        self.task_lines = [(at, line) for at, line in self.task_lines if at > self.now_s - self.started_at]
        with self.state_log.open("a", encoding="utf-8") as handle:
            handle.writelines(f"2026-10-21 10:00:00  {line}\n" for line in due)

    def now(self) -> datetime:
        return BASE + timedelta(seconds=self.now_s)

    def whoami(self) -> str:
        return r"NT AUTHORITY\SYSTEM (S-1-5-18)"

    def test_path(self, path: str) -> bool:
        assert path == r"C:\$WINDOWS.~BT\NewOS"
        return self.newos

    def run_setup(self, argv: Sequence[str]) -> upgrade.SetupRun:
        self.setup_argv = list(argv)
        if self.setup_fails:
            raise NativeCallError("Executable not found")
        if self.setup_crash:
            raise RuntimeError("boom")
        self.now_s += self.setup_seconds
        return upgrade.SetupRun(exit_code=self.setup_exit, tree_wait=upgrade.TreeWait.JOB)


def _run(host: FakeUpgradeHost, *argv: str) -> tuple[int, dict[str, object]]:
    out, err = io.StringIO(), io.StringIO()
    code = winrepair_guest.main(list(argv), commands=upgrade.commands(lambda: host), stdout=out, stderr=err)
    lines = out.getvalue().splitlines()
    assert len(lines) == 1, (lines, err.getvalue())
    return code, json.loads(lines[0])


def _data(envelope: dict[str, object]) -> dict[str, object]:
    return obj(envelope["data"])


@pytest.fixture
def stage(tmp_path: Path) -> Path:
    root = tmp_path / "upgrade"
    (root / "sources").mkdir(parents=True)
    shutil.copyfile(FIXTURE, root / "sources" / "install.wim")
    (root / "setup.exe").write_bytes(b"MZ")
    return root


@pytest.fixture
def host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeUpgradeHost:
    """A guest whose launch-relevant files exist for real under their Windows names.

    The working directory is the process's own external state, not a project internal: on Linux
    a name like ``C:\\upgrade-state.log`` is one plain file in it, so launch reads, hashes and
    deletes the real files at the absolute Windows paths it validates.
    """
    if sys.platform == "win32":
        # On Windows an absolute name replaces the base: tmp_path / TOOL IS C:\winrepair\..., so
        # there is no cwd to map the guest's paths into, and launch would act on the machine's own
        # files. A test that never reaches a fixed path uses fileless_host and runs there.
        pytest.skip("maps absolute Windows paths onto file names in the cwd, which only POSIX allows")
    monkeypatch.chdir(tmp_path)
    (tmp_path / TOOL).write_bytes(TOOL_BYTES)
    (tmp_path / SETUP).write_bytes(b"MZ")
    (tmp_path / POWERSHELL).write_bytes(b"MZ")
    # lock-dirs locked both directories before the driver copied the tool and the media in.
    return FakeUpgradeHost(
        state_log=tmp_path / STATE_LOG,
        existing=set(LOCK_DIRS),
        locked=list(LOCK_DIRS),
        entries=[TOOL, SETUP],
    )


@pytest.fixture
def fresh(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeUpgradeHost:
    """A guest the driver has not touched yet: no C:\\winrepair, no stage root, no tool.

    The directories are the fake's, but lock-dirs looks for a tool already at its fixed path on
    the real file system: in the cwd on POSIX, the machine's own C:\\winrepair on Windows. A test
    that gets that far carries :data:`READS_THE_REAL_TOOL_PATH`; the state log is under tmp_path.
    """
    monkeypatch.chdir(tmp_path)
    return FakeUpgradeHost(state_log=tmp_path / "upgrade-state.log")


#: Marks a ``fresh`` test whose lock-dirs run reaches the tool check at the fixed C:\winrepair path,
#: which on Windows reads the real machine rather than the test's cwd.
READS_THE_REAL_TOOL_PATH = pytest.mark.os_posix


@pytest.fixture
def fileless_host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeUpgradeHost:
    """The ``host`` guest with nothing at any fixed Windows path: for tests that never reach one.

    prepare and upgrade-run read only the stage root and state log they are given (both under
    ``tmp_path``), task registration only the fake scheduler, the early launch refusals stop before
    any file is read, and two lock-dirs refusals come from the fake's entries and ACLs alone. So
    these run on Windows too. The cwd is an empty directory: on POSIX a fixed name such a test
    reached by mistake would resolve there and find nothing.
    """
    (tmp_path / "cwd").mkdir()
    monkeypatch.chdir(tmp_path / "cwd")
    return FakeUpgradeHost(
        state_log=tmp_path / "upgrade-state.log",
        existing=set(LOCK_DIRS),
        locked=list(LOCK_DIRS),
        entries=[TOOL, SETUP],
    )


# --- prepare --------------------------------------------------------------------------------


def test_prepare_clears_read_only_on_every_file_below_the_stage_root(
    stage: Path, fileless_host: FakeUpgradeHost
) -> None:
    nested = stage / "sources" / "sxs" / "x.cab"
    nested.parent.mkdir()
    nested.write_bytes(b"cab")
    for path in (nested, stage / "setup.exe"):
        path.chmod(stat.S_IREAD)

    code, envelope = _run(fileless_host, "prepare", "--stage-root", str(stage))

    assert code == 0
    assert _data(envelope)["readonly_cleared"] == 2
    assert nested.stat().st_mode & stat.S_IWRITE
    assert (stage / "setup.exe").stat().st_mode & stat.S_IWRITE


def test_prepare_passes_media_newer_than_the_running_build_and_writes_the_waiver(
    stage: Path, fileless_host: FakeUpgradeHost
) -> None:
    code, envelope = _run(fileless_host, "prepare", "--stage-root", str(stage))

    assert code == 0
    data = _data(envelope)
    assert (data["gate"], data["reason"]) == ("PASS", None)
    assert data["image"] == {
        "index": 1,
        "name": "Windows-Image-0001",
        "edition": "Professional",
        "build": 26200,
        "spbuild": 8973,
        "languages": ["de-DE"],
        "default_language": "de-DE",
    }
    assert data["running"] == {"current_build": "26200", "ubr": 8875, "build": "26200.8875"}
    assert fileless_host.calls == ["create MoSetup", f"set {WAIVER}=1"]
    assert (data["waiver_readback"], data["tpm_present"]) == (1, True)
    assert [at(d, "letter") for d in items(data, "drives")] == ["C", "D"]


def test_prepare_passes_media_equal_to_the_running_build(stage: Path, fileless_host: FakeUpgradeHost) -> None:
    fileless_host.ubr = 8973

    code, envelope = _run(fileless_host, "prepare", "--stage-root", str(stage))

    assert (code, _data(envelope)["gate"]) == (0, "PASS")


def test_prepare_refuses_media_older_than_the_running_build(stage: Path, fileless_host: FakeUpgradeHost) -> None:
    fileless_host.ubr = 9711

    code, envelope = _run(fileless_host, "prepare", "--stage-root", str(stage))

    assert code == 1
    data = _data(envelope)
    assert (data["gate"], data["reason"]) == ("FAIL", "image 26200.8973 older than running 26200.9711")
    assert fileless_host.calls == []  # nothing changed on a refused gate


def test_prepare_refuses_media_of_an_older_build_whatever_its_spbuild(
    stage: Path, fileless_host: FakeUpgradeHost
) -> None:
    # The fixture's image is 26200.8973: its SPBuild beats UBR 100, its build does not beat 26300.
    fileless_host.current_build, fileless_host.ubr = "26300", 100

    code, envelope = _run(fileless_host, "prepare", "--stage-root", str(stage))

    assert code == 1
    data = _data(envelope)
    assert (data["gate"], data["reason"]) == ("FAIL", "image 26200.8973 older than running 26300.100")
    assert fileless_host.calls == []


def test_prepare_passes_media_of_a_newer_build_whatever_its_spbuild(
    stage: Path, fileless_host: FakeUpgradeHost
) -> None:
    fileless_host.current_build, fileless_host.ubr = "26100", 9999

    code, envelope = _run(fileless_host, "prepare", "--stage-root", str(stage))

    assert (code, _data(envelope)["gate"]) == (0, "PASS")


def test_prepare_refuses_a_missing_wim(stage: Path, fileless_host: FakeUpgradeHost) -> None:
    (stage / "sources" / "install.wim").unlink()

    code, envelope = _run(fileless_host, "prepare", "--stage-root", str(stage))

    assert code == 1
    assert (_data(envelope)["gate"], _data(envelope)["reason"]) == ("FAIL", "install.wim missing")


def test_prepare_refuses_a_wim_it_cannot_read(stage: Path, fileless_host: FakeUpgradeHost) -> None:
    (stage / "sources" / "install.wim").write_bytes(b"NOTAWIM!" + bytes(300))

    code, envelope = _run(fileless_host, "prepare", "--stage-root", str(stage))

    assert code == 1
    reason = _data(envelope)["reason"]
    assert isinstance(reason, str)
    assert reason.startswith("the WIM reader refused the image: ")


def _with_xml(text: str) -> bytes:
    """The fixture's real header followed by ``text`` as its UTF-16LE XML resource (BOM-led)."""
    xml = codecs.BOM_UTF16_LE + text.encode("utf-16-le")
    header = bytearray(FIXTURE.read_bytes()[:WIM_HEADER])
    header[WIM_XML_SIZE : WIM_XML_SIZE + 7] = len(xml).to_bytes(7, "little")
    return bytes(header) + xml


def _image_xml(version: str) -> str:
    return f'<WIM><IMAGE INDEX="1"><WINDOWS><VERSION>{version}</VERSION></WINDOWS><NAME>n</NAME></IMAGE></WIM>'


def test_prepare_reports_the_real_media_image_in_the_field_names_the_node_reads(
    stage: Path, fileless_host: FakeUpgradeHost
) -> None:
    # The node copies image.build and image.spbuild into the repair receipt: pwshpy's record says
    # sp_build, the envelope must keep saying spbuild.
    code, envelope = _run(fileless_host, "prepare", "--stage-root", str(stage))

    assert code == 0
    assert _data(envelope)["image"] == {
        "index": 1,
        "name": "Windows-Image-0001",
        "edition": "Professional",
        "build": 26200,
        "spbuild": 8973,
        "languages": ["de-DE"],
        "default_language": "de-DE",
    }


def test_the_fleet_media_xml_resource_is_flagged_uncompressed() -> None:
    # pwshpy refuses an XML resource flagged compressed (0x04); the real media's flag byte carries
    # only 0x02 (metadata), so the fleet's install.wim is read, not refused.
    assert FIXTURE.read_bytes()[WIM_XML_FLAGS] == 0x02


def test_prepare_refuses_a_wim_whose_xml_resource_is_compressed(stage: Path, fileless_host: FakeUpgradeHost) -> None:
    data = bytearray(FIXTURE.read_bytes())
    data[WIM_XML_FLAGS] |= 0x04
    (stage / "sources" / "install.wim").write_bytes(bytes(data))

    code, envelope = _run(fileless_host, "prepare", "--stage-root", str(stage))

    reason = _data(envelope)["reason"]
    assert code == 1
    assert isinstance(reason, str)
    assert reason.startswith("the WIM reader refused the image: ")
    assert "compressed" in reason


def test_prepare_refuses_a_wim_whose_xml_declares_an_entity(stage: Path, fileless_host: FakeUpgradeHost) -> None:
    # An entity declaration is the expansion-attack vector; no WIM writer emits a DTD.
    xml = '<!DOCTYPE WIM [<!ENTITY b "26200">]>' + _image_xml("<BUILD>&b;</BUILD><SPBUILD>8973</SPBUILD>")
    (stage / "sources" / "install.wim").write_bytes(_with_xml(xml))

    code, envelope = _run(fileless_host, "prepare", "--stage-root", str(stage))

    reason = _data(envelope)["reason"]
    assert code == 1
    assert isinstance(reason, str)
    assert reason.startswith("the WIM reader refused the image: ")


@pytest.mark.parametrize("build", ["", "<BUILD>26a00</BUILD>"])
def test_prepare_refuses_media_whose_image_names_no_build(
    stage: Path, fileless_host: FakeUpgradeHost, build: str
) -> None:
    (stage / "sources" / "install.wim").write_bytes(_with_xml(_image_xml(f"{build}<SPBUILD>8973</SPBUILD>")))

    code, envelope = _run(fileless_host, "prepare", "--stage-root", str(stage))

    assert code == 1
    assert (_data(envelope)["gate"], _data(envelope)["reason"]) == (
        "FAIL",
        "image index 1 names no build (WINDOWS/VERSION/BUILD missing or not a number)",
    )


def test_prepare_reports_drives_through_the_shared_parser(stage: Path, fileless_host: FakeUpgradeHost) -> None:
    fileless_host.disks = [
        _disk("C:", 50 * 1024**3),
        CimInstance(class_name="Win32_LogicalDisk", properties={"DeviceID": "E:", "FreeSpace": "n/a"}),
    ]

    code, envelope = _run(fileless_host, "prepare", "--stage-root", str(stage))

    assert code == 0
    assert [at(d, "letter") for d in items(envelope, "data", "drives")] == ["C"]
    assert "E:" in [at(s, "item") for s in items(envelope, "skipped")]


def test_prepare_reports_tpm_absent_and_unknown_distinctly(stage: Path, fileless_host: FakeUpgradeHost) -> None:
    fileless_host.tpm = []
    _, absent = _run(fileless_host, "prepare", "--stage-root", str(stage))
    fileless_host.tpm = None
    code, unknown = _run(fileless_host, "prepare", "--stage-root", str(stage))

    assert _data(absent)["tpm_present"] is False
    assert (code, _data(unknown)["tpm_present"]) == (0, None)
    assert unknown["skipped"] == [{"item": "Win32_Tpm", "reason": "Zugriff verweigert"}]


def test_prepare_reports_a_waiver_that_did_not_read_back(stage: Path, fileless_host: FakeUpgradeHost) -> None:
    fileless_host.waiver_fails = True

    code, envelope = _run(fileless_host, "prepare", "--stage-root", str(stage))

    assert code == 0  # the old script did not gate on the waiver either; the readback says it
    assert _data(envelope)["waiver_readback"] is None
    assert {"item": f"{MOSETUP}\\{WAIVER}", "reason": "Zugriff verweigert"} in items(envelope, "skipped")


def _running(current_build: str, ubr: int) -> probes.BuildInfo:
    return probes.BuildInfo(current_build=current_build, ubr=ubr, build=f"{current_build}.{ubr}")


@pytest.mark.parametrize(
    ("build", "spbuild", "gate"),
    [
        (19045, 9000, "FAIL"),  # an older build with a higher SPBuild than the guest's UBR
        (26100, 9000, "FAIL"),
        (26200, 7461, "FAIL"),
        (26200, 7462, "PASS"),
        (26200, 8973, "PASS"),
        (26300, 1, "PASS"),  # a newer build with a lower SPBuild
    ],
)
def test_wim_gate_compares_build_and_spbuild_against_the_running_build(build: int, spbuild: int, gate: str) -> None:
    image = WimImage(
        index=1, name="n", edition="e", build=build, spbuild=spbuild, languages=("de-DE",), default_language="de-DE"
    )

    assert upgrade.wim_gate((image,), _running("26200", 7462)).gate == upgrade.PrepareGate(gate)


def test_wim_gate_refuses_a_running_build_that_is_not_a_number() -> None:
    image = WimImage(
        index=1, name="n", edition="e", build=26200, spbuild=8973, languages=("de-DE",), default_language="de-DE"
    )

    gated = upgrade.wim_gate((image,), _running("26200a", 7462))

    assert gated == upgrade.GateResult(
        gate=upgrade.PrepareGate.FAILED, reason="running CurrentBuild '26200a' is not a number", image=image
    )


def test_wim_gate_refuses_media_without_image_index_1() -> None:
    image = WimImage(
        index=2, name="n", edition="e", build=26200, spbuild=9999, languages=("de-DE",), default_language="de-DE"
    )

    assert upgrade.wim_gate((image,), _running("26200", 8875)) == upgrade.GateResult(
        gate=upgrade.PrepareGate.FAILED, reason="the WIM has no image index 1", image=None
    )


# --- the reports' closed value sets ---------------------------------------------------------

_WAIT = upgrade.LaunchWait(status=upgrade.LaunchWaitStatus.LAUNCHED, waited_s=1.0, last_error=None)
_CLEANUP = upgrade.TaskCleanup(
    action=upgrade.TaskCleanupAction.DISARM, ended=None, disabled=False, deleted=True, error=None
)
_LOCK = upgrade.DirectoryLock(path=r"C:\winrepair", action=upgrade.DirectoryAction.CREATED)


@pytest.mark.parametrize(
    ("report", "field", "planted"),
    [
        (_WAIT, "status", "SOON"),
        (_CLEANUP, "action", "EVICT"),
        (_LOCK, "action", ""),
        (
            upgrade.LockDirsReport(
                tool=TOOL,
                tool_present=False,
                tool_sha256=None,
                directories=(_LOCK,),
                verdict=upgrade.LockDirsVerdict.OK,
                reason=None,
            ),
            "verdict",
            "MAYBE",
        ),
        (
            upgrade.LaunchReport(
                task="OVMRepairUpgrade",
                command="x",
                stale_log_removed=False,
                registered=True,
                wait=_WAIT,
                setuphost=1,
                state=None,
                task_cleanup=_CLEANUP,
                verdict=upgrade.LaunchVerdict.OK,
                reason=None,
            ),
            "verdict",
            "MAYBE",
        ),
        (
            upgrade.UpgradeRunReport(
                state_log=STATE_LOG,
                setup=SETUP,
                argv=(),
                build_before=None,
                build_after=None,
                exit_code=0,
                exit_hex="0x00000000",
                seconds=1.0,
                tree_wait=upgrade.TreeWait.JOB,
                newos_staged=True,
                verdict=probes.StateVerdict.DONE_OK,
                reason=None,
            ),
            "verdict",
            "DONE-MAYBE",
        ),
        (upgrade.SetupRun(exit_code=0, tree_wait=upgrade.TreeWait.JOB), "tree_wait", "wait"),
    ],
    ids=lambda value: type(value).__name__ if isinstance(value, BaseModel) else str(value),
)
def test_a_report_refuses_a_value_outside_its_closed_set(report: BaseModel, field: str, planted: str) -> None:
    # Each of these fields was free text, so a misspelt verdict or action reached the host as-is.
    sent = report.model_dump(mode="json")

    assert type(report).model_validate(sent) == report
    with pytest.raises(ValidationError, match=field):
        type(report).model_validate(sent | {field: planted})


def test_mo_setup_reads_only_a_dword_waiver() -> None:
    # A waiver read back as text is not the DWORD prepare wrote: it reads as None.
    assert upgrade.mo_setup([_reg(WAIVER, 1)]).waiver == 1
    assert upgrade.mo_setup([_reg(WAIVER, "1")]).waiver is None
    assert upgrade.mo_setup([_reg("Other", 1)]).waiver is None


# --- launch ---------------------------------------------------------------------------------


def _spec(host: FakeUpgradeHost) -> upgrade.TaskSpec:
    return upgrade.TaskSpec(
        path="\\OVMRepairUpgrade",
        program=POWERSHELL,
        arguments=TASK_ARGS.format(log=host.state_log),
        user_id="S-1-5-18",  # SYSTEM by SID: the account name is localised on a German guest
        logon_type=5,  # TASK_LOGON_SERVICE_ACCOUNT
        run_level=1,  # TASK_RUNLEVEL_HIGHEST
        execution_time_limit="PT72H",
        multiple_instances=2,  # TASK_INSTANCES_IGNORE_NEW
        disallow_start_on_batteries=False,
        stop_on_batteries=False,
    )


def _launch(host: FakeUpgradeHost) -> tuple[int, dict[str, object]]:
    return _run(host, "launch", "--stage-root", r"D:\upgrade", "--state-log", STATE_LOG, "--tool", TOOL)


def test_launch_creates_and_starts_the_system_task_after_removing_the_stale_log(
    host: FakeUpgradeHost,
) -> None:
    host.state_log.write_text("2026-08-01 10:00:00  STATE=DONE-OK reboot required to apply\n", encoding="utf-8")
    host.task_lines = [
        (20.0, "=== upgrade_run start ==="),
        (30.0, "launching: D:\\upgrade\\setup.exe /auto upgrade"),
    ]

    code, envelope = _launch(host)

    assert code == 0
    assert host.registered == [_spec(host)]
    # launch writes no DACL: lock-dirs locked both directories before anything was copied in.
    assert host.calls == ["register", "start \\OVMRepairUpgrade", "delete"]
    data = _data(envelope)
    assert (data["verdict"], data["setuphost"], data["registered"]) == ("OK", 1, True)
    assert data["command"] == f"{POWERSHELL} {TASK_ARGS}"
    assert data["wait"] == {"status": "LAUNCHED", "waited_s": 30.0, "last_error": None}


def test_launch_starts_the_150_second_check_only_after_the_launching_line(host: FakeUpgradeHost) -> None:
    # A first SYSTEM run may spend minutes bootstrapping uv and Python before setup starts.
    host.task_lines = [(420.0, "launching: D:\\upgrade\\setup.exe")]

    code, envelope = _launch(host)

    assert code == 0
    assert at(envelope, "data", "wait", "waited_s") == 420.0
    assert host.now_s == 420.0 + 150.0


def test_launch_gives_up_after_ten_minutes_without_a_launching_line(host: FakeUpgradeHost) -> None:
    host.task_lines = [(5.0, "=== upgrade_run start ===")]

    code, envelope = _launch(host)

    assert code == 1
    data = _data(envelope)
    assert data["verdict"] == "NO_START"
    assert at(data, "wait", "status") == "TIMEOUT"
    assert host.now_s == 600.0
    assert data["setuphost"] is None


def test_launch_is_suspect_at_once_when_the_run_ends_before_launching(host: FakeUpgradeHost) -> None:
    host.task_lines = [(10.0, "STATE=DONE-FAIL setup.exe missing")]

    code, envelope = _launch(host)

    assert code == 1
    data = _data(envelope)
    assert (data["verdict"], at(data, "wait", "status")) == ("SUSPECT", "ENDED")
    assert host.now_s == 10.0
    assert at(data, "state", "verdict") == "DONE-FAIL"


def test_launch_is_suspect_when_setuphost_is_gone_after_150_seconds(host: FakeUpgradeHost) -> None:
    host.task_lines = [(5.0, "launching: D:\\upgrade\\setup.exe")]
    host.setuphost = 0

    code, envelope = _launch(host)

    assert code == 1
    assert (_data(envelope)["verdict"], _data(envelope)["setuphost"]) == ("SUSPECT", 0)


def test_launch_fails_when_the_task_cannot_be_registered(host: FakeUpgradeHost) -> None:
    host.register_fails = True

    code, envelope = _launch(host)

    assert code == 1
    data = _data(envelope)
    assert (data["verdict"], data["registered"]) == ("FAILED", False)
    assert data["reason"] == "the task could not be registered: Zugriff verweigert"
    assert host.calls[-1] == "register"


def test_launch_fails_when_the_task_cannot_be_started(host: FakeUpgradeHost) -> None:
    host.start_fails = True

    code, envelope = _launch(host)

    assert code == 1
    assert _data(envelope)["verdict"] == "FAILED"


# --- launch: the SYSTEM task's lifecycle ------------------------------------------------------

DISARMED = {"action": "DISARM", "ended": None, "disabled": False, "deleted": True, "error": None}
REMOVED = {"action": "REMOVE", "ended": True, "disabled": False, "deleted": True, "error": None}


def test_launch_disarms_the_task_as_soon_as_setup_is_launching(host: FakeUpgradeHost) -> None:
    # The task has no trigger, but a definition left behind could still be started by hand or by
    # a second launch while this setup runs; it has no use once the run is launching.
    host.task_lines = [(30.0, "launching: D:\\upgrade\\setup.exe")]

    code, envelope = _launch(host)

    assert code == 0
    assert host.task is None  # the definition is gone, so nothing can start it by name
    assert "end" not in host.calls  # the running upgrade-run must not be killed
    assert host.task_events == [(30.0, "delete")]  # before the 150 s SetupHost check, not after
    assert _data(envelope)["task_cleanup"] == DISARMED


def test_launch_disarms_without_ending_when_setup_is_gone_after_150_seconds(host: FakeUpgradeHost) -> None:
    # upgrade-run saw setup exit and is about to write its marker: ending it would lose the verdict.
    host.task_lines = [(5.0, "launching: D:\\upgrade\\setup.exe")]
    host.setuphost = 0

    code, envelope = _launch(host)

    assert (code, _data(envelope)["verdict"]) == (1, "SUSPECT")
    assert "end" not in host.calls
    assert _data(envelope)["task_cleanup"] == DISARMED


def test_launch_ends_and_deletes_a_task_that_never_launched_setup(host: FakeUpgradeHost) -> None:
    # A slow bootstrap would otherwise still start setup after launch reported NO_START.
    host.task_lines = [(5.0, "=== upgrade_run start ===")]

    code, envelope = _launch(host)

    assert (code, _data(envelope)["verdict"]) == (1, "NO_START")
    assert host.calls[-2:] == ["end", "delete"]
    assert host.task is None
    assert _data(envelope)["task_cleanup"] == REMOVED


def test_launch_ends_and_deletes_the_task_when_the_run_ended_before_launching(host: FakeUpgradeHost) -> None:
    host.task_lines = [(10.0, "STATE=DONE-FAIL setup.exe missing")]

    code, envelope = _launch(host)

    assert (code, _data(envelope)["verdict"]) == (1, "SUSPECT")
    assert host.calls[-2:] == ["end", "delete"]
    assert _data(envelope)["task_cleanup"] == REMOVED


def test_launch_deletes_a_task_that_was_created_but_could_not_be_started(host: FakeUpgradeHost) -> None:
    # Left behind, anyone starting it by name would run setup with nobody watching.
    host.start_fails = True

    code, envelope = _launch(host)

    assert (code, _data(envelope)["verdict"]) == (1, "FAILED")
    assert host.calls[-1] == "delete"
    assert "end" not in host.calls  # nothing runs, so nothing to end
    assert host.task is None
    assert _data(envelope)["task_cleanup"] == REMOVED


def test_launch_has_nothing_to_remove_when_the_task_was_never_created(host: FakeUpgradeHost) -> None:
    host.register_fails = True

    _, envelope = _launch(host)

    assert _data(envelope)["task_cleanup"] == REMOVED


def test_launch_says_task_left_when_the_launched_task_cannot_be_deleted(host: FakeUpgradeHost) -> None:
    host.task_lines = [(30.0, "launching: D:\\upgrade\\setup.exe")]
    host.delete_fails = True

    code, envelope = _launch(host)

    assert (code, envelope["ok"]) == (1, False)  # never a silent OK with the task still defined
    data = _data(envelope)
    assert data["verdict"] == "TASK_LEFT"
    assert str(data["reason"]).startswith("OK; the task \\OVMRepairUpgrade could not be disarmed: delete: ")
    assert host.disabled  # the fallback: the definition stays, but it refuses any start
    assert data["task_cleanup"] == {
        "action": "DISARM", "ended": None, "disabled": True, "deleted": False,
        "error": "delete: Zugriff verweigert",
    }  # fmt: skip


def test_launch_keeps_a_task_it_could_not_end_so_it_can_still_be_ended_by_name(
    host: FakeUpgradeHost,
) -> None:
    host.task_lines = [(5.0, "=== upgrade_run start ===")]
    host.stop_fails = True

    code, envelope = _launch(host)

    assert code == 1
    data = _data(envelope)
    assert data["verdict"] == "TASK_LEFT"
    assert str(data["reason"]).startswith("NO_START: no 'launching' line within 600 s; the task ")
    assert "delete" not in host.calls
    assert (host.task, host.disabled) == (TaskState.RUNNING, True)
    assert data["task_cleanup"] == {
        "action": "REMOVE", "ended": False, "disabled": True, "deleted": False,
        "error": "end: Zugriff verweigert",
    }  # fmt: skip


def test_launch_waits_a_bounded_time_for_an_ended_task_to_stop_running(host: FakeUpgradeHost) -> None:
    host.task_lines = [(5.0, "=== upgrade_run start ===")]
    host.stop_ignored = True

    _, envelope = _launch(host)

    data = _data(envelope)
    assert data["verdict"] == "TASK_LEFT"
    assert at(data, "task_cleanup", "error") == "end: still running 30 s after the end request"
    assert host.now_s == 600.0 + 30.0


def test_launch_says_task_left_when_the_task_state_cannot_be_read(host: FakeUpgradeHost) -> None:
    host.start_fails = True
    host.state_fails = True

    _, envelope = _launch(host)

    data = _data(envelope)
    assert data["verdict"] == "TASK_LEFT"
    assert data["task_cleanup"] == {
        "action": "REMOVE", "ended": None, "disabled": False, "deleted": False,
        "error": "read: Task Scheduler unavailable",
    }  # fmt: skip


# --- launch: the task definition handed to the Task Scheduler COM API -------------------------
# Recording stand-ins for the COM objects; their member names are the COM interfaces' own.


class _ComTriggers:
    def __init__(self) -> None:
        self.created: list[int] = []

    @property
    def Count(self) -> int:  # noqa: N802 - mirrors the pywin32 / COM member name
        return len(self.created)

    def Create(self, kind: int) -> SimpleNamespace:  # noqa: N802 - mirrors the pywin32 / COM member name
        self.created.append(kind)
        return SimpleNamespace()


class _ComActions:
    def __init__(self) -> None:
        self.created: list[SimpleNamespace] = []

    def Create(self, kind: int) -> SimpleNamespace:  # noqa: N802 - mirrors the pywin32 / COM member name
        action = SimpleNamespace(kind=kind, Path=None, Arguments=None)
        self.created.append(action)
        return action


class _ComDefinition:
    def __init__(self) -> None:
        # Sentinels that differ from every value the assertions below expect, so a field the code
        # forgets to set reads wrong - even where it would equal the scheduler's own default.
        self.RegistrationInfo = SimpleNamespace(Description="")
        self.Principal = SimpleNamespace(UserId="", LogonType=3, RunLevel=0)
        self.Settings = SimpleNamespace(
            Enabled=False, AllowDemandStart=False, AllowHardTerminate=False, ExecutionTimeLimit="PT0S",
            MultipleInstances=0, DisallowStartIfOnBatteries=True, StopIfGoingOnBatteries=True,
        )  # fmt: skip
        self.Triggers = _ComTriggers()
        self.Actions = _ComActions()


class _ComFolder:
    def __init__(self, fails: bool) -> None:
        self.fails = fails
        self.registered: list[tuple[object, ...]] = []

    def RegisterTaskDefinition(self, *args: object) -> SimpleNamespace:  # noqa: N802 - mirrors the pywin32 / COM member name
        if self.fails:
            raise OSError(-2147024891, "Zugriff verweigert")  # what pywintypes.com_error looks like
        self.registered.append(args)
        return SimpleNamespace()


class _ComService:
    def __init__(self, *, fails: bool = False) -> None:
        self.folders: list[str] = []
        self.definition = _ComDefinition()
        self.folder = _ComFolder(fails)

    def GetFolder(self, path: str) -> _ComFolder:  # noqa: N802 - mirrors the pywin32 / COM member name
        self.folders.append(path)
        return self.folder

    def NewTask(self, flags: int) -> _ComDefinition:  # noqa: N802 - mirrors the pywin32 / COM member name
        assert flags == 0
        return self.definition


def test_register_on_demand_defines_a_system_task_with_no_trigger(fileless_host: FakeUpgradeHost) -> None:
    service = _ComService()

    upgrade.register_on_demand(lambda: service, _spec(fileless_host))

    definition = service.definition
    assert definition.Triggers.created == []  # nothing can start it but an explicit Run
    assert definition.Triggers.Count == 0
    assert vars(definition.Principal) == {"UserId": "S-1-5-18", "LogonType": 5, "RunLevel": 1}
    assert vars(definition.Settings) == {
        "Enabled": True, "AllowDemandStart": True, "AllowHardTerminate": True,
        "ExecutionTimeLimit": "PT72H", "MultipleInstances": 2,
        "DisallowStartIfOnBatteries": False, "StopIfGoingOnBatteries": False,
    }  # fmt: skip
    assert [(a.kind, a.Path, a.Arguments) for a in definition.Actions.created] == [(0, POWERSHELL, TASK_ARGS)]
    assert service.folders == ["\\"]
    # TASK_CREATE_OR_UPDATE (the old /F), the principal again (the API wants it here too), no password.
    assert service.folder.registered == [("OVMRepairUpgrade", definition, 6, "S-1-5-18", None, 5)]


def test_register_on_demand_raises_a_pwshpy_error_when_the_scheduler_refuses(fileless_host: FakeUpgradeHost) -> None:
    with pytest.raises(NativeCallError, match="Zugriff verweigert"):
        upgrade.register_on_demand(lambda: _ComService(fails=True), _spec(fileless_host))


def test_register_on_demand_raises_a_pwshpy_error_when_the_scheduler_is_unreachable(
    fileless_host: FakeUpgradeHost,
) -> None:
    def connect() -> _ComService:
        raise OSError("Der RPC-Server ist nicht verfuegbar")

    with pytest.raises(NativeCallError, match="RPC-Server"):
        upgrade.register_on_demand(connect, _spec(fileless_host))


class _ComError(Exception):
    """Stands in for pywintypes.com_error, which derives from Exception and not from OSError."""


def test_register_on_demand_wraps_a_com_error(fileless_host: FakeUpgradeHost) -> None:
    def connect() -> _ComService:
        raise _ComError(-2147024891, "Zugriff verweigert", None, None)

    with pytest.raises(NativeCallError, match="Zugriff verweigert"):
        upgrade.register_on_demand(connect, _spec(fileless_host), com_errors=(_ComError,))


def test_register_on_demand_lets_a_programming_error_through_as_internal(fileless_host: FakeUpgradeHost) -> None:
    # A typo in _define must be exit 2 (internal), never a FAILED verdict that reads like a refusal.
    def connect() -> SimpleNamespace:
        return SimpleNamespace()  # no NewTask: AttributeError inside _define

    with pytest.raises(AttributeError):
        upgrade.register_on_demand(connect, _spec(fileless_host), com_errors=(_ComError,))


@pytest.mark.parametrize(
    "root",
    [
        r"D:\up grade",
        'D:\\up"grade',
        "upgrade",
        r"D:\upgrade&calc",
        "D:\\upgrade\\",
        r"D:\..\x",
        r"D:\up\..\x",
        "/tmp/up",
    ],
)
def test_launch_refuses_a_stage_root_that_cannot_ride_in_the_task_command(
    fileless_host: FakeUpgradeHost, root: str
) -> None:
    code, envelope = _run(fileless_host, "launch", "--stage-root", root, "--tool", TOOL)

    assert code == 2
    assert "stage root" in str(_data(envelope)["error"])
    assert fileless_host.calls == []


@pytest.mark.parametrize(
    ("flag", "value"),
    [
        ("--tool", "winrepair_guest-0123456789abcdef.ps1"),
        ("--tool", r"..\winrepair_guest-0123456789abcdef.ps1"),
        ("--state-log", "upgrade-state.log"),
        ("--state-log", "/tmp/upgrade-state.log"),
        ("--state-log", r"C:\..\upgrade-state.log"),
    ],
)
def test_launch_refuses_a_relative_tool_or_state_log(fileless_host: FakeUpgradeHost, flag: str, value: str) -> None:
    # The SYSTEM task starts in System32: a relative path there names a different file.
    args = {"--tool": TOOL, "--state-log": STATE_LOG, flag: value}
    code, envelope = _run(
        fileless_host, "launch", "--stage-root", r"D:\upgrade", *(x for kv in args.items() for x in kv)
    )

    assert code == 2
    assert repr(value) in str(_data(envelope)["error"])
    assert fileless_host.calls == []


def test_launch_without_tool_is_a_usage_error_and_starts_nothing(fileless_host: FakeUpgradeHost) -> None:
    # No default: the tool lives under a content address only the driver knows, and a default
    # path would register a task whose action runs a file that is not there.
    code, envelope = _run(fileless_host, "launch", "--stage-root", r"D:\upgrade", "--state-log", STATE_LOG)

    assert code == 2
    assert "--tool" in str(_data(envelope))
    assert fileless_host.calls == []
    assert fileless_host.registered == []


def test_wait_for_launch_keeps_polling_through_read_errors() -> None:
    clock = [0.0]
    reads = iter([OSError("locked"), [], ["x  launching: setup.exe"]])

    def read() -> list[str]:
        item = next(reads)
        if isinstance(item, OSError):
            raise item
        return item

    def sleep(seconds: float) -> None:
        clock[0] += seconds

    wait = upgrade.wait_for_launch(read, clock=lambda: clock[0], sleep=sleep)

    assert wait == upgrade.LaunchWait(status=upgrade.LaunchWaitStatus.LAUNCHED, waited_s=10.0, last_error="locked")


# --- upgrade-run ----------------------------------------------------------------------------


def _run_upgrade(host: FakeUpgradeHost, stage: Path) -> tuple[int, dict[str, object]]:
    return _run(host, "upgrade-run", "--stage-root", str(stage), "--state-log", str(host.state_log))


def _log(host: FakeUpgradeHost) -> list[str]:
    return host.state_log.read_bytes().decode("utf-8").split("\r\n")[:-1]


def test_upgrade_run_writes_the_state_log_and_marks_success(stage: Path, fileless_host: FakeUpgradeHost) -> None:
    code, envelope = _run_upgrade(fileless_host, stage)

    assert code == 0
    setup = str(stage / "setup.exe")
    assert fileless_host.setup_argv == [
        setup, "/auto", "upgrade", "/quiet", "/eula", "accept", "/noreboot",
        "/compat", "ignorewarning", "/dynamicupdate", "disable", "/copylogs", f"{stage}-logs",
    ]  # fmt: skip
    assert _log(fileless_host) == [
        "2026-10-21 10:00:00  === upgrade_run start ===",
        "2026-10-21 10:00:00  whoami=NT AUTHORITY\\SYSTEM (S-1-5-18)",
        "2026-10-21 10:00:00  build_before=26200.8875",
        "2026-10-21 10:00:00  free_C_GB=50.0",
        f"2026-10-21 10:00:00  launching: {setup} " + " ".join(fileless_host.setup_argv[1:]),
        "2026-10-21 11:02:05  setup exit=0x00000000 (0) after 01:02:05",
        "2026-10-21 11:02:05  setup tree wait=job",
        "2026-10-21 11:02:05  build_after_downlevel=26200.8875 (unchanged until the apply reboot)",
        "2026-10-21 11:02:05  NewOS_staged=True",
        "2026-10-21 11:02:05  STATE=DONE-OK reboot required to apply",
        "2026-10-21 11:02:05  === upgrade_run end ===",
    ]
    data = _data(envelope)
    assert (data["verdict"], data["exit_code"], data["exit_hex"]) == ("DONE-OK", 0, "0x00000000")
    assert (data["seconds"], data["newos_staged"], data["build_before"]) == (3725.0, True, "26200.8875")
    assert probes.read_state(fileless_host.state_log).verdict == "DONE-OK"


@pytest.mark.parametrize("exit_code", [3010, 0x3010])
def test_upgrade_run_accepts_the_reboot_required_codes(
    stage: Path, fileless_host: FakeUpgradeHost, exit_code: int
) -> None:
    fileless_host.setup_exit = exit_code

    code, envelope = _run_upgrade(fileless_host, stage)

    assert (code, _data(envelope)["verdict"]) == (0, "DONE-OK")


def test_upgrade_run_marks_a_setup_failure_with_its_hresult(stage: Path, fileless_host: FakeUpgradeHost) -> None:
    fileless_host.setup_exit = 0xC1900200  # ps.exec reports the DWORD unsigned (measured on a test guest)
    fileless_host.setup_seconds = 30.0

    code, envelope = _run_upgrade(fileless_host, stage)

    assert code == 1
    log = _log(fileless_host)
    assert "2026-10-21 10:00:30  setup exit=0xC1900200 (-1047526912) after 00:00:30" in log
    assert "2026-10-21 10:00:30  STATE=DONE-FAIL rc=0xC1900200" in log
    assert _data(envelope)["exit_hex"] == "0xC1900200"
    assert probes.read_state(fileless_host.state_log).verdict == "DONE-FAIL"


def test_upgrade_run_fails_without_setup_exe(stage: Path, fileless_host: FakeUpgradeHost) -> None:
    (stage / "setup.exe").unlink()

    code, envelope = _run_upgrade(fileless_host, stage)

    assert code == 1
    assert _log(fileless_host)[-1] == "2026-10-21 10:00:00  STATE=DONE-FAIL setup.exe missing"
    assert fileless_host.setup_argv == []
    assert _data(envelope)["verdict"] == "DONE-FAIL"


def test_upgrade_run_marks_a_setup_that_could_not_start(stage: Path, fileless_host: FakeUpgradeHost) -> None:
    fileless_host.setup_fails = True

    code, _ = _run_upgrade(fileless_host, stage)

    assert code == 1
    assert "STATE=DONE-FAIL setup.exe could not run: Executable not found" in _log(fileless_host)[-2]


def test_upgrade_run_leaves_a_fail_marker_when_it_crashes(stage: Path, fileless_host: FakeUpgradeHost) -> None:
    fileless_host.setup_crash = True

    code, envelope = _run_upgrade(fileless_host, stage)

    assert (code, envelope["ok"]) == (2, False)
    assert _log(fileless_host)[-1] == "2026-10-21 10:00:00  STATE=DONE-FAIL internal error: RuntimeError: boom"
    assert probes.read_state(fileless_host.state_log).verdict == "DONE-FAIL"


def test_upgrade_run_carries_on_past_an_unreadable_build(stage: Path, fileless_host: FakeUpgradeHost) -> None:
    fileless_host.registry_fails = True

    code, envelope = _run_upgrade(fileless_host, stage)

    assert code == 0
    assert "2026-10-21 10:00:00  build_before=unknown (NativeCallError: registry unavailable)" in _log(fileless_host)
    assert _data(envelope)["build_before"] is None


@dataclass
class _ShapeChangedHost(FakeUpgradeHost):
    """whoami fails the way a pywin32 shape change would: neither OSError nor a pwshpy error."""

    def whoami(self) -> str:
        raise TypeError("'NoneType' object is not subscriptable")


def test_upgrade_run_launches_setup_when_whoami_fails_with_any_error(stage: Path, tmp_path: Path) -> None:
    host = _ShapeChangedHost(state_log=tmp_path / "upgrade-state.log")

    code, _ = _run_upgrade(host, stage)

    assert code == 0
    assert host.setup_argv[0] == str(stage / "setup.exe")
    assert _log(host)[1] == "2026-10-21 10:00:00  whoami=unknown (TypeError: 'NoneType' object is not subscriptable)"


def test_upgrade_run_appends_to_an_existing_log(stage: Path, fileless_host: FakeUpgradeHost) -> None:
    fileless_host.state_log.write_bytes(b"earlier line\r\n")

    _run_upgrade(fileless_host, stage)

    assert _log(fileless_host)[0] == "earlier line"


def test_exit_text_formats_like_the_old_powershell_line() -> None:
    assert upgrade.exit_hex(3247440384) == "0xC1900200"
    assert upgrade.signed32(3247440384) == -1047526912
    assert upgrade.signed32(3010) == 3010
    assert upgrade.elapsed_text(3725.4) == "01:02:05"


def test_account_text_names_the_token_account_with_its_sid_not_the_computer_account() -> None:
    # Measured on a test guest: GetUserNameEx(NameSamCompatible) under the SYSTEM task returned
    # the computer account EXAMPLE\\WIN-HOST$, so the state log never showed the run was SYSTEM.
    # pwshpy's get_current_identity reads the token, so a SYSTEM run reads as SYSTEM.
    system = CurrentIdentity(sid=SYSTEM_SID, account="NT AUTHORITY\\SYSTEM", name="SYSTEM", domain="NT AUTHORITY")

    assert upgrade.account_text(system) == "NT AUTHORITY\\SYSTEM (S-1-5-18)"


def test_account_text_of_a_sid_without_a_name_is_the_sid() -> None:
    # pwshpy reports an unresolvable SID with empty names instead of failing: the SID still says who.
    assert upgrade.account_text(CurrentIdentity(sid=RUNNER_SID)) == RUNNER_SID


def test_pwshpy_host_reads_this_process_identity_from_pwshpy() -> None:
    # The real adapter on any OS: the token's SID on Windows, the effective uid on POSIX.
    host, me = upgrade.PwshpyHost(), ps.get_current_identity()

    assert host.user_sid() == me.sid
    assert host.whoami() == upgrade.account_text(me)


class _UnlistableScheduler:
    """pwshpy's facade over a Task Scheduler whose root folder refuses to list its tasks."""

    def __init__(self) -> None:
        self.strict: list[bool] = []

    def get_scheduled_task(self, folder_path: str = "\\", *, strict: bool = False) -> Pipeline[ScheduledTaskInfo]:
        self.strict.append(strict)

        def walk() -> Iterator[ScheduledTaskInfo]:
            if strict:  # what pwshpy does with an item it cannot read under strict=True
                raise NativeCallError(f"cannot list the tasks in folder '{folder_path}': (5, 'Zugriff verweigert')")
            yield from ()  # lenient: the folder is skipped, which reads exactly like an absent task

        return Pipeline(walk())


def test_pwshpy_host_task_state_raises_for_a_folder_it_cannot_list(monkeypatch: pytest.MonkeyPatch) -> None:
    # The cleanup's read-back: "no such task" must mean the task is gone, never that it could not
    # be read, or a task still defined would be reported deleted. pwshpy is the third-party edge.
    scheduler = _UnlistableScheduler()
    monkeypatch.setattr(upgrade, "ps", scheduler)

    with pytest.raises(NativeCallError, match="cannot list the tasks"):
        upgrade.PwshpyHost().task_state(r"\OVMRepairUpgrade")
    assert scheduler.strict == [True]


@pytest.mark.os_windows
def test_pwshpy_host_task_state_reads_an_absent_task_as_none_on_the_real_scheduler() -> None:
    # A strict walk of the whole tree: any task this elevated account cannot read would raise here.
    assert upgrade.PwshpyHost().task_state(r"\OVMRepairUpgrade-absent-by-test") is None


_GRANDCHILD = """
import pathlib, sys, time
time.sleep(2)
pathlib.Path(sys.argv[1]).write_text("done", encoding="utf-8")
"""
# The program exits at once and leaves a grandchild that finishes the work 2 s later, the shape of
# setup.exe handing its work to SetupHost. Its output goes to DEVNULL, so no inherited pipe keeps
# a plain wait open: only a wait for the whole process tree sees it.
_HANDS_OFF = """
import subprocess, sys
subprocess.Popen([sys.executable, "-c", sys.argv[1], sys.argv[2]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
"""


def test_pwshpy_host_runs_setup_until_every_process_it_started_has_exited(tmp_path: Path) -> None:
    marker = tmp_path / "grandchild-done"

    run = upgrade.PwshpyHost().run_setup([sys.executable, "-c", _HANDS_OFF, _GRANDCHILD, str(marker)])

    assert (run.exit_code, run.tree_wait) == (0, upgrade.TreeWait.JOB)
    assert marker.read_text(encoding="utf-8") == "done"


def test_pwshpy_host_name_taken_is_true_for_anything_with_the_name(tmp_path: Path) -> None:
    (tmp_path / "file").write_bytes(b"x")
    taken = upgrade.PwshpyHost().name_taken
    assert (taken(str(tmp_path)), taken(str(tmp_path / "file"))) == (True, True)
    # Absent, and under a file (NotADirectoryError on POSIX): no such name can exist.
    assert (taken(str(tmp_path / "missing")), taken(str(tmp_path / "file" / "below"))) == (False, False)


def test_pwshpy_host_name_taken_raises_when_the_name_cannot_be_looked_up(tmp_path: Path) -> None:
    # os.path.lexists would answer False here, and lock-dirs --no-create would report ABSENT.
    if sys.platform == "win32" or os.geteuid() == 0:
        pytest.skip("needs a POSIX parent this process cannot search (root searches every directory)")
    closed = tmp_path / "closed"
    (closed / "inner").mkdir(parents=True)
    closed.chmod(0)
    try:
        with pytest.raises(PermissionError):
            upgrade.PwshpyHost().name_taken(str(closed / "inner"))
    finally:
        closed.chmod(stat.S_IRWXU)


# --- lock-dirs: both directories are locked before anything is copied into them ------------------


def _lock_dirs(host: FakeUpgradeHost, *extra: str) -> tuple[int, dict[str, object]]:
    return _run(host, "lock-dirs", "--tool", TOOL, *extra)


def _actions(envelope: dict[str, object]) -> list[tuple[object, object]]:
    return [(obj(d)["path"], obj(d)["action"]) for d in items(_data(envelope)["directories"])]


@READS_THE_REAL_TOOL_PATH
def test_lock_dirs_creates_and_locks_both_directories(fresh: FakeUpgradeHost) -> None:
    code, envelope = _lock_dirs(fresh, "--stage-root", r"D:\upgrade")

    assert code == 0
    assert fresh.calls == ["create C:\\winrepair", "create D:\\upgrade"]
    data = _data(envelope)
    assert (data["verdict"], data["reason"], data["tool_present"]) == ("OK", None, False)
    assert _actions(envelope) == [(r"C:\winrepair", "CREATED"), (r"D:\upgrade", "CREATED")]


@READS_THE_REAL_TOOL_PATH
def test_lock_dirs_without_a_stage_root_locks_only_the_tool_directory(fresh: FakeUpgradeHost) -> None:
    # The driver's push runs it from an admin-only copy before the tool goes into C:\winrepair,
    # when the stage root is not known yet.
    code, envelope = _lock_dirs(fresh)

    assert code == 0
    assert fresh.calls == ["create C:\\winrepair"]
    assert _actions(envelope) == [(r"C:\winrepair", "CREATED")]


def test_lock_dirs_leaves_an_exactly_locked_directory_and_its_content_alone(host: FakeUpgradeHost) -> None:
    # A re-run (or a live SYSTEM run executing the tool): no DACL is rewritten under it.
    code, envelope = _lock_dirs(host, "--stage-root", r"D:\upgrade")

    assert code == 0
    assert host.calls == ["create C:\\winrepair", "create D:\\upgrade"]  # both existed: nothing written
    assert _actions(envelope) == [(r"C:\winrepair", "ALREADY_LOCKED"), (r"D:\upgrade", "ALREADY_LOCKED")]
    data = _data(envelope)
    assert (data["tool_present"], data["tool_sha256"]) == (True, hashlib.sha256(TOOL_BYTES).hexdigest())


# --no-create is apply's after-reboot report: it says a directory is gone instead of making it.


@READS_THE_REAL_TOOL_PATH
def test_lock_dirs_no_create_reports_an_absent_directory_and_creates_nothing(fresh: FakeUpgradeHost) -> None:
    code, envelope = _lock_dirs(fresh, "--no-create")
    assert code == 0
    assert fresh.calls == []
    assert _actions(envelope) == [(r"C:\winrepair", "ABSENT")]


def test_lock_dirs_no_create_still_judges_an_existing_directory(host: FakeUpgradeHost) -> None:
    code, envelope = _lock_dirs(host, "--no-create")
    assert code == 0
    assert host.calls == []
    assert _actions(envelope) == [(r"C:\winrepair", "ALREADY_LOCKED")]


def test_lock_dirs_no_create_refuses_an_existing_unlocked_directory_as_without_it(fresh: FakeUpgradeHost) -> None:
    fresh.existing.add(r"C:\winrepair")

    code, envelope = _lock_dirs(fresh, "--no-create")

    assert code == 1
    assert fresh.calls == []
    _lock_refused(fresh, envelope, r"C:\winrepair existed before lock-dirs and is not locked as lock-dirs creates it")


def _lock_refused(host: FakeUpgradeHost, envelope: dict[str, object], fragment: str) -> None:
    data = _data(envelope)
    assert (envelope["ok"], data["verdict"]) == (False, "FAILED")
    assert fragment in str(data["reason"]), data["reason"]


def test_lock_dirs_refuses_an_existing_unlocked_directory_even_when_empty(fresh: FakeUpgradeHost) -> None:
    # Locking it now would not revoke a handle a local user opened while it was open: relative
    # opens through that handle are checked against the access granted when it was opened.
    fresh.existing.add(r"D:\upgrade")

    code, envelope = _lock_dirs(fresh, "--stage-root", r"D:\upgrade")

    assert code == 1
    _lock_refused(fresh, envelope, r"rd /s /q D:\upgrade")
    assert r"D:\upgrade" not in fresh.locked


def test_lock_dirs_refuses_a_locked_directory_holding_something_a_non_admin_can_change(
    fileless_host: FakeUpgradeHost,
) -> None:
    evil = r"D:\upgrade\sources\evil.dll"
    fileless_host.entries += [r"D:\upgrade\sources", evil]
    fileless_host.acl_overrides[evil] = AclReading(
        path=evil, owner=PLANTER_SID, protected=False, aces=(Ace(sid=SYSTEM_SID, kind=0, flags=0x10, mask=FULL),)
    )

    code, envelope = _lock_dirs(fileless_host, "--stage-root", r"D:\upgrade")

    assert code == 1
    _lock_refused(fileless_host, envelope, f"{evil} is owned by {PLANTER_SID}")


def test_lock_dirs_refuses_a_directory_that_held_files_before_it_was_locked(fresh: FakeUpgradeHost) -> None:
    # Anything in it may have been written or replaced by a local user while it was open to them.
    fresh.existing.add(r"D:\upgrade")
    fresh.entries = [r"D:\upgrade\sources", r"D:\upgrade\sources\evil.dll"]

    code, envelope = _lock_dirs(fresh, "--stage-root", r"D:\upgrade")

    assert code == 1
    _lock_refused(fresh, envelope, r"rd /s /q D:\upgrade")


@pytest.mark.parametrize(
    ("target", "fragment"),
    [
        (
            LockTarget(path=r"D:\upgrade", reparse_points=(r"D:\upgrade",), directory=True, owner=PLANTER_SID),
            r"D:\upgrade is a reparse point",
        ),
        (
            LockTarget(path=r"D:\upgrade", reparse_points=(), directory=True, owner=PLANTER_SID),
            f"owned by {PLANTER_SID}",
        ),
        (
            LockTarget(path=r"D:\upgrade", reparse_points=(), directory=False, owner=ADMINS_SID),
            r"D:\upgrade is not a directory",
        ),
    ],
    ids=["junction", "foreign-owner", "not-a-directory"],
)
def test_lock_dirs_refuses_an_unsafe_existing_directory_without_locking_it(
    fresh: FakeUpgradeHost, target: LockTarget, fragment: str
) -> None:
    fresh.existing.add(r"D:\upgrade")
    fresh.lock_targets[r"D:\upgrade"] = target

    code, envelope = _lock_dirs(fresh, "--stage-root", r"D:\upgrade")

    assert code == 1
    _lock_refused(fresh, envelope, fragment)
    assert r"D:\upgrade" not in fresh.locked


@pytest.mark.parametrize("root", [r"C:\Windows", r"D:\data", r"C:\Users\admin\upgrade"])
def test_lock_dirs_refuses_a_stage_root_it_must_not_lock_before_touching_anything(
    fresh: FakeUpgradeHost, root: str
) -> None:
    code, envelope = _lock_dirs(fresh, "--stage-root", root)

    assert code == 1
    _lock_refused(fresh, envelope, root)
    assert fresh.calls == []


def test_lock_dirs_refuses_a_tool_outside_the_pushed_location_before_touching_anything(
    fresh: FakeUpgradeHost,
) -> None:
    code, envelope = _run(fresh, "lock-dirs", "--tool", ntpath.join("C:\\", ntpath.basename(TOOL)))

    assert code == 1
    _lock_refused(fresh, envelope, "only tool directory")
    assert fresh.calls == []


def test_lock_dirs_refuses_a_tool_already_there_whose_bytes_do_not_match_its_name(
    host: FakeUpgradeHost, tmp_path: Path
) -> None:
    # The driver would otherwise run it as an elevated admin without pushing its own copy.
    (tmp_path / TOOL).write_bytes(b"# a local user's replacement\r\n")

    code, envelope = _lock_dirs(host)

    assert code == 1
    _lock_refused(host, envelope, "does not match its name")


def test_lock_dirs_refuses_a_tool_already_there_that_others_can_write(fileless_host: FakeUpgradeHost) -> None:
    fileless_host.acl_overrides[TOOL] = AclReading(
        path=TOOL, owner=ADMINS_SID, protected=False, aces=(Ace(sid=USERS_SID, kind=0, flags=0, mask=MODIFY),)
    )

    code, envelope = _lock_dirs(fileless_host)

    assert code == 1
    _lock_refused(fileless_host, envelope, f"lets {USERS_SID} write")


def test_lock_dirs_refuses_a_directory_it_cannot_create(fresh: FakeUpgradeHost) -> None:
    fresh.create_fails = True

    code, envelope = _lock_dirs(fresh, "--stage-root", r"D:\upgrade")

    assert code == 1
    _lock_refused(fresh, envelope, r"cannot create C:\winrepair")
    assert "create D:\\upgrade" not in fresh.calls  # nothing after a refusal


def test_lock_dirs_refuses_a_lock_that_does_not_read_back_exactly(fresh: FakeUpgradeHost) -> None:
    extra = (
        Ace(sid=SYSTEM_SID, kind=0, flags=0x3, mask=FULL),
        Ace(sid=ADMINS_SID, kind=0, flags=0x3, mask=FULL),
        Ace(sid=USERS_SID, kind=0, flags=0x3, mask=0x1200A9),
    )
    fresh.acl_overrides[r"C:\winrepair"] = AclReading(
        path=r"C:\winrepair", owner=ADMINS_SID, protected=True, aces=extra
    )

    code, envelope = _lock_dirs(fresh)

    assert code == 1
    _lock_refused(fresh, envelope, "carries 3 ACEs")


# POSIX-only like the host fixture: Path(TOOL) below is a file in the cwd only on POSIX.
@pytest.mark.os_posix
def test_lock_dirs_then_staging_then_launch_is_the_order_launch_accepts(fresh: FakeUpgradeHost) -> None:
    fresh.task_lines = [(30.0, "launching: D:\\upgrade\\setup.exe")]
    assert _lock_dirs(fresh, "--stage-root", r"D:\upgrade")[0] == 0
    Path(TOOL).write_bytes(TOOL_BYTES)  # the push and the media transfer, after the lock
    Path(SETUP).write_bytes(b"MZ")
    Path(POWERSHELL).write_bytes(b"MZ")
    fresh.entries = [TOOL, SETUP]
    fresh.state_log = Path(STATE_LOG)  # the --state-log _launch passes, a file in the cwd on POSIX

    code, envelope = _launch(fresh)

    assert code == 0
    assert _data(envelope)["verdict"] == "OK"


@dataclass
class _Win32LockHost(FakeUpgradeHost):
    """A FakeUpgradeHost whose creation, inspection and read-back go through the real lockdown over
    pywin32 stand-ins: a directory reads back with exactly the descriptor it was created with."""

    security: FakeSecurity = field(default_factory=FakeSecurity)
    files: FakeFiles = field(default_factory=FakeFiles)

    def inspect_lock_target(self, path: str) -> LockTarget:
        return lockdown.inspect_lock_target(self.security, self.files, path)

    def create_locked_dir(self, path: str) -> bool:
        created = lockdown.create_locked_dir(self.security, self.files, path)
        if created:
            self.existing.add(path)
            self.security.objects[path] = self.files.created[path]
        return created

    def read_acl(self, path: str) -> AclReading:
        if path in self.security.objects:
            return lockdown.read_acl(self.security, path)
        return super().read_acl(path)


LOCK_DESCRIPTOR_ACES = [((0, 0x3), FULL, Sid(SYSTEM_SID)), ((0, 0x3), FULL, Sid(ADMINS_SID))]


@READS_THE_REAL_TOOL_PATH
def test_lock_dirs_creates_each_directory_with_the_lock_already_in_place(fresh: FakeUpgradeHost) -> None:
    # A directory made first and locked afterwards is open to every local user in between, and a
    # handle opened then keeps its access after the lock. So each one comes into existence locked.
    real = _Win32LockHost(state_log=fresh.state_log)

    code, envelope = _lock_dirs(real, "--stage-root", r"D:\upgrade")

    assert code == 0, _data(envelope)["reason"]
    assert set(real.files.created) == {r"C:\winrepair", r"D:\upgrade"}
    for directory, descriptor in real.files.created.items():
        assert descriptor.control & 0x1000, f"{directory} was created without a protected DACL"
        assert descriptor.dacl is not None and descriptor.dacl.aces == LOCK_DESCRIPTOR_ACES, directory
    assert _actions(envelope) == [(r"C:\winrepair", "CREATED"), (r"D:\upgrade", "CREATED")]


@pytest.mark.parametrize("directory", LOCK_DIRS)
def test_lock_dirs_through_pywin32_refuses_a_junction_and_writes_no_dacl(
    fresh: FakeUpgradeHost, directory: str
) -> None:
    files = FakeFiles({directory: Node(0x410, PLANTER_SID, target=r"C:\Windows")})
    real = _Win32LockHost(state_log=fresh.state_log, files=files, existing={directory})

    code, envelope = _lock_dirs(real, "--stage-root", r"D:\upgrade")

    assert code == 1
    _lock_refused(real, envelope, f"{directory} is a reparse point")
    assert directory not in real.files.created
    assert all(handle.closed for handle in files.opened)


class _BindingRefuses(FakeSecurity):
    def SECURITY_DESCRIPTOR(self) -> Descriptor:  # noqa: N802 - mirrors the pywin32 / COM member name
        class _Refusing(Descriptor):
            def SetSecurityDescriptorControl(self, interest: int, bits: int, /) -> None:  # noqa: N802 - mirrors the pywin32 / COM member name
                raise TypeError("an integer is required (got type str)")

        return _Refusing(None, None, 0)


def test_lock_dirs_refuses_cleanly_when_the_binding_rejects_the_descriptor(fresh: FakeUpgradeHost) -> None:
    refusing = _Win32LockHost(state_log=fresh.state_log, security=_BindingRefuses())

    code, envelope = _lock_dirs(refusing)

    assert code == 1
    _lock_refused(refusing, envelope, r"cannot create C:\winrepair")
    assert refusing.files.created == {}


# --- launch: what the SYSTEM task executes was locked before it was copied in -------------------


def test_launch_verifies_both_locks_and_writes_no_dacl(host: FakeUpgradeHost) -> None:
    host.task_lines = [(30.0, "launching: D:\\upgrade\\setup.exe")]

    code, envelope = _launch(host)

    assert code == 0
    assert host.calls[:1] == ["register"]  # nothing created or locked: lock-dirs did that
    data = _data(envelope)
    assert data["locked"] == LOCK_DIRS
    assert data["tool_sha256"] == hashlib.sha256(TOOL_BYTES).hexdigest()


def _refused_before_the_task(host: FakeUpgradeHost, envelope: dict[str, object], fragment: str) -> None:
    data = _data(envelope)
    assert (envelope["ok"], data["verdict"], data["registered"]) == (False, "FAILED", False)
    assert fragment in str(data["reason"]), data["reason"]
    assert host.registered == []
    assert not [c for c in host.calls if c in ("register", "end", "delete")]
    assert not [c for c in host.calls if c.startswith("create ")]


@pytest.mark.parametrize("directory", LOCK_DIRS)
def test_launch_refuses_a_directory_lock_dirs_never_locked(host: FakeUpgradeHost, directory: str) -> None:
    # Locking it now would bless whatever a local user planted while it was open to them.
    host.locked.remove(directory)
    host.state_log.write_text("2026-08-01 10:00:00  STATE=DONE-OK\n", encoding="utf-8")

    code, envelope = _launch(host)

    assert code == 1
    _refused_before_the_task(host, envelope, f"{directory} is not locked as lock-dirs creates it")
    assert host.state_log.exists()  # the previous run's verdict is not thrown away for nothing


def test_launch_refuses_when_the_read_back_still_lets_users_write(host: FakeUpgradeHost) -> None:
    stale = AclReading(
        path=r"D:\upgrade",
        owner=ADMINS_SID,
        protected=False,
        aces=(Ace(sid=USERS_SID, kind=0, flags=0x1B, mask=MODIFY),),
    )
    host.acl_overrides[r"D:\upgrade"] = stale

    code, envelope = _launch(host)

    assert code == 1
    _refused_before_the_task(host, envelope, f"lets {USERS_SID} write")


def test_launch_refuses_a_setup_exe_that_others_can_still_write(host: FakeUpgradeHost) -> None:
    # An explicit ACE on the file survives the parent's lock.
    host.acl_overrides[SETUP] = AclReading(
        path=SETUP, owner=RUNNER_SID, protected=False, aces=(Ace(sid=USERS_SID, kind=0, flags=0, mask=MODIFY),)
    )

    code, envelope = _launch(host)

    assert code == 1
    _refused_before_the_task(host, envelope, SETUP)


def test_launch_refuses_a_tool_owned_by_an_untrusted_account(host: FakeUpgradeHost) -> None:
    host.acl_overrides[TOOL] = AclReading(
        path=TOOL, owner=USERS_SID, protected=False, aces=(Ace(sid=SYSTEM_SID, kind=0, flags=0x10, mask=FULL),)
    )

    code, envelope = _launch(host)

    assert code == 1
    _refused_before_the_task(host, envelope, f"owned by {USERS_SID}")


EVIL = r"D:\upgrade\sources\evil.dll"
INHERITED = (Ace(sid=SYSTEM_SID, kind=0, flags=0x10, mask=FULL), Ace(sid=ADMINS_SID, kind=0, flags=0x10, mask=FULL))


@pytest.mark.parametrize(
    ("reading", "fragment"),
    [
        # A file a local user created (through a handle opened before the lock): its owner can
        # rewrite its DACL, so the locked parent does not protect it.
        (
            AclReading(path=EVIL, owner=PLANTER_SID, protected=False, aces=INHERITED),
            f"{EVIL} is owned by {PLANTER_SID}",
        ),
        # An explicit grant on a child survives the parent's lock.
        (
            AclReading(
                path=EVIL,
                owner=ADMINS_SID,
                protected=False,
                aces=(*INHERITED, Ace(sid=USERS_SID, kind=0, flags=0, mask=MODIFY)),
            ),
            f"lets {USERS_SID}",
        ),
        # A same-volume move keeps the source's ACEs, still flagged inherited: they count too.
        (
            AclReading(
                path=EVIL,
                owner=ADMINS_SID,
                protected=False,
                aces=(*INHERITED, Ace(sid=USERS_SID, kind=0, flags=0x10, mask=MODIFY)),
            ),
            f"lets {USERS_SID}",
        ),
        (AclReading(path=EVIL, owner=ADMINS_SID, protected=False, aces=None), "NULL DACL"),
    ],
    ids=["planted-owner", "explicit-grant", "moved-in-grant", "null-dacl"],
)
def test_launch_refuses_a_child_a_non_admin_can_change(
    host: FakeUpgradeHost, reading: AclReading, fragment: str
) -> None:
    host.entries += [r"D:\upgrade\sources", EVIL]
    host.acl_overrides[EVIL] = reading

    code, envelope = _launch(host)

    assert code == 1
    _refused_before_the_task(host, envelope, fragment)


def test_launch_refuses_a_reparse_point_below_a_locked_directory(host: FakeUpgradeHost) -> None:
    # setup.exe would follow sources\ into a tree the lock never reached.
    host.entries += [r"D:\upgrade\sources", EVIL]
    host.reparse.add(r"D:\upgrade\sources")

    code, envelope = _launch(host)

    assert code == 1
    _refused_before_the_task(host, envelope, r"D:\upgrade\sources is a reparse point")


def test_launch_refuses_a_tree_larger_than_any_media(host: FakeUpgradeHost) -> None:
    host.entries += [rf"D:\upgrade\f{i}.dll" for i in range(upgrade.TREE_LIMIT + 1)]

    code, envelope = _launch(host)

    assert code == 1
    _refused_before_the_task(host, envelope, f"more than {upgrade.TREE_LIMIT} entries")


def test_launch_refuses_a_tree_it_cannot_walk(host: FakeUpgradeHost) -> None:
    host.walk_fails = True

    code, envelope = _launch(host)

    assert code == 1
    _refused_before_the_task(host, envelope, "Zugriff verweigert")


def test_launch_refuses_a_tool_replaced_under_its_content_address(host: FakeUpgradeHost, tmp_path: Path) -> None:
    (tmp_path / TOOL).write_bytes(b"# a local user's replacement\r\n")

    code, envelope = _launch(host)

    assert code == 1
    _refused_before_the_task(host, envelope, "does not match its name")
    assert host.calls == []


def _named_tool(tmp_path: Path, path: str) -> str:
    """Put the real tool bytes at ``path`` (a Windows name in the cwd) and return the path."""
    (tmp_path / path).write_bytes(TOOL_BYTES)
    return path


@pytest.mark.parametrize(
    "tool",
    [
        ntpath.join("C:\\", ntpath.basename(TOOL)),
        ntpath.join(r"C:\Windows", ntpath.basename(TOOL)),
        ntpath.join(r"D:\upgrade", ntpath.basename(TOOL)),
        r"C:\winrepair\winrepair_guest.ps1",
    ],
    ids=["drive-root", "windows-dir", "stage-root", "no-content-address"],
)
def test_launch_refuses_a_tool_outside_the_pushed_location_before_reading_anything(
    host: FakeUpgradeHost, tmp_path: Path, tool: str
) -> None:
    _named_tool(tmp_path, tool)

    code, envelope = _run(host, "launch", "--stage-root", r"D:\upgrade", "--state-log", STATE_LOG, "--tool", tool)

    assert code == 1
    _refused_before_the_task(host, envelope, tool)
    assert host.calls == []


@pytest.mark.parametrize("root", [r"C:\Windows", r"D:\data", r"C:\Users\admin\upgrade"])
def test_launch_refuses_a_stage_root_outside_the_driver_s_before_reading_anything(
    host: FakeUpgradeHost, tmp_path: Path, root: str
) -> None:
    (tmp_path / ntpath.join(root, "setup.exe")).write_bytes(b"MZ")

    code, envelope = _run(host, "launch", "--stage-root", root, "--state-log", STATE_LOG, "--tool", TOOL)

    assert code == 1
    _refused_before_the_task(host, envelope, root)
    assert host.calls == []


@pytest.mark.parametrize("directory", LOCK_DIRS)
def test_launch_refuses_a_lock_directory_that_is_a_junction(host: FakeUpgradeHost, directory: str) -> None:
    host.lock_targets[directory] = LockTarget(
        path=directory, reparse_points=(directory,), directory=True, owner=PLANTER_SID
    )

    code, envelope = _launch(host)

    assert code == 1
    _refused_before_the_task(host, envelope, f"{directory} is a reparse point")
    assert _data(envelope)["locked"] == []


@pytest.mark.parametrize("directory", LOCK_DIRS)
def test_launch_refuses_a_lock_directory_reached_through_a_reparse_point(host: FakeUpgradeHost, directory: str) -> None:
    ancestor = ntpath.splitdrive(directory)[0] + "\\"
    host.lock_targets[directory] = LockTarget(
        path=directory, reparse_points=(ancestor,), directory=True, owner=ADMINS_SID
    )

    code, envelope = _launch(host)

    assert code == 1
    _refused_before_the_task(host, envelope, f"reparse point at {ancestor}")


@pytest.mark.parametrize("directory", LOCK_DIRS)
def test_launch_refuses_a_lock_directory_another_account_owns(host: FakeUpgradeHost, directory: str) -> None:
    host.lock_targets[directory] = LockTarget(path=directory, reparse_points=(), directory=True, owner=PLANTER_SID)

    code, envelope = _launch(host)

    assert code == 1
    _refused_before_the_task(host, envelope, f"{directory} is owned by {PLANTER_SID}")


@pytest.mark.parametrize("directory", LOCK_DIRS)
def test_launch_refuses_a_lock_target_that_is_not_a_directory(host: FakeUpgradeHost, directory: str) -> None:
    host.lock_targets[directory] = LockTarget(path=directory, reparse_points=(), directory=False, owner=ADMINS_SID)

    code, envelope = _launch(host)

    assert code == 1
    _refused_before_the_task(host, envelope, f"{directory} is not a directory")


def test_launch_refuses_when_a_lock_directory_cannot_be_inspected(host: FakeUpgradeHost) -> None:
    host.inspect_fails = True

    code, envelope = _launch(host)

    assert code == 1
    _refused_before_the_task(host, envelope, "cannot inspect C:\\winrepair")


def test_launch_accepts_directories_system_owns(host: FakeUpgradeHost) -> None:
    host.task_lines = [(30.0, "launching: D:\\upgrade\\setup.exe")]
    for directory in LOCK_DIRS:
        host.lock_targets[directory] = LockTarget(path=directory, reparse_points=(), directory=True, owner=SYSTEM_SID)

    code, envelope = _launch(host)

    assert code == 0
    assert _data(envelope)["locked"] == LOCK_DIRS


@pytest.mark.parametrize("directory", LOCK_DIRS)
def test_launch_through_pywin32_refuses_a_junction(host: FakeUpgradeHost, directory: str) -> None:
    files = FakeFiles({directory: Node(0x410, PLANTER_SID, target=r"C:\Windows")})
    real = _Win32LockHost(state_log=host.state_log, files=files, existing=set(LOCK_DIRS), locked=list(LOCK_DIRS))

    code, envelope = _launch(real)

    assert code == 1
    _refused_before_the_task(real, envelope, f"{directory} is a reparse point")
    assert real.files.created == {}
    assert all(handle.closed for handle in files.opened)


@pytest.mark.parametrize("missing", [TOOL, SETUP, POWERSHELL])
def test_launch_refuses_a_missing_file_before_touching_anything(
    host: FakeUpgradeHost, tmp_path: Path, missing: str
) -> None:
    # Without this a missing tool cost a 10-minute NO_START with a misleading reason.
    (tmp_path / missing).unlink()

    code, envelope = _launch(host)

    assert code == 1
    _refused_before_the_task(host, envelope, missing)
    assert host.calls == []
