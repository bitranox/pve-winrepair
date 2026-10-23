"""Tests for the read-only probe subcommands.

The probes reach Windows only through the ``ProbeHost`` port. ``FakeHost`` implements it with
real pwshpy record types, and every test drives the real entry point
(``winrepair_guest.main(commands=probes.commands(lambda: host))``), so argument parsing, the
decision logic and the envelope are all exercised together; only the OS reads are substituted.
"""

from __future__ import annotations

import io
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest
from json_paths import at, items, obj
from pwshpy import (
    CimInstance,
    EventLevel,
    EventLogEntry,
    NativeCallError,
    ProcessInfo,
    ProcessResult,
    RegistryHive,
    RegistryValue,
    RegistryValueType,
    ScheduledTaskInfo,
    ServiceInfo,
    ServiceState,
    TaskState,
)

from pve_winrepair_guest import probes, winrepair_guest

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Sequence
    from pathlib import Path

CURRENT_VERSION = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
NLS_LANGUAGE = r"HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language"
LP_MESSAGE = (
    "Paket Microsoft-Windows-Client-LanguagePack-Package~31bf3856ad364e35~amd64~en-US~10.0.26100.1 "
    "(Language Pack) konnte nicht in den Status Absent gewechselt werden. Fehler: 0x800736B3"
)


def _reg(name: str, data: str | int | list[str], kind: RegistryValueType = RegistryValueType.REG_SZ) -> RegistryValue:
    return RegistryValue(hive=RegistryHive.HKLM, key="x", name=name, type=kind, data=data)


def _event(message: str | None, when: datetime) -> EventLogEntry:
    return EventLogEntry(
        log_name="Setup",
        record_id=1,
        event_id=9,
        level=EventLevel.ERROR,
        provider_name="Microsoft-Windows-Servicing",
        time_created=when,
        message=message,
    )


def _proc(name: str) -> ProcessInfo:
    return ProcessInfo(pid=1, name=name)


def _task(name: str, path: str = "\\") -> ScheduledTaskInfo:
    return ScheduledTaskInfo(task_name=name, task_path=path, state=TaskState.READY, enabled=True)


def _container(name: str) -> str:
    return json.dumps({"Names": name, "Status": "Up 3 minutes"})


@dataclass
class FakeHost:
    """A ProbeHost answering from fixed pwshpy records; a key in ``fail`` raises NativeCallError."""

    registry_values: dict[str, list[RegistryValue]] = field(default_factory=dict[str, list[RegistryValue]])
    events: list[EventLogEntry] = field(default_factory=list[EventLogEntry])
    disks: list[CimInstance] = field(default_factory=list[CimInstance])
    adapters: list[CimInstance] = field(default_factory=list[CimInstance])
    procs: list[ProcessInfo] = field(default_factory=list[ProcessInfo])
    svcs: list[ServiceInfo] = field(default_factory=list[ServiceInfo])
    tasks: list[ScheduledTaskInfo] = field(default_factory=list[ScheduledTaskInfo])
    docker: ProcessResult | None = None
    fail: set[str] = field(default_factory=set[str])
    exec_calls: list[tuple[list[str], float]] = field(default_factory=list[tuple[list[str], float]])

    def _check(self, what: str) -> None:
        if what in self.fail:
            raise NativeCallError(f"{what} unavailable")

    def registry(self, key: str) -> Iterable[RegistryValue]:
        self._check(key)
        return self.registry_values[key]

    def win_events(self, log_name: str) -> Iterator[EventLogEntry]:
        assert log_name == "Setup"
        for event in self.events:
            self._check("events")  # raise mid-stream, the way a lazy pipeline does
            yield event
        self._check("events")

    def cim(self, class_name: str, *, where: str | None = None) -> Iterable[CimInstance]:
        self._check(class_name)
        if class_name == "Win32_NetworkAdapter":
            assert where is None  # every adapter: the ones without a MAC are skipped in Python
            return self.adapters
        assert (class_name, where) == ("Win32_LogicalDisk", "DriveType=3")
        return self.disks

    def processes(self) -> Iterable[ProcessInfo]:
        return self.procs

    def services(self) -> Iterable[ServiceInfo]:
        return self.svcs

    def scheduled_tasks(self) -> Iterable[ScheduledTaskInfo]:
        return self.tasks

    def task_run_info(self, task: ScheduledTaskInfo) -> probes.TaskRunInfo:
        self._check("task_run_info")
        return probes.TaskRunInfo(last_run="2026-10-21T10:00:00", last_result=0)

    def exec(self, argv: Sequence[str], *, timeout: float) -> ProcessResult:
        self.exec_calls.append((list(argv), timeout))
        self._check("exec")
        assert self.docker is not None
        return self.docker

    def computer_name(self) -> str:
        return "GUEST-TEST"


def _run(host: FakeHost, *argv: str) -> tuple[int, dict[str, object]]:
    out, err = io.StringIO(), io.StringIO()
    code = winrepair_guest.main(list(argv), commands=probes.commands(lambda: host), stdout=out, stderr=err)
    lines = out.getvalue().splitlines()
    assert len(lines) == 1, (lines, err.getvalue())
    return code, json.loads(lines[0])


def _data(envelope: dict[str, object]) -> dict[str, object]:
    return obj(envelope["data"])


def lp_host(**overrides: object) -> FakeHost:
    host = FakeHost(
        registry_values={
            CURRENT_VERSION: [
                _reg("CurrentBuild", "26200"),
                _reg("UBR", 9711, RegistryValueType.REG_DWORD),
                _reg("InstallDate", 1761206400, RegistryValueType.REG_DWORD),
                _reg("DisplayVersion", "25H2"),
            ],
            NLS_LANGUAGE: [_reg("InstallLanguage", "0407")],
        },
    )
    for name, value in overrides.items():
        setattr(host, name, value)
    return host


# --- detect-lp-defect ---------------------------------------------------------------------


def test_lp_defect_matches_language_pack_absent_events_case_insensitively() -> None:
    old, new = datetime(2026, 8, 1, tzinfo=timezone.utc), datetime(2026, 8, 12, 9, 30, tzinfo=timezone.utc)
    host = lp_host(
        events=[
            _event(LP_MESSAGE, old),
            _event(LP_MESSAGE.replace("0x800736B3", "0x80071A2D").lower(), new),
            _event("Language Pack installed, state Installed", new),
            _event(None, new),
        ]
    )

    code, envelope = _run(host, "detect-lp-defect")

    assert code == 0
    data = _data(envelope)
    assert data["verdict"] == "AFFECTED"
    assert data["lp_absent_events"] == 2
    assert (data["events_read"], data["events_unrendered"], data["reason"]) == (4, 1, None)
    assert data["codes"] == ["0x800736B3", "0x80071a2d"]
    assert data["last"] == new.isoformat()
    assert (data["host"], data["build"], data["display_version"], data["install_language"]) == (
        "GUEST-TEST",
        "26200.9711",
        "25H2",
        "0407",
    )


def test_lp_defect_reads_only_the_newest_600_setup_events() -> None:
    now = datetime(2026, 8, 12, tzinfo=timezone.utc)
    host = lp_host(events=[_event(f"noise {i}", now) for i in range(600)] + [_event(LP_MESSAGE, now)])

    _, envelope = _run(host, "detect-lp-defect")

    data = _data(envelope)
    assert (data["lp_absent_events"], data["verdict"], data["reason"]) == (0, "CLEAN", None)
    assert (data["events_read"], data["events_unrendered"]) == (600, 0)


def test_lp_defect_unreadable_setup_log_is_unknown_not_clean() -> None:
    host = lp_host(events=[_event(LP_MESSAGE, datetime(2026, 8, 12, tzinfo=timezone.utc))], fail={"events"})

    code, envelope = _run(host, "detect-lp-defect")

    assert code == 1
    assert envelope["ok"] is False
    data = _data(envelope)
    assert data["verdict"] == "UNKNOWN"
    assert data["lp_absent_events"] is None
    assert (data["events_read"], data["reason"]) == (None, "the Setup event log could not be read")
    assert envelope["skipped"] == [{"item": "Setup event log", "reason": "events unavailable"}]


def test_lp_defect_unrendered_messages_are_unknown_not_clean() -> None:
    # pwshpy 1.5.0's get_win_event handed back None for messages it could not format; a probe
    # counting those as non-matches reported every guest CLEAN.
    now = datetime(2026, 8, 12, tzinfo=timezone.utc)
    host = lp_host(events=[_event(None, now), _event("   ", now), _event(None, now)])

    code, envelope = _run(host, "detect-lp-defect")

    assert code == 1
    assert envelope["ok"] is False
    data = _data(envelope)
    assert (data["verdict"], data["lp_absent_events"]) == ("UNKNOWN", None)
    assert (data["events_read"], data["events_unrendered"]) == (3, 3)
    assert data["reason"] == "3 of 3 Setup event messages could not be rendered"


def test_lp_defect_one_unrendered_message_among_non_matches_is_unknown() -> None:
    now = datetime(2026, 8, 12, tzinfo=timezone.utc)
    host = lp_host(
        events=[_event("Package KB1 was successfully changed to the Installed state.", now)] * 5 + [_event(None, now)]
    )

    code, envelope = _run(host, "detect-lp-defect")

    assert code == 1
    assert _data(envelope)["verdict"] == "UNKNOWN"
    assert _data(envelope)["reason"] == "1 of 6 Setup event messages could not be rendered"


def test_lp_defect_unrendered_beyond_the_600_window_does_not_count() -> None:
    now = datetime(2026, 8, 12, tzinfo=timezone.utc)
    host = lp_host(events=[_event(f"noise {i}", now) for i in range(600)] + [_event(None, now)])

    code, envelope = _run(host, "detect-lp-defect")

    assert (code, _data(envelope)["verdict"], _data(envelope)["events_unrendered"]) == (0, "CLEAN", 0)


def test_lp_defect_empty_setup_log_is_unknown_not_clean() -> None:
    # An in-place upgrade starts a fresh Setup log: zero events examined is no evidence of a repair.
    code, envelope = _run(lp_host(events=[]), "detect-lp-defect")

    assert code == 1
    data = _data(envelope)
    assert (data["verdict"], data["events_read"], data["lp_absent_events"]) == ("UNKNOWN", 0, None)
    assert data["reason"] == "the Setup log holds no events (fresh after an upgrade): no evidence either way"


def test_lp_verdict_over_no_events_is_unknown() -> None:
    assert probes.lp_verdict(probes.scan_setup_events([]))[0] == "UNKNOWN"


def test_lp_defect_missing_nls_key_is_skipped_not_fatal() -> None:
    # One rendered non-matching event: a CLEAN needs evidence, an empty log is UNKNOWN.
    host = lp_host(
        fail={NLS_LANGUAGE},
        events=[_event("Language Pack installed, state Installed", datetime(2026, 8, 1, tzinfo=timezone.utc))],
    )

    code, envelope = _run(host, "detect-lp-defect")

    assert code == 0
    assert _data(envelope)["install_language"] is None
    assert envelope["skipped"] == [{"item": NLS_LANGUAGE, "reason": f"{NLS_LANGUAGE} unavailable"}]


# --- build ----------------------------------------------------------------------------------


def test_build_reports_ubr_and_install_date_as_decimal_integers() -> None:
    code, envelope = _run(lp_host(), "build")

    assert code == 0
    assert _data(envelope) == {
        "current_build": "26200",
        "ubr": 9711,
        "build": "26200.9711",
        "install_date": 1761206400,
    }


def test_build_without_ubr_is_an_internal_error_not_a_wrong_build() -> None:
    host = FakeHost(
        registry_values={
            CURRENT_VERSION: [_reg("CurrentBuild", "26200"), _reg("InstallDate", 1, RegistryValueType.REG_DWORD)]
        }
    )

    code, envelope = _run(host, "build")

    assert code == 2
    assert "UBR" in str(_data(envelope)["error"])


@pytest.mark.parametrize(
    "install_date",
    [
        None,
        _reg("InstallDate", "1761206400"),
        _reg("InstallDate", ["1761206400"], RegistryValueType.REG_MULTI_SZ),
    ],
    ids=["missing", "text", "multi-text"],
)
def test_build_without_a_dword_install_date_is_an_internal_error(install_date: RegistryValue | None) -> None:
    # apply compares InstallDate across the apply reboot: a missing one must never read as "unchanged".
    values = [_reg("CurrentBuild", "26200"), _reg("UBR", 9711, RegistryValueType.REG_DWORD)]
    host = FakeHost(registry_values={CURRENT_VERSION: values + ([install_date] if install_date else [])})

    code, envelope = _run(host, "build")

    assert (code, envelope["ok"]) == (2, False)
    assert "InstallDate" in str(_data(envelope)["error"])


def test_install_date_refuses_a_bool_although_bool_is_an_int() -> None:
    with pytest.raises(probes.ProbeError, match="InstallDate"):
        probes.install_date({"InstallDate": True})


def test_build_unreadable_registry_is_an_internal_error() -> None:
    code, envelope = _run(lp_host(fail={CURRENT_VERSION}), "build")

    assert code == 2
    assert _data(envelope)["error_type"] == "NativeCallError"


# --- drives ---------------------------------------------------------------------------------


def _disk(device: str, free: str | int | None, size: str | int = "107374182400") -> CimInstance:
    return CimInstance(class_name="Win32_LogicalDisk", properties={"DeviceID": device, "FreeSpace": free, "Size": size})


def test_drives_reports_each_fixed_drive_with_bytes_and_rounded_gb() -> None:
    host = FakeHost(disks=[_disk("D:", "53687091200"), _disk("C:", 27_917_287_424)])

    code, envelope = _run(host, "drives")

    assert code == 0
    assert _data(envelope)["drives"] == [
        {"letter": "C", "free_bytes": 27917287424, "size_bytes": 107374182400, "free_gb": 26.0},
        {"letter": "D", "free_bytes": 53687091200, "size_bytes": 107374182400, "free_gb": 50.0},
    ]


def test_drives_skips_a_volume_whose_free_space_is_not_a_number() -> None:
    host = FakeHost(disks=[_disk("C:", "n/a"), _disk("D:", "53687091200")])

    code, envelope = _run(host, "drives")

    assert code == 0
    assert [at(d, "letter") for d in items(envelope, "data", "drives")] == ["D"]
    assert [at(s, "item") for s in items(envelope, "skipped")] == ["C:"]


def test_fixed_drives_parses_each_disk_once_and_sorts_by_letter() -> None:
    drives, skips = probes.fixed_drives([_disk("E:", None), _disk("d:", 5), _disk("C:", "7", size="x")])

    assert [(d.letter, d.free_bytes) for d in drives] == [("C", 7), ("D", 5)]
    assert [s.item for s in skips] == ["E:"]


def test_drives_without_free_space_is_skipped_and_none_left_is_an_error() -> None:
    code, envelope = _run(FakeHost(disks=[_disk("E:", None)]), "drives")

    assert code == 2
    assert "no fixed drive" in str(_data(envelope)["error"])


# --- nic-macs -------------------------------------------------------------------------------


def _adapter(name: str, mac: object) -> CimInstance:
    return CimInstance(class_name="Win32_NetworkAdapter", properties={"Name": name, "MACAddress": mac})


def test_nic_macs_reports_every_adapter_mac_normalised_sorted_and_unique() -> None:
    host = FakeHost(
        adapters=[
            _adapter("Ethernet 4", "BC:24:11:FF:00:01"),
            _adapter("Ethernet 2", "BC:24:11:0A:0B:0C"),
            _adapter("WAN Miniport (IP)", None),
            _adapter("Ethernet", "bc-24-11-01-02-03"),
            _adapter("vEthernet (copy)", "bc:24:11:0a:0b:0c"),
            _adapter("Ethernet 3", "02:00:00:00:00:01"),
        ]
    )

    code, envelope = _run(host, "nic-macs")

    assert (code, envelope["ok"]) == (0, True)
    assert _data(envelope) == {
        "macs": ["02:00:00:00:00:01", "BC:24:11:01:02:03", "BC:24:11:0A:0B:0C", "BC:24:11:FF:00:01"]
    }
    assert envelope["skipped"] == [{"item": "WAN Miniport (IP)", "reason": "no MAC address"}]


@pytest.mark.parametrize(
    "mac", ["BC:24:11:0A:0B", "BC:24:11:0A:0B:0C:0D", "BC:24-11:0A:0B:0C", "BC2411 0A0B0C", "GG:24:11:0A:0B:0C", 7]
)
def test_nic_macs_skips_a_mac_it_cannot_read_rather_than_guessing(mac: object) -> None:
    host = FakeHost(adapters=[_adapter("odd", mac), _adapter("Ethernet", "BC:24:11:01:02:03")])

    code, envelope = _run(host, "nic-macs")

    assert code == 0
    assert _data(envelope) == {"macs": ["BC:24:11:01:02:03"]}
    assert [at(s, "item") for s in items(envelope, "skipped")] == ["odd"]
    assert "not a MAC address" in str(at(envelope, "skipped", 0, "reason"))


def test_nic_macs_with_no_mac_at_all_is_an_error_never_an_empty_list() -> None:
    code, envelope = _run(FakeHost(adapters=[_adapter("WAN Miniport (IP)", None)]), "nic-macs")

    assert (code, envelope["ok"]) == (2, False)
    assert "no network adapter with a MAC address" in str(_data(envelope)["error"])


def test_nic_macs_unreadable_wmi_is_an_internal_error_never_an_empty_list() -> None:
    host = FakeHost(adapters=[_adapter("Ethernet", "BC:24:11:01:02:03")], fail={"Win32_NetworkAdapter"})

    code, envelope = _run(host, "nic-macs")

    assert (code, envelope["ok"]) == (2, False)
    assert _data(envelope)["error_type"] == "NativeCallError"


# --- verify-runners -------------------------------------------------------------------------

# The three boot tasks and the count an operator of a runner host passes; most tests below use them.
RUNNER_ARGS = ("--task", "runner", "--task", "runner-toolcache", "--task", "runner-toolcache-python")
EXPECTED_ARGS = ("--expected", "18")


def _runner_host(containers: int, **overrides: object) -> FakeHost:
    stdout = "\n".join(_container(f"runner-{i}") for i in range(containers)) + "\n"
    host = FakeHost(
        tasks=[_task("runner"), _task("Runner-Toolcache", "\\Example\\")],
        svcs=[ServiceInfo(name="docker", display_name="Docker Engine", status=ServiceState.RUNNING)],
        procs=[_proc("dockerd"), _proc("svchost")],
        docker=ProcessResult(argv=["docker"], exit_code=0, stdout=stdout),
    )
    for name, value in overrides.items():
        setattr(host, name, value)
    return host


def test_verify_runners_ok_at_the_expected_count() -> None:
    host = _runner_host(18)

    code, envelope = _run(host, "verify-runners", *RUNNER_ARGS, *EXPECTED_ARGS)

    assert code == 0
    data = _data(envelope)
    assert (data["verdict"], data["count"], data["expected"]) == ("OK", 18, 18)
    assert data["docker_service"] == "Running"
    assert data["dockerd_processes"] == 1
    assert host.exec_calls == [(["docker", "ps", "--format", "{{json .}}"], 120.0)]


def test_verify_runners_reports_missing_tasks_and_matches_names_case_insensitively() -> None:
    _, envelope = _run(_runner_host(18), "verify-runners", *RUNNER_ARGS, *EXPECTED_ARGS)

    tasks = _data(envelope)["tasks"]
    assert tasks == [
        {
            "name": "runner",
            "present": True,
            "task_path": "\\",
            "state": "Ready",
            "enabled": True,
            "last_run": "2026-10-21T10:00:00",
            "last_result": 0,
        },
        {
            "name": "runner-toolcache",
            "present": True,
            "task_path": "\\Example\\",
            "state": "Ready",
            "enabled": True,
            "last_run": "2026-10-21T10:00:00",
            "last_result": 0,
        },
        {
            "name": "runner-toolcache-python",
            "present": False,
            "task_path": None,
            "state": None,
            "enabled": None,
            "last_run": None,
            "last_result": None,
        },
    ]


def test_verify_runners_short_count_is_refused() -> None:
    code, envelope = _run(_runner_host(17), "verify-runners", *RUNNER_ARGS, *EXPECTED_ARGS)

    assert code == 1
    assert (_data(envelope)["verdict"], _data(envelope)["count"]) == ("SHORT", 17)


def test_verify_runners_expected_is_configurable() -> None:
    code, envelope = _run(_runner_host(3), "verify-runners", *RUNNER_ARGS, "--expected", "3")

    assert code == 0
    assert _data(envelope)["expected"] == 3


def test_verify_runners_timeout_is_unknown_never_zero() -> None:
    code, envelope = _run(_runner_host(18, fail={"exec"}), "verify-runners", *RUNNER_ARGS, *EXPECTED_ARGS)

    assert code == 1
    data = _data(envelope)
    assert (data["verdict"], data["count"]) == ("UNKNOWN", None)
    assert envelope["skipped"] == [{"item": "docker ps", "reason": "exec unavailable"}]


def test_verify_runners_failing_docker_cli_is_unknown_never_zero() -> None:
    failed = ProcessResult(argv=["docker"], exit_code=1, stderr="error during connect: pipe not found")

    code, envelope = _run(_runner_host(0, docker=failed), "verify-runners", *RUNNER_ARGS, *EXPECTED_ARGS)

    assert code == 1
    assert _data(envelope)["verdict"] == "UNKNOWN"
    assert "error during connect" in str(envelope["skipped"])


def test_verify_runners_task_run_info_failure_is_skipped_not_fatal() -> None:
    code, envelope = _run(_runner_host(18, fail={"task_run_info"}), "verify-runners", *RUNNER_ARGS, *EXPECTED_ARGS)

    assert code == 0
    assert {"item": "runner run info", "reason": "task_run_info unavailable"} in items(envelope, "skipped")


def test_verify_runners_ignores_lines_that_are_not_container_objects() -> None:
    stdout = _container("a") + "\nWARNING: something\n\n42\n" + _container("b") + "\n"
    host = _runner_host(0, docker=ProcessResult(argv=["docker"], exit_code=0, stdout=stdout))

    _, envelope = _run(host, "verify-runners", *RUNNER_ARGS, "--expected", "2")

    assert _data(envelope)["count"] == 2
    assert _data(envelope)["containers"] == [
        {"name": "a", "status": "Up 3 minutes"},
        {"name": "b", "status": "Up 3 minutes"},
    ]


def test_verify_runners_rejects_a_negative_expected_count() -> None:
    code, envelope = _run(_runner_host(18), "verify-runners", *RUNNER_ARGS, "--expected", "-1")

    assert code == 2
    assert _data(envelope)["error_type"] == "UsageError"


def test_verify_runners_checks_exactly_the_named_tasks() -> None:
    _, envelope = _run(_runner_host(18), "verify-runners", "--task", "runner-a", "--task", "runner-b")

    assert [at(t, "name") for t in items(envelope, "data", "tasks")] == ["runner-a", "runner-b"]


def test_verify_runners_without_tasks_checks_none() -> None:
    _, envelope = _run(_runner_host(18), "verify-runners")

    assert items(envelope, "data", "tasks") == []


def test_verify_runners_default_count_accepts_any_readable_count() -> None:
    code, envelope = _run(_runner_host(0), "verify-runners")

    assert (code, at(envelope, "data", "verdict")) == (0, "OK")


def test_verify_runners_refuses_a_task_name_with_shell_characters() -> None:
    code, envelope = _run(_runner_host(18), "verify-runners", "--task", "a&b")

    assert code == 2
    # The message pins the cause: an unknown --task flag would also exit 2 as a UsageError.
    assert "not a task name" in str(at(envelope, "data", "error"))


# --- servicing-active / setup-alive ---------------------------------------------------------


def test_servicing_active_counts_tiworker_and_trustedinstaller() -> None:
    host = FakeHost(procs=[_proc("TiWorker"), _proc("trustedinstaller"), _proc("TiWorker"), _proc("svchost")])

    code, envelope = _run(host, "servicing-active")

    assert code == 0
    assert _data(envelope) == {"counts": {"TiWorker": 2, "TrustedInstaller": 1}, "total": 3, "active": True}


def test_servicing_idle_reads_zero() -> None:
    _, envelope = _run(FakeHost(procs=[_proc("svchost")]), "servicing-active")

    assert _data(envelope) == {"counts": {"TiWorker": 0, "TrustedInstaller": 0}, "total": 0, "active": False}


def test_setup_alive_counts_setuphost() -> None:
    _, envelope = _run(FakeHost(procs=[_proc("SetupHost"), _proc("setuphost")]), "setup-alive")

    assert _data(envelope) == {"count": 2, "alive": True}


# --- staged-os ------------------------------------------------------------------------------


def test_staged_os_present_is_rearmable(tmp_path: Path) -> None:
    winload = tmp_path / "winload.efi"
    winload.write_bytes(b"MZ")

    report = probes.staged_os(winload)

    assert (report.present, report.verdict) == (True, "REARMABLE")


def test_staged_os_absent_is_rerun(tmp_path: Path) -> None:
    report = probes.staged_os(tmp_path / "NewOS" / "Windows" / "winload.efi")

    assert (report.present, report.verdict) == (False, "RERUN")


def test_staged_os_under_a_file_component_is_absent(tmp_path: Path) -> None:
    (tmp_path / "NewOS").write_text("not a directory")

    assert probes.staged_os(tmp_path / "NewOS" / "winload.efi").present is False


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="needs POSIX modes, not as root")
def test_staged_os_that_cannot_be_examined_raises_rather_than_reading_absent(tmp_path: Path) -> None:
    # "Cannot see" must never read as RERUN: that decides re-run vs apply.
    newos = tmp_path / "NewOS"
    newos.mkdir()
    newos.chmod(0)
    try:
        with pytest.raises(PermissionError):
            probes.staged_os(newos / "winload.efi")
        out, err = io.StringIO(), io.StringIO()
        table = probes.commands(FakeHost, staged_os_path=str(newos / "winload.efi"))
        code = winrepair_guest.main(["staged-os"], commands=table, stdout=out, stderr=err)
    finally:
        newos.chmod(0o700)
    assert code == 2
    assert at(json.loads(out.getvalue()), "data", "error_type") == "PermissionError"


def test_staged_os_command_names_the_newos_winload_path() -> None:
    _, envelope = _run(FakeHost(), "staged-os")

    assert _data(envelope)["path"] == r"C:\$WINDOWS.~BT\NewOS\Windows\System32\winload.efi"


# --- state ----------------------------------------------------------------------------------


def test_state_absent_log_has_no_verdict(tmp_path: Path) -> None:
    code, envelope = _run(FakeHost(), "state", "--log", str(tmp_path / "missing.log"))

    assert code == 0
    assert _data(envelope) == {
        "path": str(tmp_path / "missing.log"),
        "present": False,
        "verdict": None,
        "marker": None,
        "line_count": 0,
        "tail": [],
    }


def test_state_running_log_has_no_verdict_yet(tmp_path: Path) -> None:
    log = tmp_path / "state.log"
    log.write_bytes(
        b"\xef\xbb\xbf2026-10-21 10:00:00  === upgrade_run start ===\r\n2026-10-21 10:00:01  launching: x\r\n"
    )

    _, envelope = _run(FakeHost(), "state", "--log", str(log))

    data = _data(envelope)
    assert (data["present"], data["verdict"], data["line_count"]) == (True, None, 2)
    assert data["tail"] == [
        "2026-10-21 10:00:00  === upgrade_run start ===",
        "2026-10-21 10:00:01  launching: x",
    ]


def test_state_latest_marker_wins(tmp_path: Path) -> None:
    log = tmp_path / "state.log"
    log.write_text("a  STATE=DONE-FAIL rc=0xC1900200\nb  STATE=DONE-OK reboot required to apply\n", encoding="utf-8")

    _, envelope = _run(FakeHost(), "state", "--log", str(log))

    assert (_data(envelope)["verdict"], _data(envelope)["marker"]) == (
        "DONE-OK",
        "b  STATE=DONE-OK reboot required to apply",
    )


def test_state_reads_a_marker_written_as_utf16(tmp_path: Path) -> None:
    # The Tee-Object trap the old upgrade_run.ps1 warns about: UTF-16 text after an ASCII header.
    log = tmp_path / "state.log"
    log.write_bytes(b"x  launching\n" + "y  STATE=DONE-FAIL rc=0x1\n".encode("utf-16-le"))

    _, envelope = _run(FakeHost(), "state", "--log", str(log))

    assert _data(envelope)["verdict"] == "DONE-FAIL"


def test_state_keeps_only_the_last_200_lines(tmp_path: Path) -> None:
    log = tmp_path / "state.log"
    log.write_text("".join(f"line {i}\n" for i in range(250)), encoding="utf-8")

    _, envelope = _run(FakeHost(), "state", "--log", str(log))

    data = _data(envelope)
    assert data["line_count"] == 250
    tail = items(data, "tail")
    assert (len(tail), tail[0], tail[-1]) == (200, "line 50", "line 249")


def test_state_unreadable_log_is_an_internal_error_not_absent(tmp_path: Path) -> None:
    log = tmp_path / "state.log"
    log.mkdir()  # reading a directory raises IsADirectoryError / PermissionError, never "absent"

    code, envelope = _run(FakeHost(), "state", "--log", str(log))

    assert code == 2
    assert envelope["ok"] is False


def test_task_time_is_local_wall_text_and_never_is_none() -> None:
    # pywin32 hands Task Scheduler times over labelled UTC although they are the guest's local wall
    # time, and a task that never ran reads 1999-11-30 (no next run: 1899-12-30), measured on a test guest.
    labelled_utc = datetime(2026, 10, 21, 19, 57, 6, tzinfo=timezone.utc)

    assert probes.task_time(labelled_utc) == "2026-10-21T19:57:06"
    assert probes.task_time(datetime(1999, 11, 30, tzinfo=timezone.utc)) is None
    assert probes.task_time(datetime(1899, 12, 30, tzinfo=timezone.utc)) is None
    assert probes.task_time(None) is None
    # pywintypes times carry milliseconds; the field is whole seconds, as the docstring shows.
    assert probes.task_time(labelled_utc.replace(microsecond=123000)) == "2026-10-21T19:57:06"
