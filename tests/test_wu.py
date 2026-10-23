"""Tests for quiesce-wu / restore-wu and the bounded Windows Update search probe.

The commands reach Windows only through the ``WuHost`` port. ``FakeWuHost`` behaves like the
service control manager the old scripts fought with: a Start value written to the registry is
what WMI reports as StartMode (unless the service reverts it, as WaaSMedicSvc exists to do), and
``stop_service(wait=False)`` only ISSUES a stop, so a service leaves Running some time later or never. Time is
a fake clock the poll advances through ``sleep``. The search itself is pwshpy's
``get_windows_update`` (a killable child process); here its outcomes are mapped to the probe.
"""

from __future__ import annotations

import io
import json
import math
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import pytest
from json_paths import at, items, obj
from pwshpy import (
    CimInstance,
    NativeCallError,
    OperationTimeoutError,
    RegistryHive,
    RegistryValue,
    RegistryValueType,
    ServiceInfo,
    ServiceState,
    WindowsUpdate,
)

from pve_winrepair_guest import winrepair_guest, wu

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

SERVICES = r"HKLM\SYSTEM\CurrentControlSet\Services"
MODES = {2: "Auto", 3: "Manual", 4: "Disabled"}
FLEET_START = {"wuauserv": 3, "UsoSvc": 2, "BITS": 2, "WaaSMedicSvc": 3}
FLEET_STATE = {"wuauserv": "Running", "UsoSvc": "Running", "BITS": "Running", "WaaSMedicSvc": "Stopped"}
SEARCH_OK = wu.SearchProbe(status="OK", pending=1, titles=("KB5127690",), error=None, timeout_s=180.0)


@dataclass
class FakeWuHost:
    """A WuHost over an in-memory SCM; ``stop_delay`` is how long a stop takes (inf: never)."""

    start: dict[str, int] = field(default_factory=lambda: dict(FLEET_START))
    state: dict[str, str] = field(default_factory=lambda: dict(FLEET_STATE))
    stop_delay: dict[str, float] = field(default_factory=dict[str, float])
    reverting: set[str] = field(default_factory=set[str])
    write_fails: set[str] = field(default_factory=set[str])
    stop_fails: set[str] = field(default_factory=set[str])
    cim_fails: bool = False
    search: wu.SearchProbe = SEARCH_OK
    now: float = 0.0
    calls: list[str] = field(default_factory=list[str])
    stopping: dict[str, float] = field(default_factory=dict[str, float])
    search_timeouts: list[float] = field(default_factory=list[float])

    def _state(self, name: str) -> str:
        due = self.stopping.get(name)
        if due is None:
            return self.state[name]
        return "Stop Pending" if self.now >= due else "Running"

    def cim(self, class_name: str, *, where: str | None = None) -> Iterable[CimInstance]:
        assert class_name == "Win32_Service"
        assert where == " OR ".join(f"Name='{name}'" for name in wu.TARGETS)
        if self.cim_fails:
            raise NativeCallError("WMI unavailable")
        self.calls.append("cim")
        return [
            CimInstance(
                class_name="Win32_Service",
                properties={"Name": name, "StartMode": MODES[start], "State": self._state(name)},
            )
            for name, start in self.start.items()
        ]

    def registry(self, key: str) -> Iterable[RegistryValue]:
        name = key.removeprefix(SERVICES + "\\")
        if name not in self.start:
            raise NativeCallError(f'registry key "{key}" not found')
        value = RegistryValue(
            hive=RegistryHive.HKLM,
            key=key,
            name="Start",
            type=RegistryValueType.REG_DWORD,
            data=self.start[name],
        )
        return [value]

    def set_dword(self, key: str, name: str, value: int) -> None:
        service = key.removeprefix(SERVICES + "\\")
        assert name == "Start"
        self.calls.append(f"set {service}={value}")
        if service in self.write_fails:
            raise NativeCallError("Zugriff verweigert")
        if service not in self.reverting:
            self.start[service] = value

    def stop_service(self, name: str) -> ServiceInfo:
        self.calls.append(f"stop {name}")
        if name in self.stop_fails:
            raise NativeCallError("(1052, 'ControlService', 'Das angeforderte Steuerelement ist ungueltig.')")
        if self.state.get(name) == "Running":
            self.stopping[name] = self.now + self.stop_delay.get(name, 0.0)
            return ServiceInfo(name=name, display_name=name, status=ServiceState.STOP_PENDING)
        return ServiceInfo(name=name, display_name=name, status=ServiceState.STOPPED)

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.calls.append(f"sleep {seconds:g}")
        self.now += seconds

    def search_updates(self, timeout: float) -> wu.SearchProbe:
        self.search_timeouts.append(timeout)
        return self.search


def _run(host: FakeWuHost, *argv: str) -> tuple[int, dict[str, object]]:
    out, err = io.StringIO(), io.StringIO()
    code = winrepair_guest.main(list(argv), commands=wu.commands(lambda: host), stdout=out, stderr=err)
    lines = out.getvalue().splitlines()
    assert len(lines) == 1, (lines, err.getvalue())
    return code, json.loads(lines[0])


def _data(envelope: dict[str, object]) -> dict[str, object]:
    return obj(envelope["data"])


# --- quiesce-wu -----------------------------------------------------------------------------


def test_quiesce_disables_then_stops_and_verifies_ok() -> None:
    host = FakeWuHost()

    code, envelope = _run(host, "quiesce-wu")

    assert code == 0
    data = _data(envelope)
    assert data["verdict"] == "OK"
    assert data["previous_start_modes"] == {
        "wuauserv": "Manual",
        "UsoSvc": "Auto",
        "BITS": "Auto",
        "WaaSMedicSvc": "Manual",
    }
    assert (data["not_disabled"], data["still_running"]) == ([], [])
    assert [at(w, "result") for w in items(data, "writes")] == ["WRITTEN"] * 4
    # The registry writes (cannot hang) all come before the first stop (could).
    writes = [c for c in host.calls if c.startswith("set ")]
    assert writes == [f"set {name}=4" for name in wu.TARGETS]
    assert host.calls.index(writes[-1]) < host.calls.index("stop wuauserv")
    assert [c for c in host.calls if c.startswith("stop ")] == [f"stop {name}" for name in wu.TARGETS]


def test_quiesce_counts_stop_pending_as_not_running() -> None:
    host = FakeWuHost(stop_delay={"UsoSvc": 0.0})

    code, envelope = _run(host, "quiesce-wu")

    assert code == 0
    services = {at(s, "name"): at(s, "state") for s in items(envelope, "data", "services")}
    assert services["UsoSvc"] == "Stop Pending"


def test_quiesce_poll_is_bounded_at_180_seconds_and_fails_a_service_still_running() -> None:
    host = FakeWuHost(stop_delay={"UsoSvc": math.inf})

    code, envelope = _run(host, "quiesce-wu")

    assert code == 1
    data = _data(envelope)
    assert (data["verdict"], data["still_running"], data["not_disabled"]) == ("FAIL", ["UsoSvc"], [])
    assert data["wait"] == {"waited_s": 180.0, "timed_out": True, "still_running": ["UsoSvc"]}
    assert host.now == 180.0
    assert {c for c in host.calls if c.startswith("sleep")} == {"sleep 10"}


def test_quiesce_poll_ends_once_every_service_has_left_running() -> None:
    host = FakeWuHost(stop_delay={"BITS": 25.0})

    code, envelope = _run(host, "quiesce-wu")

    assert code == 0
    assert _data(envelope)["wait"] == {"waited_s": 30.0, "timed_out": False, "still_running": []}


def test_quiesce_fails_when_a_start_value_is_reverted() -> None:
    host = FakeWuHost(reverting={"WaaSMedicSvc"})

    code, envelope = _run(host, "quiesce-wu")

    assert code == 1
    data = _data(envelope)
    assert (data["verdict"], data["not_disabled"]) == ("FAIL", ["WaaSMedicSvc"])


def test_quiesce_reports_a_failed_write_and_still_issues_every_stop() -> None:
    host = FakeWuHost(write_fails={"wuauserv"})

    code, envelope = _run(host, "quiesce-wu")

    assert code == 1
    data = _data(envelope)
    write = obj(at(data, "writes", 0))
    assert (write["service"], write["result"], write["error"]) == ("wuauserv", "FAILED", "Zugriff verweigert")
    assert data["not_disabled"] == ["wuauserv"]
    assert len([c for c in host.calls if c.startswith("stop ")]) == 4


def test_quiesce_skips_a_service_without_a_key_and_judges_the_rest() -> None:
    host = FakeWuHost()
    del host.start["WaaSMedicSvc"]

    code, envelope = _run(host, "quiesce-wu")

    assert code == 0
    data = _data(envelope)
    absent = [w for w in items(data, "writes") if at(w, "service") == "WaaSMedicSvc"]
    assert at(absent, 0, "result") == "ABSENT"
    assert "WaaSMedicSvc" not in obj(data["previous_start_modes"])
    assert data["verdict"] == "OK"


def test_quiesce_reports_the_state_each_stop_left_a_service_in() -> None:
    host = FakeWuHost()

    _, envelope = _run(host, "quiesce-wu")

    assert items(envelope, "data", "stops") == [
        {"service": "wuauserv", "state": "StopPending", "error": None},
        {"service": "UsoSvc", "state": "StopPending", "error": None},
        {"service": "BITS", "state": "StopPending", "error": None},
        {"service": "WaaSMedicSvc", "state": "Stopped", "error": None},
    ]


def test_quiesce_records_a_refused_stop_and_carries_on() -> None:
    host = FakeWuHost(stop_fails={"wuauserv"})

    _, envelope = _run(host, "quiesce-wu")

    stop = obj(at(envelope, "data", "stops", 0))
    assert (stop["service"], stop["state"]) == ("wuauserv", None)
    assert "1052" in str(stop["error"])
    assert len([c for c in host.calls if c.startswith("stop ")]) == 4


def test_quiesce_with_no_target_service_readable_is_unknown_not_ok() -> None:
    host = FakeWuHost(start={}, state={})

    code, envelope = _run(host, "quiesce-wu")

    assert code == 1
    assert _data(envelope)["verdict"] == "UNKNOWN"


def test_quiesce_changes_nothing_when_the_previous_modes_cannot_be_read() -> None:
    host = FakeWuHost(cim_fails=True)

    code, envelope = _run(host, "quiesce-wu")

    assert code == 2
    assert envelope["ok"] is False
    assert host.calls == []


# --- restore-wu -----------------------------------------------------------------------------


def disabled_host(**changes: object) -> FakeWuHost:
    host = FakeWuHost(start=dict.fromkeys(FLEET_START, 4), state=dict.fromkeys(FLEET_START, "Stopped"))
    for name, value in changes.items():
        setattr(host, name, value)
    return host


def test_restore_writes_the_fleet_defaults_and_verifies() -> None:
    host = disabled_host()

    code, envelope = _run(host, "restore-wu")

    assert code == 0
    data = _data(envelope)
    assert host.start == FLEET_START
    assert [c for c in host.calls if c.startswith("set ")] == [
        "set wuauserv=3",
        "set UsoSvc=2",
        "set BITS=2",
        "set WaaSMedicSvc=3",
    ]
    assert (data["verdict"], data["still_disabled"]) == ("RESTORED", [])
    assert data["search"] == {
        "status": "OK",
        "pending": 1,
        "titles": ["KB5127690"],
        "error": None,
        "timeout_s": 180.0,
    }
    assert host.search_timeouts == [180.0]


def test_restore_reports_a_service_still_disabled() -> None:
    host = disabled_host(reverting={"BITS"})

    code, envelope = _run(host, "restore-wu")

    assert code == 1
    data = _data(envelope)
    assert (data["verdict"], data["still_disabled"]) == ("STILL_DISABLED", ["BITS"])


def test_restore_search_timeout_is_not_a_verdict() -> None:
    timeout = wu.SearchProbe(status="TIMEOUT", pending=None, titles=(), error=None, timeout_s=180.0)
    host = disabled_host(search=timeout)

    code, envelope = _run(host, "restore-wu")

    assert code == 0
    data = _data(envelope)
    assert data["verdict"] == "RESTORED"
    assert at(data, "search", "status") == "TIMEOUT"
    assert at(data, "search", "pending") is None


def test_restore_with_no_service_readable_is_unknown() -> None:
    host = disabled_host(start={}, state={})

    code, envelope = _run(host, "restore-wu")

    assert code == 1
    assert _data(envelope)["verdict"] == "UNKNOWN"


# --- the bounded search probe ---------------------------------------------------------------


def _updates(*titles: str) -> Callable[[], Iterable[WindowsUpdate]]:
    return lambda: [WindowsUpdate(update_id=f"u{i}", title=title) for i, title in enumerate(titles)]


def _raising(error: Exception) -> Callable[[], Iterable[WindowsUpdate]]:
    def search() -> Iterable[WindowsUpdate]:
        raise error

    return search


def test_search_probe_maps_a_finished_search() -> None:
    probe = wu.search_probe(_updates("A", "B"), timeout=180.0)

    assert probe == wu.SearchProbe(status="OK", pending=2, titles=("A", "B"), error=None, timeout_s=180.0)


def test_search_probe_keeps_a_timeout_apart_from_a_failure() -> None:
    # OperationTimeoutError IS a NativeCallError: caught second, a timeout would read FAILED.
    timeout = OperationTimeoutError("Windows Update search timed out after 5s", timeout=5.0)
    timed_out = wu.search_probe(_raising(timeout), timeout=5.0)
    failed = wu.search_probe(_raising(NativeCallError("HRESULT 0x8024402C")), timeout=5.0)
    died = wu.search_probe(_raising(NativeCallError("worker exited without a result (exit code 7)")), timeout=5.0)

    assert (timed_out.status, timed_out.pending, timed_out.error) == ("TIMEOUT", None, None)
    assert (failed.status, failed.pending, failed.error) == ("FAILED", None, "HRESULT 0x8024402C")
    assert (died.status, died.error) == ("FAILED", "worker exited without a result (exit code 7)")


@pytest.mark.os_posix  # on Windows this would run a real Windows Update search for up to 180 s
def test_the_real_search_reaches_pwshpy_and_reports_its_refusal_as_failed() -> None:
    probe = wu.PwshpyHost().search_updates(wu.SEARCH_TIMEOUT)

    assert (probe.status, probe.pending, probe.timeout_s) == ("FAILED", None, 180.0)
    assert probe.error == "Windows Update search is Windows-only."
