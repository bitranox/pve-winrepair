"""Tests for quiesce-wu / restore-wu and the bounded Windows Update search probe.

The commands reach Windows only through the ``WuHost`` port. ``FakeWuHost`` behaves like the
service control manager the old scripts fought with: a Start value written to the registry is
what WMI reports as StartMode (unless the service reverts it, as WaaSMedicSvc exists to do), and
``sc.exe stop`` only ISSUES a stop, so a service leaves Running some time later or never. Time is
a fake clock the poll advances through ``sleep``. ``run_bounded`` is tested with real spawned
processes, because killing a hung child is exactly what a fake could not prove.
"""

from __future__ import annotations

import io
import json
import math
import multiprocessing
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import mp_targets
from json_paths import at, items, obj
from pwshpy import (
    CimInstance,
    NativeCallError,
    ProcessResult,
    RegistryHive,
    RegistryValue,
    RegistryValueType,
)

from pve_winrepair_guest import winrepair_guest, wu

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

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
    sc_fails: set[str] = field(default_factory=set[str])
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

    def exec(self, argv: Sequence[str], *, timeout: float) -> ProcessResult:
        assert list(argv[:2]) == ["sc.exe", "stop"]
        assert timeout == 30.0
        service = argv[2]
        self.calls.append(f"stop {service}")
        if service in self.sc_fails:
            raise NativeCallError(f"Command {list(argv)!r} exceeded its 30.0s timeout and was killed.")
        if self.state.get(service) == "Running":
            self.stopping[service] = self.now + self.stop_delay.get(service, 0.0)
            return ProcessResult(argv=list(argv), exit_code=0, stdout="STOP_PENDING", stderr="", duration_s=0.1)
        return ProcessResult(argv=list(argv), exit_code=1062, stdout="", stderr="", duration_s=0.1)

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


def test_quiesce_records_a_hung_sc_stop_and_carries_on() -> None:
    host = FakeWuHost(sc_fails={"wuauserv"})

    _, envelope = _run(host, "quiesce-wu")

    stop = obj(at(envelope, "data", "stops", 0))
    assert (stop["service"], stop["exit_code"]) == ("wuauserv", None)
    assert "timeout" in str(stop["error"])
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


def test_search_probe_maps_a_finished_search() -> None:
    run = wu.BoundedRun(status="DONE", value={"count": 2, "titles": ["A", "B"]}, error=None)

    probe = wu.search_probe(run, timeout=180.0)

    assert probe == wu.SearchProbe(status="OK", pending=2, titles=("A", "B"), error=None, timeout_s=180.0)


def test_search_probe_maps_timeout_raise_and_death() -> None:
    timed_out = wu.search_probe(wu.BoundedRun(status="TIMEOUT", value=None, error=None), timeout=5.0)
    raised = wu.search_probe(wu.BoundedRun(status="RAISED", value=None, error="com_error: x"), timeout=5.0)
    died = wu.search_probe(wu.BoundedRun(status="DIED", value=None, error="worker exited with code 7"), timeout=5.0)

    assert (timed_out.status, timed_out.pending, timed_out.error) == ("TIMEOUT", None, None)
    assert (raised.status, raised.pending, raised.error) == ("FAILED", None, "com_error: x")
    assert (died.status, died.error) == ("FAILED", "worker exited with code 7")


def test_search_probe_refuses_a_malformed_result_as_failed() -> None:
    probe = wu.search_probe(wu.BoundedRun(status="DONE", value={"count": "two"}, error=None), timeout=5.0)

    assert (probe.status, probe.pending) == ("FAILED", None)


def test_run_bounded_returns_the_child_value() -> None:
    run = wu.run_bounded(mp_targets.answer, (42,), timeout=60.0)

    assert run == wu.BoundedRun(status="DONE", value={"value": 42}, error=None)


def test_run_bounded_reports_an_exception_in_the_child() -> None:
    run = wu.run_bounded(mp_targets.raise_error, (), timeout=60.0)

    assert (run.status, run.error) == ("RAISED", "RuntimeError: 0x8024402c search failed")


def test_run_bounded_reports_a_child_that_died_without_answering() -> None:
    run = wu.run_bounded(mp_targets.die_hard, (), timeout=60.0)

    assert (run.status, run.error) == ("DIED", "worker exited with code 7")


def test_run_bounded_kills_a_hung_child_at_the_timeout() -> None:
    started = time.monotonic()

    run = wu.run_bounded(mp_targets.sleep_forever, (), timeout=1.0)

    assert run.status == "TIMEOUT"
    assert run.error is None
    assert time.monotonic() - started < 15.0
    assert multiprocessing.active_children() == []  # killed and reaped, not abandoned
