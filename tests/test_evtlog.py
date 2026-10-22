"""Tests for the event-log reader that renders messages with the provider's metadata.

``FakeEvtModule`` stands in for pywin32's ``win32evtlog`` behind the ``EvtApi`` seam: it keeps
events as (system values, message) pairs and formats a message only when handed the metadata
object of that event's provider, the way the real ``EvtFormatMessage`` does. Formatting with
``None`` metadata returns the Win32 error string pwshpy 1.5.0 surfaced on a German guest, so a
reader that skipped the metadata would be caught by the message assertions.
"""

from __future__ import annotations

import io
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, cast

import pytest
from pwshpy import EventLevel, EventLogEntry, NativeCallError
from test_probes import LP_MESSAGE, FakeHost, lp_host

from pve_winrepair_guest import evtlog, probes, winrepair_guest

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

SERVICING = "Microsoft-Windows-Servicing"
ERROR_STRING = "Das System kann die angegebene Datei nicht finden. "
NO_MORE_ITEMS = 259


class FakeEvtError(Exception):
    """Stands in for ``pywintypes.error``."""

    def __init__(self, winerror: int, text: str = "fake failure") -> None:
        super().__init__(text)
        self.winerror = winerror


@dataclass(frozen=True)
class FakeEvent:
    provider: str
    message: str | None
    when: datetime = datetime(2026, 10, 20, 23, 42, 6, tzinfo=timezone(timedelta(hours=1)))
    level: int = 2
    record_id: int = 194
    event_id: int = 9


@dataclass(frozen=True)
class Metadata:
    provider: str


@dataclass
class FakeEvtModule:
    """The ``win32evtlog`` functions and constants the reader uses."""

    events: list[FakeEvent]
    no_metadata: set[str] = field(default_factory=set[str])
    format_fails: set[str] = field(default_factory=set[str])
    query_fails: bool = False
    next_error: int | None = None
    batch: int = 2
    metadata_opens: list[str] = field(default_factory=list[str])

    EvtQueryChannelPath = 1
    EvtQueryReverseDirection = 0x200
    EvtRenderContextSystem = 1
    EvtRenderEventValues = 0
    EvtFormatMessageEvent = 1

    def EvtQuery(self, path: str, flags: int) -> Iterator[list[FakeEvent]]:  # noqa: N802 - mirrors the pywin32 / COM member name
        assert flags == self.EvtQueryChannelPath | self.EvtQueryReverseDirection
        if self.query_fails:
            raise FakeEvtError(15007, "channel not found")
        assert path == "Setup"
        return iter([self.events[i : i + self.batch] for i in range(0, len(self.events), self.batch)])

    def EvtCreateRenderContext(self, flags: int) -> str:  # noqa: N802 - mirrors the pywin32 / COM member name
        assert flags == self.EvtRenderContextSystem
        return "system-context"

    def EvtNext(self, query: object, count: int) -> list[FakeEvent]:  # noqa: N802 - mirrors the pywin32 / COM member name
        assert count > 0
        batch = next(cast("Iterator[list[FakeEvent]]", query), None)
        if batch is None:
            if self.next_error is not None:
                raise FakeEvtError(self.next_error)
            return []
        return batch

    def EvtRender(self, event: object, flags: int, Context: object) -> list[tuple[object, int]]:  # noqa: N802, N803 - mirrors the pywin32 / COM member name
        assert (flags, Context) == (self.EvtRenderEventValues, "system-context")
        assert isinstance(event, FakeEvent)
        values: list[object] = [None] * 18
        values[0], values[2], values[4] = event.provider, event.event_id, event.level
        values[8], values[9], values[14], values[15] = event.when, event.record_id, "Setup", "test-host"
        return [(value, 0) for value in values]

    def EvtOpenPublisherMetadata(self, provider: str) -> Metadata:  # noqa: N802 - mirrors the pywin32 / COM member name
        self.metadata_opens.append(provider)
        if provider in self.no_metadata:
            raise FakeEvtError(2)
        return Metadata(provider)

    def EvtFormatMessage(self, metadata: object, event: object, flags: int) -> str | None:  # noqa: N802 - mirrors the pywin32 / COM member name
        assert flags == self.EvtFormatMessageEvent
        assert isinstance(event, FakeEvent)
        assert metadata is None or isinstance(metadata, Metadata)
        if metadata is None:
            return ERROR_STRING  # what the provider-less call returned on the German guest
        if event.provider in self.format_fails:
            raise FakeEvtError(15027)
        assert metadata.provider == event.provider
        return event.message


def _read(module: FakeEvtModule) -> list[EventLogEntry]:
    return list(evtlog.iter_events("Setup", api=evtlog.EvtApi(module=module, error=FakeEvtError)))


def test_messages_are_rendered_with_the_providers_metadata() -> None:
    module = FakeEvtModule([FakeEvent(SERVICING, "Package KB1 was successfully changed to the Installed state.")])

    [entry] = _read(module)

    assert entry.message == "Package KB1 was successfully changed to the Installed state."
    assert (entry.provider_name, entry.log_name, entry.machine_name) == (SERVICING, "Setup", "test-host")
    assert (entry.event_id, entry.record_id, entry.level) == (9, 194, EventLevel.ERROR)
    assert entry.time_created == datetime(2026, 10, 20, 22, 42, 6, tzinfo=timezone.utc)
    assert entry.time_created is not None and entry.time_created.tzinfo is timezone.utc


def test_metadata_is_opened_once_per_provider_across_batches() -> None:
    module = FakeEvtModule([FakeEvent(SERVICING, f"m{i}") for i in range(5)] + [FakeEvent("Other", "o")], batch=2)

    entries = _read(module)

    assert [e.message for e in entries] == ["m0", "m1", "m2", "m3", "m4", "o"]
    assert module.metadata_opens == [SERVICING, "Other"]


def test_a_provider_without_metadata_yields_none_not_an_error_string() -> None:
    module = FakeEvtModule([FakeEvent("Gone", "x"), FakeEvent(SERVICING, "kept")], no_metadata={"Gone"})

    assert [e.message for e in _read(module)] == [None, "kept"]


def test_a_failed_or_empty_format_yields_none() -> None:
    module = FakeEvtModule([FakeEvent("Broken", "x"), FakeEvent(SERVICING, "")], format_fails={"Broken"})

    assert [e.message for e in _read(module)] == [None, None]


def test_no_more_items_ends_the_stream_and_other_next_errors_raise() -> None:
    assert len(_read(FakeEvtModule([FakeEvent(SERVICING, "a")], next_error=NO_MORE_ITEMS))) == 1

    with pytest.raises(NativeCallError, match="EvtNext failed"):
        _read(FakeEvtModule([FakeEvent(SERVICING, "a")], next_error=5))


def test_an_unqueryable_log_raises_native_call_error() -> None:
    with pytest.raises(NativeCallError, match="cannot query event log 'Setup'"):
        _read(FakeEvtModule([], query_fails=True))


def test_pwshpy_host_reads_events_through_the_metadata_renderer() -> None:
    module = FakeEvtModule([FakeEvent(SERVICING, LP_MESSAGE)])
    host = probes.PwshpyHost(event_api=evtlog.EvtApi(module=module, error=FakeEvtError))

    assert [e.message for e in host.win_events("Setup")] == [LP_MESSAGE]


@dataclass
class AdapterEventsHost(FakeHost):
    """FakeHost whose Setup events come through the real PwshpyHost adapter and evtlog reader."""

    module: FakeEvtModule = field(default_factory=lambda: FakeEvtModule([]))

    def win_events(self, log_name: str) -> Iterator[EventLogEntry]:
        api = evtlog.EvtApi(module=self.module, error=FakeEvtError)
        yield from probes.PwshpyHost(event_api=api).win_events(log_name)


def _detect(module: FakeEvtModule) -> tuple[int, dict[str, object]]:
    host = lp_host()
    adapter_host = AdapterEventsHost(registry_values=host.registry_values, module=module)
    out, err = io.StringIO(), io.StringIO()
    commands = probes.commands(lambda: adapter_host)
    code = winrepair_guest.main(["detect-lp-defect"], commands=commands, stdout=out, stderr=err)
    envelope = json.loads(out.getvalue())
    assert isinstance(envelope, dict)
    data = cast("dict[str, object]", envelope)["data"]
    assert isinstance(data, dict)
    return code, cast("dict[str, object]", data)


def test_detect_finds_the_defect_through_the_real_reader() -> None:
    events: Sequence[FakeEvent] = [FakeEvent(SERVICING, "noise"), FakeEvent(SERVICING, LP_MESSAGE)]

    code, data = _detect(FakeEvtModule(list(events)))

    assert (code, data["verdict"], data["lp_absent_events"], data["codes"]) == (
        0,
        "AFFECTED",
        1,
        ["0x800736B3"],
    )


def test_detect_is_unknown_when_the_reader_cannot_render_any_message() -> None:
    module = FakeEvtModule([FakeEvent(SERVICING, LP_MESSAGE), FakeEvent(SERVICING, "noise")], no_metadata={SERVICING})

    code, data = _detect(module)

    assert code == 1
    assert data["verdict"] == "UNKNOWN"
    assert data["lp_absent_events"] is None
    assert data["reason"] == "2 of 2 Setup event messages could not be rendered"
