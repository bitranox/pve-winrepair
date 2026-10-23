"""Read a Windows event log with each event's message rendered by its provider's metadata.

pwshpy 1.5.0's ``get_win_event`` formats messages with ``EvtFormatMessage(None, ...)``: no
publisher metadata, failure swallowed. On a German-language Windows every Setup event then reads
"Das System kann die angegebene Datei nicht finden." (a Win32 error string, not the event text)
or None, so a probe matching message text can never fire. This module renders through
``EvtOpenPublisherMetadata(provider)`` (opened once per provider) and reports a message it cannot
format as ``None``, never as an error string, so the caller can tell "unrendered" from "no match".
Filed in pwshpy's OPEN-WORK.md; drop this module once pwshpy renders with the metadata.

The system fields come from ``EvtRender(EvtRenderEventValues)`` with a system render context, so
no event XML is parsed.

Contents:
    * :class:`EvtModule` - the ``win32evtlog`` members used here, as a typed protocol.
    * :class:`EvtApi` - the pywin32 module plus its error type (the seam the tests fake).
    * :class:`MessageRenderer` - per-provider metadata cache and message formatting.
    * :func:`iter_events` - stream a log's events newest first as pwshpy ``EventLogEntry``.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Protocol, cast

from pwshpy import EventLevel, EventLogEntry, NativeCallError, PlatformUnsupportedError

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

__all__ = ["EvtApi", "EvtModule", "MessageRenderer", "iter_events"]

_BATCH = 64
_ERROR_NO_MORE_ITEMS = 259
# EVT_SYSTEM_PROPERTY_ID indexes (winevt.h): the order of the values EvtRenderEventValues
# returns for a system render context. Measured on 26200: 18 (value, type) pairs in this order.
_PROVIDER_NAME = 0
_EVENT_ID = 2
_LEVEL = 4
_TIME_CREATED = 8
_RECORD_ID = 9
_CHANNEL = 14
_COMPUTER = 15
_LEVELS = {
    0: EventLevel.LOG_ALWAYS,
    1: EventLevel.CRITICAL,
    2: EventLevel.ERROR,
    3: EventLevel.WARNING,
    4: EventLevel.INFORMATION,
    5: EventLevel.VERBOSE,
}


class EvtModule(Protocol):
    """The ``win32evtlog`` members the reader uses (pywin32 is Windows-only, absent on the Linux dev host).

    Handles (query, render context, event, publisher metadata) are opaque objects that only ever
    go back into these functions.
    """

    @property
    def EvtQueryChannelPath(self) -> int:  # noqa: N802 - mirrors the pywin32 / COM member name
        """EvtQuery flag: the path names a channel."""
        ...

    @property
    def EvtQueryReverseDirection(self) -> int:  # noqa: N802 - mirrors the pywin32 / COM member name
        """EvtQuery flag: newest event first."""
        ...

    @property
    def EvtRenderContextSystem(self) -> int:  # noqa: N802 - mirrors the pywin32 / COM member name
        """EvtCreateRenderContext flag: the system properties."""
        ...

    @property
    def EvtRenderEventValues(self) -> int:  # noqa: N802 - mirrors the pywin32 / COM member name
        """EvtRender flag: render values through a context."""
        ...

    @property
    def EvtFormatMessageEvent(self) -> int:  # noqa: N802 - mirrors the pywin32 / COM member name
        """EvtFormatMessage flag: the event's message."""
        ...

    def EvtQuery(self, path: str, flags: int, /) -> object:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Open a query over a channel."""
        ...

    def EvtCreateRenderContext(self, flags: int, /) -> object:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Create a render context."""
        ...

    def EvtNext(self, query: object, count: int, /) -> Sequence[object]:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Return up to ``count`` event handles; empty (or ERROR_NO_MORE_ITEMS) at the end."""
        ...

    def EvtRender(self, event: object, flags: int, /, Context: object) -> Sequence[tuple[object, int]]:  # noqa: N802, N803 - mirrors the pywin32 / COM member name
        """Render an event's values through ``Context`` as (value, type) pairs."""
        ...

    def EvtOpenPublisherMetadata(self, provider: str, /) -> object:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Open a provider's metadata (its message table)."""
        ...

    def EvtFormatMessage(self, metadata: object, event: object, flags: int, /) -> str | None:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Format an event's message with its provider's metadata."""
        ...


@dataclass(frozen=True)
class EvtApi:
    """The event-log binding: the ``win32evtlog`` module and the error type its calls raise.

    Attributes:
        module: ``win32evtlog`` (or a fake with the same functions and constants).
        error: ``pywintypes.error`` (or the fake's error type).
    """

    module: EvtModule
    error: type[Exception]

    @classmethod
    def load(cls) -> EvtApi:
        """Import pywin32's event-log binding.

        Raises:
            PlatformUnsupportedError: pywin32 is absent (not Windows).
        """
        # import_module: pywin32 is a Windows-only dependency of pwshpy, not installed on the
        # Linux dev host; this only ever runs on the guest.
        try:
            module = importlib.import_module("win32evtlog")
            pywintypes = importlib.import_module("pywintypes")
        except ImportError as exc:
            raise PlatformUnsupportedError("reading the event log needs pywin32 (Windows only)") from exc
        return cls(module=cast("EvtModule", module), error=cast("type[Exception]", pywintypes.error))


class MessageRenderer:
    """Format event messages with the provider's metadata, opening it once per provider."""

    def __init__(self, api: EvtApi) -> None:
        """Bind the renderer to an event-log binding.

        Args:
            api: The binding whose metadata and formatting calls are used.
        """
        self._api = api
        self._metadata: dict[str, object] = {}

    def _metadata_for(self, provider: str) -> object:
        if provider not in self._metadata:
            try:
                self._metadata[provider] = self._api.module.EvtOpenPublisherMetadata(provider)
            except self._api.error:
                # No registered metadata for this provider: its messages cannot be formatted,
                # which the caller sees as None and must not read as "no match".
                self._metadata[provider] = None
        return self._metadata[provider]

    def render(self, handle: object, provider: str) -> str | None:
        """Return the event's formatted message, or None when it cannot be formatted.

        Args:
            handle: The event handle from ``EvtNext``.
            provider: The event's provider name (selects the metadata).

        Returns:
            The message text, or None (no metadata, formatting failed, or empty text).
        """
        metadata = self._metadata_for(provider)
        if metadata is None:
            return None
        module = self._api.module
        try:
            text = module.EvtFormatMessage(metadata, handle, module.EvtFormatMessageEvent)
        except self._api.error:
            return None
        return str(text) if text else None


def _handles(api: EvtApi, query: object) -> Iterator[object]:
    """Yield event handles in batches until the query is exhausted."""
    while True:
        try:
            batch = api.module.EvtNext(query, _BATCH)
        except api.error as exc:
            if getattr(exc, "winerror", None) == _ERROR_NO_MORE_ITEMS:
                return
            raise NativeCallError(f"EvtNext failed: {exc}") from exc
        if not batch:
            return
        yield from batch


def _utc(value: object) -> datetime | None:
    # pywintypes.datetime carries pywin32's own tzinfo; rebuilding from the POSIX timestamp
    # gives a plain aware UTC datetime like the rest of the probes use.
    if not isinstance(value, datetime):
        return None
    return datetime.fromtimestamp(value.timestamp(), tz=timezone.utc)


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _number(value: object) -> int:
    # EvtRender gives an int for a set numeric property and None for an absent one.
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _entry(api: EvtApi, context: object, handle: object, renderer: MessageRenderer) -> EventLogEntry:
    """Build one record from the event's system values and its rendered message."""
    module = api.module
    try:
        values = [value for value, _type in module.EvtRender(handle, module.EvtRenderEventValues, Context=context)]
    except api.error as exc:
        raise NativeCallError(f"EvtRender failed: {exc}") from exc
    provider = _text(values[_PROVIDER_NAME])
    level = values[_LEVEL]
    return EventLogEntry(
        log_name=_text(values[_CHANNEL]),
        record_id=_number(values[_RECORD_ID]),
        event_id=_number(values[_EVENT_ID]),
        level=_LEVELS.get(level if isinstance(level, int) else -1, EventLevel.INFORMATION),
        provider_name=provider,
        time_created=_utc(values[_TIME_CREATED]),
        machine_name=_text(values[_COMPUTER]),
        message=renderer.render(handle, provider),
    )


def iter_events(log_name: str, *, api: EvtApi | None = None) -> Iterator[EventLogEntry]:
    """Stream a log's events newest first, messages rendered with the provider's metadata.

    Args:
        log_name: The channel to read (e.g. "Setup").
        api: The binding to use; the real pywin32 one when omitted.

    Yields:
        One ``EventLogEntry`` per event; ``message`` is None when it could not be rendered.

    Raises:
        NativeCallError: The log cannot be queried or an event cannot be read.
        PlatformUnsupportedError: pywin32 is absent.
    """
    binding = api or EvtApi.load()
    module = binding.module
    try:
        query = module.EvtQuery(log_name, module.EvtQueryChannelPath | module.EvtQueryReverseDirection)
        context = module.EvtCreateRenderContext(module.EvtRenderContextSystem)
    except binding.error as exc:
        raise NativeCallError(f"cannot query event log {log_name!r}: {exc}") from exc
    renderer = MessageRenderer(binding)
    for handle in _handles(binding, query):
        yield _entry(binding, context, handle, renderer)
