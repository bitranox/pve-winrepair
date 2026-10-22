r"""The guest tool's answer contract: its envelope, the typed fields, and every way a call fails.

The guest tool (``winrepair_guest.ps1``, packed by ``pwshpy pack``) answers every subcommand with
exactly one line ``{"ok": bool, "command": str, "data": {...}, "skipped": [...]}`` on stdout and
exits 0 (ok), 1 (refused: its own gate said no) or 2 (internal error, still with an envelope).
:func:`parse_envelope` turns that into three distinct outcomes, so a failed read can never pass for
an empty or negative answer:

* an :class:`Envelope` - exit 0, or exit 1 (refused); the caller gates on its typed ``data``;
* :class:`GuestInternalError` - exit 2: the tool ran and crashed, or did not know the command;
* :class:`GuestNoAnswerError` - no envelope at all: ssh failed, timed out, or stdout held nothing
  parseable (a non-zero exit without an envelope included).

A malformed or inconsistent answer (two envelopes, ``ok`` disagreeing with the exit code, a
missing or mistyped field) is :class:`GuestProtocolError`: the driver and the packed tool disagree
about the contract, which is a bug, not a guest state.

Arguments are checked BEFORE ssh (:func:`check_argument`): the guest's ssh shell is ``cmd.exe``,
which split ``D:\up&grade`` at the ``&`` and ran the rest as a second command.

Also here, because both drivers gate on them: the state log's verdicts (:data:`STATE_MARKERS`,
:class:`RunState`, :func:`state_marker`), :data:`READ_FAILURES`, :data:`PROBE_TIMEOUT`,
:func:`guest_stderr` and :data:`WU_HELD_HINT`. Nothing here starts a process: the ssh adapter
(:mod:`pve_winrepair.adapters.guest_ssh`) runs a call and hands the finished process to
:func:`parse_envelope`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    # The finished process is only a type here; nothing in this module runs one.
    from subprocess import CompletedProcess  # nosec B404

__all__ = [
    "EXIT_INTERNAL",
    "EXIT_OK",
    "EXIT_REFUSED",
    "POWERSHELL",
    "PROBE_TIMEOUT",
    "READ_FAILURES",
    "STATE_MARKERS",
    "STDERR_TAIL_LINES",
    "WU_HELD_HINT",
    "Envelope",
    "Fields",
    "GuestCallError",
    "GuestInternalError",
    "GuestNoAnswerError",
    "GuestProtocolError",
    "GuestPushError",
    "RunState",
    "Runner",
    "UnsafeArgumentError",
    "check_argument",
    "guest_stderr",
    "parse_envelope",
    "snippet",
    "state_marker",
    "tool_argv",
]


# By full path, never resolved through PATH (on a test guest four directories precede System32 in PATH).
# The guest's ssh shell is cmd.exe, which expands %SystemRoot% to the guest's own Windows directory.
POWERSHELL = (
    r"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe",
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
)


# An allowlist, not a list of bad characters: the argument crosses ssh's join, cmd.exe and
# powershell.exe's own split before the tool's argparse sees it. Letters, digits and
# ``_ . : \ / -`` cover every subcommand, flag, drive path and number the drivers send, and none
# of them is special to any of those layers. Everything else is refused, which covers cmd.exe's
# operators and expansions (& | < > ^ " % ! ( ) and newline), whitespace (both layers split on
# it, and the guest refuses spaces in its paths anyway), PowerShell's quotes (' `), cmd's
# argument delimiters (; , =), wildcards, $, and non-ASCII (the console code page mangles it).
_SAFE_ARGUMENT = re.compile(r"[A-Za-z0-9_.:\\/-]+")
# The pack wrapper consumes these switches itself (matched case-insensitively), so a value
# spelled like one would never reach the tool.
_WRAPPER_SWITCH = re.compile(r"-pwshpy", re.IGNORECASE)
_ENVELOPE_KEYS = frozenset({"ok", "command", "data", "skipped"})
EXIT_OK, EXIT_REFUSED, EXIT_INTERNAL = 0, 1, 2
# How much of a crashed tool's stderr (its Python traceback) is kept: enough for the frames that
# matter, short enough for an operator's terminal and a --json step.
STDERR_TAIL_LINES = 20
# Probe timeouts allow for the packed tool's first run on a guest, which resolves its Python
# dependencies through uv before it answers.
PROBE_TIMEOUT = 300.0
_TOOL_EXITS = {EXIT_OK: True, EXIT_REFUSED: False, EXIT_INTERNAL: False}

Runner = Callable[[Sequence[str], float], "CompletedProcess[str]"]


class GuestCallError(RuntimeError):
    """Base of every way a guest tool call can fail.

    Attributes:
        cleanup_failure: Why the push could not remove its copy from the ssh user's profile after this
            failure, or None; set by the push and appended to the message (the failure keeps its
            own type, so a protocol error still reads as one).
    """

    cleanup_failure: str | None = None

    def __str__(self) -> str:
        """The message, plus the profile copy the push could not remove."""
        message = super().__str__()
        return message if self.cleanup_failure is None else f"{message} ({self.cleanup_failure})"


class UnsafeArgumentError(GuestCallError, ValueError):
    """An argument would be split or reinterpreted on its way to the guest; nothing was run."""


class GuestNoAnswerError(GuestCallError):
    """No envelope came back: ssh failed or timed out, or stdout held nothing parseable."""


class GuestPushError(GuestCallError):
    """The packed tool could not be copied to the guest."""


class GuestProtocolError(GuestCallError):
    """An answer broke the envelope contract: the driver and the packed tool disagree."""


class GuestInternalError(GuestCallError):
    """The tool answered exit 2: it crashed, or did not know the command.

    Attributes:
        envelope: The internal-error envelope (``data.error``, ``data.error_type``).
        stderr_tail: The last lines of the tool's stderr: its traceback, which the envelope's one
            ``error`` line does not carry.
    """

    def __init__(self, envelope: Envelope, stderr: str = "") -> None:
        """Keep the envelope and the stderr tail; name the guest's error and its last line."""
        error = envelope.data.raw("error") if "error" in envelope.data else None
        tail = tuple(line for line in stderr.splitlines() if line.strip())[-STDERR_TAIL_LINES:]
        last = f" (guest stderr ends: {tail[-1].strip()})" if tail else ""
        super().__init__(f"guest tool {envelope.command or '?'} failed: {error}{last}")
        self.envelope = envelope
        self.stderr_tail = tail


# A guest read that failed (no envelope, or the tool crashed). It is never an answer: a poll
# retries it, a gate refuses on it. A protocol error is NOT in here - it is a driver/tool mismatch.
READ_FAILURES = (GuestNoAnswerError, GuestInternalError)


# Appended to a driver's refusal once this run held Windows Update and nothing restored it: a start
# type left Disabled silently stops the machine ever patching again.
# It names a copy verified the way the apply-and-verify driver verifies one, never C:\winrepair: a
# run that stopped there may have stopped because lock-dirs refused that directory, and its copy runs
# as an admin.
WU_HELD_HINT = (
    "Windows Update is still held - to lift it if this repair is abandoned, copy the guest tool "
    "(`pve-winrepair guest-tool path`) to the ssh user's profile, check that certutil -hashfile <copy> "
    "SHA256 on the guest matches `pve-winrepair guest-tool sha256`, and run restore-wu from that copy, "
    "never from a C:\\winrepair that lock-dirs refused"
)


def guest_stderr(error: BaseException) -> tuple[str, ...] | None:
    """The guest traceback behind ``error``: the stderr tail of a GuestInternalError in its cause chain.

    The drivers wrap a crashed read into their own refusal; this finds the guest's traceback again
    so their ``error``/``internal`` step can carry it. None when no guest crash is behind ``error``.
    """
    seen: BaseException | None = error
    while seen is not None:
        if isinstance(seen, GuestInternalError):
            return seen.stderr_tail
        seen = seen.__cause__
    return None


def check_argument(argument: str) -> str:
    """Return ``argument`` if it reaches the guest tool unchanged; raise otherwise.

    Raises:
        UnsafeArgumentError: It holds a character outside the allowlist, is empty (an empty argument
            vanishes in the joins), is spelled like a pack-wrapper switch, or is a ``-name:value``
            token (powershell.exe -File splits those at the colon), or a bare ``--``.
    """
    if not _SAFE_ARGUMENT.fullmatch(argument):
        raise UnsafeArgumentError(f"argument cannot travel through cmd.exe and powershell unchanged: {argument!r}")
    if _WRAPPER_SWITCH.match(argument):
        raise UnsafeArgumentError(f"argument would be taken by the pack wrapper: {argument!r}")
    if argument.startswith("-") and ":" in argument:
        raise UnsafeArgumentError(f"powershell -File splits a -name:value argument: {argument!r}")
    if argument == "--":
        raise UnsafeArgumentError("a bare -- can be taken by powershell as the end of its own parameters")
    return argument


def tool_argv(tool: str, command: str, args: Sequence[str]) -> list[str]:
    """The remote command line running ``tool`` (a guest path) for one subcommand, every argument checked."""
    return [*POWERSHELL, check_argument(tool), *(check_argument(a) for a in (command, *args)), "--json"]


# --- typed fields ---------------------------------------------------------------------------


def _kind(value: object) -> str:
    return "null" if value is None else type(value).__name__


@dataclass(frozen=True)
class Fields:
    """A JSON object from an envelope, read by name and type.

    A missing or mistyped field raises :class:`GuestProtocolError` instead of reading as a
    default, so a field renamed on the guest side fails loudly rather than gating as "absent".

    Attributes:
        values: The object.
        where: Where it came from, for error messages (``launch.data.task_cleanup``).
    """

    values: Mapping[str, object]
    where: str

    def __contains__(self, name: str) -> bool:
        """Whether the object has the field ``name``."""
        return name in self.values

    def raw(self, name: str) -> object:
        """The value as parsed; raises when the field is missing."""
        if name not in self.values:
            raise GuestProtocolError(f"{self.where} has no field {name!r}")
        return self.values[name]

    def _typed(self, name: str, kinds: tuple[type, ...], *, optional: bool = False) -> object:
        value = self.raw(name)
        if value is None and optional:
            return None
        # bool is an int subclass in Python, but a JSON true is never a count.
        is_bool_for_number = isinstance(value, bool) and bool not in kinds
        if is_bool_for_number or not isinstance(value, kinds):
            wanted = "/".join(k.__name__ for k in kinds)
            raise GuestProtocolError(f"{self.where} field {name!r} is {_kind(value)}, expected {wanted}")
        return value

    def text(self, name: str) -> str:
        """A string field."""
        return cast("str", self._typed(name, (str,)))

    def text_or_none(self, name: str) -> str | None:
        """A string field that may be null."""
        return cast("str | None", self._typed(name, (str,), optional=True))

    def flag(self, name: str) -> bool:
        """A boolean field."""
        return cast("bool", self._typed(name, (bool,)))

    def flag_or_none(self, name: str) -> bool | None:
        """A boolean field that may be null."""
        return cast("bool | None", self._typed(name, (bool,), optional=True))

    def integer(self, name: str) -> int:
        """An integer field (a JSON true/false is not one)."""
        return cast("int", self._typed(name, (int,)))

    def integer_or_none(self, name: str) -> int | None:
        """An integer field that may be null."""
        return cast("int | None", self._typed(name, (int,), optional=True))

    def number(self, name: str) -> float:
        """A numeric field, integer or float."""
        return float(cast("int | float", self._typed(name, (int, float))))

    def section(self, name: str) -> Fields:
        """A nested object."""
        return Fields(cast("Mapping[str, object]", self._typed(name, (dict,))), f"{self.where}.{name}")

    def section_or_none(self, name: str) -> Fields | None:
        """A nested object that may be null."""
        value = self._typed(name, (dict,), optional=True)
        return None if value is None else Fields(cast("Mapping[str, object]", value), f"{self.where}.{name}")

    def _items(self, name: str) -> list[object]:
        return cast("list[object]", self._typed(name, (list,)))

    def texts(self, name: str) -> tuple[str, ...]:
        """A list of strings."""
        items = self._items(name)
        if not all(isinstance(item, str) for item in items):
            raise GuestProtocolError(f"{self.where} field {name!r} is not a list of strings")
        return tuple(cast("list[str]", items))

    def sections(self, name: str) -> tuple[Fields, ...]:
        """A list of objects."""
        items = self._items(name)
        if not all(isinstance(item, dict) for item in items):
            raise GuestProtocolError(f"{self.where} field {name!r} is not a list of objects")
        return tuple(
            Fields(cast("Mapping[str, object]", item), f"{self.where}.{name}[{i}]") for i, item in enumerate(items)
        )


@dataclass(frozen=True)
class Envelope:
    """One guest tool answer that the caller gates on (exit 0 ok, or exit 1 refused).

    Attributes:
        ok: True on exit 0; False when the command's own gate refused (exit 1).
        command: The subcommand that answered.
        data: The payload, read through typed getters.
        skipped: What the command could not check, as ``{item, reason}`` objects.
        exit_code: The tool's exit code.
    """

    ok: bool
    command: str
    data: Fields
    skipped: tuple[Fields, ...]
    exit_code: int

    def gate(self, name: str, passing: str) -> str:
        """Return the verdict field ``name``, checking it agrees with ``ok``.

        Raises:
            GuestProtocolError: ``ok`` is set but the verdict is not ``passing``, or the reverse.
        """
        value = self.data.text(name)
        if (value == passing) != self.ok:
            raise GuestProtocolError(f"{self.command}: ok={self.ok} contradicts {name}={value!r} (pass is {passing!r})")
        return value


def _envelope_object(line: str) -> Mapping[str, object] | None:
    """The line as an envelope-shaped JSON object, or None for any other line."""
    text = line.strip()
    if not text.startswith("{"):
        return None
    try:
        parsed: object = json.loads(text)
    except ValueError:
        return None
    if not isinstance(parsed, dict):
        return None
    obj = cast("dict[str, object]", parsed)
    return obj if obj.keys() >= _ENVELOPE_KEYS else None


def snippet(text: str) -> str:
    r"""``text`` on one line, cut to 300 characters: a process's output quoted in an error message.

    Example:
        >>> snippet("CertUtil: failed\r\n  0x80070002\r\n")
        'CertUtil: failed 0x80070002'
    """
    return " ".join(text.split())[:300]


def _no_answer(command: str, proc: CompletedProcess[str], why: str) -> GuestNoAnswerError:
    return GuestNoAnswerError(
        f"guest tool {command}: {why} (exit {proc.returncode}; stdout: {snippet(proc.stdout)!r}; "
        f"stderr: {snippet(proc.stderr)!r})"
    )


def _single_envelope(command: str, proc: CompletedProcess[str]) -> Mapping[str, object]:
    """The one envelope line in stdout; anything else around it is wrapper noise."""
    found = [obj for obj in map(_envelope_object, proc.stdout.splitlines()) if obj is not None]
    if not found:
        raise _no_answer(command, proc, "no envelope on stdout")
    if len(found) > 1:
        raise GuestProtocolError(f"guest tool {command}: {len(found)} envelopes on stdout, expected one")
    return found[0]


def _build_envelope(obj: Mapping[str, object], exit_code: int) -> Envelope:
    ok, name, data, skipped = obj["ok"], obj["command"], obj["data"], obj["skipped"]
    if not isinstance(ok, bool) or not isinstance(name, str):
        raise GuestProtocolError(f"envelope ok/command have the wrong type: {ok!r}, {name!r}")
    if not isinstance(data, dict) or not isinstance(skipped, list):
        raise GuestProtocolError(f"envelope {name}: data must be an object and skipped a list")
    top = Fields({"skipped": cast("list[object]", skipped)}, f"{name}")
    return Envelope(
        ok,
        name,
        Fields(cast("Mapping[str, object]", data), f"{name}.data"),
        top.sections("skipped"),
        exit_code,
    )


def parse_envelope(command: str, proc: CompletedProcess[str]) -> Envelope:
    """Read one guest tool answer.

    Args:
        command: The subcommand that was run (the envelope must name it).
        proc: The finished ssh call.

    Returns:
        The envelope, for exit 0 (ok) and exit 1 (refused).

    Raises:
        GuestNoAnswerError: No envelope, or an exit code the tool never uses (ssh's 255 included).
        GuestInternalError: Exit 2.
        GuestProtocolError: The envelope contradicts its exit code or the command, or is malformed.
    """
    obj = _single_envelope(command, proc)
    if proc.returncode not in _TOOL_EXITS:
        raise _no_answer(command, proc, "an exit code the tool never uses")
    envelope = _build_envelope(obj, proc.returncode)
    if proc.returncode == EXIT_INTERNAL:
        raise GuestInternalError(envelope, proc.stderr)
    if envelope.command != command:
        raise GuestProtocolError(f"asked {command!r}, the envelope answers {envelope.command!r}")
    if envelope.ok != _TOOL_EXITS[proc.returncode]:
        raise GuestProtocolError(f"guest tool {command}: ok={envelope.ok} with exit {proc.returncode}")
    return envelope


# The guest's state-log verdicts and the marker line each stands for. The marker text is a contract:
# the guest writes exactly these lines and every reader of the log matches on them.
STATE_MARKERS = {"DONE-OK": "STATE=DONE-OK", "DONE-FAIL": "STATE=DONE-FAIL"}


@dataclass(frozen=True)
class RunState:
    """The upgrade run on a guest, as its two probes (``setup-alive``, ``state``) report it.

    Attributes:
        alive: SetupHost is running.
        log_present: The state log exists.
        log_path: Where the state log is on the guest.
        verdict: ``DONE-OK`` / ``DONE-FAIL`` from the log's last marker line, or None.
    """

    alive: bool
    log_present: bool
    log_path: str
    verdict: str | None

    @property
    def marker(self) -> str | None:
        """The verdict as its marker line (``STATE=DONE-OK``), or None."""
        return None if self.verdict is None else STATE_MARKERS[self.verdict]

    @property
    def live(self) -> bool:
        """A run may still be going: SetupHost runs, or the log shows a run with no DONE marker.

        The guest appends its marker only after setup.exe returns, so a log without one is never
        read as finished, even with SetupHost gone.
        """
        return self.alive or (self.log_present and self.verdict is None)


def state_marker(state: Fields) -> str | None:
    """The marker line (``STATE=DONE-OK``) for a ``state`` probe's verdict, or None while it has none.

    Raises:
        GuestProtocolError: The log carries a verdict this driver does not know.
    """
    verdict = state.text_or_none("verdict")
    if verdict is None:
        return None
    if verdict not in STATE_MARKERS:
        raise GuestProtocolError(f"state: unknown verdict {verdict!r}")
    return STATE_MARKERS[verdict]
