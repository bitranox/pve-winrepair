r"""Talk to the winrepair guest tool over ssh: push it, run one subcommand, read its JSON envelope.

Shared by the node's repair and apply-and-verify drivers, which run ON the PVE node. Besides the
guest calls it owns what both drivers share: the :class:`Node` bundle (how ``qm``, ssh, the clock
and the guest are reached, the tests' seam), :func:`read_run_state` (the live-run gate both run
before they stop or relaunch a guest), :func:`state_marker`, and :data:`READ_FAILURES` /
:data:`PROBE_TIMEOUT`.

The guest tool (``winrepair_guest.ps1``, packed by ``pwshpy pack``) answers every subcommand with
exactly one line ``{"ok": bool, "command": str, "data": {...}, "skipped": [...]}`` on stdout and
exits 0 (ok), 1 (refused: its own gate said no) or 2 (internal error, still with an envelope).
This module turns that into three distinct outcomes, so a failed read can never pass for an empty
or negative answer:

* an :class:`Envelope` - exit 0, or exit 1 (refused); the caller gates on its typed ``data``;
* :class:`GuestInternalError` - exit 2: the tool ran and crashed, or did not know the command;
* :class:`GuestNoAnswerError` - no envelope at all: ssh failed, timed out, or stdout held nothing
  parseable (a non-zero exit without an envelope included).

A malformed or inconsistent answer (two envelopes, ``ok`` disagreeing with the exit code, a
missing or mistyped field) is :class:`GuestProtocolError`: the driver and the packed tool disagree
about the contract, which is a bug, not a guest state.

Arguments are checked BEFORE ssh (:func:`check_argument`): the guest's ssh shell is ``cmd.exe``,
which split ``D:\up&grade`` at the ``&`` and ran the rest as a second command.

The tool lives on the guest under a content address,
``C:\winrepair\winrepair_guest-<first 16 hex of its sha256>.ps1``. A SYSTEM upgrade run executes
the file it was launched with for hours, and a re-run of a driver pushes again; a fixed name would
be overwritten under that live run. With a content address the same bytes are already there (the
push copies nothing in) and a new version gets a new name, so a push never writes a file a run
executes.

``C:\winrepair`` is locked to SYSTEM and Administrators before the tool is ever copied into it: a
directory created under ``C:\`` is open to every local user until then, and the tool runs as an
elevated admin and as SYSTEM. The tool itself does the locking (``lock-dirs``), so every push first
puts it in the ssh user's profile, which only SYSTEM, Administrators and that user can write, checks
the copy's bytes against the node's digest, and runs it from there (see :func:`push_tool`). After
the apply reboot the apply-and-verify driver runs the tool from such a verified profile copy only
(:meth:`Guest.stage_tool`), never from ``C:\winrepair``, whose lock the upgrade may have changed.

Settings:
    The key, the user and the host-key options come from the ``[ssh]`` section
    (:class:`~pve_winrepair.domain.settings.SshSettings`). A guest whose sshd refuses the configured
    key is reached by overriding it for that run through the environment:
    ``PVE_WINREPAIR___SSH__KEY=<path>``. The packed tool ships inside this package (:data:`TOOL_DIR`).
"""

from __future__ import annotations

import hashlib
import json
import ntpath
import re

# ssh and scp are the one boundary this module crosses; run() below says why its argv is safe.
import subprocess  # nosec B404
import time
from collections.abc import Callable, Generator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from pve_winrepair.domain.settings import SshSettings

__all__ = [
    "CERTUTIL",
    "GUEST_TOOL_DIR",
    "PROBE_TIMEOUT",
    "READ_FAILURES",
    "STATE_MARKERS",
    "STDERR_TAIL_LINES",
    "TOOL_DIR",
    "TOOL_NAME",
    "WU_HELD_HINT",
    "Envelope",
    "Fields",
    "Guest",
    "GuestCallError",
    "GuestInternalError",
    "GuestNoAnswerError",
    "GuestProtocolError",
    "GuestPushError",
    "Node",
    "PackedTool",
    "Pushed",
    "RunState",
    "Runner",
    "UnsafeArgumentError",
    "check_argument",
    "guest_stderr",
    "guest_tool",
    "packed_tool",
    "parse_envelope",
    "push_tool",
    "read_run_state",
    "remove_staged",
    "run",
    "ssh_options",
    "stage_tool",
    "state_marker",
    "tool_argv",
]

TOOL_NAME = "winrepair_guest.ps1"
# The packed tool ships inside this package; resolved from this file, never by importing the root
# package for its __file__ (an adapter importing the composition root breaks the layer contract).
TOOL_DIR = Path(__file__).resolve().parent / "guest_tool"
GUEST_TOOL_DIR = "C:\\winrepair"
# 64 bits of the sha256: a collision between two tool versions is not a practical concern, and the
# name stays short enough to read in a task's action line.
_TOOL_HASH_CHARS = 16
PUSH_TIMEOUT = 300.0
REMOTE_TIMEOUT = 60.0
# The pushed copy's first run may bootstrap uv and Python on the guest before it answers.
LOCK_TIMEOUT = 300.0
# Options fixed for every guest, either side of the two host-key options (ssh_options keeps that
# order). BatchMode plus publickey: a rejected key fails at once instead of hanging an unattended
# run on a password prompt.
_AUTH_OPTS = (
    "-o", "BatchMode=yes",
    "-o", "PreferredAuthentications=publickey",
)  # fmt: skip
_TIMEOUT_OPTS = (
    "-o", "ConnectTimeout=20",
    "-o", "ServerAliveInterval=30",
)  # fmt: skip
# By full path, never resolved through PATH (on a test guest four directories precede System32 in PATH).
# The guest's ssh shell is cmd.exe, which expands %SystemRoot% to the guest's own Windows directory.
POWERSHELL = (
    r"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe",
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
)
# The guest's own hasher, by full path for the same reason. Its hex line is the one part of its
# output that is not localised; older builds print it as spaced byte pairs.
CERTUTIL = r"%SystemRoot%\System32\certutil.exe"
_SHA256_LINE = re.compile(r"[0-9A-Fa-f]{64}")

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

Runner = Callable[[Sequence[str], float], "subprocess.CompletedProcess[str]"]


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


def run(cmd: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
    """Run a command, capturing stdout and stderr SEPARATELY as UTF-8 text.

    Separate on purpose: ssh's own warnings go to stderr and must never splice into the
    envelope line on stdout.
    """
    # An argv list, never a shell, and every word bound for the guest passed check_argument.
    return subprocess.run(  # noqa: S603 - argv list, no shell  # nosec B603
        list(cmd),
        capture_output=True,
        text=True,
        timeout=timeout,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def ssh_options(ssh: SshSettings) -> tuple[str, ...]:
    """The ``-o`` options of every ssh and scp call to a guest.

    ``strict_host_key_checking`` maps to ``StrictHostKeyChecking=yes`` or ``no``: guests are cloned
    and rebuilt, so a fleet that accepts a changed host key sets it to false. ``known_hosts_file``
    is passed as written, never expanded here: ssh expands a leading ``~`` itself, against the HOME
    of the account that runs it. Keep it a real file, never ``/dev/null``: that makes every connect a
    first connect, and ssh then prints "Permanently added" on every call.

    Example:
        >>> from pve_winrepair.domain.settings import SshSettings
        >>> ssh_options(SshSettings(strict_host_key_checking=False, known_hosts_file="~/.ssh/kh"))[4:8]
        ('-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=~/.ssh/kh')
    """
    checking = "yes" if ssh.strict_host_key_checking else "no"
    return (
        *_AUTH_OPTS,
        "-o",
        f"StrictHostKeyChecking={checking}",
        "-o",
        f"UserKnownHostsFile={ssh.known_hosts_file}",
        *_TIMEOUT_OPTS,
    )


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


def _ssh_argv(ip: str, ssh: SshSettings, remote: Sequence[str]) -> list[str]:
    return ["ssh", "-i", ssh.key, *ssh_options(ssh), f"{ssh.user}@{ip}", *remote]


def _scp_argv(ip: str, ssh: SshSettings, sources: Sequence[str], dest: str, *, recursive: bool) -> list[str]:
    return [
        "scp",
        "-q",
        "-i",
        ssh.key,
        *ssh_options(ssh),
        *(["-r"] if recursive else []),
        *sources,
        f"{ssh.user}@{ip}:{dest}",
    ]


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


def _snippet(text: str) -> str:
    return " ".join(text.split())[:300]


def _no_answer(command: str, proc: subprocess.CompletedProcess[str], why: str) -> GuestNoAnswerError:
    return GuestNoAnswerError(
        f"guest tool {command}: {why} (exit {proc.returncode}; stdout: {_snippet(proc.stdout)!r}; "
        f"stderr: {_snippet(proc.stderr)!r})"
    )


def _single_envelope(command: str, proc: subprocess.CompletedProcess[str]) -> Mapping[str, object]:
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


def parse_envelope(command: str, proc: subprocess.CompletedProcess[str]) -> Envelope:
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


def _call(runner: Runner, argv: Sequence[str], timeout: float, what: str) -> subprocess.CompletedProcess[str]:
    """Run ``argv``; a timeout or a failure to start is :class:`GuestNoAnswerError`."""
    try:
        return runner(argv, timeout)
    except subprocess.TimeoutExpired as exc:
        raise GuestNoAnswerError(f"{what}: timed out after {timeout:g} s") from exc
    except OSError as exc:
        raise GuestNoAnswerError(f"{what}: could not run {argv[0]}: {exc}") from exc


def guest_tool(guest: Guest, command: str, *args: str, timeout: float) -> Envelope:
    """Run one subcommand of the tool copy at ``guest.tool_path`` and return its envelope (ok or refused).

    Raises:
        UnsafeArgumentError: Before ssh, see :func:`check_argument`.
        GuestPushError: The packed tool is missing on this node, so its guest path is unknown.
        GuestNoAnswerError, GuestInternalError, GuestProtocolError: See :func:`parse_envelope`.
    """
    argv = _ssh_argv(guest.ip, guest.ssh_settings, tool_argv(guest.tool_path, command, args))
    return parse_envelope(command, _call(guest.runner, argv, timeout, f"guest tool {command}"))


@dataclass(frozen=True)
class PackedTool:
    """The packed tool on this node and the content address it gets on the guest.

    Attributes:
        source: The packed tool on this node.
        guest_path: Its content address on the guest.
        sha256: Its full sha256, which every guest copy is checked against before it runs.
    """

    source: Path
    guest_path: str
    sha256: str

    @property
    def staged(self) -> str:
        """The profile copy's name: plain, so ssh and scp resolve it in the ssh user's profile."""
        return ntpath.basename(self.guest_path)


@dataclass(frozen=True)
class Pushed:
    """Where the tool is on the guest, and whether this push copied it (False: already there).

    Attributes:
        path: The content address.
        copied: Whether this push copied it in.
        staged_left: Why the profile copy could not be removed, or None once it is gone. A copy
            left there is not a failure of the push: only an administrator can write the profile,
            and the next push overwrites it.
    """

    path: str
    copied: bool
    staged_left: str | None = None


def packed_tool(directory: Path) -> PackedTool:
    r"""Hash ``directory/winrepair_guest.ps1`` into its guest path ``C:\winrepair\winrepair_guest-<sha>.ps1``.

    Raises:
        GuestPushError: The packed tool is missing or unreadable.
    """
    source = directory / TOOL_NAME
    try:
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
    except OSError as exc:
        raise GuestPushError(
            f"{source} is missing: the package is missing its guest tool - reinstall pve-winrepair ({exc})"
        ) from exc
    stem = TOOL_NAME.removesuffix(".ps1")
    return PackedTool(source, f"{GUEST_TOOL_DIR}\\{stem}-{digest[:_TOOL_HASH_CHARS]}.ps1", digest)


def _remote(
    runner: Runner, ip: str, ssh: SshSettings, remote: Sequence[str], what: str
) -> subprocess.CompletedProcess[str]:
    """One raw ``cmd.exe`` command of the push; no answer at all is a push failure naming ``what``."""
    try:
        return _call(runner, _ssh_argv(ip, ssh, remote), REMOTE_TIMEOUT, what)
    except GuestNoAnswerError as exc:
        raise GuestPushError(str(exc)) from exc


def _checked(proc: subprocess.CompletedProcess[str], what: str) -> None:
    if proc.returncode != 0:
        raise GuestPushError(f"{what} failed rc={proc.returncode}: {_snippet(proc.stderr or proc.stdout)}")


def _lock_tool_dir(runner: Runner, ip: str, ssh: SshSettings, staged: str, dest: str) -> bool:
    """Run lock-dirs from the profile copy ``staged``; return whether ``dest`` is already in place.

    Raises:
        GuestPushError: It refused, gave no answer, or crashed (the guest traceback is chained).
        GuestProtocolError: Its answer broke the envelope contract.
    """
    command = "lock-dirs"
    argv = _ssh_argv(ip, ssh, tool_argv(staged, command, ("--tool", dest)))
    try:
        envelope = parse_envelope(command, _call(runner, argv, LOCK_TIMEOUT, f"guest tool {command}"))
    except READ_FAILURES as exc:
        raise GuestPushError(f"{command} before the push: {exc}") from exc
    if envelope.gate("verdict", "OK") != "OK":
        raise GuestPushError(f"{command} refused, nothing was copied in: {envelope.data.text_or_none('reason')}")
    return envelope.data.flag("tool_present")


def _guest_sha256(runner: Runner, ip: str, ssh: SshSettings, path: str) -> str:
    """The sha256 of the guest file ``path``, read with the guest's certutil."""
    what = f"hashing {path}"
    proc = _remote(runner, ip, ssh, (CERTUTIL, "-hashfile", path, "SHA256"), what)
    _checked(proc, what)
    found = {"".join(line.split()).lower() for line in proc.stdout.splitlines()}
    digests = {line for line in found if _SHA256_LINE.fullmatch(line)}
    if len(digests) != 1:
        raise GuestPushError(f"{what}: certutil printed no single SHA256 line: {_snippet(proc.stdout)!r}")
    return digests.pop()


def _verify(runner: Runner, ip: str, ssh: SshSettings, path: str, tool: PackedTool) -> None:
    """Refuse unless the guest file ``path`` (the profile copy or the copy in place) is exactly ``tool``."""
    digest = _guest_sha256(runner, ip, ssh, path)
    if digest != tool.sha256:
        label = "the profile copy" if path == tool.staged else "the copy in place"
        raise GuestPushError(
            f"{label} {path} hashes to {digest} on the guest, expected {tool.sha256} (the node's "
            f"{tool.source.name}): refused, it is not run"
        )


def remove_staged(runner: Runner, ip: str, ssh: SshSettings, staged: str) -> str | None:
    """Delete the profile copy ``staged``; None once done, else why not. Never raises."""
    removing = f"removing the profile copy {staged}"
    try:
        _checked(_remote(runner, ip, ssh, ("del", "/Q", staged), removing), removing)
    except GuestPushError as exc:
        return f"the profile copy {staged} was left in the ssh user's profile: {exc}"
    return None


@contextmanager
def _removed_on_failure(runner: Runner, ip: str, ssh: SshSettings, staged: str) -> Generator[None, None, None]:
    """Delete the profile copy when the body fails, naming a delete that failed too in the error."""
    try:
        yield
    except GuestCallError as exc:
        exc.cleanup_failure = remove_staged(runner, ip, ssh, staged)
        raise
    except BaseException:
        remove_staged(runner, ip, ssh, staged)
        raise


def stage_tool(
    ip: str, tool: PackedTool, *, ssh: SshSettings, runner: Runner = run, timeout: float = PUSH_TIMEOUT
) -> str:
    """Copy ``tool`` to the ssh user's profile and check its bytes there; return its (relative) name.

    The copy is hashed on the guest against the node's digest before anything runs it, so a
    profile that is not what it should be cannot hand an elevated run other bytes. On any failure
    the copy is deleted again (see :func:`remove_staged`); on success the caller deletes it.

    Raises:
        GuestPushError: The copy failed, its hash could not be read, or it is not ``tool``.
    """
    staged = tool.staged
    with _removed_on_failure(runner, ip, ssh, staged):
        try:
            proc = _call(runner, _scp_argv(ip, ssh, [str(tool.source)], staged, recursive=False), timeout, "push")
        except GuestNoAnswerError as exc:
            raise GuestPushError(str(exc)) from exc
        _checked(proc, f"pushing {TOOL_NAME} to the ssh user's profile")
        _verify(runner, ip, ssh, staged, tool)
    return staged


def push_tool(
    ip: str, tool: PackedTool, *, ssh: SshSettings, runner: Runner = run, timeout: float = PUSH_TIMEOUT
) -> Pushed:
    r"""Put ``tool`` at its content address on the guest, into a ``C:\winrepair`` locked beforehand.

    The tool first goes to the ssh user's profile under its plain name (ssh and scp start there, and
    only SYSTEM, Administrators and that user may write it), is hashed there against the node's
    digest (:func:`stage_tool`), and runs ``lock-dirs`` from there: that creates ``C:\winrepair``
    with the lock in place before anything is copied in, and checks a tool already at the content
    address against its name. Only then is the profile copy copied in, beside the final name, and
    renamed into place, so a cut copy never sits under a name a run executes; the copy in place is
    hashed once more before anyone runs it. The profile copy is deleted on every path.

    The final name is never written while it exists: a live SYSTEM run may be executing it, and
    the same name means the same bytes (lock-dirs checked them).

    Raises:
        GuestPushError: A step failed, a hash did not match, or lock-dirs refused; nothing was copied
            into ``C:\winrepair`` unless lock-dirs passed.
    """
    dest = tool.guest_path
    staged = stage_tool(ip, tool, ssh=ssh, runner=runner, timeout=timeout)
    part = dest + ".part"
    with _removed_on_failure(runner, ip, ssh, staged):
        present = _lock_tool_dir(runner, ip, ssh, staged, dest)
        if not present:
            copying = f"copying {staged} to {part}"
            _checked(_remote(runner, ip, ssh, ("copy", "/Y", "/B", staged, part), copying), copying)
            renaming = f"renaming {part} into place"
            _checked(_remote(runner, ip, ssh, ("move", "/Y", part, dest), renaming), renaming)
        _verify(runner, ip, ssh, dest, tool)
    return Pushed(dest, copied=not present, staged_left=remove_staged(runner, ip, ssh, staged))


@dataclass(frozen=True)
class Guest:
    """One guest as the drivers reach it: address, ssh settings, where the packed tool is, and the runner.

    The runner is the seam the tests use; production runs :func:`run`.
    """

    ip: str
    ssh_settings: SshSettings
    tool_dir: Path = TOOL_DIR
    runner: Runner = run
    # Set only on the Guest :meth:`stage_tool` returns: its calls run that verified profile copy.
    profile_copy: str | None = None

    @cached_property
    def packed(self) -> PackedTool:
        """The packed tool, hashed once per Guest so every call names the copy this Guest pushed.

        Raises:
            GuestPushError: The packed tool is missing (see :func:`packed_tool`).
        """
        return packed_tool(self.tool_dir)

    @property
    def tool_path(self) -> str:
        """The copy this Guest's tool calls run: the content address, or the verified profile copy."""
        return self.profile_copy or self.packed.guest_path

    def push_tool(self) -> Pushed:
        """See :func:`push_tool`."""
        return push_tool(self.ip, self.packed, ssh=self.ssh_settings, runner=self.runner)

    def stage_tool(self) -> Guest:
        r"""Copy the tool to the ssh user's profile and verify it (:func:`stage_tool`); calls run that copy.

        Returns:
            This guest, with every tool call running the verified profile copy instead of the one in
            ``C:\winrepair``. Delete the copy with :meth:`remove_profile_copy` when done.
        """
        staged = stage_tool(self.ip, self.packed, ssh=self.ssh_settings, runner=self.runner)
        guest = replace(self, profile_copy=staged)
        guest.__dict__["packed"] = self.packed  # the digest just verified, not a re-read of the node file
        return guest

    def remove_profile_copy(self) -> str | None:
        """Delete the profile copy this Guest runs; None once done, else why not (never raises)."""
        return remove_staged(self.runner, self.ip, self.ssh_settings, self.packed.staged)

    def tool(self, command: str, *args: str, timeout: float) -> Envelope:
        """See :func:`guest_tool`; runs the copy at :attr:`tool_path`."""
        return guest_tool(self, command, *args, timeout=timeout)

    def probe(self, command: str, *args: str, timeout: float) -> Fields:
        """Run a subcommand that never refuses (a pure probe) and return its data.

        Raises:
            GuestProtocolError: It refused anyway.
        """
        envelope = self.tool(command, *args, timeout=timeout)
        if not envelope.ok:
            raise GuestProtocolError(f"probe {command} refused (exit {envelope.exit_code}); it never should")
        return envelope.data

    def ssh(self, *remote: str, timeout: float) -> subprocess.CompletedProcess[str]:
        """Run a raw remote command (``hostname``, ``mkdir``); the caller checks the result.

        A timeout or an ssh that cannot start comes back as a failed process (rc 255), the code
        ssh itself uses for a connection failure, so a readiness poll simply tries again.
        """
        argv = _ssh_argv(self.ip, self.ssh_settings, remote)
        try:
            return _call(self.runner, argv, timeout, "ssh")
        except GuestNoAnswerError as exc:
            return subprocess.CompletedProcess(argv, 255, "", str(exc))

    def copy_to(self, sources: Sequence[str], dest: str, *, timeout: float) -> subprocess.CompletedProcess[str]:
        """``scp -r`` ``sources`` into the guest directory ``dest``; the caller checks the result.

        Like :meth:`ssh`, a timeout or an scp that cannot start comes back as a failed process
        (rc 255) naming why, so the caller reports a failed transfer rather than crashing.
        """
        argv = _scp_argv(self.ip, self.ssh_settings, sources, dest, recursive=True)
        try:
            return _call(self.runner, argv, timeout, "media transfer")
        except GuestNoAnswerError as exc:
            return subprocess.CompletedProcess(argv, 255, "", str(exc))


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


def read_run_state(guest: Guest, *, timeout: float) -> RunState:
    """Ask the guest whether an upgrade run is live and how its last run ended.

    The one reading both drivers gate on before they stop, relaunch or restage a guest.

    Raises:
        GuestNoAnswerError, GuestInternalError: The guest could not be asked - NEVER an idle guest.
        GuestProtocolError: The log carries a verdict this driver does not know.
    """
    alive = guest.probe("setup-alive", timeout=timeout).flag("alive")
    state = guest.probe("state", timeout=timeout)
    marker = state_marker(state)
    verdict = None if marker is None else marker.removeprefix("STATE=")
    return RunState(alive, state.flag("present"), state.text("path"), verdict)


@dataclass(frozen=True)
class Node:
    """The PVE node a driver runs on: how it runs ``qm`` and ssh, waits, and reaches a guest.

    One bundle so every PVE step and every guest call goes through the same runner; the tests pass
    a fake runner and clock here and observe the whole sequence of node and guest calls in order.
    """

    ssh: SshSettings
    runner: Runner = run
    clock: Callable[[], float] = time.time
    sleep: Callable[[float], None] = time.sleep
    tool_dir: Path = TOOL_DIR

    def qm(self, *args: str, timeout: int = 600) -> subprocess.CompletedProcess[str]:
        """Run ``qm`` on this node."""
        return self.runner(["qm", *args], timeout)

    def guest(self, ip: str) -> Guest:
        """The guest at ``ip``, reached with this node's ssh settings, tool dir and runner."""
        return Guest(ip, ssh_settings=self.ssh, tool_dir=self.tool_dir, runner=self.runner)
