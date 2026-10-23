"""The guest tool's output contract: one JSON envelope per run, and the exit code it implies.

Every subcommand answers with exactly one line on stdout,
``{"ok": bool, "command": str, "data": {...}, "skipped": [...]}``, and exits 0 (ok), 1 (refused:
the command's own gate said no, or it could not decide) or 2 (internal error, still with an
envelope). The host drivers parse that line instead of regex-matching KEY=VALUE text, which a
guest's locale breaks (a German decimal comma, for one, breaks a number parse).

This module is the seam the feature modules plug into: each module builds a tuple of
:class:`Command`, and the entry script registers them. It lives apart from ``winrepair_guest.py``
because a feature module that imported the entry script would load a second copy of it under its
own name, next to the one running as ``__main__``.

Contents:
    * :class:`Outcome`, :class:`Skip` - what a command returns.
    * :class:`Command` - one registered subcommand.
    * :class:`ExitCode` - the three exit codes.
    * :func:`build`, :func:`internal_error`, :func:`render`, :func:`exit_code`, :func:`jsonable`.
"""

from __future__ import annotations

import dataclasses
import enum
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    import argparse

__all__ = [
    "Command",
    "ExitCode",
    "Outcome",
    "Skip",
    "build",
    "exit_code",
    "internal_error",
    "jsonable",
    "render",
]


class ExitCode(enum.IntEnum):
    """Process exit codes of the guest tool."""

    OK = 0
    REFUSED = 1
    INTERNAL = 2


@dataclass(frozen=True)
class Skip:
    """Something a command did not check, and why - so a gap is visible rather than silent.

    Attributes:
        item: What was skipped (a registry key, a log, a lookup).
        reason: Why it was skipped, usually the error that prevented it.
    """

    item: str
    reason: str


@dataclass(frozen=True)
class Outcome:
    """A command's result before it is wrapped into an envelope.

    Attributes:
        ok: True when the command answered its question; False when its gate said no or it
            could not decide (exit 1). Internal errors are exceptions, not an Outcome.
        data: The command's payload: a mapping or a dataclass instance (made JSON-safe).
        skipped: What the command could not check.
    """

    ok: bool
    data: object
    skipped: tuple[Skip, ...] = field(default=())


def _no_arguments(_parser: argparse.ArgumentParser) -> None:
    """Default ``configure`` for a command that takes no arguments."""


@dataclass(frozen=True)
class Command:
    """One subcommand of the guest tool.

    Attributes:
        name: The subcommand name (``detect-lp-defect``).
        help: One line for ``--help``.
        run: Runs the command on the parsed arguments.
        configure: Adds the command's own arguments to its subparser.
    """

    name: str
    help: str
    run: Callable[[argparse.Namespace], Outcome]
    configure: Callable[[argparse.ArgumentParser], None] = _no_arguments


def jsonable(value: object) -> object:
    """Convert dataclasses, enums, tuples and mappings into plain JSON types.

    Example:
        >>> jsonable({"a": (1, Skip("x", "y"))})
        {'a': [1, {'item': 'x', 'reason': 'y'}]}
    """
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, enum.Enum):
        # .value, never str(): an f-string of a str-Enum flips between value and NAME at 3.11.
        return jsonable(value.value)
    # isinstance narrows an ``object`` to Mapping[Unknown]; the casts restate what JSON allows.
    if isinstance(value, Mapping):
        return {str(k): jsonable(v) for k, v in cast("Mapping[object, object]", value).items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in cast("Sequence[object]", value)]
    return value


def build(command: str, outcome: Outcome) -> dict[str, object]:
    """Wrap an outcome into the envelope mapping.

    Example:
        >>> build("build", Outcome(ok=True, data={"ubr": 8973}))
        {'ok': True, 'command': 'build', 'data': {'ubr': 8973}, 'skipped': []}
    """
    return {
        "ok": outcome.ok,
        "command": command,
        "data": jsonable(outcome.data),
        "skipped": jsonable(outcome.skipped),
    }


def internal_error(command: str, error: BaseException) -> dict[str, object]:
    """Build the envelope for an internal error: ok=false, the error text and its type.

    Example:
        >>> internal_error("build", OSError("denied"))["data"]
        {'error': 'denied', 'error_type': 'OSError'}
    """
    data = {"error": str(error) or type(error).__name__, "error_type": type(error).__name__}
    return {"ok": False, "command": command, "data": data, "skipped": []}


def render(envelope: Mapping[str, object]) -> str:
    """Serialize an envelope to one ASCII line.

    ASCII on purpose: the guest's stdout is a cp1252 console pipe under Windows, where a
    non-ASCII character in a German event message would raise UnicodeEncodeError mid-write.

    Example:
        >>> render({"ok": True})
        '{"ok": true}'
    """
    return json.dumps(envelope, ensure_ascii=True)


def exit_code(outcome: Outcome) -> ExitCode:
    """Map an outcome to its exit code (0 ok, 1 refused).

    Example:
        >>> exit_code(Outcome(ok=False, data={})).value
        1
    """
    return ExitCode.OK if outcome.ok else ExitCode.REFUSED
