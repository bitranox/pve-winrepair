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
    * :class:`Report` - the base of every payload; :class:`Skip`, :class:`InternalError`.
    * :class:`Outcome` - what a command returns.
    * :class:`Envelope` - the one line a run prints.
    * :class:`Command` - one registered subcommand.
    * :class:`ExitCode` - the three exit codes.
    * :func:`build`, :func:`internal_error`, :func:`render`, :func:`exit_code`.
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, SerializeAsAny

if TYPE_CHECKING:
    import argparse
    from collections.abc import Callable

__all__ = [
    "Command",
    "Envelope",
    "ExitCode",
    "InternalError",
    "Outcome",
    "Report",
    "Skip",
    "build",
    "exit_code",
    "internal_error",
    "render",
]


class Report(BaseModel):
    """Base of everything a command puts into its envelope: frozen, and closed to unknown fields.

    ``extra="forbid"`` makes a misspelt field a construction error on the guest instead of a key
    the host driver never reads; the host's own answer models forbid unknown fields too, so a field
    added on one side only fails the contract tests rather than travelling unread.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")


class ExitCode(enum.IntEnum):
    """Process exit codes of the guest tool."""

    OK = 0
    REFUSED = 1
    INTERNAL = 2


class Skip(Report):
    """Something a command did not check, and why - so a gap is visible rather than silent.

    Attributes:
        item: What was skipped (a registry key, a log, a lookup).
        reason: Why it was skipped, usually the error that prevented it.
    """

    item: str
    reason: str


class InternalError(Report):
    """The payload of an exit-2 envelope: the tool crashed, or did not know the command.

    Attributes:
        error: The exception's message, or its type name when the message is empty.
        error_type: The exception's type name.
    """

    error: str
    error_type: str


@dataclass(frozen=True)
class Outcome:
    """A command's result before it is wrapped into an envelope (never serialised itself).

    Attributes:
        ok: True when the command answered its question; False when its gate said no or it
            could not decide (exit 1). Internal errors are exceptions, not an Outcome.
        data: The command's payload.
        skipped: What the command could not check.
    """

    ok: bool
    data: Report
    skipped: tuple[Skip, ...] = field(default=())


class Envelope(BaseModel):
    """The one line a run prints: the outcome, named by its command (frozen, closed like a Report).

    Attributes:
        ok: The outcome's ``ok``.
        command: The subcommand, or "" when the command line named none the tool knows.
        data: The command's payload, serialised as the subclass it is.
        skipped: What the command could not check.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ok: bool
    command: str
    # SerializeAsAny: a field declared as the bare Report base would dump every payload as {}.
    data: SerializeAsAny[Report]
    skipped: tuple[Skip, ...]


def _no_arguments(_parser: argparse.ArgumentParser) -> None:
    """Default ``configure`` for a command that takes no arguments."""


@dataclass(frozen=True)
class Command:
    """One subcommand of the guest tool (a table entry holding callables, never serialised).

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


def build(command: str, outcome: Outcome) -> Envelope:
    """Wrap an outcome into its envelope.

    Example:
        >>> build("build", Outcome(ok=True, data=Skip(item="x", reason="y"))).model_dump(mode="json")
        {'ok': True, 'command': 'build', 'data': {'item': 'x', 'reason': 'y'}, 'skipped': []}
    """
    return Envelope(ok=outcome.ok, command=command, data=outcome.data, skipped=outcome.skipped)


def internal_error(command: str, error: BaseException) -> Envelope:
    """Build the envelope for an internal error: ok=false, the error text and its type.

    Example:
        >>> internal_error("build", OSError("denied")).data
        InternalError(error='denied', error_type='OSError')
    """
    data = InternalError(error=str(error) or type(error).__name__, error_type=type(error).__name__)
    return build(command, Outcome(ok=False, data=data))


def render(envelope: Envelope) -> str:
    r"""Serialize an envelope to one ASCII line.

    ASCII on purpose: the guest's stdout is a cp1252 console pipe under Windows, where a
    non-ASCII character in a German event message would raise UnicodeEncodeError mid-write.
    ``json.dumps`` rather than ``model_dump_json``: the host parsers and every recorded answer
    read its ``", "`` and ``": "`` separators, which ``model_dump_json`` writes without spaces.

    Example:
        >>> render(build("x", Outcome(ok=True, data=Skip(item="Gr\u00fc\u00dfe", reason="r"))))
        '{"ok": true, "command": "x", "data": {"item": "Gr\\u00fc\\u00dfe", "reason": "r"}, "skipped": []}'
    """
    return json.dumps(envelope.model_dump(mode="json"), ensure_ascii=True)


def exit_code(outcome: Outcome) -> ExitCode:
    """Map an outcome to its exit code (0 ok, 1 refused).

    Example:
        >>> exit_code(Outcome(ok=False, data=Skip(item="x", reason="y"))).value
        1
    """
    return ExitCode.OK if outcome.ok else ExitCode.REFUSED
