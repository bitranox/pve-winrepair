# /// script
# requires-python = ">=3.11"
# dependencies = ["pwshpy==1.8.0", "pydantic==2.14.1", "pywin32==312; sys_platform == 'win32'"]
# ///
r"""winrepair guest tool: every in-guest step of the repair as one typed command line tool.

Runs inside the Windows guest (packed into ``winrepair_guest.ps1`` by ``pwshpy pack``) and is
called by the host drivers over ssh as
``powershell -NoProfile -ExecutionPolicy Bypass -File C:\winrepair\winrepair_guest-<sha16>.ps1 <command>
... --json`` (``<sha16>``: the first 16 hex of the packed file's sha256, see ``guestcall``).

Contract (see ``envelope.py``): exactly one JSON envelope on stdout, progress and diagnostics on
stderr, exit 0 ok / 1 refused / 2 internal error. A usage error or a crash still prints an
envelope, so the caller never has to tell "no answer" from "empty answer" by guessing.

Adding a module: give it a ``commands()`` function returning a tuple of ``envelope.Command`` and
list it in :func:`default_commands`.

Contents:
    * :func:`main` - parse, run one command, print its envelope, return the exit code.
    * :func:`default_commands` - every registered subcommand.
"""

from __future__ import annotations

import argparse
import sys
import traceback
from typing import TYPE_CHECKING, NoReturn, TextIO

from pve_winrepair_guest.envelope import Command, ExitCode, build, exit_code, internal_error, render

if TYPE_CHECKING:
    from collections.abc import Sequence

    from pve_winrepair_guest.envelope import Envelope

__all__ = ["UsageError", "default_commands", "main"]


class UsageError(Exception):
    """The command line did not parse (unknown command, missing or bad argument)."""


class _Parser(argparse.ArgumentParser):
    """An ArgumentParser that raises instead of printing usage and exiting 2.

    argparse's own error path writes to stderr and exits without an envelope, which would leave
    the caller with an empty stdout it cannot tell from a lost answer.
    """

    def error(self, message: str) -> NoReturn:
        raise UsageError(f"{self.prog}: {message}")


def default_commands() -> tuple[Command, ...]:
    """Every subcommand the packed tool offers.

    Returns:
        The commands of each feature module, in registration order.
    """
    # Imported here, not at the top: a feature module that fails to import (a broken pwshpy
    # install on the guest) must still produce an internal-error envelope from main().
    from pve_winrepair_guest import probes, upgrade, wu  # noqa: PLC0415 - deferred so an import failure becomes an envelope

    return (*probes.commands(), *wu.commands(), *upgrade.commands())


def _build_parser(commands: Sequence[Command]) -> argparse.ArgumentParser:
    """Build the parser with one subparser per command, each accepting ``--json``."""
    # --json is accepted everywhere because the drivers append it; output is always JSON.
    json_flag = _Parser(add_help=False)
    json_flag.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    parser = _Parser(prog="winrepair_guest", parents=[json_flag], description=__doc__)
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True
    for command in commands:
        child = sub.add_parser(command.name, help=command.help, parents=[json_flag])
        command.configure(child)
        child.set_defaults(handler=command)
    return parser


def _command_name(argv: Sequence[str], commands: Sequence[Command]) -> str:
    """Return the command a failed parse was aimed at, for the envelope's ``command`` field."""
    known = {command.name for command in commands}
    return next((token for token in argv if token in known), "")


def _emit(stdout: TextIO, envelope: Envelope, code: ExitCode) -> int:
    """Print the envelope as one line and return the exit code."""
    stdout.write(render(envelope) + "\n")
    stdout.flush()
    return int(code)


def _fail(stdout: TextIO, stderr: TextIO, command: str, error: Exception) -> int:
    """Print the traceback to stderr and an internal-error envelope to stdout."""
    traceback.print_exception(type(error), error, error.__traceback__, file=stderr)
    return _emit(stdout, internal_error(command, error), ExitCode.INTERNAL)


def main(
    argv: Sequence[str] | None = None,
    *,
    commands: Sequence[Command] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run one command and print its envelope.

    Args:
        argv: The arguments without the program name; ``sys.argv[1:]`` when None.
        commands: The command table; :func:`default_commands` when None.
        stdout: Where the envelope goes; ``sys.stdout`` when None.
        stderr: Where diagnostics go; ``sys.stderr`` when None.

    Returns:
        The process exit code: 0 ok, 1 refused, 2 internal or usage error.
    """
    out, err = stdout or sys.stdout, stderr or sys.stderr
    tokens = list(sys.argv[1:] if argv is None else argv)
    try:
        table = tuple(commands) if commands is not None else default_commands()
    except Exception as exc:  # a feature module failed to import
        return _fail(out, err, "", exc)
    try:
        args = _build_parser(table).parse_args(tokens)
    except UsageError as exc:
        return _fail(out, err, _command_name(tokens, table), exc)
    command: Command = args.handler
    try:
        outcome = command.run(args)
    except Exception as exc:  # the envelope reports it; the traceback goes to stderr only
        return _fail(out, err, command.name, exc)
    return _emit(out, build(command.name, outcome), exit_code(outcome))


if __name__ == "__main__":
    raise SystemExit(main())
