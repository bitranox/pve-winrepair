"""What the ``repair`` and ``apply`` commands share: settings, the checks before any call, and the output.

A run command reads the node CLI settings (a configuration that does not load or validate exits 78
before anything else), checks what would otherwise fail only deep inside the run (:func:`check_node`),
and then hands the use case a node and a receipt store from the composition.

The operator sees each step on stderr as it happens (:func:`echo_step`); stdout carries only the
result (:func:`finish`): the ``--json`` envelope, or one ``vm <vmid>: <verdict>`` line. The use
cases' progress lines between steps are stdlib ``logging`` records: they reach the operator the way
every log event does, through the root logger's lib_log_rich bridge (its scrubber, its console on
stderr at the configured level, its backends), so nothing here handles or re-levels them. An
internal error without ``--json`` prints nothing to stdout, so a caller reading that line never
mistakes a crash for a verdict.

Contents:
    * :class:`RunCommand` - ``repair`` or ``apply``, the envelope's ``command``.
    * :class:`RunEnvelope` - the ``--json`` envelope of a run.
    * :class:`PreflightError` - a check before any call failed; the message names the setting or option.
    * :func:`load_run_settings` - the node CLI settings, or exit 78 naming every refused value.
    * :func:`check_node` - refuse an unconfigured ``[ssh] key`` or an unusable ``[node] state_dir``.
    * :func:`check_link` - refuse a remote node that does not answer, refuses the key or has no ``qm``.
    * :func:`resolve_snapshot_name` - ``--snapshot-name`` validated as ``[repair] snapshot_name`` is.
    * :func:`refused` - the run result of a :class:`PreflightError`, shaped like the use cases' own.
    * :func:`echo_step` - one step on stderr.
    * :func:`finish` - print the result and exit with the run's code.
"""

from __future__ import annotations

import json
import stat
from enum import Enum
from typing import TYPE_CHECKING, NoReturn

from pydantic import BaseModel, ConfigDict, TypeAdapter, ValidationError

from pve_winrepair.adapters.config.settings import SettingsError
from pve_winrepair.domain.report import Report, RunExit, RunResult, RunVerdict, Step, StepName
from pve_winrepair.domain.settings import SnapshotName

from .. import safe_console
from ..config_load import require_config
from ..exit_codes import ExitCode

if TYPE_CHECKING:
    from pathlib import Path

    import rich_click as click

    from pve_winrepair.application.ports import NodePort
    from pve_winrepair.domain.settings import RepairSettings, Settings

    from ..context import CLIContext

__all__ = [
    "PreflightError",
    "RunCommand",
    "RunEnvelope",
    "check_link",
    "check_node",
    "echo_step",
    "finish",
    "load_run_settings",
    "refused",
    "resolve_snapshot_name",
]

#: The step name column is this wide on stderr, so the details line up.
_STEP_WIDTH = 22
#: The ``--json`` envelope's indentation, part of its byte form.
_JSON_INDENT = 2

_SNAPSHOT_NAME: TypeAdapter[str] = TypeAdapter(SnapshotName)


class RunCommand(str, Enum):
    """The run command an envelope reports."""

    REPAIR = "repair"
    APPLY = "apply"


class RunEnvelope(BaseModel):
    """The ``--json`` envelope of a run: how it ended, for which guest, and every step in order."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ok: bool
    command: RunCommand
    vmid: int
    verdict: RunVerdict
    steps: tuple[Step, ...]


class PreflightError(Exception):
    """A check before any node or guest call failed; the message names the setting or option."""


def load_run_settings(ctx: click.Context, cli_ctx: CLIContext) -> Settings:
    """The node CLI settings, or exit 78 with one ``Error: <section>.<field>: <reason>`` line per problem.

    A configuration that did not load at all exits 78 the same way, through ``require_config``.
    """
    config = require_config(ctx, cli_ctx)
    try:
        return cli_ctx.services.load_settings(config)
    except SettingsError as error:
        for line in error.lines:
            safe_console.echo(f"Error: {line}", err=True)
        ctx.exit(ExitCode.CONFIG_ERROR)


def check_node(settings: Settings) -> None:
    """Refuse what would otherwise fail only deep inside the run.

    Raises:
        PreflightError: ``[ssh] key`` is empty (every guest call would fail), or ``[node] state_dir`` is
            not a directory and cannot be created as one (the receipt write would fail after the
            snapshot, the media copy, the Windows Update hold and prepare).
    """
    if not settings.ssh.key:
        raise PreflightError(
            "[ssh] key is not configured: set it to the private key the node logs in to the guests with"
        )
    blocker = _not_a_directory(settings.node.state_dir)
    if blocker is not None:
        raise PreflightError(f"[node] state_dir {settings.node.state_dir} cannot be a directory: {blocker}")


def check_link(node: NodePort) -> None:
    """Refuse a remote node that cannot be used, before any call touches the VM.

    Raises:
        PreflightError: The linked node did not answer, refused the key or its host key, or has no
            ``qm``; the message is :meth:`NodePort.check_link`'s reason. A node without a link passes.
    """
    reason = node.check_link()
    if reason is not None:
        raise PreflightError(reason)


def _not_a_directory(path: Path) -> str | None:
    """Why ``path`` cannot be a directory, or None: it is one, or its nearest existing ancestor is one.

    Only the kind of the nearest existing path is judged: whether this user may create the
    directory there shows on the write, which names the file and the OS reason. ``stat`` itself is
    asked rather than ``Path.exists()``, whose handling of an unsearchable parent changed in Python
    3.14 (it raises before, answers False since), so the verdict is the same on every version.
    """
    probe = path
    while True:
        try:
            mode = probe.stat().st_mode
        except (FileNotFoundError, NotADirectoryError):
            if probe.is_symlink():  # exists as a name, so no directory can be made there
                return f"{probe} is a symbolic link to nothing"
            if probe.parent == probe:  # a root that does not exist (a Windows drive letter)
                return f"{probe} does not exist"
            probe = probe.parent
            continue
        except OSError as exc:
            return f"{probe} cannot be checked: {exc.strerror or exc}"
        return None if stat.S_ISDIR(mode) else f"{probe} is not a directory"


def resolve_snapshot_name(repair: RepairSettings, override: str | None) -> str:
    """``--snapshot-name``, held to ``[repair] snapshot_name``'s rule (:data:`SnapshotName`); the setting without it.

    Checked here rather than as a click parameter type: a bad name is a refused run (exit 1,
    verdict ERROR, an ``error`` step naming the option), not a usage error (exit 2).

    Raises:
        PreflightError: The override breaks the rule; the message names the option and the rule, never
            the value.
    """
    if override is None:
        return repair.snapshot_name
    try:
        return _SNAPSHOT_NAME.validate_python(override)
    except ValidationError as error:
        raise PreflightError("; ".join(f"--snapshot-name: {item['msg']}" for item in error.errors())) from None


def refused(vmid: int, refusal: PreflightError, *, wu_held: bool) -> RunResult:
    """The result of a run refused before any call: verdict ERROR, one ``error`` step, echoed like a step.

    Args:
        vmid: The guest the run was for.
        refusal: Why it was refused.
        wu_held: Windows Update is held on the guest (apply: a repair held it), so the step says so,
            as the use case's own refusals do.
    """
    rep = Report(vmid, on_step=echo_step, held_at_start=wu_held)
    rep.failure(StepName.ERROR, str(refusal), refusal)
    return RunResult(exit=RunExit.REFUSED, verdict=RunVerdict.ERROR, steps=tuple(rep.steps))


def echo_step(step: Step) -> None:
    """Write one step to stderr: ``[ok ]`` or ``[FAIL]``, its name, then ``key=value`` per detail.

    Each value is written as Python's ``str`` of it (a list as ``['a', 'b']``); the values are plain
    JSON values, so no enum member reaches the line.
    """
    state = "ok " if step.ok else "FAIL"
    detail = " ".join(f"{key}={value}" for key, value in step.items())
    safe_console.echo(f"[{state}] {step.step.value:<{_STEP_WIDTH}} {detail}".rstrip(), err=True)


def finish(ctx: click.Context, result: RunResult, *, command: RunCommand, vmid: int, as_json: bool) -> NoReturn:
    """Print the result on stdout and exit with the run's code (0 OK, 1 refused, 2 internal).

    Args:
        ctx: The running command's click context.
        result: How the run ended.
        command: The envelope's ``command``.
        vmid: The guest the run was for.
        as_json: Print the ``{"ok", "command", "vmid", "verdict", "steps"}`` envelope instead of
            the ``vm <vmid>: <verdict>`` line.
    """
    if as_json:
        envelope = RunEnvelope(
            ok=result.exit is RunExit.OK, command=command, vmid=vmid, verdict=result.verdict, steps=result.steps
        )
        # json.dumps, not model_dump_json: the envelope's bytes are its indented, ASCII-escaped rendering.
        safe_console.echo(json.dumps(envelope.model_dump(mode="json"), indent=_JSON_INDENT))
    elif result.exit is not RunExit.INTERNAL:
        safe_console.echo(f"vm {vmid}: {result.verdict.value}")
    ctx.exit(int(result.exit))
