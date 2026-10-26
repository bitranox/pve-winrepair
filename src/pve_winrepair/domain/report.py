"""The steps of one driver run, in order, and how the run ended.

A :class:`Report` collects each step as it happens and hands it to ``on_step`` (the CLI prints it
for the operator); the CLI also turns the steps into the ``steps`` of the JSON envelope.
:class:`StepName` names every step a run records, :class:`Step` is one of them, :class:`RunVerdict`
is how a run ended in words, :class:`RunExit` the exit code it maps to, and :class:`RunResult`
the three together.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import TYPE_CHECKING, Final, TypeAlias

from pydantic import BaseModel, ConfigDict, JsonValue, model_serializer, model_validator

from pve_winrepair.domain.envelope import WU_HELD_HINT, guest_stderr

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Sequence

__all__ = ["Report", "RunExit", "RunResult", "RunVerdict", "Step", "StepName", "StepValue"]

if TYPE_CHECKING:
    # What a step measured, for the type checker: Sequence and Mapping are covariant, so a step can
    # record the list[str] or dict[str, float] it built without a copy. pydantic cannot build a
    # schema from a self-referencing plain alias (it recurses), so at runtime the same values are
    # validated as JsonValue, which also turns a str enum member into its plain value.
    StepValue: TypeAlias = str | bool | int | float | Sequence["StepValue"] | Mapping[str, "StepValue"] | None
else:
    StepValue = JsonValue


class StepName(str, Enum):
    """Every step a repair or apply run records; the value is the ``step`` of the envelope."""

    BUILD_AFTER = "build_after"
    BUILD_BEFORE = "build_before"
    CLEAN_STOP = "clean_stop"
    ERROR = "error"
    GATE_STAGED = "gate_staged"
    GUEST_BACK = "guest_back"
    GUEST_IDENTITY = "guest_identity"
    INTERNAL = "internal"
    LAUNCH = "launch"
    LOCK_DIRS = "lock_dirs"
    NO_LIVE_RUN = "no_live_run"
    POLL = "poll"
    PREPARE = "prepare"
    PUSH_TOOL = "push_tool"
    QUIESCE_WU = "quiesce_wu"
    RECEIPT = "receipt"
    REMOVE_PROFILE_COPY = "remove_profile_copy"
    RESTORE_WU = "restore_wu"
    RUN_FINISHED = "run_finished"
    RUNNING = "running"
    SERVICING_IDLE = "servicing_idle"
    SHUTDOWN = "shutdown"
    SNAPSHOT = "snapshot"
    STAGE_MEDIA = "stage_media"
    STAGE_ROOT = "stage_root"
    STAGE_TOOL = "stage_tool"
    STAGED = "staged"
    START = "start"
    VERIFY_BUILD = "verify_build"
    VTPM = "vtpm"
    WINREPAIR_LOCK = "winrepair_lock"


class RunVerdict(str, Enum):
    """How a repair or apply run ended: the envelope's ``verdict`` and the ``vm <vmid>: <verdict>`` line.

    One vocabulary for both commands: ``ERROR`` and ``INTERNAL`` end either, and a refusal before
    any call (the CLI's own checks) is shaped the same for both. The repair run's poll answers carry
    the guest's marker line itself (``STATE=DONE-OK``).
    """

    #: repair: the state log ended ``STATE=DONE-OK``.
    DONE_OK = "STATE=DONE-OK"
    #: repair: the state log ended ``STATE=DONE-FAIL``.
    DONE_FAIL = "STATE=DONE-FAIL"
    #: repair: SetupHost exited and no marker appeared within the grace window.
    WORKER_GONE = "WORKER_GONE"
    #: repair: no marker within the poll deadline.
    TIMEOUT = "TIMEOUT"
    #: repair --stage-only: the media are staged, nothing was launched.
    STAGED = "STAGED"
    #: apply: the guest runs the build the receipt recorded, and Windows Update is restored.
    VERIFIED = "VERIFIED"
    #: apply: SetupHost is still running.
    RUN_LIVE = "RUN_LIVE"
    #: apply: the run started and SetupHost is gone, but no DONE marker was written.
    RUN_UNFINISHED = "RUN_UNFINISHED"
    #: apply: the run ended ``STATE=DONE-FAIL``.
    RUN_FAILED = "RUN_FAILED"
    #: apply: no state log, so no run to apply.
    NO_RUN = "NO_RUN"
    #: apply: the guest did not reach the recorded build, or same-build media left no trace.
    REVERTED_OR_UNCHANGED = "REVERTED_OR_UNCHANGED"
    #: either: refused (a gate, a timeout, a guest that is not the VM, a check before any call).
    ERROR = "ERROR"
    #: either: an unexpected failure (a driver/tool mismatch).
    INTERNAL = "INTERNAL"


class RunExit(IntEnum):
    """How a run ended: repaired or launched, refused or failed, or an internal error."""

    OK = 0
    REFUSED = 1
    INTERNAL = 2


#: The step keys with a meaning of their own; every other key is a measurement of that one step.
_TYPED_KEYS: Final[frozenset[str]] = frozenset({"message", "note", "wu_held", "guest_stderr"})


class Step(BaseModel):
    """One step of a run: its name, whether it passed, and what it measured.

    Serialised (``model_dump``) as one flat object: ``step``, ``ok``, then every other key in the
    order the run recorded it, which is the order the ``--json`` envelope and the stderr line show.

    Attributes:
        step: Which step.
        ok: It passed.
        message: Why the run ended here (the ``error`` and ``internal`` steps).
        note: A sentence for the operator.
        wu_held: The run leaves Windows Update held; only set when it does.
        guest_stderr: The guest traceback behind an ``error`` or ``internal`` step.
        detail: The measurements of this step, keyed by name (each step has its own).
        key_order: Every key after ``step`` and ``ok``, in recording order: the typed ones that
            were given and the ``detail`` keys.

    Example:
        >>> step = Step.record(StepName.POLL, ok=False, fields={"verdict": RunVerdict.TIMEOUT, "note": "late"})
        >>> step.model_dump()
        {'step': 'poll', 'ok': False, 'verdict': 'TIMEOUT', 'note': 'late'}
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    step: StepName
    ok: bool
    message: str | None = None
    note: str | None = None
    wu_held: bool | None = None
    guest_stderr: tuple[str, ...] | None = None
    detail: Mapping[str, StepValue]
    key_order: tuple[str, ...]

    @classmethod
    def record(cls, step: StepName, *, ok: bool, fields: Mapping[str, StepValue]) -> Step:
        """The step ``step`` with ``fields`` kept in the order given.

        The typed keys (``message``, ``note``, ``wu_held``, ``guest_stderr``) go into their own
        fields, every other key into ``detail``.

        Raises:
            pydantic.ValidationError: A typed key has the wrong type, or a value is no JSON value.
        """
        typed = {key: value for key, value in fields.items() if key in _TYPED_KEYS}
        detail = {key: value for key, value in fields.items() if key not in _TYPED_KEYS}
        return cls.model_validate({"step": step, "ok": ok, **typed, "detail": detail, "key_order": tuple(fields)})

    @model_validator(mode="after")
    def _key_order_names_every_key_once(self) -> Step:
        # A typed key given as None is still written out (as null), so it may be named while unset.
        overlap = (_TYPED_KEYS | {"step", "ok"}) & set(self.detail)
        if overlap:
            raise ValueError(f"detail repeats the keys {sorted(overlap)}")
        given = {key for key, value in self._typed().items() if value is not None} | set(self.detail)
        named = set(self.key_order)
        if len(named) != len(self.key_order) or not given <= named <= given | _TYPED_KEYS:
            raise ValueError(f"key_order {list(self.key_order)} does not name each recorded key once")
        return self

    def _typed(self) -> dict[str, StepValue]:
        """The typed keys as they are written out (``guest_stderr`` as a list, as JSON has it)."""
        stderr = None if self.guest_stderr is None else list(self.guest_stderr)
        return {"message": self.message, "note": self.note, "wu_held": self.wu_held, "guest_stderr": stderr}

    def items(self) -> Iterator[tuple[str, StepValue]]:
        """Every key after ``step`` and ``ok`` with its value, in recording order."""
        typed = self._typed()
        for key in self.key_order:
            yield key, typed[key] if key in _TYPED_KEYS else self.detail[key]

    def held(self, hint: str) -> Step:
        """This step flagged as leaving Windows Update held, ``hint`` appended to its note.

        A key the step already had keeps its place; ``wu_held`` and ``note`` are added at the end
        when it did not.
        """
        added = tuple(key for key in ("wu_held", "note") if key not in self.key_order)
        note = f"{self.note} - {hint}" if self.note else hint
        return self.model_copy(update={"wu_held": True, "note": note, "key_order": self.key_order + added})

    @model_serializer(mode="plain")
    def _flat(self) -> dict[str, StepValue]:
        return {"step": self.step.value, "ok": self.ok, **dict(self.items())}


@dataclass(frozen=True)
class RunResult:
    """How a run ended: its exit, its verdict, and its steps (the failure step included)."""

    exit: RunExit
    verdict: RunVerdict
    steps: tuple[Step, ...]


def _ignore(_step: Step) -> None:
    """The default ``on_step``: the steps are only collected."""


class Report:
    """The steps of one run, in order; they become the ``steps`` of the --json envelope."""

    def __init__(self, vmid: int, *, on_step: Callable[[Step], None] = _ignore, held_at_start: bool = False) -> None:
        """Start an empty report for ``vmid``.

        Args:
            vmid: The guest the run is about.
            on_step: Called with each step as it is recorded, and again with the last step only
                when :meth:`ended_held` has to flag a step not recorded by :meth:`add_held_end`.
                Steps are frozen, so what the caller kept still shows the step as it was when it
                was emitted.
            held_at_start: Windows Update was already held when this run began (by an earlier run).
        """
        self.vmid = vmid
        self.steps: list[Step] = []
        self._on_step = on_step
        self._held_at_start = held_at_start

    def add(self, step: StepName, *, ok: bool, **fields: StepValue) -> None:
        """Record a step, its fields in the order given, and hand it to ``on_step``."""
        self._emit(Step.record(step, ok=ok, fields=fields))

    def add_held_end(self, step: StepName, *, ok: bool, **fields: StepValue) -> None:
        """Record the last step of a run whose verdict nobody applies (STAGED, a failed poll).

        When Windows Update is held the step is flagged with the hold before it is handed to
        ``on_step``, so the operator reads it once, complete.
        """
        recorded = Step.record(step, ok=ok, fields=fields)
        self._emit(recorded.held(WU_HELD_HINT) if self.wu_held else recorded)

    def _emit(self, recorded: Step) -> None:
        self.steps.append(recorded)
        self._on_step(recorded)

    @property
    def wu_held(self) -> bool:
        """Windows Update is held: it was at the start, or a quiesce step of this run passed."""
        return self._held_at_start or any(s.step is StepName.QUIESCE_WU and s.ok for s in self.steps)

    def failure(self, step: StepName, message: str, exc: BaseException) -> None:
        """Record the run's last step: the error, the guest traceback behind it, and the WU hold."""
        fields: dict[str, StepValue] = {"message": message}
        if self.wu_held:
            fields.update(message=f"{message} - {WU_HELD_HINT}", wu_held=True)
        stderr = guest_stderr(exc)
        if stderr is not None:
            fields["guest_stderr"] = list(stderr)
        self.add(step, ok=False, **fields)

    def ended_held(self) -> None:
        """Flag the hold on the last step of a run that ended without a verdict worth applying.

        The poll's DONE-FAIL, WORKER_GONE and TIMEOUT are answers, not exceptions, so
        :meth:`failure` never sees them; they leave Windows Update held all the same. A last step
        recorded by :meth:`add_held_end` already carries the hold and is left as it is; any other
        is flagged here and handed to ``on_step`` again, so a path that recorded its last step with
        :meth:`add` still shows the hold.
        """
        if not self.wu_held or not self.steps or self.steps[-1].wu_held:
            return
        self.steps[-1] = self.steps[-1].held(WU_HELD_HINT)
        # The step was emitted before the hold was known; emit it again so the operator sees it.
        self._on_step(self.steps[-1])
