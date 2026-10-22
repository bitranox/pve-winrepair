"""The steps of one driver run, in order, and how the run ended.

A :class:`Report` collects each step as it happens and hands it to ``on_step`` (the CLI prints it
for the operator); the CLI also turns the steps into the ``steps`` of the JSON envelope.
:class:`RunExit` is the exit code a run maps to, :class:`RunResult` how a run ended.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING

from pve_winrepair.domain.envelope import WU_HELD_HINT, guest_stderr

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = ["Report", "RunExit", "RunResult", "Step"]

#: One step of a run: ``step`` (its name), ``ok``, and the details it measured.
Step = dict[str, object]


class RunExit(IntEnum):
    """How a run ended: repaired or launched, refused or failed, or an internal error."""

    OK = 0
    REFUSED = 1
    INTERNAL = 2


@dataclass(frozen=True)
class RunResult:
    """How a run ended: its exit, its verdict (``STATE=DONE-OK``, ``VERIFIED``, ``ERROR``, ...), its steps."""

    exit: RunExit
    verdict: str
    steps: tuple[Step, ...]


def _ignore(_step: Step) -> None:
    """The default ``on_step``: the steps are only collected."""


class Report:
    """The steps of one run, in order; they become the ``steps`` of the --json envelope."""

    def __init__(self, vmid: int, *, on_step: Callable[[Step], None] = _ignore, held_at_start: bool = False) -> None:
        """Start an empty report for ``vmid``.

        Args:
            vmid: The guest the run is about.
            on_step: Called with a COPY of each step as it is recorded, and again with a copy of
                the last step when :meth:`ended_held` changes it. A copy, so what the caller kept
                still shows the step as it was when it was emitted.
            held_at_start: Windows Update was already held when this run began (by an earlier run).
        """
        self.vmid = vmid
        self.steps: list[Step] = []
        self._on_step = on_step
        self._held_at_start = held_at_start

    def add(self, step: str, *, ok: bool, **detail: object) -> None:
        """Record a step and hand it to ``on_step``."""
        self.steps.append({"step": step, "ok": ok, **detail})
        self._on_step(dict(self.steps[-1]))

    @property
    def wu_held(self) -> bool:
        """Windows Update is held: it was at the start, or a quiesce step of this run passed."""
        return self._held_at_start or any(s["step"] == "quiesce_wu" and s["ok"] for s in self.steps)

    def failure(self, step: str, message: str, exc: BaseException) -> None:
        """Record the run's last step: the error, the guest traceback behind it, and the WU hold."""
        detail: dict[str, object] = {"message": message}
        if self.wu_held:
            detail.update(message=f"{message} - {WU_HELD_HINT}", wu_held=True)
        stderr = guest_stderr(exc)
        if stderr is not None:
            detail["guest_stderr"] = list(stderr)
        self.add(step, ok=False, **detail)

    def ended_held(self) -> None:
        """Flag the hold on the last step of a run that ended without a verdict worth applying.

        The poll's DONE-FAIL, WORKER_GONE and TIMEOUT are answers, not exceptions, so
        :meth:`failure` never sees them; they leave Windows Update held all the same. The updated
        step is handed to ``on_step`` again.
        """
        if not self.wu_held or not self.steps:
            return
        last = self.steps[-1]
        note = last.get("note")
        last.update(wu_held=True, note=f"{note} - {WU_HELD_HINT}" if note else WU_HELD_HINT)
        # The step was emitted before the hold was known; emit it again so the operator sees it.
        self._on_step(dict(last))
