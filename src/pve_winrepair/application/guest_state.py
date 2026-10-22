"""The live-run gate both drivers read before they stop, relaunch or restage a guest."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pve_winrepair.domain.envelope import RunState, state_marker

if TYPE_CHECKING:
    from pve_winrepair.application.ports import GuestPort

__all__ = ["read_run_state"]


def read_run_state(guest: GuestPort, *, timeout: float) -> RunState:
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
