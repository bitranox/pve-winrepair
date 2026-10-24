"""What both drivers read from the guest: the live-run gate, and the build with its InstallDate."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pve_winrepair.domain.envelope import RunState
from pve_winrepair.domain.guest_answers import BuildAnswer, GuestCommand, SetupAliveAnswer, StateAnswer
from pve_winrepair.domain.receipt import GuestBuild

if TYPE_CHECKING:
    from pve_winrepair.application.ports import GuestPort

__all__ = ["read_guest_build", "read_run_state"]


def read_guest_build(guest: GuestPort, *, timeout: float) -> GuestBuild:
    """CurrentBuild, UBR and InstallDate, as the guest tool's ``build`` reports them.

    The guest reports UBR and InstallDate as decimal integers, so there is no hex to parse here.

    Raises:
        GuestNoAnswerError, GuestInternalError: The guest could not be asked - NOT a wrong build.
        GuestProtocolError: A field is missing or has the wrong type, or CurrentBuild is no number.
    """
    return GuestBuild.from_answer(guest.ask(GuestCommand.BUILD, BuildAnswer, timeout=timeout).data)


def read_run_state(guest: GuestPort, *, timeout: float) -> RunState:
    """Ask the guest whether an upgrade run is live and how its last run ended.

    The one reading both drivers gate on before they stop, relaunch or restage a guest.

    Raises:
        GuestNoAnswerError, GuestInternalError: The guest could not be asked - NEVER an idle guest.
        GuestProtocolError: The log carries a verdict this driver does not know.
    """
    alive = guest.ask(GuestCommand.SETUP_ALIVE, SetupAliveAnswer, timeout=timeout).data.alive
    state = guest.ask(GuestCommand.STATE, StateAnswer, timeout=timeout).data
    return RunState(alive=alive, log_present=state.present, log_path=state.path, verdict=state.verdict)
