"""What both drivers read from the guest: the live-run gate, and the build with its InstallDate."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from pve_winrepair.domain.envelope import GuestProtocolError, RunState, state_marker
from pve_winrepair.domain.receipt import GuestBuild

if TYPE_CHECKING:
    from pve_winrepair.application.ports import GuestPort

__all__ = ["read_guest_build", "read_run_state"]

# CurrentBuild is a registry string; the drivers compare it as a number. ASCII digits only, bounded
# so int() never meets a huge or non-ASCII numeral.
_BUILD_NUMBER = re.compile(r"[0-9]{1,9}")


def read_guest_build(guest: GuestPort, *, timeout: float) -> GuestBuild:
    """CurrentBuild, UBR and InstallDate, as the guest tool's ``build`` reports them.

    The guest reports UBR and InstallDate as decimal integers, so there is no hex to parse here.

    Raises:
        GuestNoAnswerError, GuestInternalError: The guest could not be asked - NOT a wrong build.
        GuestProtocolError: A field is missing or has the wrong type, or CurrentBuild is no number.
    """
    data = guest.probe("build", timeout=timeout)
    current = data.text("current_build")
    if not _BUILD_NUMBER.fullmatch(current):
        raise GuestProtocolError(f"build: CurrentBuild {current!r} is not a number")
    return GuestBuild(build=int(current), ubr=data.integer("ubr"), install_date=data.integer("install_date"))


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
