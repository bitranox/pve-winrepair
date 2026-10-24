"""The VM's power state as ``qm status`` reports it, and the bounded wait for a wanted one.

Shared by the repair and the apply-and-verify use cases; each passes its own bound (``tries``) and
maps a :class:`VmStatusError` to its refusal.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pve_winrepair.application.ports import NodePort

__all__ = ["UnknownVmStatusError", "VmStatus", "VmStatusError", "VmStatusTimeoutError", "vm_status", "wait_status"]


class VmStatus(str, Enum):
    """The VM's power state, the word ``qm status`` prints after ``status:``.

    Without ``--verbose`` PVE reports only whether the VM's QEMU process exists: ``running`` or
    ``stopped`` (a paused VM still reads ``running``).
    """

    RUNNING = "running"
    STOPPED = "stopped"


class VmStatusError(RuntimeError):
    """The VM's status could not be read, or it never reached the wanted one; the message names the VM."""


class UnknownVmStatusError(VmStatusError):
    """``qm status`` answered without a status this driver knows: it failed, or PVE changed its words."""


class VmStatusTimeoutError(VmStatusError):
    """The VM did not reach the wanted status within the bound; the message names VM and status."""


def vm_status(node: NodePort, vmid: int) -> VmStatus:
    """The VM's status, read from ``qm status <vmid>`` (``status: running``).

    Raises:
        UnknownVmStatusError: The answer's last word is no :class:`VmStatus` (``qm status`` failed,
            for a VM this node does not have, or printed something else). Never read as "not
            running": a stop or start decided on a status nobody read acts on a guest blindly.
    """
    proc = node.qm("status", str(vmid), timeout=60)
    word = proc.stdout.strip().split(" ")[-1]
    try:
        return VmStatus(word)
    except ValueError:
        said = (proc.stderr.strip() or proc.stdout.strip())[:400]
        raise UnknownVmStatusError(
            f"qm status {vmid} reported no status running or stopped (rc={proc.returncode}): {said!r}"
        ) from None


def wait_status(node: NodePort, vmid: int, want: VmStatus, *, tries: int) -> None:
    """Poll the VM status until it is ``want``.

    Args:
        node: The PVE node the VM runs on.
        vmid: The VM.
        want: The status to wait for.
        tries: How many reads, 5 s apart, before giving up.

    Raises:
        VmStatusTimeoutError: ``tries`` reads passed without ``want``; when the last read itself
            failed, the message names that failure.
    """
    last_failure: UnknownVmStatusError | None = None
    for _ in range(tries):
        # The wait spans the VM's own stop or start, when a single read can fail for a moment (the
        # config lock is held mid-transition). That is "not there yet", not a refusal: the bound
        # still ends the wait, and a read that never recovers is named when it does.
        try:
            if vm_status(node, vmid) is want:
                return
            last_failure = None
        except UnknownVmStatusError as exc:
            last_failure = exc
        node.sleep(5)
    message = f"vm {vmid} did not reach status {want.value}"
    if last_failure is not None:
        raise VmStatusTimeoutError(f"{message}; the last read failed: {last_failure}") from last_failure
    raise VmStatusTimeoutError(message)
