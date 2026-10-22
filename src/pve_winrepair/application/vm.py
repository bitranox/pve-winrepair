"""The VM's power state as ``qm status`` reports it, and the bounded wait for a wanted one.

Shared by the repair and the apply-and-verify use cases; each passes its own bound (``tries``) and
maps :class:`VmStatusTimeoutError` to its refusal.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pve_winrepair.application.ports import NodePort

__all__ = ["VmStatusTimeoutError", "vm_status", "wait_status"]


class VmStatusTimeoutError(RuntimeError):
    """The VM did not reach the wanted status within the bound; the message names VM and status."""


def vm_status(node: NodePort, vmid: int) -> str:
    """The VM's status word (running, stopped)."""
    return node.qm("status", str(vmid), timeout=60).stdout.strip().split(" ")[-1]


def wait_status(node: NodePort, vmid: int, want: str, *, tries: int) -> None:
    """Poll the VM status until it is ``want``.

    Args:
        node: The PVE node the VM runs on.
        vmid: The VM.
        want: The status word to wait for (``running``, ``stopped``).
        tries: How many reads, 5 s apart, before giving up.

    Raises:
        VmStatusTimeoutError: ``tries`` reads passed without ``want``.
    """
    for _ in range(tries):
        if vm_status(node, vmid) == want:
            return
        node.sleep(5)
    raise VmStatusTimeoutError(f"vm {vmid} did not reach status {want}")
