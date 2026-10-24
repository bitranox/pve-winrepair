"""Bind the guest at an operator-typed address to the VM the run acts on, by NIC MAC.

``repair --ip`` and ``apply`` reach the guest at ``--ip`` but stop, snapshot and start the VM
``--vmid`` names; a typo would ACPI-stop one VM mid-setup while the guest tool runs on another. So
before anything acts on the VM, the guest's adapters (the guest tool's ``nic-macs``) must include a
MAC of one of the VM's ``netN`` devices in ``qm config``.

The check is membership, never equality: a guest lists adapters its VM config does not have (WAN
miniports, a Hyper-V vEthernet switch on a docker guest). A MAC changed inside Windows is refused;
that fails safe. Shared by the repair and the apply-and-verify use cases; each maps
:class:`GuestMismatchError` to its refusal.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pve_winrepair.domain.addresses import normalise_mac, vm_macs
from pve_winrepair.domain.envelope import PROBE_TIMEOUT, READ_FAILURES, GuestProtocolError, snippet
from pve_winrepair.domain.guest_answers import GuestCommand, NicMacsAnswer

if TYPE_CHECKING:
    from pve_winrepair.application.ports import GuestPort, NodePort
    from pve_winrepair.domain.report import Report

__all__ = ["GuestMismatchError", "check_guest_is_vm"]


class GuestMismatchError(RuntimeError):
    """The guest at the address is not provably the VM: no common MAC, or one side could not be read."""


def _configured_macs(node: NodePort, vmid: int, ip: str) -> frozenset[str]:
    proc = node.qm("config", str(vmid), timeout=60)
    if proc.returncode != 0:
        raise GuestMismatchError(
            f"cannot read qm config {vmid} to bind the guest at {ip} to it: "
            f"rc={proc.returncode}: {snippet(proc.stderr or proc.stdout)}"
        )
    macs = vm_macs(proc.stdout)
    if not macs:
        raise GuestMismatchError(
            f"VM {vmid} has no network device with a MAC in qm config, so the guest at {ip} cannot be bound to it"
        )
    return macs


def _guest_macs(guest: GuestPort) -> frozenset[str]:
    try:
        reported = guest.ask(GuestCommand.NIC_MACS, NicMacsAnswer, timeout=PROBE_TIMEOUT).data.macs
    except READ_FAILURES as exc:
        raise GuestMismatchError(f"cannot read the NIC MACs of the guest at {guest.ip}: {exc}") from exc
    macs: set[str] = set()
    for text in reported:
        mac = normalise_mac(text)
        if mac is None:
            raise GuestProtocolError(f"nic-macs: {text!r} is not a MAC address")
        macs.add(mac)
    return frozenset(macs)


def check_guest_is_vm(node: NodePort, guest: GuestPort, vmid: int, rep: Report) -> None:
    """Refuse unless a MAC of VM ``vmid``'s ``netN`` devices is one of the guest's adapters.

    Records the ``guest_identity`` step: the common MACs, or both lists when there are none.

    Raises:
        GuestMismatchError: No common MAC, the VM config has no network device with a MAC, or
            either side could not be read.
        GuestProtocolError: The guest reported a value that is not a MAC (a driver/tool mismatch).
    """
    configured = _configured_macs(node, vmid, guest.ip)
    reported = _guest_macs(guest)
    common = sorted(configured & reported)
    if common:
        rep.add("guest_identity", ok=True, ip=guest.ip, macs=common)
        return
    rep.add("guest_identity", ok=False, ip=guest.ip, vm_macs=sorted(configured), guest_macs=sorted(reported))
    raise GuestMismatchError(
        f"the guest at {guest.ip} is not VM {vmid}: none of its NIC MACs ({', '.join(sorted(reported))}) "
        f"is a MAC of VM {vmid} in qm config ({', '.join(sorted(configured))}) - check --ip"
    )
