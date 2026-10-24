"""What the node reads of a VM's own configuration: ``qm config`` and ``qm listsnapshot``, parsed once.

``qm config`` prints one ``key: value`` line per setting. :func:`parse_vm_config` reads the lines
the drivers decide on into a :class:`VmConfig`: the disks with their storage and media kind, whether
a PVE vTPM (``tpmstate0``) or a launcher TPM (``args: ... --tpm``) is there, and the MACs of the
network devices. Only a line that STARTS with its key counts: a ``description:`` may quote any other
line, and reading that quote would put a vTPM on a pool this node cannot see or bind a guest by a MAC
the VM does not have.

``qm listsnapshot`` prints the snapshot tree; :func:`parse_snapshot_names` reads its names.
"""

from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel, ConfigDict

from pve_winrepair.domain.addresses import normalise_mac

__all__ = ["DiskMedia", "VmConfig", "VmConfigRead", "VmDisk", "parse_snapshot_names", "parse_vm_config"]

# A disk of the VM: ``scsi0: local-zfs:vm-1-disk-0,size=64G``. The storage is the text before the
# volume's first colon; an entry without one (``ide2: none,media=cdrom``) names no storage.
_DISK_LINE = re.compile(r"((?:scsi|virtio|sata|ide)[0-9]+):\s*([^:,]+):(.*)")
# An openvmm guest's launcher arguments carrying its TPM.
_LAUNCHER_TPM = re.compile(r"args:.*--tpm\b")
# A network device line: ``net0: virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,...``. The model key (virtio,
# e1000, vmxnet3, rtl8139, ...) varies; the MAC is the value of that key, or of ``macaddr``.
_NET_LINE = re.compile(r"net[0-9]+:[ \t]*(\S+)")
# One entry of the snapshot tree: ``  `-> name   <date>   <description>``; the name follows the arrow.
_SNAPSHOT_LINE = re.compile(r"[\s`|+\\>-]*->\s*(\S+)")
# PVE's you-are-here marker in that tree, not a snapshot.
_CURRENT = "current"


class DiskMedia(str, Enum):
    """What a disk entry holds: a disk image, or an optical medium (``media=cdrom``)."""

    DISK = "disk"
    CDROM = "cdrom"


class VmDisk(BaseModel):
    """One disk entry of ``qm config`` that names a storage.

    Attributes:
        key: The entry's key (``scsi0``, ``virtio1``, ``sata2``, ``ide3``).
        storage: The PVE storage its volume lives on.
        media: A disk image, or an optical medium.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    key: str
    storage: str
    media: DiskMedia


class VmConfig(BaseModel):
    """The settings of ``qm config`` the drivers decide on.

    Attributes:
        disks: Every disk entry that names a storage, in the order ``qm config`` lists them.
        tpmstate: The VM has a PVE vTPM volume (``tpmstate0``).
        launcher_tpm: The VM's launcher arguments provide a TPM (an openvmm guest's ``args: ... --tpm``).
        macs: The MAC of every network device, normalised (``AA:BB:CC:DD:EE:FF``).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    disks: tuple[VmDisk, ...] = ()
    tpmstate: bool = False
    launcher_tpm: bool = False
    macs: frozenset[str] = frozenset()


class VmConfigRead(BaseModel):
    """One ``qm config`` call: how it exited, its output for a refusal, and what its stdout says.

    The configuration is parsed whatever the exit code; a reader that must not trust a failed call
    checks ``returncode`` first.

    Attributes:
        returncode: ``qm config``'s exit code.
        output: Its stderr, or its stdout when stderr is empty: the text a refusal quotes.
        config: Its stdout, parsed.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    returncode: int
    output: str
    config: VmConfig


def _disk(line: str) -> VmDisk | None:
    """The disk ``line`` names, or None when it is no disk entry with a storage."""
    match = _DISK_LINE.match(line)
    if match is None:
        return None
    options = {item.strip() for item in match.group(3).split(",")[1:]}
    media = DiskMedia.CDROM if "media=cdrom" in options else DiskMedia.DISK
    return VmDisk(key=match.group(1), storage=match.group(2).strip(), media=media)


def _net_macs(line: str) -> set[str]:
    """The MACs of the network device ``line`` names; none when it is no ``net<N>:`` line."""
    device = _NET_LINE.fullmatch(line.rstrip())
    if device is None:
        return set()
    found: set[str] = set()
    for item in device.group(1).split(","):
        mac = normalise_mac(item.partition("=")[2])
        if mac is not None:
            found.add(mac)
    return found


def parse_vm_config(text: str) -> VmConfig:
    """``qm config`` output as a :class:`VmConfig`.

    Example:
        >>> config = parse_vm_config(
        ...     "scsi0: local-zfs:vm-1-disk-0,size=64G\\n"
        ...     "ide2: local:iso/win.iso,media=cdrom\\n"
        ...     "net0: virtio=bc:24:11:aa:bb:cc,bridge=vmbr0\\n"
        ... )
        >>> [(d.key, d.storage, d.media.value) for d in config.disks]
        [('scsi0', 'local-zfs', 'disk'), ('ide2', 'local', 'cdrom')]
        >>> sorted(config.macs), config.tpmstate, config.launcher_tpm
        (['BC:24:11:AA:BB:CC'], False, False)
    """
    disks: list[VmDisk] = []
    macs: set[str] = set()
    tpmstate = launcher_tpm = False
    for line in text.splitlines():
        disk = _disk(line)
        if disk is not None:
            disks.append(disk)
        tpmstate = tpmstate or line.startswith("tpmstate0:")
        launcher_tpm = launcher_tpm or _LAUNCHER_TPM.match(line) is not None
        macs |= _net_macs(line)
    return VmConfig(disks=tuple(disks), tpmstate=tpmstate, launcher_tpm=launcher_tpm, macs=frozenset(macs))


def parse_snapshot_names(text: str) -> frozenset[str]:
    r"""The snapshot names in ``qm listsnapshot`` output, without PVE's ``current`` marker.

    Example:
        >>> sorted(parse_snapshot_names("`-> pre_winrepair  2026-10-24  before\n `-> current  You are here!\n"))
        ['pre_winrepair']
    """
    names = {match.group(1) for match in map(_SNAPSHOT_LINE.match, text.splitlines()) if match is not None}
    return frozenset(names - {_CURRENT})
