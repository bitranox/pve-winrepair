"""Tests for reading ``qm config`` and ``qm listsnapshot`` output into typed values, against the shapes PVE prints."""

from __future__ import annotations

import pytest

from pve_winrepair.domain.vm_config import DiskMedia, VmConfig, VmDisk, parse_snapshot_names, parse_vm_config

# A Windows guest on the shapes PVE prints: disks on each bus, an ISO and an empty drive, a vTPM, and
# two NICs of different models.
WINDOWS_GUEST = (
    "agent: 1\n"
    "boot: order=scsi0;ide2;net0\n"
    "description: moved from local-lvm:vm-1-disk-9 and net0: virtio=BC:24:11:99:99:99\n"
    "efidisk0: local-zfs:vm-1-disk-2,efitype=4m,pre-enrolled-keys=1,size=1M\n"
    "ide0: none,media=cdrom\n"
    "ide2: local:iso/Win11_24H2.iso,media=cdrom,size=5819564K\n"
    "net0: virtio=bc:24:11:aa:bb:cc,bridge=vmbr0,firewall=1\n"
    "net1: e1000=BC:24:11:00:00:01,bridge=vmbr1,tag=40\n"
    "sata1: tank:vm-1-disk-3,size=200G\n"
    "scsi0: local-zfs:vm-1-disk-0,discard=on,iothread=1,size=64G,ssd=1\n"
    "tpmstate0: local-zfs:vm-1-disk-1,size=4M,version=v2.0\n"
    "virtio2: other-pool:vm-1-disk-4,size=32G\n"
)


def test_a_windows_guest_s_config_parses_into_its_disks_tpm_and_macs() -> None:
    assert parse_vm_config(WINDOWS_GUEST) == VmConfig(
        disks=(
            VmDisk(key="ide2", storage="local", media=DiskMedia.CDROM),
            VmDisk(key="sata1", storage="tank", media=DiskMedia.DISK),
            VmDisk(key="scsi0", storage="local-zfs", media=DiskMedia.DISK),
            VmDisk(key="virtio2", storage="other-pool", media=DiskMedia.DISK),
        ),
        tpmstate=True,
        launcher_tpm=False,
        macs=frozenset({"BC:24:11:AA:BB:CC", "BC:24:11:00:00:01"}),
    )


def test_empty_output_is_a_config_with_nothing_in_it() -> None:
    assert parse_vm_config("") == VmConfig()


@pytest.mark.parametrize(
    ("line", "launcher_tpm"),
    [
        ("args: -launcher openvmm --tpm\n", True),
        ("args: --tpm --uefi\n", True),
        ("args: --tpmfoo\n", False),
        ("description: args: --tpm\n", False),
        ("#args: --tpm\n", False),
    ],
)
def test_a_launcher_tpm_is_read_from_the_args_line_only(line: str, launcher_tpm: bool) -> None:
    config = parse_vm_config(line)
    assert (config.launcher_tpm, config.tpmstate) == (launcher_tpm, False)


@pytest.mark.parametrize(
    "line", ["description: tpmstate0: local-zfs:vm-1-disk-1\n", "#tpmstate0: x:y\n", "tpmstate1: x:y\n"]
)
def test_only_a_tpmstate0_line_is_a_vtpm(line: str) -> None:
    assert parse_vm_config(line).tpmstate is False


def test_a_quoted_disk_line_is_no_disk() -> None:
    # A disk named inside a description would put the vTPM on a pool this node may not see.
    config = parse_vm_config("description: scsi0: elsewhere:vm-1-disk-0\n#scsi0: other:vm-1-disk-0\nunused0: z:vm-1\n")
    assert config.disks == ()


def test_the_storage_is_the_text_before_the_volume_s_first_colon_stripped() -> None:
    assert parse_vm_config("scsi0:  local-zfs :vm-1-disk-0\n").disks == (
        VmDisk(key="scsi0", storage="local-zfs", media=DiskMedia.DISK),
    )


def test_every_net_line_counts_whatever_the_model() -> None:
    config = (
        "boot: order=scsi0;net0\n"
        "net0: virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,firewall=1\n"
        "net1: e1000=bc:24:11:00:00:01,bridge=vmbr1,tag=40\n"
        "net2: vmxnet3=BC:24:11:00:00:02,bridge=vmbr0\n"
        "net13: rtl8139=BC:24:11:00:00:03,bridge=vmbr0,link_down=1\n"
        "scsi0: local-zfs:vm-1-disk-0,size=64G\n"
    )
    assert parse_vm_config(config).macs == frozenset(
        {"BC:24:11:AA:BB:CC", "BC:24:11:00:00:01", "BC:24:11:00:00:02", "BC:24:11:00:00:03"}
    )


def test_what_is_not_a_net_device_line_carries_no_mac() -> None:
    config = (
        "description: moved from net0: virtio=BC:24:11:99:99:99\n"
        "#net0: virtio=BC:24:11:99:99:98,bridge=vmbr0\n"
        "netx: virtio=BC:24:11:99:99:97\n"
        "scsi0: local-zfs:vm-1-disk-0,size=64G\n"
    )
    assert parse_vm_config(config).macs == frozenset()


def test_the_macaddr_key_is_a_mac_too() -> None:
    assert parse_vm_config("net0: model=virtio,macaddr=BC:24:11:AA:BB:CC,bridge=vmbr0\n").macs == {"BC:24:11:AA:BB:CC"}


# --- qm listsnapshot -------------------------------------------------------------------------


def test_the_snapshot_tree_yields_every_name_but_the_current_marker() -> None:
    tree = (
        "`-> base                     2026-10-01 09:00:00     installed\n"
        "    `-> pre_winrepair        2026-10-24 10:00:00     before an in-place repair upgrade\n"
        "        `-> current                                  You are here!\n"
    )
    assert parse_snapshot_names(tree) == frozenset({"base", "pre_winrepair"})


def test_a_vm_without_snapshots_has_none() -> None:
    assert parse_snapshot_names("`-> current                                        You are here!\n") == frozenset()
    assert parse_snapshot_names("") == frozenset()
