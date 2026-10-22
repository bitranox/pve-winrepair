"""Tests for the repair receipt and the file store that keeps one per VM in ``[node] state_dir``.

The store is exercised on real files under ``tmp_path``: what apply trusts is what a later process
reads back from disk, so a round trip through the filesystem is the contract.
"""

from __future__ import annotations

import stat
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from pve_winrepair.adapters.receipts import FileReceiptStore, ReceiptError
from pve_winrepair.domain.receipt import RepairReceipt

if TYPE_CHECKING:
    from pathlib import Path

WRITTEN_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _receipt(vmid: int = 1, spbuild: int = 8973) -> RepairReceipt:
    return RepairReceipt(vmid=vmid, image_build=26200, image_spbuild=spbuild, written_at=WRITTEN_AT)


def test_expected_build_joins_build_and_spbuild() -> None:
    assert _receipt().expected_build() == "26200.8973"


def test_a_receipt_refuses_an_unknown_field() -> None:
    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        RepairReceipt.model_validate({**_receipt().model_dump(), "ubr": 1})


def test_write_then_read_round_trips(tmp_path: Path) -> None:
    store = FileReceiptStore(tmp_path / "state")
    written = store.write(_receipt())
    assert written == store.path(1) == tmp_path / "state" / "receipt-1.json"
    assert store.read(1) == _receipt()


def test_a_fresh_store_reads_back_what_another_store_wrote(tmp_path: Path) -> None:
    FileReceiptStore(tmp_path).write(_receipt())
    read = FileReceiptStore(tmp_path).read(1)
    assert read == _receipt()
    assert read is not None
    assert read.written_at == WRITTEN_AT


def test_a_second_write_replaces_the_first_and_leaves_no_temp_file(tmp_path: Path) -> None:
    store = FileReceiptStore(tmp_path)
    store.write(_receipt(spbuild=8973))
    store.write(_receipt(spbuild=9000))
    assert store.read(1) == _receipt(spbuild=9000)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["receipt-1.json"]


@pytest.mark.os_posix
def test_the_file_is_0600_and_a_created_directory_0700(tmp_path: Path) -> None:
    state_dir = tmp_path / "var" / "state"
    FileReceiptStore(state_dir).write(_receipt())
    assert stat.S_IMODE(state_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((state_dir / "receipt-1.json").stat().st_mode) == 0o600


@pytest.mark.os_posix
def test_an_existing_directory_keeps_its_mode(tmp_path: Path) -> None:
    tmp_path.chmod(0o750)
    FileReceiptStore(tmp_path).write(_receipt())
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o750


def test_read_of_an_absent_vmid_is_none(tmp_path: Path) -> None:
    assert FileReceiptStore(tmp_path / "never-created").read(1) is None


def test_a_receipt_for_one_vm_is_never_returned_for_another(tmp_path: Path) -> None:
    store = FileReceiptStore(tmp_path)
    store.write(_receipt(vmid=1))
    assert store.read(2) is None


def test_a_receipt_file_naming_another_vm_is_refused(tmp_path: Path) -> None:
    store = FileReceiptStore(tmp_path)
    store.write(_receipt(vmid=1))
    store.path(1).replace(store.path(2))
    with pytest.raises(ReceiptError) as caught:
        store.read(2)
    assert str(caught.value) == f"the repair receipt {store.path(2)} is for VM 1, not VM 2"


def test_invalid_json_raises_naming_the_path(tmp_path: Path) -> None:
    store = FileReceiptStore(tmp_path)
    store.path(1).write_text("{not json", encoding="utf-8")
    with pytest.raises(ReceiptError) as caught:
        store.read(1)
    assert str(caught.value).startswith(f"the repair receipt {store.path(1)} is not valid: ")
    assert "Invalid JSON" in str(caught.value)


def test_a_receipt_missing_a_field_raises_naming_the_field(tmp_path: Path) -> None:
    store = FileReceiptStore(tmp_path)
    store.path(1).write_text('{"vmid": 1, "image_build": 26200, "written_at": "2026-01-02T03:04:05Z"}', "utf-8")
    with pytest.raises(ReceiptError) as caught:
        store.read(1)
    assert str(caught.value) == f"the repair receipt {store.path(1)} is not valid: image_spbuild: Field required"


def test_a_receipt_that_is_not_utf8_raises_naming_the_path(tmp_path: Path) -> None:
    store = FileReceiptStore(tmp_path)
    store.path(1).write_bytes(b"\xff\xfe{")
    with pytest.raises(ReceiptError, match="cannot read the repair receipt"):
        store.read(1)


def test_a_state_dir_that_is_a_file_cannot_be_written(tmp_path: Path) -> None:
    blocker = tmp_path / "state"
    blocker.write_text("", encoding="utf-8")
    store = FileReceiptStore(blocker)
    with pytest.raises(ReceiptError) as caught:
        store.write(_receipt())
    assert str(caught.value).startswith(f"cannot write the repair receipt {store.path(1)}: ")


def test_delete_removes_the_file(tmp_path: Path) -> None:
    store = FileReceiptStore(tmp_path)
    store.write(_receipt())
    store.delete(1)
    assert store.read(1) is None
    assert not store.path(1).exists()


def test_delete_of_an_absent_receipt_is_a_no_op(tmp_path: Path) -> None:
    store = FileReceiptStore(tmp_path / "never-created")
    store.delete(1)
    assert not (tmp_path / "never-created").exists()


def test_delete_leaves_another_vms_receipt_alone(tmp_path: Path) -> None:
    store = FileReceiptStore(tmp_path)
    store.write(_receipt(vmid=1))
    store.write(_receipt(vmid=2))
    store.delete(1)
    assert store.read(1) is None
    assert store.read(2) == _receipt(vmid=2)


def test_delete_that_cannot_remove_raises_naming_the_path(tmp_path: Path) -> None:
    store = FileReceiptStore(tmp_path)
    store.path(1).mkdir()
    with pytest.raises(ReceiptError) as caught:
        store.delete(1)
    assert str(caught.value).startswith(f"cannot remove the repair receipt {store.path(1)}: ")


def test_a_state_dir_that_is_a_file_holds_no_receipt_to_read_or_delete(tmp_path: Path) -> None:
    # A path through a regular file can never name a receipt (ENOTDIR), so there is none to trust
    # and none left to remove; writing there is what fails.
    blocker = tmp_path / "state"
    blocker.write_text("", encoding="utf-8")
    store = FileReceiptStore(blocker)
    assert store.read(1) is None
    store.delete(1)
    assert blocker.is_file()


def test_a_write_that_cannot_replace_the_file_leaves_no_temporary_file(tmp_path: Path) -> None:
    store = FileReceiptStore(tmp_path)
    store.path(1).mkdir()  # a directory where the receipt goes: the final move fails
    with pytest.raises(ReceiptError) as caught:
        store.write(_receipt())
    assert str(caught.value).startswith(f"cannot write the repair receipt {store.path(1)}: ")
    assert [p.name for p in tmp_path.iterdir()] == ["receipt-1.json"]
