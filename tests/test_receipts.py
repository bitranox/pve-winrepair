"""Tests for the repair receipt and the file store that keeps one per VM in ``[node] state_dir``.

The store is exercised on real files under ``tmp_path``: what apply trusts is what a later process
reads back from disk, so a round trip through the filesystem is the contract.
"""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from pydantic import BaseModel, ConfigDict

from pve_winrepair.adapters.receipts import FileReceiptStore, ReceiptError
from pve_winrepair.domain.envelope import GuestProtocolError
from pve_winrepair.domain.guest_answers import BuildAnswer
from pve_winrepair.domain.receipt import BuildPair, GuestBuild, RepairReceipt

if TYPE_CHECKING:
    from pathlib import Path

WRITTEN_AT = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def _receipt(vmid: int = 1, spbuild: int = 8973) -> RepairReceipt:
    return RepairReceipt(
        vmid=vmid,
        image_build=26200,
        image_spbuild=spbuild,
        build_before=BuildPair(build=26200, ubr=7462),
        install_date_before=1761206400,
        written_at=WRITTEN_AT,
    )


def test_expected_build_joins_build_and_spbuild() -> None:
    assert _receipt().expected_build() == "26200.8973"


def test_a_receipt_refuses_an_unknown_field() -> None:
    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        RepairReceipt.model_validate({**_receipt().model_dump(), "ubr": 1})


def test_same_build_compares_the_image_with_the_build_before() -> None:
    assert _receipt().same_build() is False
    assert _receipt().model_copy(update={"build_before": (26200, 8973)}).same_build() is True
    assert _receipt().model_copy(update={"build_before": (26100, 8973)}).same_build() is False


@pytest.mark.parametrize("missing", ["build_before", "install_date_before"])
def test_a_receipt_without_a_field_apply_needs_is_refused(tmp_path: Path, missing: str) -> None:
    store = FileReceiptStore(tmp_path)
    store.path(1).write_text(_receipt().model_dump_json(exclude={missing}), encoding="utf-8")
    with pytest.raises(ReceiptError, match=f"is not valid: {missing}: Field required"):
        store.read(1)


# The object form: a NamedTuple field would build itself from one, but the 1.0.0 format is an array.
@pytest.mark.parametrize(
    "build_before",
    [[26200], [26200, 1, 2], [26200, "7462"], [26200, -1], [True, 1], {"build": 26200, "ubr": 1}],
    ids=str,
)
def test_a_build_before_that_is_not_two_counts_is_refused(tmp_path: Path, build_before: object) -> None:
    store = FileReceiptStore(tmp_path)
    document = _receipt().model_dump(mode="json") | {"build_before": build_before}
    store.path(1).write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ReceiptError, match="is not valid: build_before"):
        store.read(1)


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


def test_a_receipt_file_replaces_the_per_vm_name(tmp_path: Path) -> None:
    store = FileReceiptStore(tmp_path / "unused", tmp_path / "mine" / "r.json")
    assert store.path(7) == tmp_path / "mine" / "r.json"
    store.write(_receipt(vmid=7))
    assert store.read(7) == _receipt(vmid=7)
    assert not (tmp_path / "unused").exists()


def test_a_receipt_file_of_another_vm_is_still_refused(tmp_path: Path) -> None:
    file = tmp_path / "r.json"
    FileReceiptStore(tmp_path, file).write(_receipt(vmid=7))
    with pytest.raises(ReceiptError, match="is for VM 7, not VM 8"):
        FileReceiptStore(tmp_path, file).read(8)


def test_other_vm_names_the_vm_a_receipt_file_of_another_vm_holds(tmp_path: Path) -> None:
    file = tmp_path / "r.json"
    FileReceiptStore(tmp_path, file).write(_receipt(vmid=7))
    assert FileReceiptStore(tmp_path, file).other_vm(8) == 7


def test_other_vm_is_none_without_a_file_and_for_the_same_vm(tmp_path: Path) -> None:
    store = FileReceiptStore(tmp_path, tmp_path / "r.json")
    assert store.other_vm(8) is None
    store.write(_receipt(vmid=8))
    assert store.other_vm(8) is None


NO_RECEIPTS = pytest.mark.parametrize(
    "content",
    [b"{not json", b"\xff\xfe{", b'{"vmid": 7}', b'[node]\nhost = "pve1"\n'],
    ids=["json", "utf8", "fields", "toml"],
)


@NO_RECEIPTS
def test_other_vm_is_none_for_a_per_vm_file_that_is_no_valid_receipt(tmp_path: Path, content: bytes) -> None:
    # The store's own receipt-<vmid>.json names no VM whose receipt could be lost: the repair removes it later.
    store = FileReceiptStore(tmp_path)
    store.path(8).write_bytes(content)
    assert store.other_vm(8) is None


@NO_RECEIPTS
def test_other_vm_refuses_a_receipt_file_given_that_is_no_valid_receipt(tmp_path: Path, content: bytes) -> None:
    # An operator-named file may be anything (a config, a key): it is never treated as a stale receipt.
    file = tmp_path / "config.toml"
    file.write_bytes(content)
    with pytest.raises(ReceiptError) as caught:
        FileReceiptStore(tmp_path, file).other_vm(8)
    assert str(caught.value).startswith(f"--receipt {file} is not a repair receipt, so it is left alone - ")
    assert file.read_bytes() == content


@NO_RECEIPTS
def test_delete_refuses_a_receipt_file_given_that_is_no_valid_receipt(tmp_path: Path, content: bytes) -> None:
    file = tmp_path / "config.toml"
    file.write_bytes(content)
    with pytest.raises(ReceiptError, match=r"is not a repair receipt, so it is left alone"):
        FileReceiptStore(tmp_path, file).delete(8)
    assert file.read_bytes() == content


@pytest.mark.os_posix
def test_other_vm_refuses_a_receipt_file_given_that_cannot_be_read(tmp_path: Path) -> None:
    file = tmp_path / "r.json"
    FileReceiptStore(tmp_path, file).write(_receipt(vmid=8))
    file.chmod(0o000)
    try:
        if os.access(file, os.R_OK):
            pytest.skip("running as root: a 0000 file is still readable")
        with pytest.raises(ReceiptError, match=r"^--receipt .* is not a repair receipt, so it is left alone - "):
            FileReceiptStore(tmp_path, file).other_vm(8)
    finally:
        file.chmod(0o600)
    assert FileReceiptStore(tmp_path, file).read(8) == _receipt(vmid=8)


def test_delete_removes_a_receipt_file_given_that_holds_a_receipt(tmp_path: Path) -> None:
    file = tmp_path / "r.json"
    store = FileReceiptStore(tmp_path / "unused", file)
    store.write(_receipt(vmid=8))
    store.delete(8)
    assert not file.exists()
    store.delete(8)  # absent: still fine


def test_other_vm_is_none_below_a_regular_file(tmp_path: Path) -> None:
    blocker = tmp_path / "a-file"
    blocker.write_text("", encoding="utf-8")
    assert FileReceiptStore(blocker).other_vm(1) is None


def test_other_vm_is_none_for_a_file_that_cannot_be_read(tmp_path: Path) -> None:
    store = FileReceiptStore(tmp_path)
    store.path(1).mkdir()  # a directory where the receipt goes: reading it fails
    assert store.other_vm(1) is None


@pytest.mark.os_posix
def test_the_directory_created_for_a_receipt_file_is_0700(tmp_path: Path) -> None:
    file = tmp_path / "var" / "mine" / "r.json"
    FileReceiptStore(tmp_path / "unused", file).write(_receipt())
    assert stat.S_IMODE(file.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(file.stat().st_mode) == 0o600


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
    assert str(caught.value) == (
        f"the repair receipt {store.path(1)} is not valid: image_spbuild: Field required; "
        "build_before: Field required; install_date_before: Field required"
    )


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


#: A receipt exactly as pve-winrepair 1.0.0 writes it; receipts in this form exist on nodes.
RECEIPT_1_0_0 = (
    '{\n  "vmid": 1,\n  "image_build": 26200,\n  "image_spbuild": 8973,\n  "build_before": [\n    26200,\n'
    '    7462\n  ],\n  "install_date_before": 1761206400,\n  "written_at": "2026-01-02T03:04:05Z"\n}\n'
)


def test_a_receipt_written_by_1_0_0_loads_and_is_rewritten_byte_identical(tmp_path: Path) -> None:
    store = FileReceiptStore(tmp_path)
    store.path(1).write_text(RECEIPT_1_0_0, encoding="utf-8")
    receipt = store.read(1)
    assert receipt == _receipt()
    assert receipt is not None
    store.write(receipt)
    assert store.path(1).read_text(encoding="utf-8") == RECEIPT_1_0_0


class _PairHolder(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    build_before: BuildPair


def test_a_build_pair_field_keeps_the_receipt_s_json_array() -> None:
    holder = _PairHolder(build_before=BuildPair(build=26200, ubr=7462))
    assert holder.model_dump_json() == '{"build_before":[26200,7462]}'
    assert _PairHolder.model_validate_json('{"build_before":[26200,7462]}').build_before.ubr == 7462


def _build_answer(current: str) -> BuildAnswer:
    return BuildAnswer(current_build=current, ubr=7462, build=f"{current}.7462", install_date=1761206400)


def test_the_guest_build_is_read_from_the_build_answer() -> None:
    build = GuestBuild.from_answer(_build_answer("26200"))
    assert build == GuestBuild(build=26200, ubr=7462, install_date=1761206400)
    assert (build.text, build.pair) == ("26200.7462", BuildPair(build=26200, ubr=7462))


@pytest.mark.parametrize(
    "current", ["", "26200a", "1" * 10, "2" + chr(0x0662)], ids=["empty", "suffix", "huge", "arabic"]
)
def test_a_current_build_that_is_no_ascii_number_is_a_protocol_error(current: str) -> None:
    with pytest.raises(GuestProtocolError, match="is not a number"):
        GuestBuild.from_answer(_build_answer(current))
