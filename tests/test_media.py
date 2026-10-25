"""Tests for where a repair's installation media come from: :class:`LocalMedia`, a directory on this machine.

The copy goes through the guest's own scp on the ``FakeRunner`` seam, so these tests see the argv
and the timeout the real transfer would get.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from guest_fakes import FakeRunner, Reply, make_guest

from pve_winrepair.adapters.media import LocalMedia

if TYPE_CHECKING:
    from pathlib import Path


def test_local_media_copies_every_entry_in_name_order(tmp_path: Path) -> None:
    for name in ("sources", "boot", "setup.exe"):
        (tmp_path / name).touch()
    runner = FakeRunner().on("scp", Reply(0))
    LocalMedia(tmp_path).copy_into(make_guest(runner), "D:\\upgrade\\", timeout=5400)
    assert runner.calls[0][-4:-1] == [str(tmp_path / n) for n in ("boot", "setup.exe", "sources")]
    assert runner.timeouts == [5400]


def test_local_media_refuses_a_missing_and_an_empty_directory(tmp_path: Path) -> None:
    assert LocalMedia(tmp_path / "gone").check() == f"media directory missing: {tmp_path / 'gone'}"
    assert LocalMedia(tmp_path).check() == f"media directory is empty: {tmp_path}"
    (tmp_path / "setup.exe").touch()
    assert LocalMedia(tmp_path).check() is None
