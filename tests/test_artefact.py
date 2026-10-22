"""The committed guest tool is a fresh pack of the current guest sources.

These tests read the REAL checkout, not a copy: they are the gate's guard that nobody changed a
guest module without running ``make custom pack``. The comparison goes through ``same_pack``
(decoded members plus wrapper text), never raw bytes, because the compressed payload depends on the
zlib build of the packing host. A missing pwshpy makes ``pack`` raise, so the stale test FAILS rather
than skips: a skip would let a stale artefact through the gate unseen.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pack_guest
import pytest

if TYPE_CHECKING:
    from pathlib import Path

GUEST_MODULES = (
    "__init__",
    "envelope",
    "evtlog",
    "lockdown",
    "probes",
    "upgrade",
    "wim",
    "winrepair_guest",
    "wu",
)


def _committed() -> str:
    return (pack_guest.PROJECT / pack_guest.ARTEFACT).read_bytes().decode("utf-8")


@pytest.mark.os_agnostic
def test_the_committed_tool_is_a_fresh_pack_of_the_guest_sources(tmp_path: Path) -> None:
    fresh = tmp_path / "fresh.ps1"
    pack_guest.pack(pack_guest.PROJECT, fresh)
    assert pack_guest.same_pack(_committed(), fresh.read_bytes().decode("utf-8")), (
        "the committed guest tool is stale: run `make custom pack` and commit the .ps1"
    )


@pytest.mark.os_agnostic
def test_the_payload_is_the_shim_the_empty_init_and_the_eight_modules() -> None:
    members = pack_guest.decode_payload(_committed())
    expected = ["__pwshpy_pack_main__.py", *(f"pve_winrepair_guest/{m}.py" for m in sorted(GUEST_MODULES))]
    assert sorted(members) == sorted(expected)
    assert members["pve_winrepair_guest/__init__.py"] == b""
    src = pack_guest.PROJECT / "src"
    for name, data in members.items():
        if name.startswith("pve_winrepair_guest/"):
            assert data == (src / name).read_bytes(), name
