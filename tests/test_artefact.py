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
    "winrepair_guest",
    "wu",
)


def _committed() -> str:
    """The real checkout's packed tool.

    Never kept in a test's local nor asserted on whole: pytest prints a failing assert's operands
    and, with ``-l``, a test's locals; the artefact's tail can carry a private token (a refused
    block appended at its end). Tests assert on booleans, counts and member names instead.
    """
    __tracebackhide__ = True
    return (pack_guest.PROJECT / pack_guest.ARTEFACT).read_bytes().decode("utf-8")


def _payload_against_sources() -> tuple[list[str], bool, list[str]]:
    """(sorted member names, whether the package's __init__ is empty, members that differ from src)."""
    __tracebackhide__ = True  # its locals hold the decoded members
    members = pack_guest.decode_payload(_committed())
    src = pack_guest.PROJECT / "src"
    differing = [
        name
        for name, data in members.items()
        if name.startswith("pve_winrepair_guest/")
        and not ((src / name).is_file() and data == (src / name).read_bytes())
    ]
    return sorted(members), members.get("pve_winrepair_guest/__init__.py") == b"", differing


@pytest.mark.os_agnostic
def test_the_committed_tool_is_a_fresh_pack_of_the_guest_sources(tmp_path: Path) -> None:
    fresh = tmp_path / "fresh.ps1"
    pack_guest.pack(pack_guest.PROJECT, fresh)
    is_fresh = pack_guest.same_pack(_committed(), fresh.read_bytes().decode("utf-8"))
    assert is_fresh, "the committed guest tool is stale: run `make custom pack` and commit the .ps1"


@pytest.mark.os_agnostic
def test_the_payload_is_the_shim_and_every_guest_module_with_an_empty_init() -> None:
    # A member's bytes are compared in a hidden helper: a failing == would print the stale member.
    names, empty_init, differing = _payload_against_sources()
    expected = ["__pwshpy_pack_main__.py", *(f"pve_winrepair_guest/{m}.py" for m in sorted(GUEST_MODULES))]
    assert names == sorted(expected)
    assert empty_init
    assert differing == []
