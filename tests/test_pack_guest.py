"""Tests for scripts/pack_guest.py: pack, check, and its exit codes.

Every test packs into its own project copy under ``tmp_path`` (the real guest sources, packed by
the real ``pwshpy`` packer), except the missing-pwshpy test, which runs the script against the real
project because pwshpy's absence stops it before it reads or writes anything.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pack_guest
import pytest

PROJECT = pack_guest.PROJECT
GUEST = Path("src") / "pve_winrepair_guest"


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A project root with the real guest sources and a fresh committed artefact."""
    shutil.copytree(PROJECT / GUEST, tmp_path / GUEST, ignore=shutil.ignore_patterns("__pycache__"))
    (tmp_path / pack_guest.ARTEFACT).parent.mkdir(parents=True)
    assert pack_guest.main([], project=tmp_path) == 0
    return tmp_path


def _artefact_text(project: Path) -> str:
    return (project / pack_guest.ARTEFACT).read_bytes().decode("utf-8")


def _append(path: Path, line: str) -> None:
    with path.open("ab") as handle:
        handle.write(line.encode("utf-8"))


# --- write ------------------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_write_repacks_a_stale_artefact(project: Path, tmp_path: Path) -> None:
    _append(project / GUEST / "wim.py", "# a change\n")
    assert pack_guest.main([], project=project) == 0
    expected = tmp_path / "expected.ps1"
    pack_guest.pack(project, expected)
    assert pack_guest.same_pack(_artefact_text(project), expected.read_bytes().decode("utf-8"))
    assert b"# a change" in pack_guest.decode_payload(_artefact_text(project))["pve_winrepair_guest/wim.py"]


@pytest.mark.os_agnostic
def test_write_reports_the_artefact_and_its_sha256(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    capsys.readouterr()
    assert pack_guest.main([], project=project) == 0
    out = capsys.readouterr().out
    assert out.startswith(f"packed {pack_guest.ARTEFACT.as_posix()} sha256=")
    assert len(out.strip().rsplit("=", 1)[1]) == 64


# --- check ------------------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_check_passes_when_everything_is_in_sync(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    capsys.readouterr()
    assert pack_guest.main(["--check"], project=project) == 0
    assert "up to date" in capsys.readouterr().out


@pytest.mark.os_agnostic
def test_check_fails_when_the_guest_source_changed_after_packing(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    packed = (project / pack_guest.ARTEFACT).read_bytes()
    _append(project / GUEST / "wim.py", "# a change after the last pack\n")
    capsys.readouterr()
    assert pack_guest.main(["--check"], project=project) == 1
    assert f"{pack_guest.ARTEFACT.as_posix()} is stale" in capsys.readouterr().err
    # --check writes nothing, not even the artefact.
    assert (project / pack_guest.ARTEFACT).read_bytes() == packed


@pytest.mark.os_agnostic
def test_check_fails_on_a_stale_artefact_alone(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _append(project / pack_guest.ARTEFACT, "# edited by hand\n")
    capsys.readouterr()
    assert pack_guest.main(["--check"], project=project) == 1
    assert "is stale" in capsys.readouterr().err


@pytest.mark.os_agnostic
def test_check_leaves_a_stale_artefact_byte_identical(project: Path) -> None:
    _append(project / pack_guest.ARTEFACT, "# stale\n")
    before = (project / pack_guest.ARTEFACT).read_bytes()
    assert pack_guest.main(["--check"], project=project) == 1
    assert (project / pack_guest.ARTEFACT).read_bytes() == before


@pytest.mark.os_agnostic
def test_check_calls_a_missing_artefact_stale(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (project / pack_guest.ARTEFACT).unlink()
    capsys.readouterr()
    assert pack_guest.main(["--check"], project=project) == 1
    assert "is stale" in capsys.readouterr().err
    assert not (project / pack_guest.ARTEFACT).exists()


# --- exit codes: 1 is drift, 2 is an error ----------------------------------------------------


@pytest.mark.os_agnostic
def test_a_pack_failure_is_an_error(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (project / GUEST / "winrepair_guest.py").write_text("import (\n", encoding="utf-8")
    capsys.readouterr()
    assert pack_guest.main(["--check"], project=project) == 2
    err = capsys.readouterr().err
    assert err.startswith("pack failed: ")
    assert err.count("\n") == 1
    assert "Traceback" not in err


@pytest.mark.os_agnostic
def test_a_failed_write_leaves_the_artefact_and_no_temp_file(project: Path) -> None:
    before = (project / pack_guest.ARTEFACT).read_bytes()
    (project / GUEST / "winrepair_guest.py").write_text("import (\n", encoding="utf-8")
    assert pack_guest.main([], project=project) == 2
    assert (project / pack_guest.ARTEFACT).read_bytes() == before
    assert sorted(p.name for p in (project / pack_guest.ARTEFACT).parent.iterdir()) == [pack_guest.ARTEFACT.name]


@pytest.mark.os_agnostic
def test_an_unknown_flag_is_refused_by_the_parser(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as raised:
        pack_guest.main(["--chek"])
    assert raised.value.code == 2
    assert "unrecognized arguments: --chek" in capsys.readouterr().err


@pytest.mark.os_agnostic
def test_a_missing_pwshpy_is_an_error_not_drift() -> None:
    # -S: no site-packages, so pwshpy cannot be imported - the state of a bare interpreter.
    artefact = PROJECT / pack_guest.ARTEFACT
    before = artefact.read_bytes()
    argv = [sys.executable, "-S", str(PROJECT / "scripts" / "pack_guest.py"), "--check"]
    proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", check=False)  # noqa: S603 - fixed argv
    assert proc.returncode == 2, proc.stderr
    assert proc.stderr.startswith("pwshpy ")
    assert "Traceback" not in proc.stderr
    assert artefact.read_bytes() == before


# --- the comparison ---------------------------------------------------------------------------


def _committed() -> str:
    return (PROJECT / pack_guest.ARTEFACT).read_bytes().decode("utf-8")


@pytest.mark.os_agnostic
def test_the_committed_artefact_decodes_to_the_shim_and_the_guest_package() -> None:
    members = pack_guest.decode_payload(_committed())
    guest = sorted(p.name for p in (PROJECT / GUEST).glob("*.py"))
    assert sorted(members) == ["__pwshpy_pack_main__.py", *(f"pve_winrepair_guest/{name}" for name in guest)]
    assert members["pve_winrepair_guest/__init__.py"] == b""


@pytest.mark.os_agnostic
def test_same_pack_holds_for_identical_text() -> None:
    assert pack_guest.same_pack(_committed(), _committed())


@pytest.mark.os_agnostic
def test_same_pack_sees_a_member_edit(project: Path, tmp_path: Path) -> None:
    _append(project / GUEST / "wim.py", "# a member edit\n")
    edited = tmp_path / "edited.ps1"
    pack_guest.pack(project, edited)
    assert not pack_guest.same_pack(_artefact_text(project), edited.read_bytes().decode("utf-8"))


@pytest.mark.os_agnostic
def test_same_pack_sees_a_wrapper_edit() -> None:
    assert not pack_guest.same_pack(_committed(), _committed() + "# x\n")


@pytest.mark.os_agnostic
def test_same_pack_is_false_when_a_side_does_not_decode() -> None:
    assert not pack_guest.same_pack(_committed(), "no payload here\n")


@pytest.mark.os_agnostic
def test_wrapper_without_payload_drops_the_payload_and_the_sha_line() -> None:
    wrapper = pack_guest.wrapper_without_payload(_committed())
    assert "$PwshPyPayload = @'" not in wrapper
    assert "$PwshPySha = '" not in wrapper
    assert len(wrapper) < len(_committed()) // 4


@pytest.mark.os_agnostic
def test_decode_payload_refuses_a_wrong_sha() -> None:
    text = _committed()
    marker = "$PwshPySha = '"
    at = text.index(marker) + len(marker)
    flipped = "1" if text[at] != "1" else "2"
    with pytest.raises(ValueError, match="sha256"):
        pack_guest.decode_payload(text[:at] + flipped + text[at + 1 :])


@pytest.mark.os_agnostic
def test_decode_payload_refuses_text_without_a_payload() -> None:
    with pytest.raises(ValueError, match="payload"):
        pack_guest.decode_payload("Write-Output 'hello'\n")
