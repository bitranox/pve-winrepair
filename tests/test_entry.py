"""Tests for the guest tool's entry point and its one-envelope-per-run contract.

Commands are injected through ``main(commands=...)``, the same seam the real modules plug into,
so these tests drive the real argument parsing, envelope building and exit-code mapping.
"""

from __future__ import annotations

import ast
import io
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import rtoml
from json_paths import at

from pve_winrepair_guest import envelope, winrepair_guest
from pve_winrepair_guest.envelope import Command, Outcome, Report, Skip

if TYPE_CHECKING:
    import argparse

GUEST = Path(__file__).resolve().parent.parent / "src" / "pve_winrepair_guest" / "winrepair_guest.py"


class _Echoed(Report):
    value: str


class _Said(Report):
    verdict: str


class _Named(Report):
    name: str


class _Nested(Report):
    """A payload holding a report and a tuple of reports, as PrepareReport holds its image and drives."""

    inner: Skip
    many: tuple[Skip, ...]


def _echo(args: argparse.Namespace) -> Outcome:
    return Outcome(ok=True, data=_Echoed(value=args.value), skipped=(Skip(item="extra", reason="not asked"),))


def _configure_echo(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--value", required=True)


def _refuse(_args: argparse.Namespace) -> Outcome:
    return Outcome(ok=False, data=_Said(verdict="NO"))


def _crash(_args: argparse.Namespace) -> Outcome:
    raise RuntimeError("Zugriff verweigert")


COMMANDS = (
    Command(name="echo", help="echo a value", run=_echo, configure=_configure_echo),
    Command(name="refuse", help="a gate that says no", run=_refuse),
    Command(name="crash", help="an internal error", run=_crash),
)


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = winrepair_guest.main(argv, commands=COMMANDS, stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def _one_envelope(stdout: str) -> dict[str, object]:
    lines = stdout.splitlines()
    assert len(lines) == 1, f"expected exactly one stdout line, got {lines!r}"
    parsed = json.loads(lines[0])
    assert set(parsed) == {"ok", "command", "data", "skipped"}
    return parsed


def test_ok_command_prints_one_envelope_and_exits_0() -> None:
    code, out, _ = _run(["echo", "--value", "C:\\upgrade"])

    assert code == 0
    assert _one_envelope(out) == {
        "ok": True,
        "command": "echo",
        "data": {"value": "C:\\upgrade"},
        "skipped": [{"item": "extra", "reason": "not asked"}],
    }


def test_json_flag_is_accepted_after_the_subcommand_arguments() -> None:
    code, out, _ = _run(["echo", "--value", "x", "--json"])

    assert code == 0
    assert _one_envelope(out)["data"] == {"value": "x"}


def test_json_flag_is_accepted_before_the_subcommand() -> None:
    code, out, _ = _run(["--json", "echo", "--value", "x"])

    assert code == 0
    assert _one_envelope(out)["command"] == "echo"


def test_refused_command_exits_1_with_ok_false() -> None:
    code, out, _ = _run(["refuse"])

    assert code == 1
    envelope_ = _one_envelope(out)
    assert envelope_["ok"] is False
    assert envelope_["data"] == {"verdict": "NO"}


def test_internal_error_exits_2_with_an_envelope_and_no_traceback_on_stdout() -> None:
    code, out, err = _run(["crash"])

    assert code == 2
    envelope_ = _one_envelope(out)
    assert envelope_["ok"] is False
    assert envelope_["command"] == "crash"
    assert envelope_["data"] == {"error": "Zugriff verweigert", "error_type": "RuntimeError"}
    assert "Traceback" not in out
    assert "Traceback" in err


def test_unknown_command_exits_2_with_a_usage_envelope() -> None:
    code, out, _ = _run(["nope"])

    assert code == 2
    envelope_ = _one_envelope(out)
    assert envelope_["ok"] is False
    assert at(envelope_, "data", "error_type") == "UsageError"


def test_missing_required_argument_exits_2_with_a_usage_envelope() -> None:
    code, out, _ = _run(["echo"])

    assert code == 2
    envelope_ = _one_envelope(out)
    assert envelope_["command"] == "echo"
    assert "--value" in str(envelope_["data"])


def test_no_command_exits_2_with_a_usage_envelope() -> None:
    code, out, _ = _run([])

    assert code == 2
    assert _one_envelope(out)["ok"] is False


def test_non_ascii_data_is_escaped_so_a_cp1252_console_cannot_crash_the_write() -> None:
    rendered = envelope.render(envelope.build("x", Outcome(ok=True, data=_Named(name="Gr\u00fc\u00dfe"))))

    assert rendered.isascii()
    assert json.loads(rendered)["data"] == {"name": "Gr\u00fc\u00dfe"}


def test_a_payload_is_rendered_as_the_report_subclass_it_is_nested_fields_included() -> None:
    # The envelope declares its data as the Report base; serialised by that declared type, every
    # payload would come out as {} while its keys-only checks still passed.
    data = _Nested(inner=Skip(item="D:", reason="locked"), many=(Skip(item="E:", reason="gone"),))

    rendered = json.loads(envelope.render(envelope.build("x", Outcome(ok=True, data=data))))

    assert at(rendered, "data", "inner", "reason") == "locked"
    assert rendered["data"]["many"] == [{"item": "E:", "reason": "gone"}]


def test_the_envelope_keeps_its_separators_and_key_order() -> None:
    # The host parsers and every recorded answer read json.dumps' ", " and ": " separators.
    rendered = envelope.render(envelope.build("x", Outcome(ok=False, data=_Said(verdict="NO"))))

    assert rendered == '{"ok": false, "command": "x", "data": {"verdict": "NO"}, "skipped": []}'


def test_header_pins_pywin32_for_windows_only() -> None:
    # A direct dependency (win32security, win32file, win32com) must not float on pwshpy's own
    # unpinned requirement; the marker keeps Linux tests and packing free of it.
    block = GUEST.read_text(encoding="utf-8").split("# ///")[1]
    line = next(raw for raw in block.splitlines() if raw.startswith("# dependencies"))
    dependencies = ast.literal_eval(line.split("=", 1)[1].strip())
    assert "pwshpy==1.6.0" in dependencies
    assert [d for d in dependencies if d.startswith("pywin32")] == ["pywin32==312; sys_platform == 'win32'"]


def test_header_pins_pydantic_to_the_locked_version() -> None:
    # The report models import pydantic directly, so it must not float on pwshpy's own unpinned
    # requirement either; pinning it to uv.lock keeps the packed tool on the pydantic the tests ran.
    block = GUEST.read_text(encoding="utf-8").split("# ///")[1]
    line = next(raw for raw in block.splitlines() if raw.startswith("# dependencies"))
    dependencies = ast.literal_eval(line.split("=", 1)[1].strip())
    lock = rtoml.load(GUEST.parents[2] / "uv.lock")
    locked = [p["version"] for p in lock["package"] if p["name"] == "pydantic"]
    assert len(locked) == 1
    assert [d for d in dependencies if d.startswith("pydantic")] == [f"pydantic=={locked[0]}"]


def test_default_commands_cover_every_feature_module() -> None:
    names = {command.name for command in winrepair_guest.default_commands()}

    assert {
        "detect-lp-defect",
        "drives",
        "verify-runners",
        "build",
        "staged-os",
        "servicing-active",
        "setup-alive",
        "state",
        "quiesce-wu",
        "restore-wu",
        "prepare",
        "launch",
        "upgrade-run",
    } <= names


@pytest.mark.parametrize("marker", ["STATE=DONE-OK reboot required to apply", "STATE=DONE-FAIL rc=0x1"])
def test_real_entry_reads_a_state_log_end_to_end(tmp_path: Path, marker: str) -> None:
    log = tmp_path / "upgrade-state.log"
    log.write_text(f"2026-10-21 10:00:00  launching\n2026-10-21 12:00:00  {marker}\n", encoding="utf-8")

    src = str(GUEST.parents[1])
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(filter(None, (src, os.environ.get("PYTHONPATH"))))}
    proc = subprocess.run(  # noqa: S603 - fixed argv: this interpreter running the guest entry on a test log
        [sys.executable, str(GUEST), "state", "--log", str(log), "--json"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        env=env,
    )

    assert proc.returncode == 0, proc.stderr
    data = _one_envelope(proc.stdout)["data"]
    assert at(data, "verdict") == marker.split(maxsplit=1)[0].removeprefix("STATE=")


def test_readme_lists_every_guest_subcommand() -> None:
    # The README's subcommand table is the operator's reference; a command added or renamed in
    # the tool must show up there too.
    readme = (GUEST.parents[2] / "README.md").read_text(encoding="utf-8")
    section = readme.split("## Guest tool subcommands", 1)[1].split("\n## ", 1)[0]
    listed = [row.split("|")[1].strip().strip("`").split()[0] for row in section.splitlines() if row.startswith("| `")]
    assert listed == [command.name for command in winrepair_guest.default_commands()]


def test_the_entry_runs_main_only_under_its_main_guard() -> None:
    # pwshpy's get_windows_update searches in a spawn child, which re-imports this script: without
    # the guard the child would run a whole command instead of the search.
    tree = ast.parse(GUEST.read_text(encoding="utf-8"))
    guards = [
        node
        for node in tree.body
        if isinstance(node, ast.If) and ast.unparse(node.test) in {"__name__ == '__main__'", '__name__ == "__main__"'}
    ]
    calls = [node for node in tree.body if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)]
    assert len(guards) == 1
    assert calls == []
