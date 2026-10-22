"""``pve-winrepair apply`` end to end: the receipt from ``[node] state_dir``, refusals, output and exit codes.

Every run goes through the real ``main()`` with the testing composition; the node is injected through
``build_testing(make_node=...)`` and answers from the fake guest the use-case tests use
(:func:`guest_fakes.apply_runner`).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from guest_fakes import (
    DONE_OK,
    GONE,
    GUEST_IP,
    FakePve,
    answer,
    apply_runner,
    cli_config,
    envelope_steps,
    json_envelope,
    run_cli,
)

from pve_winrepair.adapters.receipts import FileReceiptStore
from pve_winrepair.domain.envelope import WU_HELD_HINT
from pve_winrepair.domain.receipt import RepairReceipt

if TYPE_CHECKING:
    from pathlib import Path

    from guest_fakes import FakeRunner

APPLY = ["apply", "--vmid", "1", "--ip", GUEST_IP]
#: What a repair's prepare step measured for VM 1; the fake guest comes back on 26200.8973.
RECEIPT = RepairReceipt(
    vmid=1, image_build=26200, image_spbuild=8973, written_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
)


def _with_receipt(tmp_path: Path) -> dict[str, dict[str, object]]:
    """The CLI configuration, with VM 1's receipt already in its state directory."""
    config = cli_config(tmp_path)
    FileReceiptStore(tmp_path / "state").write(RECEIPT)
    return config


def _runner() -> FakeRunner:
    return apply_runner(FakePve(), GONE, DONE_OK)


def test_apply_json_with_a_receipt_is_verified(tmp_path: Path) -> None:
    run = run_cli([*APPLY, "--json"], _with_receipt(tmp_path), _runner())
    envelope = json_envelope(run.stdout)
    assert run.exit_code == 0
    assert set(envelope) == {"ok", "command", "vmid", "verdict", "steps"}
    assert (envelope["ok"], envelope["command"], envelope["vmid"], envelope["verdict"]) == (
        True,
        "apply",
        1,
        "VERIFIED",
    )
    steps = envelope_steps(envelope)
    receipt = next(step for step in steps if step["step"] == "receipt")
    assert (receipt["path"], receipt["want"]) == (str(tmp_path / "state" / "receipt-1.json"), "26200.8973")
    assert steps[-1]["step"] == "remove_profile_copy"
    assert "[ok ] verify_build" in run.stderr


def test_apply_without_json_prints_one_verdict_line(tmp_path: Path) -> None:
    run = run_cli(APPLY, _with_receipt(tmp_path), _runner())
    assert (run.exit_code, run.stdout) == (0, "vm 1: VERIFIED\n")


def test_apply_without_a_receipt_is_refused_before_any_call(tmp_path: Path) -> None:
    runner = _runner()
    run = run_cli([*APPLY, "--json"], cli_config(tmp_path), runner)
    envelope = json_envelope(run.stdout)
    assert (run.exit_code, envelope["ok"], envelope["verdict"]) == (1, False, "ERROR")
    assert str(envelope_steps(envelope)[-1]["message"]).startswith(
        f"no repair receipt for VM 1 at {tmp_path / 'state' / 'receipt-1.json'} - "
    )
    assert runner.calls == []


def test_apply_minutes_option_is_how_long_the_guest_may_take_to_come_back(tmp_path: Path) -> None:
    run = run_cli([*APPLY, "--apply-minutes", "0", "--json"], _with_receipt(tmp_path), _runner())
    message = str(envelope_steps(json_envelope(run.stdout))[-1]["message"])
    assert run.exit_code == 1
    assert message.startswith("guest did not answer ssh within 0.0 min")


def test_apply_with_a_state_dir_that_is_a_regular_file_is_refused_before_any_call(tmp_path: Path) -> None:
    config = cli_config(tmp_path)
    blocker = tmp_path / "state-is-a-file"
    blocker.write_text("", encoding="utf-8")
    config["node"]["state_dir"] = str(blocker)
    runner = _runner()
    run = run_cli([*APPLY, "--json"], config, runner)
    envelope = json_envelope(run.stdout)
    assert (run.exit_code, envelope["verdict"]) == (1, "ERROR")
    assert str(envelope_steps(envelope)[-1]["message"]) == (
        f"[node] state_dir {blocker} cannot be a directory: {blocker} is not a directory - {WU_HELD_HINT}"
    )
    assert runner.calls == []


def test_apply_with_an_unconfigured_ssh_key_is_refused_before_any_call(tmp_path: Path) -> None:
    config = _with_receipt(tmp_path)
    config["ssh"]["key"] = ""
    runner = _runner()
    run = run_cli(APPLY, config, runner)
    assert (run.exit_code, run.stdout) == (1, "vm 1: ERROR\n")
    assert "[ssh] key is not configured" in run.stderr
    assert runner.calls == []


def test_apply_driver_tool_mismatch_exits_2_with_empty_stdout(tmp_path: Path) -> None:
    runner = _runner()
    runner.replies["build"] = [answer("build", {"CurrentBuild": "26200", "UBR": 8973})]
    run = run_cli(APPLY, _with_receipt(tmp_path), runner)
    assert (run.exit_code, run.stdout) == (2, "")
    assert "[FAIL] internal" in run.stderr
