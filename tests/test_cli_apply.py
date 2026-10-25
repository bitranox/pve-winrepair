"""``pve-winrepair apply`` end to end: the receipt from ``[node] state_dir``, refusals, output and exit codes.

Every run goes through the real ``main()`` with the testing composition; the node is injected through
``build_testing(make_node=...)`` and answers from the fake guest the use-case tests use
(:func:`guest_fakes.apply_runner`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from guest_fakes import (
    ALIVE,
    DONE_OK,
    GONE,
    GUEST_IP,
    NEEDS_A_POSIX_STATE_DIR,
    NODE_LINK,
    RECEIPT,
    FakePve,
    FakeRunner,
    Reply,
    answer,
    apply_runner,
    cli_config,
    envelope_steps,
    json_envelope,
    run_cli,
)

from pve_winrepair.adapters.receipts import FileReceiptStore
from pve_winrepair.domain.envelope import WU_HELD_HINT

if TYPE_CHECKING:
    from pathlib import Path

APPLY = ["apply", "--vmid", "1", "--ip", GUEST_IP]


def _with_receipt(tmp_path: Path) -> dict[str, dict[str, object]]:
    """The CLI configuration, with VM 1's receipt already in its state directory."""
    config = cli_config(tmp_path)
    FileReceiptStore(tmp_path / "state").write(RECEIPT)
    return config


def _runner() -> FakeRunner:
    return apply_runner(FakePve(), GONE, DONE_OK)


@NEEDS_A_POSIX_STATE_DIR
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


@NEEDS_A_POSIX_STATE_DIR
def test_apply_reads_the_receipt_from_the_file_given(tmp_path: Path) -> None:
    file = tmp_path / "elsewhere" / "r.json"
    FileReceiptStore(tmp_path / "unused", file).write(RECEIPT)
    run = run_cli([*APPLY, "--receipt", str(file), "--json"], cli_config(tmp_path), _runner())
    envelope = json_envelope(run.stdout)
    assert (run.exit_code, envelope["verdict"]) == (0, "VERIFIED")
    receipt = next(step for step in envelope_steps(envelope) if step["step"] == "receipt")
    assert receipt["path"] == str(file)


@NEEDS_A_POSIX_STATE_DIR
def test_apply_refuses_a_receipt_file_below_a_regular_file_before_any_call(tmp_path: Path) -> None:
    blocker = tmp_path / "a-file"
    blocker.write_text("", encoding="utf-8")
    runner = _runner()
    run = run_cli([*APPLY, "--receipt", str(blocker / "r.json"), "--json"], cli_config(tmp_path), runner)
    envelope = json_envelope(run.stdout)
    assert (run.exit_code, envelope["verdict"]) == (1, "ERROR")
    assert str(envelope_steps(envelope)[-1]["message"]) == (
        f"--receipt {blocker / 'r.json'}: directory {blocker} cannot be a directory: {blocker} is not a directory"
        f" - {WU_HELD_HINT}"
    )
    assert runner.calls == []


@NEEDS_A_POSIX_STATE_DIR
def test_a_live_run_is_refused_with_its_verdict_written_as_text_on_stderr(tmp_path: Path) -> None:
    """The step carries the refusal's RunVerdict: the line must show its value, not RunVerdict.RUN_LIVE."""
    run = run_cli([*APPLY, "--json"], _with_receipt(tmp_path), apply_runner(FakePve(), ALIVE, DONE_OK))
    assert (run.exit_code, json_envelope(run.stdout)["verdict"]) == (1, "RUN_LIVE")
    expected = "[FAIL] run_finished" + " " * 11 + "verdict=RUN_LIVE alive=True marker=STATE=DONE-OK"
    assert expected in run.stderr.splitlines()


@NEEDS_A_POSIX_STATE_DIR
def test_apply_without_json_prints_one_verdict_line(tmp_path: Path) -> None:
    run = run_cli(APPLY, _with_receipt(tmp_path), _runner())
    assert (run.exit_code, run.stdout) == (0, "vm 1: VERIFIED\n")


@NEEDS_A_POSIX_STATE_DIR
def test_apply_without_a_receipt_is_refused_before_any_call(tmp_path: Path) -> None:
    runner = _runner()
    run = run_cli([*APPLY, "--json"], cli_config(tmp_path), runner)
    envelope = json_envelope(run.stdout)
    assert (run.exit_code, envelope["ok"], envelope["verdict"]) == (1, False, "ERROR")
    assert str(envelope_steps(envelope)[-1]["message"]).startswith(
        f"no repair receipt for VM 1 at {tmp_path / 'state' / 'receipt-1.json'} - "
    )
    assert runner.calls == []


@NEEDS_A_POSIX_STATE_DIR
def test_apply_minutes_option_is_how_long_the_guest_may_take_to_come_back(tmp_path: Path) -> None:
    runner = _runner()
    runner.replies["hostname"] = [Reply(255, "", "Connection timed out")]
    run = run_cli([*APPLY, "--apply-minutes", "0.5", "--json"], _with_receipt(tmp_path), runner)
    message = str(envelope_steps(json_envelope(run.stdout))[-1]["message"])
    assert run.exit_code == 1
    assert message.startswith("guest did not answer ssh within 0.5 min")


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "x"])
def test_apply_minutes_that_are_no_positive_finite_number_are_refused_before_any_call(
    tmp_path: Path, value: str
) -> None:
    runner = _runner()
    run = run_cli([*APPLY, "--apply-minutes", value], _with_receipt(tmp_path), runner)
    assert run.exit_code == 2
    assert "Invalid value for '--apply-minutes'" in run.stderr
    assert runner.calls == []


@pytest.mark.parametrize("value", ["999.1.1.1", "192.0.2.010", "host.example", ""])
def test_apply_with_an_ip_that_is_no_ipv4_address_is_refused_before_any_call(tmp_path: Path, value: str) -> None:
    runner = _runner()
    run = run_cli(["apply", "--vmid", "1", "--ip", value], _with_receipt(tmp_path), runner)
    assert run.exit_code == 2
    assert "Invalid value for '--ip'" in run.stderr
    assert "not an IPv4 address" in run.stderr
    assert runner.calls == []


@NEEDS_A_POSIX_STATE_DIR
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


@NEEDS_A_POSIX_STATE_DIR
def test_apply_with_an_unconfigured_ssh_key_is_refused_before_any_call(tmp_path: Path) -> None:
    config = _with_receipt(tmp_path)
    config["ssh"]["key"] = ""
    runner = _runner()
    run = run_cli(APPLY, config, runner)
    assert (run.exit_code, run.stdout) == (1, "vm 1: ERROR\n")
    assert "[ssh] key is not configured" in run.stderr
    assert runner.calls == []


@NEEDS_A_POSIX_STATE_DIR
def test_apply_driver_tool_mismatch_exits_2_with_empty_stdout(tmp_path: Path) -> None:
    runner = _runner()
    runner.replies["build"] = [answer("build", {"CurrentBuild": "26200", "UBR": 8973})]
    run = run_cli(APPLY, _with_receipt(tmp_path), runner)
    assert (run.exit_code, run.stdout) == (2, "")
    assert "[FAIL] internal" in run.stderr


@NEEDS_A_POSIX_STATE_DIR
def test_apply_on_an_unusable_remote_node_is_refused_before_any_vm_call(tmp_path: Path) -> None:
    config = _with_receipt(tmp_path)
    config["node"] = {**config["node"], "ssh_key": "/keys/node.key", "known_hosts_file": NODE_LINK.known_hosts}
    runner = FakeRunner().on("command", Reply(255, "", "Host key verification failed.\n"))
    run = run_cli([*APPLY, "--json", "--node", "pve1"], config, runner)
    envelope = json_envelope(run.stdout)
    assert (run.exit_code, envelope["verdict"]) == (1, "ERROR")
    assert "node root@pve1 is not usable: Host key verification failed." in str(envelope_steps(envelope)[-1]["message"])
    assert runner.calls == [NODE_LINK.ssh_argv(["command", "-v", "qm"])]


def test_apply_with_a_node_option_ssh_could_read_as_an_option_is_a_usage_error(tmp_path: Path) -> None:
    runner = FakeRunner()
    run = run_cli([*APPLY, "--node=-oX"], cli_config(tmp_path), runner)
    assert run.exit_code == 2
    assert "Invalid value for '--node'" in run.stderr
    assert runner.calls == []


@NEEDS_A_POSIX_STATE_DIR
def test_apply_with_the_node_option_runs_every_qm_call_on_that_node(tmp_path: Path) -> None:
    config = _with_receipt(tmp_path)
    config["node"] = {**config["node"], "ssh_key": NODE_LINK.key, "known_hosts_file": NODE_LINK.known_hosts}
    runner = _runner().on("command", Reply(0, "/usr/sbin/qm\n", ""))
    run = run_cli([*APPLY, "--json", "--node", NODE_LINK.host], config, runner)
    assert (run.exit_code, json_envelope(run.stdout)["verdict"]) == (0, "VERIFIED")
    remote = [call for call in runner.calls if call[0] == "ssh" and call[-2] == NODE_LINK.target]
    assert remote[0] == NODE_LINK.ssh_argv(["command", "-v", "qm"])
    assert len(remote) > 1
    assert not any(call[0] == "qm" for call in runner.calls)
