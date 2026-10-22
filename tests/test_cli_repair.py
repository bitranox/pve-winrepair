"""``pve-winrepair repair`` end to end: options, settings, refusals before any call, output and exit codes.

Every run goes through the real ``main()`` with the testing composition; the node is injected through
``build_testing(make_node=...)`` and answers from the fake guest every use-case test uses
(:func:`guest_fakes.agent_runner`), so these tests pin the command, not the repair sequence.
"""

from __future__ import annotations

import dataclasses
import logging
import os
import sys
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner
from guest_fakes import (
    ALIVE,
    DONE_OK,
    GONE,
    GUEST_IP,
    KEY,
    NO_LOG,
    FakePve,
    Reply,
    agent_runner,
    answer,
    call_labels,
    cli_config,
    envelope_steps,
    json_envelope,
    prepare_report,
    run_cli,
    state_log,
)
from lib_layered_config import Config

from pve_winrepair.adapters.cli.commands.runs import operator_progress
from pve_winrepair.adapters.cli.main import main
from pve_winrepair.composition import AppServices, build_testing

if TYPE_CHECKING:
    from pathlib import Path

    from guest_fakes import FakeRunner

#: The steps of a whole agent-path repair to STATE=DONE-OK, the receipt step included.
DONE_OK_STEPS = [
    "running", "push_tool", "no_live_run", "quiesce_wu", "servicing_idle", "vtpm", "running",
    "snapshot", "push_tool", "no_live_run", "stage_root", "lock_dirs", "stage_media", "quiesce_wu",
    "prepare", "receipt", "launch", "poll",
]  # fmt: skip


def test_repair_json_runs_the_agent_path_to_done_ok(tmp_path: Path) -> None:
    config = cli_config(tmp_path)
    runner = agent_runner(FakePve())
    run = run_cli(["repair", "--vmid", "1", "--json"], config, runner)
    envelope = json_envelope(run.stdout)
    assert run.exit_code == 0
    assert set(envelope) == {"ok", "command", "vmid", "verdict", "steps"}
    assert (envelope["ok"], envelope["command"], envelope["vmid"], envelope["verdict"]) == (
        True,
        "repair",
        1,
        "STATE=DONE-OK",
    )
    assert [step["step"] for step in envelope_steps(envelope)] == DONE_OK_STEPS
    # The receipt went to [node] state_dir, the node reached the guest with the [ssh] key.
    assert (tmp_path / "state" / "receipt-1.json").is_file()
    assert all(call[call.index("-i") + 1] == KEY for call in runner.calls if call[0] in ("ssh", "scp"))


def test_repair_echoes_each_step_to_stderr_as_it_happens(tmp_path: Path) -> None:
    run = run_cli(["repair", "--vmid", "1", "--json"], cli_config(tmp_path), agent_runner(FakePve()))
    lines = [line for line in run.stderr.splitlines() if line.startswith("[")]
    assert [line.split("] ", 1)[1].split()[0] for line in lines] == DONE_OK_STEPS
    assert lines[-1].startswith("[ok ] poll ")
    assert "verdict=STATE=DONE-OK" in lines[-1]


def test_repair_without_json_prints_one_verdict_line(tmp_path: Path) -> None:
    run = run_cli(["repair", "--vmid", "1"], cli_config(tmp_path), agent_runner(FakePve()))
    assert (run.exit_code, run.stdout) == (0, "vm 1: STATE=DONE-OK\n")


def test_repair_snapshot_name_defaults_to_the_setting(tmp_path: Path) -> None:
    config = cli_config(tmp_path)
    config["repair"]["snapshot_name"] = "pre_from_config"
    runner = agent_runner(FakePve())
    run_cli(["repair", "--vmid", "1"], config, runner)
    snapshots = [call for call in runner.calls if call[:2] == ["qm", "snapshot"]]
    assert [call[3] for call in snapshots] == ["pre_from_config"]


def test_repair_snapshot_name_option_overrides_the_setting(tmp_path: Path) -> None:
    runner = agent_runner(FakePve())
    run_cli(["repair", "--vmid", "1", "--snapshot-name", "pre_from_option"], cli_config(tmp_path), runner)
    snapshots = [call for call in runner.calls if call[:2] == ["qm", "snapshot"]]
    assert [call[3] for call in snapshots] == ["pre_from_option"]


def test_a_bad_snapshot_name_option_is_refused_naming_it_before_any_call(tmp_path: Path) -> None:
    runner = agent_runner(FakePve())
    run = run_cli(
        ["repair", "--vmid", "1", "--snapshot-name", "1-starts-with-a-digit", "--json"], cli_config(tmp_path), runner
    )
    envelope = json_envelope(run.stdout)
    assert (run.exit_code, envelope["ok"], envelope["verdict"]) == (1, False, "ERROR")
    message = str(envelope_steps(envelope)[-1]["message"])
    assert message.startswith("--snapshot-name: String should match pattern ")
    assert "1-starts-with-a-digit" not in message
    assert runner.calls == []


def test_a_refusal_exits_1_with_verdict_error_naming_the_reason(tmp_path: Path) -> None:
    refused = answer("prepare", prepare_report("FAIL", "image SPBuild 8973 older than running 9711"), ok=False)
    run = run_cli(["repair", "--vmid", "1", "--json"], cli_config(tmp_path), agent_runner(FakePve(), prepare=refused))
    envelope = json_envelope(run.stdout)
    assert (run.exit_code, envelope["ok"], envelope["verdict"]) == (1, False, "ERROR")
    last = envelope_steps(envelope)[-1]
    assert (last["step"], last["wu_held"]) == ("error", True)
    assert str(last["message"]).startswith("guest gate refused: image SPBuild 8973 older than running 9711")


def test_a_refusal_without_json_prints_the_verdict_line(tmp_path: Path) -> None:
    refused = answer("prepare", prepare_report("FAIL", "image too old"), ok=False)
    run = run_cli(["repair", "--vmid", "1"], cli_config(tmp_path), agent_runner(FakePve(), prepare=refused))
    assert (run.exit_code, run.stdout) == (1, "vm 1: ERROR\n")


def test_a_driver_tool_mismatch_exits_2_internal_with_json(tmp_path: Path) -> None:
    runner = agent_runner(FakePve(), state=answer("state", {"present": True}))
    run = run_cli(["repair", "--vmid", "1", "--json"], cli_config(tmp_path), runner)
    envelope = json_envelope(run.stdout)
    assert (run.exit_code, envelope["ok"], envelope["verdict"]) == (2, False, "INTERNAL")
    assert envelope_steps(envelope)[-1]["step"] == "internal"


def test_a_driver_tool_mismatch_without_json_leaves_stdout_empty(tmp_path: Path) -> None:
    runner = agent_runner(FakePve(), state=answer("state", {"present": True}))
    run = run_cli(["repair", "--vmid", "1"], cli_config(tmp_path), runner)
    assert (run.exit_code, run.stdout) == (2, "")
    assert "[FAIL] internal" in run.stderr


def test_an_unconfigured_ssh_key_is_refused_before_any_call(tmp_path: Path) -> None:
    config = cli_config(tmp_path)
    config["ssh"]["key"] = ""
    runner = agent_runner(FakePve())
    run = run_cli(["repair", "--vmid", "1", "--json"], config, runner)
    envelope = json_envelope(run.stdout)
    assert (run.exit_code, envelope["verdict"]) == (1, "ERROR")
    assert str(envelope_steps(envelope)[-1]["message"]).startswith("[ssh] key is not configured: ")
    assert "[ssh] key is not configured" in run.stderr
    assert runner.calls == []


def test_an_unknown_setting_exits_78_naming_it_before_any_call(tmp_path: Path) -> None:
    config = cli_config(tmp_path)
    config["ssh"]["keyy"] = "/keys/typo.key"
    runner = agent_runner(FakePve())
    run = run_cli(["repair", "--vmid", "1", "--json"], config, runner)
    assert (run.exit_code, run.stdout) == (78, "")
    assert "Error: ssh.keyy: Extra inputs are not permitted" in run.stderr.splitlines()
    assert runner.calls == []


def test_a_state_dir_that_is_a_regular_file_is_refused_before_any_call(tmp_path: Path) -> None:
    config = cli_config(tmp_path)
    blocker = tmp_path / "state-is-a-file"
    blocker.write_text("", encoding="utf-8")
    config["node"]["state_dir"] = str(blocker)
    runner = agent_runner(FakePve())
    run = run_cli(["repair", "--vmid", "1", "--json"], config, runner)
    envelope = json_envelope(run.stdout)
    assert (run.exit_code, envelope["verdict"]) == (1, "ERROR")
    assert str(envelope_steps(envelope)[-1]["message"]) == (
        f"[node] state_dir {blocker} cannot be a directory: {blocker} is not a directory"
    )
    assert runner.calls == []


def test_a_state_dir_below_a_regular_file_is_refused_naming_the_file(tmp_path: Path) -> None:
    config = cli_config(tmp_path)
    blocker = tmp_path / "a-file"
    blocker.write_text("", encoding="utf-8")
    config["node"]["state_dir"] = str(blocker / "state")
    runner = agent_runner(FakePve())
    run = run_cli(["repair", "--vmid", "1"], config, runner)
    assert run.exit_code == 1
    assert f"[node] state_dir {blocker / 'state'} cannot be a directory: {blocker} is not a directory" in run.stderr
    assert runner.calls == []


def test_a_waiting_poll_reports_its_progress_on_stderr_never_on_stdout(tmp_path: Path) -> None:
    run = run_cli(["repair", "--vmid", "1", "--json"], cli_config(tmp_path), _waiting_poll_runner())
    assert run.exit_code == 0
    assert "    ... waiting, SetupHost running=True" in run.stderr.splitlines()
    assert json_envelope(run.stdout)["verdict"] == "STATE=DONE-OK"


def _waiting_poll_runner() -> FakeRunner:
    """The agent-path guest, whose poll finds setup running once before its marker."""
    runner = agent_runner(FakePve())
    # Two live-run checks see no run; the poll then finds setup running once before its marker.
    runner.replies["setup-alive"] = [GONE, GONE, ALIVE]
    runner.replies["state"] = [NO_LOG, NO_LOG, answer("state", state_log("launching: setup.exe")), DONE_OK]
    return runner


def test_progress_lines_never_reach_a_root_handler_and_the_logger_is_restored(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A handler on the root logger (production's lib_log_rich bridge) would print each line again."""
    application = logging.getLogger("pve_winrepair.application")
    before = (application.level, application.propagate, list(application.handlers))
    with caplog.at_level(logging.INFO):
        run = run_cli(["repair", "--vmid", "1"], cli_config(tmp_path), _waiting_poll_runner())
    assert "    ... waiting, SetupHost running=True" in run.stderr.splitlines()
    assert [record.getMessage() for record in caplog.records if record.name.startswith(application.name)] == []
    assert (application.level, application.propagate, list(application.handlers)) == before


def test_stage_only_stops_after_staging(tmp_path: Path) -> None:
    run = run_cli(["repair", "--vmid", "1", "--stage-only", "--json"], cli_config(tmp_path), agent_runner(FakePve()))
    envelope = json_envelope(run.stdout)
    assert (run.exit_code, envelope["verdict"]) == (0, "STAGED")
    assert "launch" not in [step["step"] for step in envelope_steps(envelope)]


def test_stage_root_option_reaches_the_stage_root_step(tmp_path: Path) -> None:
    run = run_cli(
        ["repair", "--vmid", "1", "--stage-root", "C:", "--json"], cli_config(tmp_path), agent_runner(FakePve())
    )
    stage_root = next(step for step in envelope_steps(json_envelope(run.stdout)) if step["step"] == "stage_root")
    assert (stage_root["root"], stage_root["note"]) == ("C:\\upgrade", "explicit")


def test_hours_option_is_the_poll_deadline(tmp_path: Path) -> None:
    run = run_cli(["repair", "--vmid", "1", "--hours", "0", "--json"], cli_config(tmp_path), agent_runner(FakePve()))
    assert (run.exit_code, json_envelope(run.stdout)["verdict"]) == (1, "TIMEOUT")


def test_tpm_storage_option_is_where_a_new_vtpm_goes(tmp_path: Path) -> None:
    pve = FakePve()
    pve.config = "scsi0: local-zfs:vm-1-disk-0,size=64G\n"
    runner = agent_runner(pve)
    run_cli(["repair", "--vmid", "1", "--tpm-storage", "tpmstore"], cli_config(tmp_path), runner)
    sets = [call for call in runner.calls if call[:2] == ["qm", "set"]]
    assert [call[3:] for call in sets] == [["-tpmstate0", "tpmstore:1,version=v2.0"]]


def test_ip_option_takes_the_agentless_path(tmp_path: Path) -> None:
    runner = agent_runner(FakePve(), hostname=Reply(255, "", "Connection timed out"))
    run = run_cli(["repair", "--vmid", "1", "--ip", GUEST_IP, "--json"], cli_config(tmp_path), runner)
    assert run.exit_code == 1
    assert "never answered ssh" in str(envelope_steps(json_envelope(run.stdout))[-1]["message"])
    assert "qm guest" not in call_labels(runner.calls)


def test_the_testing_composition_without_a_node_runs_nothing(tmp_path: Path) -> None:
    """``build_testing()`` alone never reaches a real ``qm`` or ssh: its node refuses every call."""
    config = Config(cli_config(tmp_path), {})

    def services() -> AppServices:
        def get_config(**_kwargs: object) -> Config:
            return config

        return dataclasses.replace(build_testing(), get_config=get_config)

    with CliRunner().isolation() as (stdout, _stderr, _output):
        exit_code = main(["repair", "--vmid", "1", "--json"], services_factory=services)
    envelope = json_envelope(stdout.getvalue().decode("utf-8"))
    assert (exit_code, envelope["verdict"]) == (2, "INTERNAL")
    assert "build_testing runs no command (qm): pass make_node to build_testing" in str(
        envelope_steps(envelope)[-1]["message"]
    )


@pytest.mark.os_posix
def test_a_state_dir_that_is_a_dangling_symlink_is_refused_before_any_call(tmp_path: Path) -> None:
    config = cli_config(tmp_path)
    link = tmp_path / "state-link"
    link.symlink_to(tmp_path / "nowhere")
    config["node"]["state_dir"] = str(link)
    runner = agent_runner(FakePve())
    run = run_cli(["repair", "--vmid", "1"], config, runner)
    assert run.exit_code == 1
    assert f"[node] state_dir {link} cannot be a directory: {link} is a symbolic link to nothing" in run.stderr
    assert runner.calls == []


@pytest.mark.os_posix
@pytest.mark.skipif(sys.platform != "win32" and os.geteuid() == 0, reason="root searches any directory")
def test_a_state_dir_below_an_unsearchable_directory_is_refused_naming_it(tmp_path: Path) -> None:
    config = cli_config(tmp_path)
    locked = tmp_path / "locked"
    locked.mkdir()
    config["node"]["state_dir"] = str(locked / "state")
    runner = agent_runner(FakePve())
    locked.chmod(0)
    try:
        run = run_cli(["repair", "--vmid", "1"], config, runner)
    finally:
        locked.chmod(0o700)
    assert run.exit_code == 1
    assert f"cannot be a directory: {locked / 'state'} cannot be checked: Permission denied" in run.stderr
    assert runner.calls == []


def test_a_progress_line_that_cannot_be_formatted_never_breaks_the_run(capsys: pytest.CaptureFixture[str]) -> None:
    with operator_progress():
        logging.getLogger("pve_winrepair.application.repair").info("%d processes", "not a number")
    assert "--- Logging error ---" in capsys.readouterr().err
