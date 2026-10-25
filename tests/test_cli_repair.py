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
    NEEDS_A_POSIX_STATE_DIR,
    NO_LOG,
    NODE_LINK,
    NODE_LOGGING,
    CliRun,
    FakePve,
    FakeRunner,
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

from pve_winrepair.adapters.cli.commands.runs import PreflightError, resolve_link, resolve_snapshot_name
from pve_winrepair.adapters.cli.main import main
from pve_winrepair.composition import AppServices, build_testing
from pve_winrepair.domain.envelope import WU_HELD_HINT
from pve_winrepair.domain.node_link import NodeLink
from pve_winrepair.domain.settings import NodeSettings, RepairSettings, Settings

if TYPE_CHECKING:
    from pathlib import Path

#: The steps of a whole agent-path repair to STATE=DONE-OK, the receipt step included.
DONE_OK_STEPS = [
    "running", "push_tool", "no_live_run", "quiesce_wu", "servicing_idle", "vtpm", "running",
    "snapshot", "push_tool", "no_live_run", "stage_root", "lock_dirs", "stage_media", "quiesce_wu",
    "prepare", "build_before", "receipt", "launch", "poll",
]  # fmt: skip


@NEEDS_A_POSIX_STATE_DIR
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


@NEEDS_A_POSIX_STATE_DIR
def test_repair_echoes_each_step_to_stderr_as_it_happens(tmp_path: Path) -> None:
    run = run_cli(["repair", "--vmid", "1", "--json"], cli_config(tmp_path), agent_runner(FakePve()))
    lines = [line for line in run.stderr.splitlines() if line.startswith("[")]
    assert [line.split("] ", 1)[1].split()[0] for line in lines] == DONE_OK_STEPS
    # Exactly: the step name and the verdict are str enums inside, and must reach the line as their
    # values, never as StepName.POLL or RunVerdict.DONE_OK.
    assert lines[-1] == "[ok ] poll" + " " * 19 + "verdict=STATE=DONE-OK"


@NEEDS_A_POSIX_STATE_DIR
def test_repair_without_json_prints_one_verdict_line(tmp_path: Path) -> None:
    run = run_cli(["repair", "--vmid", "1"], cli_config(tmp_path), agent_runner(FakePve()))
    assert (run.exit_code, run.stdout) == (0, "vm 1: STATE=DONE-OK\n")


@NEEDS_A_POSIX_STATE_DIR
def test_repair_snapshot_name_defaults_to_the_setting(tmp_path: Path) -> None:
    config = cli_config(tmp_path)
    config["repair"]["snapshot_name"] = "pre_from_config"
    runner = agent_runner(FakePve())
    run_cli(["repair", "--vmid", "1"], config, runner)
    snapshots = [call for call in runner.calls if call[:2] == ["qm", "snapshot"]]
    assert [call[3] for call in snapshots] == ["pre_from_config"]


@NEEDS_A_POSIX_STATE_DIR
def test_repair_snapshot_name_option_overrides_the_setting(tmp_path: Path) -> None:
    runner = agent_runner(FakePve())
    run_cli(["repair", "--vmid", "1", "--snapshot-name", "pre_from_option"], cli_config(tmp_path), runner)
    snapshots = [call for call in runner.calls if call[:2] == ["qm", "snapshot"]]
    assert [call[3] for call in snapshots] == ["pre_from_option"]


@NEEDS_A_POSIX_STATE_DIR
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


#: The exact refusal of a --snapshot-name that breaks [repair] snapshot_name's rule.
BAD_SNAPSHOT_NAME = "--snapshot-name: String should match pattern '^[A-Za-z][A-Za-z0-9_-]{1,39}$'"


def test_a_snapshot_name_override_is_validated_alone_never_with_the_other_settings() -> None:
    """Only the option is judged: the rest of ``[repair]`` was validated when it loaded.

    ``model_construct`` builds settings no load would pass (a negative floor); the override is
    still accepted or refused on its own rule.
    """
    unchecked = RepairSettings.model_construct(
        media_dir="", snapshot_name="pre_ok", stage_free_gb=-1.0, system_free_gb=25.0
    )
    assert resolve_snapshot_name(unchecked, "pre_from_option") == "pre_from_option"
    with pytest.raises(PreflightError) as refused:
        resolve_snapshot_name(unchecked, "1-starts-with-a-digit")
    assert str(refused.value) == BAD_SNAPSHOT_NAME


@NEEDS_A_POSIX_STATE_DIR
def test_a_refused_run_prints_the_envelope_byte_for_byte(tmp_path: Path) -> None:
    """The --json envelope's exact bytes (two-space indent, key order), and the step on stderr."""
    run = run_cli(
        ["repair", "--vmid", "1", "--snapshot-name", "1-bad", "--json"], cli_config(tmp_path), agent_runner(FakePve())
    )
    assert run.stdout == (
        '{\n  "ok": false,\n  "command": "repair",\n  "vmid": 1,\n  "verdict": "ERROR",\n  "steps": [\n'
        '    {\n      "step": "error",\n      "ok": false,\n'
        f'      "message": "{BAD_SNAPSHOT_NAME}"\n    }}\n  ]\n}}\n'
    )
    assert run.stderr == f"[FAIL] error                  message={BAD_SNAPSHOT_NAME}\n"


@NEEDS_A_POSIX_STATE_DIR
def test_a_refusal_exits_1_with_verdict_error_naming_the_reason(tmp_path: Path) -> None:
    refused = answer("prepare", prepare_report("FAIL", "image 26200.8973 older than running 26200.9711"), ok=False)
    run = run_cli(["repair", "--vmid", "1", "--json"], cli_config(tmp_path), agent_runner(FakePve(), prepare=refused))
    envelope = json_envelope(run.stdout)
    assert (run.exit_code, envelope["ok"], envelope["verdict"]) == (1, False, "ERROR")
    last = envelope_steps(envelope)[-1]
    assert (last["step"], last["wu_held"]) == ("error", True)
    assert str(last["message"]).startswith("guest gate refused: image 26200.8973 older than running 26200.9711")


@NEEDS_A_POSIX_STATE_DIR
def test_a_refusal_without_json_prints_the_verdict_line(tmp_path: Path) -> None:
    refused = answer("prepare", prepare_report("FAIL", "image too old"), ok=False)
    run = run_cli(["repair", "--vmid", "1"], cli_config(tmp_path), agent_runner(FakePve(), prepare=refused))
    assert (run.exit_code, run.stdout) == (1, "vm 1: ERROR\n")


#: A state answer missing every field but one, as a tool out of step with the driver sends it; built
#: by hand because no guest model can build it.
BROKEN_STATE = Reply(0, '{"ok": true, "command": "state", "data": {"present": true}, "skipped": []}\r\n')


@NEEDS_A_POSIX_STATE_DIR
def test_a_driver_tool_mismatch_exits_2_internal_with_json(tmp_path: Path) -> None:
    runner = agent_runner(FakePve(), state=BROKEN_STATE)
    run = run_cli(["repair", "--vmid", "1", "--json"], cli_config(tmp_path), runner)
    envelope = json_envelope(run.stdout)
    assert (run.exit_code, envelope["ok"], envelope["verdict"]) == (2, False, "INTERNAL")
    assert envelope_steps(envelope)[-1]["step"] == "internal"


@NEEDS_A_POSIX_STATE_DIR
def test_a_driver_tool_mismatch_without_json_leaves_stdout_empty(tmp_path: Path) -> None:
    runner = agent_runner(FakePve(), state=BROKEN_STATE)
    run = run_cli(["repair", "--vmid", "1"], cli_config(tmp_path), runner)
    assert (run.exit_code, run.stdout) == (2, "")
    assert "[FAIL] internal" in run.stderr


@NEEDS_A_POSIX_STATE_DIR
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


@NEEDS_A_POSIX_STATE_DIR
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


@NEEDS_A_POSIX_STATE_DIR
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


def _waiting_poll_runner() -> FakeRunner:
    """The agent-path guest, whose poll finds setup running once before its marker."""
    runner = agent_runner(FakePve())
    # Two live-run checks see no run; the poll then finds setup running once before its marker.
    runner.replies["setup-alive"] = [GONE, GONE, ALIVE]
    runner.replies["state"] = [NO_LOG, NO_LOG, answer("state", state_log("launching: setup.exe")), DONE_OK]
    return runner


PROGRESS = "waiting, SetupHost running=True"


def _node_logging_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, argv: list[str], runner: FakeRunner, **logging_overrides: object
) -> CliRun:
    """``main()`` with logging started as on a node, from ``[lib_log_rich]`` alone.

    The shell's ``LOG_*`` variables and any ``.env`` would decide the console level, so they are
    removed and an empty ``--env-file`` is named.
    """
    for name in list(os.environ):
        if name.upper().startswith("LOG_"):
            monkeypatch.delenv(name)
    env_file = tmp_path / "empty.env"
    env_file.write_text("", encoding="utf-8")
    config: dict[str, object] = {**cli_config(tmp_path), "lib_log_rich": {**NODE_LOGGING, **logging_overrides}}
    return run_cli(["--env-file", str(env_file), *argv], config, runner, production_logging=True)


@NEEDS_A_POSIX_STATE_DIR
def test_a_waiting_poll_reports_its_progress_on_stderr_through_lib_log_rich_never_on_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _node_logging_run(tmp_path, monkeypatch, ["repair", "--vmid", "1", "--json"], _waiting_poll_runner())
    assert run.exit_code == 0
    progress = [line for line in run.stderr.splitlines() if PROGRESS in line]
    # Exactly once, in lib_log_rich's console layout: nothing else prints the line.
    assert len(progress) == 1
    assert "[INFO]" in progress[0]
    assert json_envelope(run.stdout)["verdict"] == "STATE=DONE-OK"


@NEEDS_A_POSIX_STATE_DIR
def test_each_progress_record_reaches_the_root_bridge_once_and_no_handler_of_ours(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Production bridges the ROOT logger into lib_log_rich: its scrubber, console and backends."""
    application = logging.getLogger("pve_winrepair.application")
    seen: list[tuple[bool, int]] = []
    runner = _waiting_poll_runner()
    replies = list(runner.replies["setup-alive"])

    def watching(_cmd: list[str]) -> Reply:
        # Read mid-run, while the use case is logging: how the application logger is wired.
        seen.append((application.propagate, len(application.handlers)))
        reply = replies.pop(0) if len(replies) > 1 else replies[0]
        assert isinstance(reply, Reply)
        return reply

    runner.replies["setup-alive"] = [watching]
    with caplog.at_level(logging.INFO):
        run = _node_logging_run(tmp_path, monkeypatch, ["repair", "--vmid", "1"], runner)
    assert run.exit_code == 0
    assert seen and set(seen) == {(True, 0)}
    assert [record.getMessage() for record in caplog.records].count(PROGRESS) == 1
    assert any(type(handler).__name__ == "StdlibLoggingHandler" for handler in logging.getLogger().handlers)


@NEEDS_A_POSIX_STATE_DIR
def test_a_console_at_warning_shows_no_progress_line(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = _node_logging_run(
        tmp_path, monkeypatch, ["repair", "--vmid", "1"], _waiting_poll_runner(), console_level="WARNING"
    )
    assert run.exit_code == 0
    assert PROGRESS not in run.stderr


@NEEDS_A_POSIX_STATE_DIR
def test_stage_only_stops_after_staging(tmp_path: Path) -> None:
    run = run_cli(["repair", "--vmid", "1", "--stage-only", "--json"], cli_config(tmp_path), agent_runner(FakePve()))
    envelope = json_envelope(run.stdout)
    assert (run.exit_code, envelope["verdict"]) == (0, "STAGED")
    assert "launch" not in [step["step"] for step in envelope_steps(envelope)]


@NEEDS_A_POSIX_STATE_DIR
def test_stage_only_says_windows_update_is_still_held_and_how_to_lift_it(tmp_path: Path) -> None:
    run = run_cli(["repair", "--vmid", "1", "--stage-only", "--json"], cli_config(tmp_path), agent_runner(FakePve()))
    last = envelope_steps(json_envelope(run.stdout))[-1]
    assert (run.exit_code, last["step"], last["ok"], last["wu_held"]) == (0, "staged", True, True)
    assert str(last["note"]).endswith(WU_HELD_HINT)
    assert "no receipt" in str(last["note"])
    # The operator sees the hold on stderr too, on the step printed last.
    assert WU_HELD_HINT in run.stderr.splitlines()[-1]


@NEEDS_A_POSIX_STATE_DIR
def test_stage_root_option_reaches_the_stage_root_step(tmp_path: Path) -> None:
    run = run_cli(
        ["repair", "--vmid", "1", "--stage-root", "C:", "--json"], cli_config(tmp_path), agent_runner(FakePve())
    )
    stage_root = next(step for step in envelope_steps(json_envelope(run.stdout)) if step["step"] == "stage_root")
    assert (stage_root["root"], stage_root["note"]) == ("C:\\upgrade", "explicit")


@NEEDS_A_POSIX_STATE_DIR
@pytest.mark.parametrize("value", ["d", "D", "d:", "D:\\"])
def test_stage_root_option_takes_any_spelling_of_one_drive(tmp_path: Path, value: str) -> None:
    run = run_cli(
        ["repair", "--vmid", "1", "--stage-root", value, "--json"], cli_config(tmp_path), agent_runner(FakePve())
    )
    stage_root = next(step for step in envelope_steps(json_envelope(run.stdout)) if step["step"] == "stage_root")
    assert (run.exit_code, stage_root["root"], stage_root["note"]) == (0, "D:\\upgrade", "explicit")


@pytest.mark.parametrize("value", ["", "1:", "CD", "C:\\upgrade", "C;", chr(0x00E4) + ":"])
def test_a_stage_root_that_is_no_drive_letter_is_refused_before_any_call(tmp_path: Path, value: str) -> None:
    run, runner = _usage_error(["repair", "--vmid", "1", "--stage-root", value], tmp_path)
    assert run.exit_code == 2
    assert "Invalid value for '--stage-root'" in run.stderr
    assert "is not a drive letter" in run.stderr
    assert runner.calls == []


@NEEDS_A_POSIX_STATE_DIR
def test_a_stage_root_the_guest_does_not_have_is_refused_naming_it(tmp_path: Path) -> None:
    run = run_cli(
        ["repair", "--vmid", "1", "--stage-root", "e", "--json"], cli_config(tmp_path), agent_runner(FakePve())
    )
    envelope = json_envelope(run.stdout)
    assert (run.exit_code, envelope["verdict"]) == (1, "ERROR")
    assert str(envelope_steps(envelope)[-1]["message"]).startswith(
        "--stage-root names E: which the guest does not have: {'C': 60.0, 'D': 200.0} - "
    )


@NEEDS_A_POSIX_STATE_DIR
def test_hours_option_is_the_poll_deadline(tmp_path: Path) -> None:
    runner = agent_runner(FakePve(), state=NO_LOG)
    runner.replies["setup-alive"] = [GONE, GONE, ALIVE]  # both guards pass, then setup runs past the deadline
    run = run_cli(["repair", "--vmid", "1", "--hours", "0.001", "--json"], cli_config(tmp_path), runner)
    envelope = json_envelope(run.stdout)
    assert (run.exit_code, envelope["verdict"]) == (1, "TIMEOUT")
    assert "no verdict within 0.001 h" in str(envelope_steps(envelope)[-1]["note"])


def _usage_error(argv: list[str], tmp_path: Path) -> tuple[CliRun, FakeRunner]:
    runner = agent_runner(FakePve())
    return run_cli(argv, cli_config(tmp_path), runner), runner


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "-inf", "x"])
def test_hours_that_are_no_positive_finite_number_are_refused_before_any_call(tmp_path: Path, value: str) -> None:
    run, runner = _usage_error(["repair", "--vmid", "1", "--hours", value], tmp_path)
    assert run.exit_code == 2
    assert "Invalid value for '--hours'" in run.stderr
    assert runner.calls == []


@pytest.mark.parametrize(
    "value", ["a", "1local", "local-", "local zfs", "local-zfs:1", "local,x=1", "-tpm", "x" * 0, chr(0x00E4) + "b"]
)
def test_a_tpm_storage_that_is_no_pve_storage_id_is_refused_before_any_call(tmp_path: Path, value: str) -> None:
    run, runner = _usage_error(["repair", "--vmid", "1", "--tpm-storage", value], tmp_path)
    assert run.exit_code == 2
    assert "Invalid value for '--tpm-storage'" in run.stderr
    assert "not a PVE storage ID" in run.stderr
    assert runner.calls == []


@NEEDS_A_POSIX_STATE_DIR
@pytest.mark.parametrize("value", ["local-zfs", "Tpm.Store_1", "ab"])
def test_a_tpm_storage_that_is_a_pve_storage_id_reaches_qm_set(tmp_path: Path, value: str) -> None:
    pve = FakePve()
    pve.config = "scsi0: local-zfs:vm-1-disk-0,size=64G\n"
    runner = agent_runner(pve)
    run_cli(["repair", "--vmid", "1", "--tpm-storage", value], cli_config(tmp_path), runner)
    sets = [call for call in runner.calls if call[:2] == ["qm", "set"]]
    assert [call[3:] for call in sets] == [["-tpmstate0", f"{value}:1,version=v2.0"]]


@pytest.mark.parametrize("value", ["999.1.1.1", "192.0.2", "192.0.2.010", "host.example", "2001:db8::1", ""])
def test_an_ip_that_is_no_ipv4_address_is_refused_before_any_call(tmp_path: Path, value: str) -> None:
    run, runner = _usage_error(["repair", "--vmid", "1", "--ip", value], tmp_path)
    assert run.exit_code == 2
    assert "Invalid value for '--ip'" in run.stderr
    assert "not an IPv4 address" in run.stderr
    assert runner.calls == []


@NEEDS_A_POSIX_STATE_DIR
def test_tpm_storage_option_is_where_a_new_vtpm_goes(tmp_path: Path) -> None:
    pve = FakePve()
    pve.config = "scsi0: local-zfs:vm-1-disk-0,size=64G\n"
    runner = agent_runner(pve)
    run_cli(["repair", "--vmid", "1", "--tpm-storage", "tpmstore"], cli_config(tmp_path), runner)
    sets = [call for call in runner.calls if call[:2] == ["qm", "set"]]
    assert [call[3:] for call in sets] == [["-tpmstate0", "tpmstore:1,version=v2.0"]]


@NEEDS_A_POSIX_STATE_DIR
def test_ip_option_takes_the_agentless_path(tmp_path: Path) -> None:
    runner = agent_runner(FakePve(), hostname=Reply(255, "", "Connection timed out"))
    run = run_cli(["repair", "--vmid", "1", "--ip", GUEST_IP, "--json"], cli_config(tmp_path), runner)
    assert run.exit_code == 1
    assert "never answered ssh" in str(envelope_steps(json_envelope(run.stdout))[-1]["message"])
    assert "qm guest" not in call_labels(runner.calls)


@NEEDS_A_POSIX_STATE_DIR
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


@NEEDS_A_POSIX_STATE_DIR
def test_an_unusable_remote_node_is_refused_before_any_vm_call(tmp_path: Path) -> None:
    config = cli_config(tmp_path)
    config["node"] = {
        **config["node"],
        "host": "pve1",
        "ssh_key": "/keys/node.key",
        "known_hosts_file": NODE_LINK.known_hosts,
    }
    runner = FakeRunner().on("command", Reply(255, "", "Host key verification failed.\n"))
    run = run_cli(["repair", "--vmid", "1", "--json"], config, runner)
    assert run.exit_code == 1
    assert "node root@pve1 is not usable: Host key verification failed." in run.stdout
    assert runner.calls == [NODE_LINK.ssh_argv(["command", "-v", "qm"])]


@NEEDS_A_POSIX_STATE_DIR
def test_the_node_option_names_the_node_the_run_drives(tmp_path: Path) -> None:
    config = cli_config(tmp_path)
    config["node"] = {
        **config["node"],
        "host": "pve9",
        "ssh_key": "/keys/node.key",
        "known_hosts_file": NODE_LINK.known_hosts,
    }
    runner = FakeRunner().on("command", Reply(255, "", "Host key verification failed.\n"))
    run = run_cli(["repair", "--vmid", "1", "--json", "--node", "pve1"], config, runner)
    assert run.exit_code == 1
    assert "node root@pve1 is not usable: Host key verification failed." in run.stdout
    assert runner.calls == [NODE_LINK.ssh_argv(["command", "-v", "qm"])]


def test_no_node_host_anywhere_means_this_machine() -> None:
    assert resolve_link(Settings(), None) is None


def test_the_node_host_setting_builds_the_link_with_the_node_user_and_key() -> None:
    settings = Settings(node=NodeSettings(host="pve1", ssh_user="admin1", ssh_key="/k"))
    assert resolve_link(settings, None) == NodeLink(
        host="pve1", user="admin1", key="/k", known_hosts="~/.ssh/known_hosts"
    )


def test_the_node_option_overrides_the_setting() -> None:
    settings = Settings(node=NodeSettings(host="pve1", ssh_key="/k"))
    assert resolve_link(settings, "pve2") == NodeLink(
        host="pve2", user="root", key="/k", known_hosts="~/.ssh/known_hosts"
    )


def test_the_link_takes_the_node_known_hosts_setting() -> None:
    settings = Settings(node=NodeSettings(host="pve1", ssh_key="/k", known_hosts_file="/kh"))
    assert resolve_link(settings, None) == NodeLink(host="pve1", user="root", key="/k", known_hosts="/kh")


def test_a_node_without_a_node_key_is_refused_by_name() -> None:
    with pytest.raises(PreflightError, match=r"^\[node\] ssh_key is not configured: "):
        resolve_link(Settings(), "pve1")


def test_a_node_option_ssh_could_read_as_an_option_is_a_usage_error(tmp_path: Path) -> None:
    runner = FakeRunner()
    run = run_cli(["repair", "--vmid", "1", "--node=-oX"], cli_config(tmp_path), runner)
    assert run.exit_code == 2
    assert "--node" in run.stderr
    assert runner.calls == []


@NEEDS_A_POSIX_STATE_DIR
def test_repair_with_the_node_option_runs_every_qm_call_on_that_node(tmp_path: Path) -> None:
    config = cli_config(tmp_path)
    config["node"] = {**config["node"], "ssh_key": NODE_LINK.key, "known_hosts_file": NODE_LINK.known_hosts}
    runner = agent_runner(FakePve()).on("command", Reply(0, "/usr/sbin/qm\n", ""))
    run = run_cli(["repair", "--vmid", "1", "--json", "--node", NODE_LINK.host], config, runner)
    assert (run.exit_code, json_envelope(run.stdout)["verdict"]) == (0, "STATE=DONE-OK")
    remote = [call for call in runner.calls if call[0] == "ssh" and call[-2] == NODE_LINK.target]
    assert remote[0] == NODE_LINK.ssh_argv(["command", "-v", "qm"])
    assert any(call[-1].startswith("qm snapshot 1 ") for call in remote)
    assert not any(call[0] == "qm" for call in runner.calls)


@NEEDS_A_POSIX_STATE_DIR
def test_a_bad_snapshot_name_is_refused_before_the_remote_node_is_called(tmp_path: Path) -> None:
    config = cli_config(tmp_path)
    config["node"] = {**config["node"], "ssh_key": NODE_LINK.key, "known_hosts_file": NODE_LINK.known_hosts}
    runner = FakeRunner()
    run = run_cli(["repair", "--vmid", "1", "--snapshot-name", "1x", "--node", NODE_LINK.host], config, runner)
    assert run.exit_code == 1
    assert "--snapshot-name: String should match pattern " in run.stderr
    assert runner.calls == []
