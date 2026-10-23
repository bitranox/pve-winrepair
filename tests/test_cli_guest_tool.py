"""``pve-winrepair guest-tool path`` and ``guest-tool sha256``: the packed tool this install ships."""

from __future__ import annotations

import dataclasses
import hashlib
import os
from pathlib import Path
from typing import TYPE_CHECKING

from click.testing import CliRunner
from guest_fakes import expected_guest_path
from lib_layered_config import ConfigError

from pve_winrepair.adapters.cli.main import main
from pve_winrepair.composition import AppServices, build_testing

if TYPE_CHECKING:
    from collections.abc import Callable


def _run(argv: list[str], services: Callable[[], AppServices] = build_testing) -> tuple[int, str]:
    with CliRunner().isolation() as (stdout, _stderr, _output):
        exit_code = main(argv, services_factory=services)
    # CliRunner's text stream writes each "\n" as os.linesep, as a Windows stdout does: undo that.
    return exit_code, stdout.getvalue().decode("utf-8").replace(os.linesep, "\n")


def test_path_prints_the_packed_tool_this_install_ships() -> None:
    exit_code, stdout = _run(["guest-tool", "path"])
    path = Path(stdout.rstrip("\n"))
    assert exit_code == 0
    assert stdout.endswith("\n") and "\n" not in stdout[:-1]
    assert path.is_absolute()
    assert path.is_file()
    assert path.as_posix().endswith("/guest_tool/winrepair_guest.ps1")


def test_sha256_prints_the_digest_and_the_content_address() -> None:
    _, path = _run(["guest-tool", "path"])
    tool = Path(path.rstrip("\n"))
    exit_code, stdout = _run(["guest-tool", "sha256"])
    assert exit_code == 0
    assert stdout == f"{hashlib.sha256(tool.read_bytes()).hexdigest()}  {expected_guest_path(tool)}\n"


def test_guest_tool_runs_with_a_configuration_that_does_not_load() -> None:
    def broken(**_kwargs: object) -> object:
        raise ConfigError("broken configuration")

    def services() -> AppServices:
        return dataclasses.replace(build_testing(), get_config=broken)

    exit_code, stdout = _run(["guest-tool", "path"], services)
    assert exit_code == 0
    assert stdout.rstrip("\n").endswith("winrepair_guest.ps1")
