"""Integration tests for config display wrapper.

Tests the thin wrapper that delegates to lib_layered_config's display_config.
The wrapper adds log flushing before display. Core display behavior is tested
in lib_layered_config's test suite.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import TYPE_CHECKING, Any, cast

import pytest
from lib_layered_config import Config

from pve_winrepair import __init__conf__
from pve_winrepair.adapters.config.display import display_config
from pve_winrepair.domain.enums import OutputFormat

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from lib_layered_config.domain.config import SourceInfo

# ======================== display_config - error paths ========================


@pytest.mark.os_agnostic
def test_display_config_raises_for_nonexistent_section(
    config_factory: Callable[[dict[str, Any]], Config],
) -> None:
    """Requesting a section that doesn't exist must raise ValueError."""
    config = config_factory({"existing_section": {"key": "value"}})
    with pytest.raises(ValueError, match="not found"):
        display_config(config, output_format=OutputFormat.HUMAN, section="nonexistent")


@pytest.mark.os_agnostic
def test_display_config_raises_for_nonexistent_section_json(
    config_factory: Callable[[dict[str, Any]], Config],
) -> None:
    """Requesting a nonexistent section in JSON format must also raise ValueError."""
    config = config_factory({"existing_section": {"key": "value"}})
    with pytest.raises(ValueError, match="not found"):
        display_config(config, output_format=OutputFormat.JSON, section="nonexistent")


# ======================== display_config - wrapper integration ========================


@pytest.mark.os_agnostic
def test_display_human_renders_output(capsys: pytest.CaptureFixture[str]) -> None:
    """Wrapper must produce human-readable output via lib_layered_config."""
    config = Config({"app_name": "myapp", "section": {"key": "val"}}, {})
    display_config(config, output_format=OutputFormat.HUMAN)
    output = capsys.readouterr().out

    assert 'app_name = "myapp"' in output
    assert "[section]" in output


@pytest.mark.os_agnostic
def test_display_json_renders_output(capsys: pytest.CaptureFixture[str]) -> None:
    """Wrapper must produce JSON output via lib_layered_config."""
    config = Config({"section": {"key": "value"}}, {})
    display_config(config, output_format=OutputFormat.JSON)
    output = capsys.readouterr().out

    assert '"section"' in output
    assert '"key": "value"' in output


@pytest.mark.os_agnostic
def test_display_human_renders_profile_in_provenance(
    capsys: pytest.CaptureFixture[str],
    source_info_factory: Callable[..., SourceInfo],
) -> None:
    """Profile name must pass through to lib_layered_config."""
    metadata: dict[str, SourceInfo] = {
        "section.key": source_info_factory("section.key", "user", "/home/user/.config/app/config.toml"),
    }
    config = Config({"section": {"key": "value"}}, metadata)

    display_config(config, output_format=OutputFormat.HUMAN, profile="production")

    output = capsys.readouterr().out
    assert "# layer:user profile:production" in output


# ======================== Falsey value handling ========================


@pytest.mark.os_agnostic
def test_display_config_displays_section_with_zero_value(capsys: pytest.CaptureFixture[str]) -> None:
    """Section with integer zero value must display (not raise as 'not found')."""
    config = Config({"section": {"count": 0}}, {})

    display_config(config, output_format=OutputFormat.HUMAN, section="section")

    output = capsys.readouterr().out
    assert "count = 0" in output


@pytest.mark.os_agnostic
def test_display_config_displays_section_with_false_value(capsys: pytest.CaptureFixture[str]) -> None:
    """Section with boolean False value must display (not raise as 'not found')."""
    config = Config({"section": {"enabled": False}}, {})

    display_config(config, output_format=OutputFormat.HUMAN, section="section")

    output = capsys.readouterr().out
    # TOML uses lowercase 'false', not Python's 'False'
    assert "enabled = false" in output


@pytest.mark.os_agnostic
def test_display_config_json_displays_section_with_falsey_values(capsys: pytest.CaptureFixture[str]) -> None:
    """JSON format with falsey values must display (not raise as 'not found')."""
    config = Config({"section": {"count": 0, "enabled": False, "items": []}}, {})

    display_config(config, output_format=OutputFormat.JSON, section="section")

    output = capsys.readouterr().out
    assert '"count": 0' in output
    assert '"enabled": false' in output
    assert '"items": []' in output


# ======================== config: what is redacted ========================

_PREFIX = __init__conf__.LAYEREDCONF_SLUG.upper().replace("-", "_")
_HOMES = ("HOME", "USERPROFILE", "XDG_CONFIG_HOME", "APPDATA", "LOCALAPPDATA")


def _config_json(tmp_path: Path, *options: str) -> dict[str, Any]:
    """Run the real ``config --format json`` with every configuration location under ``tmp_path``."""
    env = {k: v for k, v in os.environ.items() if not k.startswith((_PREFIX, "LOG_", "LIB_LAYERED_CONFIG"))}
    env.update(dict.fromkeys(_HOMES, str(tmp_path)))
    completed = subprocess.run(  # noqa: S603 - fixed argv: this interpreter running this package
        [sys.executable, "-m", "pve_winrepair", *options, "config", "--format", "json"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return cast("dict[str, Any]", json.loads(completed.stdout))


def _value(shown: dict[str, Any], dotted: str) -> object:
    node: Any = shown
    for part in dotted.split("."):
        node = node[part]
    return cast("object", node)


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "options", [(), ("--set", "lib_log_rich.payload_limits.context_max_keys=30")], ids=["loaded", "with-set"]
)
def test_config_shows_the_logging_key_counts_and_still_redacts_the_password(
    tmp_path: Path, options: tuple[str, ...]
) -> None:
    """``*_max_keys`` are counts whose names only look secret; a password stays hidden."""
    shown = _config_json(tmp_path, "--set", "remote.password=hunter2", *options)

    assert _value(shown, "lib_log_rich.payload_limits.context_max_keys") == (30 if options else 20)
    assert _value(shown, "lib_log_rich.payload_limits.extra_max_keys") == 25
    assert _value(shown, "remote.password") == "***REDACTED***"


@pytest.mark.os_agnostic
@pytest.mark.parametrize("field", ["password", "secret", "token"])
def test_config_shows_the_shipped_scrub_patterns_but_hides_an_added_one(tmp_path: Path, field: str) -> None:
    """A scrub pattern is a regex naming what to hide; only an application-added field stays redacted."""
    shown = _config_json(tmp_path, "--set", "lib_log_rich.scrub_patterns.api_key=.+")

    assert _value(shown, f"lib_log_rich.scrub_patterns.{field}") == ".+"
    assert _value(shown, "lib_log_rich.scrub_patterns.api_key") == "***REDACTED***"
