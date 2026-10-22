"""Digit-only ``.env`` values reach every text setting as the text the operator wrote.

lib_layered_config's dotenv and environment layers turn an unquoted value into an int whenever
that number reads back as the same text (``4711`` -> ``4711``). A text setting must therefore
accept such a number and keep its digits; otherwise a perfectly ordinary ``.env`` line stops the
program at startup.

These tests load a real ``.env`` through the real loader, so a change in the library's coercion
shows up here rather than on a deployed host.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from pve_winrepair.adapters.logging.setup import (
    _build_runtime_config,  # pyright: ignore[reportPrivateUsage]
)
from pve_winrepair.composition import build_production

if TYPE_CHECKING:
    from pathlib import Path

    from lib_layered_config import Config


def _load_dotenv(tmp_path: Path, line: str) -> Config:
    dotenv = tmp_path / ".env"
    dotenv.write_text(f"{line}\n", encoding="utf-8")
    return build_production().get_config(dotenv_path=str(dotenv))


@pytest.mark.os_agnostic
@pytest.mark.parametrize("key", ["SERVICE", "ENVIRONMENT"])
def test_a_digit_only_logging_name_reaches_lib_log_rich_as_its_text(
    user_layer_in_tmp_path: Path, clear_config_cache: None, key: str
) -> None:
    config = _load_dotenv(user_layer_in_tmp_path, f"LIB_LOG_RICH__{key}=4711")
    # Premise: the library hands the value over as a number. Without it the test proves nothing.
    assert isinstance(config.get("lib_log_rich", {})[key.lower()], int)

    runtime = _build_runtime_config(config)

    assert getattr(runtime, key.lower()) == "4711"


@pytest.mark.os_agnostic
def test_an_invalid_logging_value_is_still_refused(user_layer_in_tmp_path: Path, clear_config_cache: None) -> None:
    config = _load_dotenv(user_layer_in_tmp_path, "LIB_LOG_RICH__SERVICE=[1, 2]")

    with pytest.raises(ValidationError):
        _build_runtime_config(config)
