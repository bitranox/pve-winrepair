"""Tests for the logging configuration model.

LoggingConfigModel validation is tested here. The init_logging function
is tested via CLI integration tests in test_cli_core.py.
"""

from __future__ import annotations

import lib_log_rich.runtime
import pytest
from pydantic import ValidationError

from pve_winrepair import __init__conf__
from pve_winrepair.adapters.logging.setup import LoggingConfigModel


@pytest.mark.os_agnostic
def test_the_section_validates_into_lib_log_rich_s_own_runtime_config() -> None:
    """The section is validated once, into the model lib_log_rich.init() takes."""
    parsed = LoggingConfigModel.model_validate({"service": "test", "environment": "dev", "console_theme": "light"})

    assert isinstance(parsed, lib_log_rich.runtime.RuntimeConfig)
    assert (parsed.service, parsed.environment, parsed.console_theme) == ("test", "dev", "light")


@pytest.mark.os_agnostic
def test_a_key_lib_log_rich_does_not_know_is_ignored() -> None:
    """An unknown key is dropped, as lib_log_rich's RuntimeConfig drops it."""
    parsed = LoggingConfigModel.model_validate({"custom_field": "value"})

    assert "custom_field" not in parsed.model_dump()


@pytest.mark.os_agnostic
def test_logging_config_model_defaults() -> None:
    """Empty input names the package as the service and runs in prod."""
    parsed = LoggingConfigModel.model_validate({})

    assert parsed.service == __init__conf__.name
    assert parsed.environment == "prod"


@pytest.mark.os_agnostic
def test_an_empty_service_names_the_package() -> None:
    assert LoggingConfigModel.model_validate({"service": ""}).service == __init__conf__.name


@pytest.mark.os_agnostic
def test_a_null_setting_keeps_lib_log_rich_s_default() -> None:
    """A null keeps the library default instead of being refused or replacing it."""
    parsed = LoggingConfigModel.model_validate({"service": None, "console_theme": None, "ring_buffer_size": None})

    default = lib_log_rich.runtime.RuntimeConfig(service="s", environment="e")
    assert parsed.service == __init__conf__.name
    assert parsed.console_theme == default.console_theme
    assert parsed.ring_buffer_size == default.ring_buffer_size


@pytest.mark.os_agnostic
def test_a_null_environment_is_refused() -> None:
    with pytest.raises(ValidationError) as caught:
        LoggingConfigModel.model_validate({"environment": None})

    assert [error["loc"] for error in caught.value.errors()] == [("environment",)]


@pytest.mark.os_agnostic
def test_a_number_becomes_text_only_for_service_and_environment() -> None:
    """The digit coercion covers the two names, never lib_log_rich's own text settings."""
    parsed = LoggingConfigModel.model_validate({"service": 4711, "environment": 7})
    assert (parsed.service, parsed.environment) == ("4711", "7")

    with pytest.raises(ValidationError):
        LoggingConfigModel.model_validate({"graylog_protocol": 5})
