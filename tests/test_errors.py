"""Domain error types: instantiation and message preservation."""

from __future__ import annotations

import pytest

from pve_winrepair.domain.errors import ConfigurationError


@pytest.mark.os_agnostic
def test_configuration_error_preserves_message() -> None:
    """Instantiation stores the message for display."""
    exc = ConfigurationError("guest not configured")
    assert str(exc) == "guest not configured"
