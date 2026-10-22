"""Domain-specific exceptions for typed error handling at boundaries."""

from __future__ import annotations


class ConfigurationError(Exception):
    """Missing, invalid, or incomplete configuration.

    Raised when required configuration values are absent, malformed, or
    logically inconsistent. Typically caught at CLI boundaries to provide
    user-friendly error messages.

    Example:
        >>> from pve_winrepair.domain.errors import ConfigurationError
        >>> err = ConfigurationError("No guest configured")
        >>> str(err)
        'No guest configured'
    """


__all__ = [
    "ConfigurationError",
]
