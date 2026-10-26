"""Configuration loader with caching and profile/override support."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Final, Protocol, cast

from lib_layered_config import (
    DEFAULT_MAX_PROFILE_LENGTH,
    Config,
    read_config,
    validate_profile_name,
)
from lib_layered_config import ValidationError as _LibValidationError

from pve_winrepair import __init__conf__

#: Dotted paths whose names look secret to lib_layered_config's redaction but hold no secret, so
#: ``config`` shows their values: the ``*_max_keys`` limits are plain counts, and the shipped
#: ``scrub_patterns`` fields hold the regex that says what the log scrubber hides, which a reader
#: needs to see to check the scrubbing; ``ssh.strict_host_key_checking`` is a yes/no switch whose
#: name holds ``key``; ``node.ssh_key`` is the PATH of a key file, shown like ``ssh.key`` (whose
#: name the redaction does not match), never key material. A field an operator adds to
#: ``scrub_patterns`` is not declared and stays redacted. Every Config this application builds
#: carries the declaration: the loader passes it to ``read_config``, and ``--set`` rebuilds pass it on.
NOT_SENSITIVE: Final[tuple[str, ...]] = (
    "lib_log_rich.payload_limits.context_max_keys",
    "lib_log_rich.payload_limits.extra_max_keys",
    "lib_log_rich.scrub_patterns.password",
    "lib_log_rich.scrub_patterns.secret",
    "lib_log_rich.scrub_patterns.token",
    "node.ssh_key",
    "ssh.strict_host_key_checking",
)


class ConfigLoaderProtocol(Protocol):
    """Protocol for config loader with cache_clear method."""

    def __call__(
        self, *, profile: str | None = None, start_dir: str | None = None, dotenv_path: str | None = None
    ) -> Config: ...
    def cache_clear(self) -> None: ...


def validate_profile(profile: str, max_length: int | None = None) -> None:
    """Validate profile name using lib_layered_config.

    Delegates to lib_layered_config.validate_profile_name() which provides
    comprehensive validation including length limits, character restrictions,
    Windows reserved name checks, and path traversal prevention.

    Args:
        profile: The profile name to validate.
        max_length: Optional maximum length. Defaults to DEFAULT_MAX_PROFILE_LENGTH (64).

    Raises:
        ValueError: If profile name is invalid (empty, too long, invalid chars,
            Windows reserved name, path traversal attempt, etc.).

    Examples:
        >>> validate_profile("production")  # valid, no exception

        >>> validate_profile("staging-v2")  # hyphens allowed

        >>> validate_profile("../etc/passwd")  # doctest: +IGNORE_EXCEPTION_DETAIL
        Traceback (most recent call last):
        ...
        ValueError: profile contains invalid characters: ../etc/passwd

        >>> validate_profile("a" * 65)  # doctest: +IGNORE_EXCEPTION_DETAIL
        Traceback (most recent call last):
        ...
        ValueError: profile exceeds maximum length...
    """
    length = max_length if max_length is not None else DEFAULT_MAX_PROFILE_LENGTH
    try:
        validate_profile_name(profile, max_length=length)
    except _LibValidationError as exc:
        # Normalise the dependency's exception to the documented ValueError contract so callers'
        # `except ValueError` guards catch every invalid profile uniformly.
        raise ValueError(str(exc)) from exc


@lru_cache(maxsize=1)
def get_default_config_path() -> Path:
    """Return the path to the bundled default configuration file.

    The default configuration ships with the package and needs to be
    locatable at runtime regardless of how the package is installed.
    Uses __file__ to locate the defaultconfig.toml file relative to this
    module.

    Returns:
        Absolute path to defaultconfig.toml.

    Note:
        This function is cached since the path never changes during runtime.

    Example:
        >>> path = get_default_config_path()
        >>> path.name
        'defaultconfig.toml'
        >>> path.exists()
        True
    """
    return Path(__file__).parent / "defaultconfig.toml"


# Configuration is loaded once per (profile, start_dir) tuple and cached
# for the process lifetime. Intentional for a short-lived CLI process.
@lru_cache(maxsize=4)
def _get_config_impl(
    *, profile: str | None = None, start_dir: str | None = None, dotenv_path: str | None = None
) -> Config:
    """Internal cached implementation of config loading.

    Profile validation must be done by caller before invoking this function.
    """
    return read_config(
        vendor=__init__conf__.LAYEREDCONF_VENDOR,
        app=__init__conf__.LAYEREDCONF_APP,
        slug=__init__conf__.LAYEREDCONF_SLUG,
        profile=profile,
        default_file=get_default_config_path(),
        start_dir=start_dir,
        dotenv_path=dotenv_path,
        not_sensitive=NOT_SENSITIVE,
    )


def _get_config(*, profile: str | None = None, start_dir: str | None = None, dotenv_path: str | None = None) -> Config:
    """Load layered configuration with application defaults.

    Centralizes configuration loading so all entry points use the same
    precedence rules and default values without duplicating the discovery
    logic. Uses lru_cache to avoid redundant file reads when called from
    multiple modules.

    Loads configuration from multiple sources in precedence order:
    defaults → app → host → user → dotenv → env

    The vendor, app, and slug identifiers determine platform-specific paths:
    - Linux: Uses XDG directories with slug
    - macOS: Uses Library/Application Support with vendor/app
    - Windows: Uses ProgramData/AppData with vendor/app

    When a profile is specified, configuration is loaded from profile-specific
    subdirectories (e.g., ~/.config/slug/profile/<name>/config.toml).

    Args:
        profile: Optional profile name for environment isolation. When specified,
            a ``profile/<name>/`` subdirectory is inserted into all configuration
            paths. Valid names: alphanumeric, hyphens, underscores. Examples:
            'test', 'production', 'staging-v2'. Defaults to None (no profile).
        start_dir: Optional directory that seeds .env discovery. Defaults to current
            working directory when None.
        dotenv_path: Optional explicit path to a ``.env`` file. When set, this
            file is loaded directly instead of searching upward from *start_dir*.

    Returns:
        Immutable configuration object with provenance tracking.

    Note:
        This function is cached (maxsize=4). The first call loads and parses all
        configuration files; subsequent calls with the same parameters return the
        cached Config instance immediately.

    Example:
        >>> config = get_config()
        >>> isinstance(config.as_dict(), dict)
        True
        >>> config.get("nonexistent", default="fallback")
        'fallback'

        >>> # Load production profile
        >>> prod_config = get_config(profile="production")  # doctest: +SKIP

    See Also:
        lib_layered_config.read_config: Underlying configuration loader.
    """
    if profile is not None:
        validate_profile(profile)
    return _get_config_impl(profile=profile, start_dir=start_dir, dotenv_path=dotenv_path)


def _cache_clear() -> None:
    """Clear the internal configuration cache.

    Call this function to invalidate cached configuration and force a fresh
    read from disk on the next ``get_config()`` call. Useful in tests or when
    configuration files have been modified during runtime.

    Example:
        >>> get_config.cache_clear()  # Force re-read on next call
    """
    _get_config_impl.cache_clear()


# Attach cache_clear method to satisfy ConfigLoaderProtocol.
# Required because lru_cache's cache_clear isn't visible to static type checkers
# when the decorated function is later cast to a Protocol type. The type: ignore
# is necessary since we're dynamically adding an attribute to a function object.
_get_config.cache_clear = _cache_clear  # type: ignore[attr-defined]
get_config: ConfigLoaderProtocol = cast("ConfigLoaderProtocol", _get_config)


__all__ = [
    "NOT_SENSITIVE",
    "get_config",
    "get_default_config_path",
    "validate_profile",
]
