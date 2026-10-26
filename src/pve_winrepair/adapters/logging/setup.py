"""Centralized logging initialization for all entry points.

Provides a single source of truth for lib_log_rich runtime configuration,
eliminating duplication between module entry (__main__.py) and console script
(cli.py) while ensuring initialization happens exactly once.

Contents:
    * :func:`init_logging` - idempotent logging initialization from the ``[lib_log_rich]``
      section and the ``LOG_*`` variables (the environment, plus the ``LOG_*`` lines of a ``.env``).
    * :func:`check_logging_config` - refuse another configuration's logging settings without touching the runtime.
    * :func:`log_variables_hidden` - remove every ``LOG_*`` variable for a block, then put each back.
    * :class:`InvalidLoggingConfigError` - the ``[lib_log_rich]`` section or a ``LOG_*`` variable
      cannot configure logging.
    * :func:`_build_runtime_config` - constructs RuntimeConfig from layered sources.

System Role:
    Lives in the adapters/platform layer. All entry points (module execution,
    console scripts, tests) delegate to this module for logging setup, ensuring
    consistent runtime behavior across invocation paths.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, cast

import lib_log_rich.runtime
from dotenv import dotenv_values
from lib_layered_config import Config, Layer
from pydantic import Field, ValidationError, field_validator, model_validator

from pve_winrepair import __init__conf__
from pve_winrepair.domain.errors import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Generator

    from pydantic_core import ErrorDetails


#: The service name logging reports when the ``[lib_log_rich]`` section names none.
_DEFAULT_SERVICE = __init__conf__.name


class LoggingConfigModel(lib_log_rich.runtime.RuntimeConfig):
    """lib_log_rich's own ``RuntimeConfig``, validated straight from the ``[lib_log_rich]`` section.

    The section is the runtime configuration as written, so it is validated once, into the
    library's model, with three differences from that model: ``service`` defaults to the
    package name (also when it is empty), ``environment`` defaults to ``prod``, and a setting
    written as null keeps lib_log_rich's default. A key the library does not know is ignored,
    as the library ignores it.

    Example:
        >>> model = LoggingConfigModel.model_validate({"service": "myapp", "environment": "staging"})
        >>> model.service, model.environment
        ('myapp', 'staging')

        >>> default = LoggingConfigModel.model_validate({"service": "", "console_theme": None})
        >>> default.service == __init__conf__.name, default.environment, default.console_theme.value
        (True, 'prod', 'dark')
    """

    # lib_layered_config reads an unquoted all-digit .env value as an int; the conversion is
    # lossless, so turning it back into text keeps a digit-only service or environment name valid
    # instead of failing startup. Only these two: every other text setting is lib_log_rich's own.
    service: Annotated[str, Field(coerce_numbers_to_str=True)] = _DEFAULT_SERVICE
    environment: Annotated[str, Field(coerce_numbers_to_str=True)] = "prod"

    @model_validator(mode="before")
    @classmethod
    def _drop_null_settings(cls, data: object) -> object:
        """Leave out every setting written as null, so it keeps its default as an absent one does.

        ``environment`` is the exception: it has no null default to fall back to, and a null
        there is refused as not being text.
        """
        if not isinstance(data, Mapping):
            return data
        section = cast("Mapping[object, object]", data)
        return {key: value for key, value in section.items() if value is not None or key == "environment"}

    @field_validator("service", mode="before")
    @classmethod
    def _empty_service_is_unset(cls, value: object) -> object:
        """An empty ``service`` names the package, as an absent one does."""
        return _DEFAULT_SERVICE if value == "" else value


def _build_runtime_config(config: Config) -> lib_log_rich.runtime.RuntimeConfig:
    """Build RuntimeConfig from a Config object.

    Centralizes the mapping from lib_layered_config to lib_log_rich
    RuntimeConfig. Uses Pydantic for single-parse validation at the boundary.

    Args:
        config: Already-loaded layered configuration object.

    Returns:
        Fully configured runtime settings ready for lib_log_rich.init().

    Raises:
        ValidationError: The section holds a value of the wrong type.

    Note:
        Configuration is read from the [lib_log_rich] section. All parameters
        documented in defaultconfig.toml can be specified. Unspecified values
        use lib_log_rich's built-in defaults. The service and environment
        parameters default to package metadata when not configured.
    """
    section: object = config.get("lib_log_rich", default={})
    # An empty value (a section written as "" or []) configures nothing, like a missing one.
    return LoggingConfigModel.model_validate(section or {})


class InvalidLoggingConfigError(ConfigurationError):
    """lib_log_rich refuses its settings: one ``<key>: <reason>`` in :attr:`problems` per problem.

    The settings are the ``[lib_log_rich]`` section plus any ``LOG_*`` variable. A problem the
    type check of the section finds names the key and never repeats the refused value; one no
    single key owns (TLS over UDP for Graylog) reads ``lib_log_rich: <reason>``. A value only
    lib_log_rich itself refuses, such as an unknown level in ``LOG_CONSOLE_LEVEL`` or in the
    section's ``console_level``, is reported in lib_log_rich's own words, which name the setting
    and repeat the value (``lib_log_rich: Invalid runtime settings: console_level: Unknown log
    level: 'bogus'``).

    Attributes:
        problems: One line per refused setting.

    Example:
        >>> try:
        ...     _build_runtime_config(Config({"lib_log_rich": {"rate_limit": "100:60"}}, {}))
        ... except ValidationError as exc:
        ...     print(InvalidLoggingConfigError(_problems(exc, {"rate_limit": "100:60"})))
        lib_log_rich.rate_limit: Input should be a valid tuple
    """

    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


#: The variables lib_log_rich reads itself; the only lines of a ``.env`` logging takes.
_LOG_VARIABLE_PREFIX = "LOG_"


def _problems(error: BaseException, section: object) -> list[str]:
    """One line per problem: key and reason from the first pydantic error in ``error``'s chain.

    ``section`` is the ``[lib_log_rich]`` section the settings were built from; it tells the keys
    the reader wrote from the tags pydantic adds for each arm of a union. Arms that fail for the
    same reason collapse into one line. A pydantic problem never repeats the refused value; one no
    single key owns (a model-wide check) has no key and reads ``lib_log_rich: <reason>``. Without
    a pydantic error in the chain, the line is lib_log_rich's own first line, which may repeat the
    value (``Invalid runtime settings: console_level: Unknown log level: 'bogus'``).
    """
    cause: BaseException | None = error
    while cause is not None and not isinstance(cause, ValidationError):
        cause = cause.__cause__ or cause.__context__
    if cause is None:
        # Not a pydantic error (e.g. an unknown level name in a LOG_* variable): lib_log_rich's
        # own first line.
        return [f"lib_log_rich: {str(error).splitlines()[0]}"]
    lines = [f"{_problem_key(item['loc'], section)}: {_reason(item)}" for item in cause.errors()]
    return list(dict.fromkeys(lines))


def _reason(item: ErrorDetails) -> str:
    """The reason as its validator wrote it, without the ``Value error, `` pydantic puts in front.

    Example:
        >>> _reason({"type": "value_error", "loc": (), "msg": "Value error, x", "input": 0,
        ...          "ctx": {"error": ValueError("queue_maxsize must be positive")}})
        'queue_maxsize must be positive'
        >>> _reason({"type": "tuple_type", "loc": (), "msg": "Input should be a valid tuple", "input": 0})
        'Input should be a valid tuple'
    """
    error = item.get("ctx", {}).get("error")
    if item["type"] == "value_error" and isinstance(error, ValueError):
        return str(error)
    return item["msg"]


#: pydantic's location part for a refused mapping KEY (not its value).
_KEY_PART = "[key]"


def _problem_key(loc: tuple[int | str, ...], section: object) -> str:
    """``lib_log_rich.<key>`` for a problem located at a key, bare ``lib_log_rich`` for a model-wide one.

    Only the location parts present in ``section`` are keys the reader wrote; every other part is
    a tag pydantic gives one arm of a union (``dict[str,str]``) and is left out. A refused mapping
    key itself ends in `` (key)``.

    Example:
        >>> _problem_key(("rate_limit",), {"rate_limit": "100:60"})
        'lib_log_rich.rate_limit'
        >>> _problem_key(("console_styles", "dict[str,str]", "INFO"), {"console_styles": {"INFO": 3}})
        'lib_log_rich.console_styles.INFO'
        >>> _problem_key(("console_styles", "dict[int-enum[LogLevel],str]", "INFO", "[key]"),
        ...              {"console_styles": {"INFO": 3}})
        'lib_log_rich.console_styles.INFO (key)'
        >>> _problem_key((), {})
        'lib_log_rich'
    """
    parts = ["lib_log_rich"]
    node: object = section
    for index, part in enumerate(loc):
        if part == _KEY_PART:
            return ".".join(parts) + " (key)"
        if index == 0 or _holds(node, part):
            parts.append(str(part))
            node = _child(node, part)
    return ".".join(parts)


def _holds(node: object, part: int | str) -> bool:
    """Whether ``part`` is a key of the mapping, or an index of the list, the reader wrote."""
    if isinstance(node, Mapping):
        return part in cast("Mapping[object, object]", node)
    if isinstance(node, Sequence) and not isinstance(node, str) and isinstance(part, int):
        return 0 <= part < len(cast("Sequence[object]", node))
    return False


def _child(node: object, part: int | str) -> object:
    """The value under ``part``, or None when ``node`` does not hold it."""
    if not _holds(node, part):
        return None
    if isinstance(node, Mapping):
        return cast("Mapping[object, object]", node)[part]
    return cast("Sequence[object]", node)[cast("int", part)]


def _configured_dotenv(config: Config) -> Path | None:
    """The ``.env`` the configuration's dotenv layer was read from, as its provenance records it.

    lib_layered_config turns every ``LOG_*`` line of that file into a top-level key, so a file
    holding one is always found here; a file holding none has nothing for logging anyway.

    Example:
        >>> source = {"layer": "dotenv", "path": "/srv/app/.env", "key": "log_console_level"}
        >>> _configured_dotenv(Config({"log_console_level": "DEBUG"}, {"log_console_level": source})).as_posix()
        '/srv/app/.env'
        >>> _configured_dotenv(Config({}, {})) is None
        True
    """
    for key in config:
        source = config.origin(key)
        if source is not None and source["layer"] == Layer.DOTENV.value and source["path"] is not None:
            return Path(source["path"])
    return None


def _nearest_dotenv() -> Path | None:
    """The first ``.env`` from the working directory up to the filesystem root.

    The same walk lib_layered_config makes for its ``.env`` layer, used when the configuration
    did not load and so cannot say which file it read. There is no project-root stop: the
    loader has none, so a checkout nested in another (a worktree) reads the outer ``.env``.
    Walks by path only: no ``chdir``, and a directory that cannot be read is passed over.
    """
    try:
        start = Path.cwd()
    except OSError:
        return None
    for directory in (start, *start.parents):
        found = _dotenv_in(directory)
        if found is not None:
            return found
    return None


def _dotenv_in(directory: Path) -> Path | None:
    """The ``.env`` file in ``directory``, or None.

    A directory that cannot be read has none: Python before 3.14 raises for a path behind a
    directory without search permission instead of answering False.
    """
    try:
        candidate = directory / ".env"
        return candidate if candidate.is_file() else None
    except OSError:
        return None


def _load_log_variables(config: Config, dotenv_path: str | None) -> None:
    """Copy the ``LOG_*`` lines of a ``.env`` into the environment, never replacing a set variable.

    The file is ``dotenv_path`` when one is given, otherwise the one the configuration loader
    read (it walks past a nested project root and falls back to the ``.env`` in the user
    configuration directory), so a ``LOG_*`` line applies wherever that file's other lines do.
    Only when the configuration did not load is it the first ``.env`` on the loader's own walk.

    Only ``LOG_*``: any other line would be read as the environment layer by a later
    configuration load (``config --profile``, the deploy's permission read). A file that
    cannot be read or decoded is skipped; the configuration loader reports it.
    """
    path = Path(dotenv_path) if dotenv_path is not None else _configured_dotenv(config) or _nearest_dotenv()
    if path is None:
        return
    try:
        values = dotenv_values(path, encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    for name, value in values.items():
        if name.startswith(_LOG_VARIABLE_PREFIX) and value is not None:
            os.environ.setdefault(name, value)


@contextmanager
def log_variables_hidden() -> Generator[None]:
    """Remove every ``LOG_*`` variable from the environment for the block, then put each back.

    Example:
        >>> os.environ["LOG_HIDDEN_PROBE"] = "x"
        >>> with log_variables_hidden():
        ...     "LOG_HIDDEN_PROBE" in os.environ
        False
        >>> os.environ.pop("LOG_HIDDEN_PROBE")
        'x'
    """
    names = [name for name in os.environ if name.startswith(_LOG_VARIABLE_PREFIX)]
    hidden = {name: os.environ.pop(name) for name in names}
    try:
        yield
    finally:
        os.environ.update(hidden)


def _start_default_logging() -> None:
    """Start lib_log_rich with the package defaults; without the ``LOG_*`` variables only if needed.

    lib_log_rich reads the ``LOG_*`` variables from the environment on every init. When the
    refused setting came from the ``[lib_log_rich]`` section, the defaults start with them and
    a valid ``LOG_CONSOLE_LEVEL`` still applies. When one of them is the refused setting, that
    start is refused again, and only then do the defaults start with every ``LOG_*`` hidden.
    """
    try:
        lib_log_rich.runtime.init(_build_runtime_config(Config({}, {})))
    except ValueError:  # pydantic's ValidationError is a ValueError
        with log_variables_hidden():
            lib_log_rich.runtime.init(_build_runtime_config(Config({}, {})))


def init_logging(config: Config, *, dotenv_path: str | None = None) -> None:
    """Initialize lib_log_rich runtime with the provided configuration.

    All entry points need logging configured, but the runtime should only
    be initialized once regardless of how many times this function is called.
    Loads .env files (to make LOG_* variables available), checks if lib_log_rich
    is already initialized, and configures it with settings from the provided
    Config object. Bridges standard Python logging to lib_log_rich for domain
    code compatibility.

    Args:
        config: Already-loaded layered configuration object containing logging
            settings in the [lib_log_rich] section.
        dotenv_path: The ``.env`` the configuration was loaded with (``--env-file``), or None
            to use the ``.env`` the configuration's provenance names (when it did not load: the
            first ``.env`` from the working directory up to the filesystem root, the same walk
            the loader makes).

    Raises:
        InvalidLoggingConfigError: The ``[lib_log_rich]`` section or a ``LOG_*`` variable holds
            a value lib_log_rich refuses. Logging is started anyway, with the package defaults
            and the ``LOG_*`` variables (every one of them ignored if the defaults are refused
            with them too), so the caller can record the failure and run the commands that do
            not read the configuration. Only the first call can raise: logging is running after
            it, so a later call returns at once, also with the same refused configuration.

    Side Effects:
        Copies the ``LOG_*`` lines of that ``.env`` into the process environment on first
        invocation; no other line, and no variable that is already set.
        May initialize the global lib_log_rich runtime on first invocation.
        Subsequent calls have no effect.

    Note:
        This function is safe to call multiple times. The first call loads .env
        and initializes the runtime; subsequent calls check the initialization
        state and return immediately if already initialized.

        The .env loading lets lib_log_rich read its LOG_* variables from a .env file:
        the highest precedence override for logging configuration.

    Example:
        >>> from lib_layered_config import Config
        >>> config = Config({"lib_log_rich": {"environment": "test"}}, {})
        >>> init_logging(config)  # doctest: +SKIP
    """
    if lib_log_rich.runtime.is_initialised():
        return
    _load_log_variables(config, dotenv_path)
    try:
        lib_log_rich.runtime.init(_build_runtime_config(config))
    except ValueError as exc:  # pydantic's ValidationError is a ValueError
        # The type check of the section and lib_log_rich's own range checks (which also see the
        # LOG_* variables) both refuse here; neither has started the runtime.
        _start_default_logging()
        lib_log_rich.runtime.attach_std_logging()
        raise InvalidLoggingConfigError(_problems(exc, _section(config))) from exc
    lib_log_rich.runtime.attach_std_logging()


def check_logging_config(config: Config) -> None:
    """Refuse ``config``'s logging settings as :func:`init_logging` would, without touching the runtime.

    :func:`init_logging` returns at once while a runtime is running, so a configuration loaded
    after logging started (``config --profile``'s reload) would never have its logging settings
    judged. lib_log_rich's ``validate_config`` refuses exactly what its ``init`` refuses, with the
    same message and the same ``LOG_*`` overrides, and neither reads nor replaces the running
    runtime, so logging keeps running with the settings it started with, on every thread.

    Args:
        config: Already-loaded layered configuration object.

    Raises:
        InvalidLoggingConfigError: As for :func:`init_logging`, with the same problem lines.

    Example:
        >>> check_logging_config(Config({"lib_log_rich": {"console_level": "info"}}, {}))
        >>> try:
        ...     check_logging_config(Config({"lib_log_rich": {"rate_limit": "100:60"}}, {}))
        ... except InvalidLoggingConfigError as exc:
        ...     print(exc)
        lib_log_rich.rate_limit: Input should be a valid tuple
    """
    try:
        lib_log_rich.runtime.validate_config(_build_runtime_config(config))
    except ValueError as exc:  # pydantic's ValidationError is a ValueError
        raise InvalidLoggingConfigError(_problems(exc, _section(config))) from exc


def _section(config: Config) -> object:
    """The ``[lib_log_rich]`` section as written, for telling its keys from pydantic's union tags."""
    return config.get("lib_log_rich", default={})


__all__ = [
    "InvalidLoggingConfigError",
    "LoggingConfigModel",
    "check_logging_config",
    "init_logging",
    "log_variables_hidden",
]
