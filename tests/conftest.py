"""Shared pytest fixtures for CLI and module-entry tests.

Centralizes test infrastructure following clean architecture principles:
- All shared fixtures live here
- Tests import fixtures implicitly via pytest's conftest discovery
- Fixtures use descriptive names that read as plain English
"""

from __future__ import annotations

import dataclasses
import logging
import os
import re
import sys
from dataclasses import fields
from pathlib import Path
from typing import TYPE_CHECKING, Any

import lib_cli_exit_tools
import lib_log_rich.runtime
import pytest
import rich_click.rich_click
from cli_fakes import FAILING_COMMAND, FAILING_MESSAGE
from click.testing import CliRunner
from lib_layered_config import Config

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping

    from lib_layered_config.domain.config import SourceInfo

    from pve_winrepair.composition import AppServices

#: Which platforms each ``os_*`` marker lets a test run on. Registering a marker in pyproject only
#: silences pytest's unknown-marker warning; without this table a marked test runs everywhere.
_PLATFORM_MARKERS: dict[str, Callable[[str], bool]] = {
    "os_windows": lambda platform: platform == "win32",
    "os_macos": lambda platform: platform == "darwin",
    "os_linux": lambda platform: platform.startswith("linux"),
    "os_posix": lambda platform: platform != "win32",
}


def pytest_runtest_setup(item: pytest.Item) -> None:
    """Skip a test whose ``os_*`` marker names a platform other than the running one."""
    for name, runs_on in _PLATFORM_MARKERS.items():
        if item.get_closest_marker(name) is not None and not runs_on(sys.platform):
            pytest.skip(f"marked {name}; this is {sys.platform}")


def _load_dotenv() -> None:
    """Load .env file when it exists for integration test configuration."""
    try:
        from dotenv import load_dotenv

        env_file = Path(__file__).parent.parent / ".env"
        if env_file.exists():
            load_dotenv(env_file)
    except ImportError:
        pass


_load_dotenv()

ANSI_ESCAPE_PATTERN = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
CONFIG_FIELDS: tuple[str, ...] = tuple(field.name for field in fields(type(lib_cli_exit_tools.config)))


def _remove_ansi_codes(text: str) -> str:
    """Return *text* stripped of ANSI escape sequences."""
    return ANSI_ESCAPE_PATTERN.sub("", text)


def _snapshot_cli_config() -> dict[str, object]:
    """Capture every attribute from ``lib_cli_exit_tools.config``."""
    return {name: getattr(lib_cli_exit_tools.config, name) for name in CONFIG_FIELDS}


def _restore_cli_config(snapshot: dict[str, object]) -> None:
    """Reapply a configuration snapshot captured by ``_snapshot_cli_config``."""
    for name, value in snapshot.items():
        setattr(lib_cli_exit_tools.config, name, value)


@pytest.fixture
def cli_runner() -> CliRunner:
    """Provide a fresh CliRunner per test.

    Click 8.x provides separate result.stdout and result.stderr attributes.
    Use result.stdout for clean output (e.g., JSON parsing) to avoid
    async log messages from stderr contaminating the output.

    Returns:
        CliRunner: A fresh Click test runner instance.

    Example:
        def test_help(cli_runner: CliRunner) -> None:
            result = cli_runner.invoke(cli, ["--help"])
            assert result.exit_code == 0
    """
    return CliRunner()


def _restore_logging_state(handlers: list[logging.Handler], level: int, propagate: bool) -> None:
    """Shut down a live lib_log_rich runtime and put the root logger back as it was.

    ``runtime.shutdown()`` alone is not enough: production ``init_logging`` also attaches a
    stdlib handler to the root logger and raises its level, and shutting the runtime down
    undoes neither, so a later test's stdlib warnings would be swallowed.
    """
    if lib_log_rich.runtime.is_initialised():
        lib_log_rich.runtime.shutdown()
    root = logging.getLogger()
    root.handlers[:] = handlers
    root.setLevel(level)
    root.propagate = propagate


@pytest.fixture(autouse=True)
def isolated_logging_state() -> Iterator[Callable[[], None]]:
    """Reset the process-global logging state after every test.

    The lib_log_rich runtime and the stdlib root logger are process-global. Once a command
    (under the production or the testing composition) starts a runtime, it would otherwise
    stay live for every later test, so a test would pass or fail by what ran before it rather
    than by its own setup. The root logger is snapshotted before the test and restored after,
    together with shutting the runtime down.

    Yields:
        The same restore step, so a test can apply it mid-test and assert its effect.
    """
    root = logging.getLogger()
    handlers, level, propagate = list(root.handlers), root.level, root.propagate

    def _restore() -> None:
        _restore_logging_state(handlers, level, propagate)

    yield _restore
    _restore()


#: The width every test's CLI output is rendered at. Wider than the 80 columns the assertions were
#: written against, so a message that fits one line there cannot wrap on a narrower runner.
_CLI_OUTPUT_WIDTH = 120


@pytest.fixture(autouse=True)
def deterministic_cli_output(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give every test the same uncoloured, fixed-width CLI output, on any machine and in CI.

    rich-click decides colour and width once, when it is imported, into module globals that each
    command reads again when it formats an error; an environment variable changed per test arrives
    after that import and changes nothing, so the globals are reset here:

    - ``FORCE_TERMINAL`` comes from FORCE_COLOR, PY_COLORS or GITHUB_ACTIONS, and GitHub sets
      GITHUB_ACTIONS on every runner, so CI output was coloured and local output was not.
    - ``WIDTH`` and ``MAX_WIDTH`` come from the terminal, which is 79 columns on the Windows
      runners and 80 elsewhere, so an error box wrapped its message on Windows only.

    rich itself reads FORCE_COLOR whenever a ``Console`` is built, which happens per command, so
    removing the variable for the test reaches it. A console built at import time is out of reach
    of all of this: lib_layered_config's default display console is one, so the
    ``display_config`` tests still see colour when FORCE_COLOR is exported for the whole run.
    """
    monkeypatch.setattr(rich_click.rich_click, "FORCE_TERMINAL", None)
    monkeypatch.setattr(rich_click.rich_click, "WIDTH", _CLI_OUTPUT_WIDTH)
    monkeypatch.setattr(rich_click.rich_click, "MAX_WIDTH", _CLI_OUTPUT_WIDTH)
    monkeypatch.delenv("FORCE_COLOR", raising=False)


@pytest.fixture
def production_factory() -> Callable[[], AppServices]:
    """Provide the production services factory for tests.

    Use this when invoking CLI commands that don't need custom injection.
    Returns the ``build_production`` factory which wires real adapters.

    Returns:
        Callable[[], AppServices]: Factory returning production-wired AppServices.

    Example:
        def test_info(cli_runner: CliRunner, production_factory: Callable[[], AppServices]) -> None:
            result = cli_runner.invoke(cli, ["info"], obj=production_factory)
            assert result.exit_code == 0
    """
    from pve_winrepair.composition import build_production

    return build_production


@pytest.fixture
def user_layer_in_tmp_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point every OS's user-layer location at ``tmp_path`` and return it.

    A deploy then writes under ``tmp_path`` rather than into the real user configuration
    directory, and the developer's own user-layer files cannot decide a result.
    """
    for name in ("HOME", "USERPROFILE", "XDG_CONFIG_HOME", "APPDATA", "LOCALAPPDATA"):
        monkeypatch.setenv(name, str(tmp_path))
    return tmp_path


@pytest.fixture
def strip_ansi() -> Callable[[str], str]:
    """Return a helper that strips ANSI escape sequences from a string.

    Useful for comparing CLI output that may contain rich formatting
    (colors, bold, etc.) against expected plain text.

    Returns:
        Callable[[str], str]: Function that removes ANSI codes from input.

    Example:
        def test_output(cli_runner: CliRunner, strip_ansi: Callable[[str], str]) -> None:
            result = cli_runner.invoke(cli, ["info"])
            plain = strip_ansi(result.output)
            assert "version" in plain
    """

    def _strip(value: str) -> str:
        return _remove_ansi_codes(value)

    return _strip


@pytest.fixture
def managed_traceback_state() -> Iterator[None]:
    """Reset traceback flags to a known baseline and restore after the test.

    Combines the responsibilities of the former ``isolated_traceback_config``
    (reset to clean state) and ``preserve_traceback_state`` (snapshot/restore)
    into a single fixture.  Use this whenever a test reads or mutates the
    global ``lib_cli_exit_tools.config`` traceback flags.

    Yields:
        None: Test runs with isolated traceback state.

    Example:
        def test_traceback_flag(managed_traceback_state: None) -> None:
            lib_cli_exit_tools.config.traceback = True
            # State automatically restored after test
    """
    lib_cli_exit_tools.reset_config()
    lib_cli_exit_tools.config.traceback = False
    lib_cli_exit_tools.config.traceback_force_color = False
    snapshot = _snapshot_cli_config()
    try:
        yield
    finally:
        _restore_cli_config(snapshot)


@pytest.fixture
def failing_command(monkeypatch: pytest.MonkeyPatch) -> str:
    """Register a command that raises ``RuntimeError`` on the root group, for one test only.

    How an uncaught exception is rendered (exit code, ``--traceback``, the module entry) belongs to
    ``main()`` and ``lib_cli_exit_tools``, not to any command, and the CLI ships no command that
    fails on purpose. The test adds one through Click's own registry, which monkeypatch restores.

    Returns:
        The command name to put in argv.
    """
    from pve_winrepair.adapters.cli import cli

    @rich_click.command(FAILING_COMMAND)
    def fail() -> None:
        raise RuntimeError(FAILING_MESSAGE)

    monkeypatch.setitem(cli.commands, FAILING_COMMAND, fail)
    return FAILING_COMMAND


@pytest.fixture
def isolated_layers(monkeypatch: pytest.MonkeyPatch, user_layer_in_tmp_path: Path, clear_config_cache: None) -> Path:
    """Every configuration layer but the shipped defaults points into ``tmp_path``, which is the cwd.

    All three app roots are set because each platform reads its own (``/etc`` on Linux, the
    Application Support root on macOS, ProgramData on Windows); an inherited ``PVE_WINREPAIR___``
    variable would decide a result, so every one is removed.
    """
    root = user_layer_in_tmp_path
    monkeypatch.setenv("LIB_LAYERED_CONFIG_ETC", str(root / "etc"))
    monkeypatch.setenv("LIB_LAYERED_CONFIG_MAC_APP_ROOT", str(root / "macapp"))
    monkeypatch.setenv("LIB_LAYERED_CONFIG_PROGRAMDATA", str(root / "programdata"))
    for name in list(os.environ):
        if name.upper().startswith("PVE_WINREPAIR___"):
            monkeypatch.delenv(name)
    monkeypatch.chdir(root)
    return root


@pytest.fixture
def clear_config_cache() -> Iterator[None]:
    """Clear the get_config lru_cache before each test.

    A test that needs a fresh load after it changed a file calls ``get_config.cache_clear()``
    itself.

    Yields:
        None: Test runs with cleared config cache.

    Example:
        def test_config_reload(clear_config_cache: None) -> None:
            config1 = get_config()
            # Cache was cleared, so this is a fresh load
    """
    from pve_winrepair.adapters.config import loader as config_mod

    config_mod.get_config.cache_clear()
    yield


@pytest.fixture
def config_factory() -> Callable[[dict[str, Any]], Config]:
    """Create real Config instances from test data dicts.

    Builds actual ``lib_layered_config.Config`` objects without filesystem I/O.
    The second argument (empty dict) represents no source provenance info.

    Returns:
        Callable[[dict[str, Any]], Config]: Factory that creates Config from dict.

    Example:
        def test_section(config_factory: Callable[[dict[str, Any]], Config]) -> None:
            config = config_factory({"section": {"hosts": ["host.example.com"]}})
            assert config.get("section.hosts") == ["host.example.com"]
    """

    def _factory(data: dict[str, Any]) -> Config:
        return Config(data, {})

    return _factory


@pytest.fixture
def source_info_factory() -> Callable[[str, str, str | None], SourceInfo]:
    """Create SourceInfo dicts for provenance-tracking tests.

    Reduces coupling to the SourceInfo TypedDict structure.  If
    ``lib_layered_config`` adds or renames keys, only this factory
    needs updating.

    Returns:
        Callable[[str, str, str | None], SourceInfo]: Factory creating SourceInfo dicts.

    Example:
        def test_provenance(source_info_factory: Callable[..., SourceInfo]) -> None:
            info = source_info_factory("section.hosts", "user", "/home/user/.config/...")
            assert info["layer"] == "user"
    """

    def _factory(key: str, layer: str, path: str | None = None) -> SourceInfo:
        return {"layer": layer, "path": path, "key": key}

    return _factory


@pytest.fixture
def inject_config(
    clear_config_cache: None,
) -> Callable[[Config], Callable[[], AppServices]]:
    """Return a factory that provides test services with injected Config.

    Creates a services factory with the injected config loader,
    avoiding filesystem I/O while exercising the real Config API.
    Only replaces the I/O boundary (``get_config``), not the Config object itself.

    Args:
        clear_config_cache: Implicit fixture dependency ensuring cache is cleared.

    Returns:
        Callable[[Config], Callable[[], AppServices]]: Function that accepts a Config
            and returns a services factory callable suitable for ``cli_runner.invoke(obj=...)``.

    Example:
        def test_config_display(
            cli_runner: CliRunner,
            config_factory: Callable[[dict[str, Any]], Config],
            inject_config: Callable[[Config], Callable[[], AppServices]],
        ) -> None:
            config = config_factory({"section": {"key": "value"}})
            factory = inject_config(config)
            result = cli_runner.invoke(cli, ["config"], obj=factory)
            assert "key" in result.output
    """
    from pve_winrepair.adapters.memory import check_logging_config_in_memory, init_logging_in_memory
    from pve_winrepair.composition import build_production

    def _inject(config: Config) -> Callable[[], AppServices]:
        def _fake_get_config(**_kwargs: Any) -> Config:
            return config

        prod = build_production()
        test_services = dataclasses.replace(
            prod,
            get_config=_fake_get_config,
            # The quiet runtime: production init_logging queues INFO lines that race into
            # CliRunner's stderr, so a stderr assertion would depend on timing.
            init_logging=init_logging_in_memory,
            check_logging_config=check_logging_config_in_memory,
        )
        return lambda: test_services

    return _inject


@pytest.fixture
def inject_config_with_profile_capture(
    clear_config_cache: None,
) -> Callable[[Config, list[str | None]], Callable[[], AppServices]]:
    """Return a factory that captures profile arguments during get_config.

    Creates a services factory with a get_config that records profile
    arguments for assertion in tests verifying --profile propagation.

    Args:
        clear_config_cache: Implicit fixture dependency ensuring cache is cleared.

    Returns:
        Callable[[Config, list[str | None]], Callable[[], AppServices]]: Function
            that accepts (Config, capture_list) and returns a services factory.
            Profile values passed to get_config are appended to capture_list.

    Example:
        def test_profile_passed(
            cli_runner: CliRunner,
            config_factory: Callable[[dict[str, Any]], Config],
            inject_config_with_profile_capture: Callable[..., Callable[[], AppServices]],
        ) -> None:
            captured: list[str | None] = []
            config = config_factory({})
            factory = inject_config_with_profile_capture(config, captured)
            cli_runner.invoke(cli, ["--profile", "staging", "config"], obj=factory)
            assert captured == ["staging"]
    """
    from pve_winrepair.adapters.memory import check_logging_config_in_memory, init_logging_in_memory
    from pve_winrepair.composition import build_production

    def _inject(config: Config, captured_profiles: list[str | None]) -> Callable[[], AppServices]:
        def _capturing_get_config(*, profile: str | None = None, **_kwargs: Any) -> Config:
            captured_profiles.append(profile)
            return config

        prod = build_production()
        test_services = dataclasses.replace(
            prod,
            get_config=_capturing_get_config,
            # The quiet runtime: production init_logging queues INFO lines that race into
            # CliRunner's stderr, so a stderr assertion would depend on timing.
            init_logging=init_logging_in_memory,
            check_logging_config=check_logging_config_in_memory,
        )
        return lambda: test_services

    return _inject


@pytest.fixture
def inject_deploy_with_profile_capture(
    clear_config_cache: None,
) -> Callable[[Path, list[str | None]], Callable[[], AppServices]]:
    """Return a factory with deploy_configuration that captures profile arguments.

    Creates a services factory with a deploy_configuration that records
    profile arguments for assertion in tests verifying --profile propagation
    to deployment operations.

    Args:
        clear_config_cache: Implicit fixture dependency ensuring cache is cleared.

    Returns:
        Callable[[Path, list[str | None]], Callable[[], AppServices]]: Function
            that accepts (deployed_path, capture_list) and returns a services factory.
            The fake deploy always returns [deployed_path] and appends profile to capture_list.

    Example:
        def test_deploy_profile(
            cli_runner: CliRunner,
            tmp_path: Path,
            inject_deploy_with_profile_capture: Callable[..., Callable[[], AppServices]],
        ) -> None:
            captured: list[str | None] = []
            factory = inject_deploy_with_profile_capture(tmp_path / "config.toml", captured)
            cli_runner.invoke(cli, ["--profile", "prod", "config-deploy", ...], obj=factory)
            assert captured == ["prod"]
    """
    from pve_winrepair.adapters.memory import check_logging_config_in_memory, init_logging_in_memory
    from pve_winrepair.composition import build_production

    def _inject(deployed_path: Path, captured_profiles: list[str | None]) -> Callable[[], AppServices]:
        def _capturing_deploy(
            *,
            targets: Any,
            force: bool = False,
            profile: str | None = None,
            set_permissions: bool | None = None,
            dir_mode: int | None = None,
            file_mode: int | None = None,
            permission_overrides: Mapping[str, object] | None = None,
        ) -> list[Path]:
            captured_profiles.append(profile)
            return [deployed_path]

        prod = build_production()
        test_services = dataclasses.replace(
            prod,
            deploy_configuration=_capturing_deploy,
            # The quiet runtime: production init_logging queues INFO lines that race into
            # CliRunner's stderr, so a stderr assertion would depend on timing.
            init_logging=init_logging_in_memory,
            check_logging_config=check_logging_config_in_memory,
        )
        return lambda: test_services

    return _inject


@pytest.fixture
def inject_deploy_configuration() -> Callable[[Callable[..., list[Path]]], Callable[[], AppServices]]:
    """Return a factory with a custom deploy_configuration function.

    Creates a services factory with the provided deploy_configuration
    function while keeping other services as production. Use this for
    testing deploy behavior with custom implementations (mocks, spies).

    Returns:
        Callable[[Callable[..., list[Path]]], Callable[[], AppServices]]: Function
            that accepts a deploy function and returns a services factory.

    Example:
        def test_deploy_called(
            cli_runner: CliRunner,
            inject_deploy_configuration: Callable[..., Callable[[], AppServices]],
        ) -> None:
            calls = []
            def spy_deploy(**kwargs) -> list[Path]:
                calls.append(kwargs)
                return [Path("/fake/path")]
            factory = inject_deploy_configuration(spy_deploy)
            cli_runner.invoke(cli, ["config-deploy", "--target", "user"], obj=factory)
            assert len(calls) == 1
    """
    from pve_winrepair.adapters.memory import check_logging_config_in_memory, init_logging_in_memory
    from pve_winrepair.composition import build_production

    def _inject(deploy_fn: Callable[..., list[Path]]) -> Callable[[], AppServices]:
        prod = build_production()
        test_services = dataclasses.replace(
            prod,
            deploy_configuration=deploy_fn,
            # The quiet runtime: production init_logging queues INFO lines that race into
            # CliRunner's stderr, so a stderr assertion would depend on timing.
            init_logging=init_logging_in_memory,
            check_logging_config=check_logging_config_in_memory,
        )
        return lambda: test_services

    return _inject


@pytest.fixture
def inject_test_services() -> Callable[[], Callable[[], AppServices]]:
    """Return the build_testing factory for full in-memory testing.

    For full service replacement with in-memory adapters. Use
    ``inject_config`` or ``config_cli_context`` for more granular control.

    Returns:
        Callable[[], Callable[[], AppServices]]: Function that returns the
            ``build_testing`` factory (in-memory adapters, no filesystem I/O).

    Example:
        def test_with_memory_services(
            cli_runner: CliRunner,
            inject_test_services: Callable[[], Callable[[], AppServices]],
        ) -> None:
            factory = inject_test_services()
            result = cli_runner.invoke(cli, ["config"], obj=factory)
            # Uses in-memory config, no disk access
    """
    from pve_winrepair.composition import build_testing

    def _inject() -> Callable[[], AppServices]:
        return build_testing

    return _inject


@pytest.fixture
def config_cli_context(
    clear_config_cache: None,
) -> Callable[[dict[str, Any]], Callable[[], AppServices]]:
    """Create CLI test context with injected config.

    Combines config creation and injection into a single fixture.
    Simpler than ``inject_config`` when you don't need a pre-built Config object.

    Args:
        clear_config_cache: Implicit fixture dependency ensuring cache is cleared.

    Returns:
        Callable[[dict[str, Any]], Callable[[], AppServices]]: Function that takes
            a config dict and returns a services factory for CLI invocation.

    Example:
        def test_config_display(
            cli_runner: CliRunner,
            config_cli_context: Callable[[dict[str, Any]], Callable[[], AppServices]],
        ) -> None:
            factory = config_cli_context({"section": {"key": "value"}})
            result = cli_runner.invoke(cli, ["config"], obj=factory)
            assert "key" in result.output
    """
    from pve_winrepair.adapters.memory import check_logging_config_in_memory, init_logging_in_memory
    from pve_winrepair.composition import build_production

    def _create(config_data: dict[str, Any]) -> Callable[[], AppServices]:
        config = Config(config_data, {})
        prod = build_production()

        def _fake_get_config(**_kwargs: Any) -> Config:
            return config

        test_services = dataclasses.replace(
            prod,
            get_config=_fake_get_config,
            # The quiet runtime: production init_logging queues INFO lines that race into
            # CliRunner's stderr, so a stderr assertion would depend on timing.
            init_logging=init_logging_in_memory,
            check_logging_config=check_logging_config_in_memory,
        )
        return lambda: test_services

    return _create
