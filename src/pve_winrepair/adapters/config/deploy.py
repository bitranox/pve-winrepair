"""Deploy default configuration to app/host/user target directories."""

from __future__ import annotations

import re
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Final

from lib_layered_config import deploy_config
from lib_layered_config.examples.deploy import DeployAction

from pve_winrepair import __init__conf__
from pve_winrepair.adapters.config.loader import get_default_config_path, validate_profile

if TYPE_CHECKING:
    from collections.abc import Generator, Mapping, Sequence

    from pve_winrepair.domain.enums import DeployTarget

_DEPLOYED_ACTIONS = frozenset({DeployAction.CREATED, DeployAction.OVERWRITTEN})

#: The ``defaultconfig.d`` files deployed as documentation only, every setting commented out. A
#: deploy writes the host or user layer, which is read after the app layer
#: (``/etc/pve-winrepair/config.toml``, where a site's settings live), so an active key in a deployed
#: copy would hide the app file's value for that key. The package's own file stays as it is: it is
#: the defaults layer.
DOCUMENTATION_ONLY: Final[frozenset[str]] = frozenset({"20-winrepair.toml"})

#: A ``[table]`` header, kept active so an uncommented key lands in its own table. An
#: ``[[array-of-tables]]`` header is not matched: it creates a value, so it is commented like a key.
_TABLE_HEADER = re.compile(r"\s*\[(?!\[)[^\]]*\]\s*(#.*)?")

_COMMENTED_HEADER: Final[str] = (
    "# Deployed by `pve-winrepair config-deploy` with every setting commented out: this file\n"
    "# documents the settings and sets none of them, so the values in the app file\n"
    "# (/etc/pve-winrepair/config.toml on Linux) stay in force. Uncomment a line to set that value\n"
    "# in this layer; it then hides the app file's value for that key.\n"
    "\n"
)


def commented_settings(text: str) -> str:
    r"""Return *text* with every setting commented out, for a deployed documentation copy.

    A line stays as it is when it is blank, already a comment, or a ``[table]`` header; every other
    line (a key, an ``[[array-of-tables]]`` header, a continuation of a multi-line value) gets
    ``# `` in front. Line endings are kept. A short note on top says why the file sets nothing.
    The rule reads lines, not TOML: a multi-line string holding a line that starts with ``#`` would
    keep that line's text, which is why a test loads the shipped files' result and requires every
    table empty.

    Args:
        text: The shipped TOML text.

    Returns:
        The same document with every setting commented out and the note on top.

    Example:
        >>> shipped = '[ssh]\n# Purpose: the account\nuser = "admin"\n'
        >>> print(commented_settings(shipped).split("\n\n", 1)[1], end="")
        [ssh]
        # Purpose: the account
        # user = "admin"
    """
    lines = text.splitlines(keepends=True)
    newline = "\r\n" if lines and lines[0].endswith("\r\n") else "\n"
    out = [_COMMENTED_HEADER.replace("\n", newline)]
    for line in lines:
        body = line.rstrip("\r\n")
        keep = not body.strip() or body.lstrip().startswith("#") or _TABLE_HEADER.fullmatch(body) is not None
        out.append(line if keep else f"# {line}")
    return "".join(out)


@contextmanager
def _staged_source(source: Path) -> Generator[Path]:
    """Yield a temporary copy of *source* and its ``.d`` directory, the documentation-only files commented.

    lib_layered_config deploys a source file and its companion ``.d`` directory byte for byte, so
    the deployed text is staged here rather than kept as a second copy of the defaults in the
    package. The copy is deterministic: a ``--force`` deploy over an identical file writes nothing.
    """
    source_dot_d = source.with_suffix(".d")
    with tempfile.TemporaryDirectory(prefix=f"{__init__conf__.LAYEREDCONF_SLUG}-deploy-") as tmp:
        staged = Path(tmp) / source.name
        shutil.copyfile(source, staged)
        staged_dot_d = staged.with_suffix(".d")
        staged_dot_d.mkdir()
        for path in sorted(source_dot_d.iterdir()):
            target = staged_dot_d / path.name
            if path.name in DOCUMENTATION_ONLY:
                text = path.read_bytes().decode("utf-8")
                target.write_bytes(commented_settings(text).encode("utf-8"))
            else:
                shutil.copyfile(path, target)
        yield staged


def deploy_configuration(
    *,
    targets: Sequence[DeployTarget],
    force: bool = False,
    profile: str | None = None,
    set_permissions: bool | None = None,
    dir_mode: int | None = None,
    file_mode: int | None = None,
    permission_overrides: Mapping[str, object] | None = None,
) -> list[Path]:
    r"""Deploy default configuration to specified target layers.

    Users need to initialize configuration files in standard locations
    (application, host, or user config directories) without manually
    copying files or knowing platform-specific paths. Uses
    lib_layered_config.deploy_config() to copy the bundled defaultconfig.toml
    and its ``defaultconfig.d`` files to requested target layers (app, host, user).
    ``20-winrepair.toml`` is deployed with every setting commented out
    (:data:`DOCUMENTATION_ONLY`), so a deploy sets no winrepair value and the
    app file keeps deciding them; ``40-layered-config.toml`` and ``90-logging.toml``
    are deployed as shipped, with their keys active.

    Args:
        targets: Sequence of DeployTarget enum values specifying target layers.
            Valid values: DeployTarget.APP, DeployTarget.HOST, DeployTarget.USER.
            Multiple targets can be specified to deploy to several locations at once.
        force: If True, overwrite existing configuration files. If False (default),
            skip files that already exist.
        profile: Optional profile name for environment isolation. When specified,
            configuration is deployed to profile-specific subdirectories
            (e.g., ~/.config/slug/profile/<name>/config.toml).
        set_permissions: True sets Unix modes on the files and directories written, False
            leaves them to the umask, None (default) lets lib_layered_config follow the
            configured ``[lib_layered_config.default_permissions].enabled`` (on when unset).
            Each mode not given explicitly comes from that section for the target's layer,
            else the built-in one (755/644 for app/host, 700/600 for user). lib_layered_config
            reads the section itself, from the bundled defaults, the app, host and user files
            this call does not write, and the environment - never from ``.env``.
        dir_mode: Directory mode for every target (octal integer, e.g., 0o750), overriding
            the configured and built-in ones.
        file_mode: File mode for every target (octal integer, e.g., 0o640), overriding
            the configured and built-in ones.
        permission_overrides: Runtime values for keys of
            ``[lib_layered_config.default_permissions]`` by setting name
            (``{"user_file": "0o640"}``), laid over lib_layered_config's own read of the
            section and validated like configured values.

    Returns:
        List of paths where configuration files were created or would be created.
        Empty list if all target files already exist and force=False.

    Raises:
        PermissionError: When deploying to app/host without sufficient privileges.
        ValueError: When invalid target names are provided.
        DeployModeError: A mode is unsafe, or one was given with ``set_permissions=False``.
        DeployPermissionsError: The permission settings cannot be read or are invalid, or a
            ``permission_overrides`` value is refused; nothing has been written.

    Side Effects:
        Creates configuration files in platform-specific directories:
        - app: System-wide application config (requires privileges)
        - host: System-wide host config (requires privileges)
        - user: User-specific config (current user's home directory)

    Note:
        Platform-specific paths (without profile):
        - Linux (app): /etc/xdg/{slug}/config.toml
        - Linux (host): /etc/xdg/{slug}/hosts/{hostname}.toml
        - Linux (user): ~/.config/{slug}/config.toml
        - macOS (app): /Library/Application Support/{vendor}/{app}/config.toml
        - macOS (host): /Library/Application Support/{vendor}/{app}/hosts/{hostname}.toml
        - macOS (user): ~/Library/Application Support/{vendor}/{app}/config.toml
        - Windows (app): C:\ProgramData\{vendor}\{app}\config.toml
        - Windows (host): C:\ProgramData\{vendor}\{app}\hosts\{hostname}.toml
        - Windows (user): %APPDATA%\{vendor}\{app}\config.toml

        Platform-specific paths (with profile='production'):
        - Linux (user): ~/.config/{slug}/profile/production/config.toml
        - Linux (host): /etc/xdg/{slug}/profile/production/hosts/{hostname}.toml
        - etc.
    """
    if profile is not None:
        validate_profile(profile)
    # Convert enum values to strings for lib_layered_config
    target_strings = [t.value for t in targets]

    with _staged_source(get_default_config_path()) as source:
        results = deploy_config(
            source=source,
            vendor=__init__conf__.LAYEREDCONF_VENDOR,
            app=__init__conf__.LAYEREDCONF_APP,
            slug=__init__conf__.LAYEREDCONF_SLUG,
            profile=profile,
            targets=target_strings,
            force=force,
            set_permissions=set_permissions,
            dir_mode=dir_mode,
            file_mode=file_mode,
            permission_overrides=permission_overrides,
        )

    # Extract paths where files were actually created or overwritten
    paths: list[Path] = []
    for result in results:
        if result.action in _DEPLOYED_ACTIONS:
            paths.append(result.destination)
        paths.extend(
            dot_d_result.destination
            for dot_d_result in result.dot_d_results
            if dot_d_result.action in _DEPLOYED_ACTIONS
        )
    return paths


__all__ = [
    "DOCUMENTATION_ONLY",
    "commented_settings",
    "deploy_configuration",
]
