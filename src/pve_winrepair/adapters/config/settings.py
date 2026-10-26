"""Turn a loaded configuration into the node CLI's typed settings.

``load_settings`` validates the ``[ssh] [guest] [repair] [node]`` sections of a ``Config`` into
:class:`~pve_winrepair.domain.settings.Settings`. A refused value raises :class:`SettingsError` with
one ``<section>.<field>: <reason>`` line per problem, built from pydantic's structured errors and
never from ``str(ValidationError)``, which repeats the refused input (a key path may hold a secret).

A top-level section (a table) that neither the settings nor the libraries read is refused too, one
``<section>: not a section pve-winrepair reads (...)`` line each, in the same error: a misspelt
section would otherwise be skipped as silently as a misspelt key used to be. The usual source is a
``.env`` line written with the environment prefix, which lands in a section of that name. A
top-level key that is not a table is no section and is left alone: a ``.env`` line without a
``__`` separator, such as lib_log_rich's own ``LOG_CONSOLE_LEVEL``, arrives that way.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Final

from lib_layered_config import default_env_prefix
from pydantic import ValidationError

from pve_winrepair import __init__conf__
from pve_winrepair.domain.settings import Settings

if TYPE_CHECKING:
    from lib_layered_config import Config
    from pydantic_core import ErrorDetails

#: The configuration sections the settings model reads.
SECTIONS: Final[tuple[str, ...]] = ("ssh", "guest", "repair", "node")

#: The sections the libraries read: lib_log_rich its logging settings, lib_layered_config the
#: ``config-deploy`` permissions. Any other section (a top-level table) is refused.
LIBRARY_SECTIONS: Final[tuple[str, ...]] = ("lib_log_rich", "lib_layered_config")

_READ_SECTIONS: Final[tuple[str, ...]] = (*SECTIONS, *LIBRARY_SECTIONS)

#: The prefix an environment variable carries and a ``.env`` line must not: lib_layered_config
#: reads ``.env`` lines as ``SECTION__KEY``, so ``PVE_WINREPAIR___SSH__KEY`` there becomes the
#: section below, holding ``_ssh.key``.
_ENV_PREFIX: Final[str] = default_env_prefix(__init__conf__.LAYEREDCONF_SLUG)
_PREFIX_SECTION: Final[str] = _ENV_PREFIX.removesuffix("___").lower()


class SettingsError(ValueError):
    """The configuration holds a section nothing reads, or a value the settings refuse.

    ``lines`` holds one ``<section>: <reason>`` or ``<section>.<field>: <reason>`` line per
    problem; ``str()`` joins them.

    Example:
        >>> error = SettingsError(("ssh.keyy: Extra inputs are not permitted",))
        >>> str(error)
        'ssh.keyy: Extra inputs are not permitted'
    """

    def __init__(self, lines: tuple[str, ...]) -> None:
        super().__init__("\n".join(lines))
        self.lines = lines


def load_settings(config: Config) -> Settings:
    """Validate the node CLI's sections of ``config``; an absent section takes its defaults.

    Args:
        config: The loaded layered configuration.

    Returns:
        The validated settings.

    Raises:
        SettingsError: ``config`` holds a section nothing reads, or a section holds an unknown key
            or a value its field refuses; every problem gets its line, the unknown sections first.

    Example:
        >>> from lib_layered_config import Config
        >>> load_settings(Config({"ssh": {"user": "admin"}}, {})).ssh.user
        'admin'
        >>> load_settings(Config({"repiar": {}}, {}))
        Traceback (most recent call last):
        ...
        pve_winrepair.adapters.config.settings.SettingsError: repiar: not a section pve-winrepair reads (...)
    """
    data = config.as_dict()
    unknown = tuple(
        _unknown_section_line(name)
        for name, value in data.items()
        if isinstance(value, Mapping) and name not in _READ_SECTIONS
    )
    try:
        settings = Settings.model_validate({name: data.get(name, {}) for name in SECTIONS})
    except ValidationError as error:
        raise SettingsError((*unknown, *(_line(item) for item in error.errors()))) from None
    if unknown:
        raise SettingsError(unknown)
    return settings


def _unknown_section_line(name: str) -> str:
    """The refusal line for a top-level section nothing reads; the prefix section adds the ``.env`` rule.

    Example:
        >>> print(_unknown_section_line("repiar"))
        repiar: not a section pve-winrepair reads (it reads ssh, guest, repair, node, lib_log_rich,
        lib_layered_config)
        >>> _unknown_section_line("pve_winrepair").endswith(
        ...     "; .env lines take SECTION__KEY without the PVE_WINREPAIR___ prefix")
        True
    """
    line = f"{name}: not a section pve-winrepair reads (it reads {', '.join(_READ_SECTIONS)})"
    if name == _PREFIX_SECTION:
        return f"{line}; .env lines take SECTION__KEY without the {_ENV_PREFIX} prefix"
    return line


def _line(item: ErrorDetails) -> str:
    """``<section>.<field>: <reason>``; the location parts are the keys the reader wrote.

    Example:
        >>> _line({"type": "extra_forbidden", "loc": ("ssh", "keyy"), "msg": "Extra inputs are not permitted",
        ...        "input": "x"})
        'ssh.keyy: Extra inputs are not permitted'
    """
    return f"{'.'.join(str(part) for part in item['loc'])}: {_reason(item)}"


def _reason(item: ErrorDetails) -> str:
    """The reason as its validator wrote it, without the ``Value error, `` pydantic puts in front.

    Example:
        >>> _reason({"type": "value_error", "loc": (), "msg": "Value error, x", "input": 0,
        ...          "ctx": {"error": ValueError("must be an IPv4 network")}})
        'must be an IPv4 network'
    """
    error = item.get("ctx", {}).get("error")
    if item["type"] == "value_error" and isinstance(error, ValueError):
        return str(error)
    return item["msg"]


__all__ = [
    "LIBRARY_SECTIONS",
    "SECTIONS",
    "SettingsError",
    "load_settings",
]
