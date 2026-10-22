"""Turn a loaded configuration into the node CLI's typed settings.

``load_settings`` validates the ``[ssh] [guest] [repair] [node]`` sections of a ``Config`` into
:class:`~pve_winrepair.domain.settings.Settings`. A refused value raises :class:`SettingsError` with
one ``<section>.<field>: <reason>`` line per problem, built from pydantic's structured errors and
never from ``str(ValidationError)``, which repeats the refused input (a key path may hold a secret).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from pydantic import ValidationError

from pve_winrepair.domain.settings import Settings

if TYPE_CHECKING:
    from lib_layered_config import Config
    from pydantic_core import ErrorDetails

#: The configuration sections the settings model reads; every other section belongs to someone else.
SECTIONS: Final[tuple[str, ...]] = ("ssh", "guest", "repair", "node")


class SettingsError(ValueError):
    """The configuration holds a value the settings refuse.

    ``lines`` holds one ``<section>.<field>: <reason>`` line per problem; ``str()`` joins them.

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
        SettingsError: A section holds an unknown key or a value its field refuses.

    Example:
        >>> from lib_layered_config import Config
        >>> load_settings(Config({"ssh": {"user": "admin"}}, {})).ssh.user
        'admin'
    """
    data = config.as_dict()
    try:
        return Settings.model_validate({name: data.get(name, {}) for name in SECTIONS})
    except ValidationError as error:
        raise SettingsError(tuple(_line(item) for item in error.errors())) from None


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
    "SECTIONS",
    "SettingsError",
    "load_settings",
]
