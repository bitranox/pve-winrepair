"""The click parameter types of the ``repair`` and ``apply`` options: each refuses a bad value as a usage error.

A value refused here exits 2 before any node or guest call, naming the option, instead of failing
deep inside a run: ``--hours 0`` would end the poll at once with TIMEOUT, a ``--tpm-storage`` is
interpolated into ``qm set -tpmstate0 <storage>:1,...``, ``--ip`` names the guest every call goes to,
and the stage root built from ``--stage-root`` is a raw argument to cmd.exe on the guest.

Contents:
    * :class:`PositiveFiniteFloat` - a float above zero that is neither NaN nor infinite.
    * :class:`StorageId` - a PVE storage ID.
    * :class:`Ipv4Address` - a dotted-quad IPv4 address.
    * :class:`WindowsDrive` - a Windows drive letter, as a :class:`~pve_winrepair.domain.enums.DriveLetter`.
"""

from __future__ import annotations

import math
import re
from ipaddress import IPv4Address
from typing import TYPE_CHECKING

import rich_click as click

from pve_winrepair.domain.enums import DriveLetter

if TYPE_CHECKING:
    from typing import Any

__all__ = ["Ipv4Address", "PositiveFiniteFloat", "StorageId", "WindowsDrive"]

# PVE's own rule for a storage ID (pve-storage-id, PVE::JSONSchema parse_storage_id): a letter, then
# letters, digits, "-", "_" or ".", ending in a letter or a digit, case-insensitive. ASCII ranges
# only: re's IGNORECASE alone would also fold non-ASCII letters into [a-z].
_STORAGE_ID = re.compile(r"[a-z][a-z0-9_.-]*[a-z0-9]", re.IGNORECASE | re.ASCII)


class PositiveFiniteFloat(click.FloatRange):
    """A float above zero; NaN and infinity are refused (a plain range lets NaN through: it compares false)."""

    name = "positive number"

    def __init__(self) -> None:
        """A range open at zero, without an upper bound."""
        super().__init__(min=0, min_open=True)

    def convert(self, value: Any, param: click.Parameter | None, ctx: click.Context | None) -> float:
        """The value as a float, refused unless it is finite and above zero."""
        number = super().convert(value, param, ctx)
        if not math.isfinite(number):
            self.fail(f"{value!r} is not a finite number.", param, ctx)
        return number


class StorageId(click.ParamType[str, str]):
    """A PVE storage ID, such as ``local-zfs``."""

    name = "storage"

    def convert(self, value: str, param: click.Parameter | None, ctx: click.Context | None) -> str:
        """The value unchanged, refused unless it is a PVE storage ID."""
        if not _STORAGE_ID.fullmatch(value):
            self.fail(
                f"{value!r} is not a PVE storage ID (a letter, then letters, digits, '-', '_' or '.', "
                "ending in a letter or digit).",
                param,
                ctx,
            )
        return value


class Ipv4Address(click.ParamType[IPv4Address, str]):
    """A dotted-quad IPv4 address, returned as an ``ipaddress.IPv4Address``."""

    name = "ipv4"

    def convert(self, value: str, param: click.Parameter | None, ctx: click.Context | None) -> IPv4Address:
        """The address, refused unless ``ipaddress`` parses it (leading zeros are refused)."""
        try:
            return IPv4Address(value)
        except ValueError:
            self.fail(f"{value!r} is not an IPv4 address.", param, ctx)


class WindowsDrive(click.ParamType[DriveLetter, str]):
    r"""A Windows drive letter such as ``D:``; ``d``, ``D`` and ``D:\`` name the same drive."""

    name = "drive"

    def convert(self, value: str, param: click.Parameter | None, ctx: click.Context | None) -> DriveLetter:
        """The drive letter, refused unless ``value`` is one letter, optionally followed by ``:`` and ``\\``."""
        try:
            return DriveLetter.parse(value)
        except ValueError:
            self.fail(f"{value!r} is not a drive letter (such as C: or D:).", param, ctx)
