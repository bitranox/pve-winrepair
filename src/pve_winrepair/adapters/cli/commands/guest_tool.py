r"""``pve-winrepair guest-tool``: where the packed guest tool of this install is, and its content address.

``guest-tool path`` prints the absolute path of the packaged ``winrepair_guest.ps1``;
``guest-tool sha256`` prints its sha256 and the content address a push gives it on a guest
(``C:\winrepair\winrepair_guest-<first 16 hex>.ps1``), so an operator can match a guest's copy to
this install. Neither reads the configuration: both work while it is broken.

Contents:
    * :func:`cli_guest_tool` - the ``guest-tool`` group.
    * :func:`cli_guest_tool_path` - ``guest-tool path``.
    * :func:`cli_guest_tool_sha256` - ``guest-tool sha256``.
"""

from __future__ import annotations

import rich_click as click

from pve_winrepair.adapters.guest_ssh import TOOL_DIR, TOOL_NAME, packed_tool

from .. import safe_console
from ..constants import CLICK_CONTEXT_SETTINGS

__all__ = ["cli_guest_tool", "cli_guest_tool_path", "cli_guest_tool_sha256"]


@click.group("guest-tool", context_settings=CLICK_CONTEXT_SETTINGS)
def cli_guest_tool() -> None:
    """The packed guest tool this install pushes to the guests."""


@cli_guest_tool.command("path", context_settings=CLICK_CONTEXT_SETTINGS)
def cli_guest_tool_path() -> None:
    """Print the absolute path of the packed guest tool."""
    safe_console.echo(str(TOOL_DIR / TOOL_NAME))


@cli_guest_tool.command("sha256", context_settings=CLICK_CONTEXT_SETTINGS)
def cli_guest_tool_sha256() -> None:
    """Print the packed guest tool's sha256 and its content address on a guest."""
    tool = packed_tool(TOOL_DIR)
    safe_console.echo(f"{tool.sha256}  {tool.guest_path}")
