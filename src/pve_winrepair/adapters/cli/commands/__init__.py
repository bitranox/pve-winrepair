"""CLI command implementations.

Collects all subcommand functions and re-exports them for registration
with the root CLI group.

Contents:
    * Info commands from :mod:`.info`
    * Config commands from :mod:`.config`
    * Run commands from :mod:`.repair` and :mod:`.apply`
    * The packed guest tool from :mod:`.guest_tool`
"""

from __future__ import annotations

from .apply import cli_apply
from .config import cli_config, cli_config_deploy, cli_config_generate_examples
from .guest_tool import cli_guest_tool
from .info import cli_info
from .repair import cli_repair

__all__ = [
    "cli_apply",
    "cli_config",
    "cli_config_deploy",
    "cli_config_generate_examples",
    "cli_guest_tool",
    "cli_info",
    "cli_repair",
]
