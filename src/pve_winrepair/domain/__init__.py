"""Domain layer - pure business logic with no I/O or framework dependencies.

Contains entities, value objects, and domain services that form the core
business logic of the application.

Contents:
    * :mod:`.enums` - Domain enumerations (OutputFormat, DeployTarget)
    * :mod:`.envelope` - The guest tool's answer contract and how a call fails
    * :mod:`.guest_answers` - The guest tool's answers as typed models, one per subcommand
    * :mod:`.errors` - Domain exception types
"""

from __future__ import annotations

from .enums import DeployTarget, OutputFormat
from .errors import ConfigurationError

__all__ = [
    # Errors
    "ConfigurationError",
    # Enums
    "DeployTarget",
    "OutputFormat",
]
