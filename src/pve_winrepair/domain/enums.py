"""Type-safe domain enums for output formats, deployment targets and guest drive letters."""

from __future__ import annotations

from enum import Enum


class OutputFormat(str, Enum):
    """Output format options for configuration display.

    Defines valid output format choices for the config command.
    Inherits from str to allow direct string comparison and Click integration.

    Attributes:
        HUMAN: Human-readable TOML-like output format.
        JSON: Machine-readable JSON output format.

    Example:
        >>> OutputFormat.HUMAN.value
        'human'
        >>> OutputFormat.JSON == "json"
        True
    """

    HUMAN = "human"
    JSON = "json"


class DeployTarget(str, Enum):
    """Configuration deployment target layers.

    Defines valid target layers for configuration file deployment.
    Inherits from str to allow direct string comparison and Click integration.

    Attributes:
        APP: System-wide application configuration (requires privileges).
        HOST: System-wide host-specific configuration (requires privileges).
        USER: User-specific configuration (~/.config on Linux).

    Example:
        >>> DeployTarget.USER.value
        'user'
        >>> DeployTarget.APP == "app"
        True
    """

    APP = "app"
    HOST = "host"
    USER = "user"


class DriveLetter(str, Enum):
    r"""A Windows drive letter, as the operator names the drive to stage the media on.

    :meth:`parse` takes the forms an operator types (``d``, ``D:``, ``D:\``) and refuses anything
    that is not one letter: the stage root built from it (:attr:`stage_root`) is a raw ssh argument
    to cmd.exe on the guest.

    Example:
        >>> DriveLetter.parse("d:\\").stage_root
        'D:\\upgrade'
        >>> DriveLetter.parse("CD")
        Traceback (most recent call last):
        ...
        ValueError: 'CD' is not a valid DriveLetter
    """

    DRIVE_A = "A"
    DRIVE_B = "B"
    DRIVE_C = "C"
    DRIVE_D = "D"
    DRIVE_E = "E"
    DRIVE_F = "F"
    DRIVE_G = "G"
    DRIVE_H = "H"
    DRIVE_I = "I"
    DRIVE_J = "J"
    DRIVE_K = "K"
    DRIVE_L = "L"
    DRIVE_M = "M"
    DRIVE_N = "N"
    DRIVE_O = "O"
    DRIVE_P = "P"
    DRIVE_Q = "Q"
    DRIVE_R = "R"
    DRIVE_S = "S"
    DRIVE_T = "T"
    DRIVE_U = "U"
    DRIVE_V = "V"
    DRIVE_W = "W"
    DRIVE_X = "X"
    DRIVE_Y = "Y"
    DRIVE_Z = "Z"

    @classmethod
    def parse(cls, text: str) -> DriveLetter:
        """The letter ``text`` names, without its trailing ``:`` and ``\\``, in upper case.

        Raises:
            ValueError: What is left is not one letter A to Z.
        """
        return cls(text.rstrip(":\\").upper())

    @property
    def stage_root(self) -> str:
        """The stage root on this drive (``D:\\upgrade``)."""
        return f"{self.value}:\\upgrade"


__all__ = [
    "DeployTarget",
    "DriveLetter",
    "OutputFormat",
]
