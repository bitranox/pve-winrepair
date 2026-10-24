"""Typed settings for the node CLI: the ``[ssh]``, ``[guest]``, ``[repair]`` and ``[node]`` sections.

Each section is a frozen model that refuses an unknown key. Text fields accept a number and keep its
digits, because lib_layered_config hands an unquoted digit-only ``.env`` or environment value over as
an int. An empty ``ssh.key`` or ``repair.media_dir`` validates: it means "not configured", and the
commands that need the value refuse to run without it.

``guest.runner_tasks`` and ``guest.expected_runners`` are not read by any node command; they hold the
values an operator passes to the guest tool's ``verify-runners --task NAME --expected N``, and are
validated with the same rules that verb applies, so ``pve-winrepair config`` shows values it accepts.
"""

from __future__ import annotations

from ipaddress import IPv4Network
from pathlib import Path, PurePath, PurePosixPath
from typing import Annotated, Final

from pydantic import BaseModel, ConfigDict, Field, field_validator

#: A Windows account name as the guest's sshd takes it: no domain part, no spaces.
_USER_PATTERN: Final[str] = r"^[A-Za-z0-9_.-]{1,64}$"
#: A Proxmox snapshot name: a letter first, 2 to 40 characters (PVE's CONFIGID_RE needs at least two).
_SNAPSHOT_PATTERN: Final[str] = r"^[A-Za-z][A-Za-z0-9_-]{1,39}$"
#: A scheduled task name as ``verify-runners --task`` accepts it.
_TASK_PATTERN: Final[str] = r"^[A-Za-z0-9_.-]{1,64}$"
#: The largest count ``verify-runners --expected`` accepts (six digits).
_MAX_EXPECTED_RUNNERS: Final[int] = 999_999

_SECTION_CONFIG: Final[ConfigDict] = ConfigDict(frozen=True, extra="forbid", coerce_numbers_to_str=True)

TaskName = Annotated[str, Field(pattern=_TASK_PATTERN)]
#: ``[repair] snapshot_name``'s rule, which ``repair --snapshot-name`` is held to as well.
SnapshotName = Annotated[str, Field(pattern=_SNAPSHOT_PATTERN)]


def _refuse_a_boolean(value: object) -> object:
    """Refuse ``true``/``false`` where a number belongs; pydantic's lax mode would read it as 1 or 0.

    Example:
        >>> _refuse_a_boolean("4")
        '4'
        >>> _refuse_a_boolean(True)
        Traceback (most recent call last):
        ...
        ValueError: must be a number, not true or false
    """
    if isinstance(value, bool):
        raise ValueError("must be a number, not true or false")
    return value


class SshSettings(BaseModel):
    """How the node reaches a guest over ssh.

    Example:
        >>> SshSettings().user
        'Administrator'
        >>> SshSettings(user=4711).user
        '4711'
    """

    model_config = _SECTION_CONFIG

    key: str = ""
    user: str = Field(default="Administrator", pattern=_USER_PATTERN)
    strict_host_key_checking: bool = True
    # Kept as written: ssh expands a leading "~" itself, so the node passes the text unchanged.
    known_hosts_file: str = "~/.ssh/known_hosts"


class GuestSettings(BaseModel):
    """What the node expects of a guest.

    ``subnet`` takes an IPv4 network in CIDR or netmask form (``192.0.2.0/24`` or
    ``192.0.2.0/255.255.255.0``) with no host bits set, or "" for "not configured".

    Example:
        >>> GuestSettings(subnet="192.0.2.0/24").network()
        IPv4Network('192.0.2.0/24')
        >>> GuestSettings().network() is None
        True
    """

    model_config = _SECTION_CONFIG

    subnet: str = ""
    runner_tasks: tuple[TaskName, ...] = ()
    expected_runners: int = Field(default=0, ge=0, le=_MAX_EXPECTED_RUNNERS)

    _expected_runners_is_not_a_boolean = field_validator("expected_runners", mode="before")(_refuse_a_boolean)

    @field_validator("subnet")
    @classmethod
    def _subnet_is_a_strict_ipv4_cidr(cls, value: str) -> str:
        if value == "":
            return value
        # A bare address would parse as a /32; the setting names a LAN, so the prefix is required.
        if "/" not in value:
            raise ValueError("must be an IPv4 network in CIDR or netmask form (a.b.c.d/n or a.b.c.d/m.m.m.m), or empty")
        try:
            IPv4Network(value, strict=True)
        except ValueError:
            # Neither the input nor ipaddress's message (which repeats it) goes into the reason.
            raise ValueError(
                "must be an IPv4 network in CIDR or netmask form with no host bits set, or empty"
            ) from None
        return value

    def network(self) -> IPv4Network | None:
        """The subnet as a network for membership checks, or None when it is not configured."""
        return IPv4Network(self.subnet) if self.subnet else None


class RepairSettings(BaseModel):
    """Where the installation media live and what a repair needs on the guest.

    Example:
        >>> RepairSettings().snapshot_name
        'pre_winrepair'
    """

    model_config = _SECTION_CONFIG

    media_dir: str = ""
    snapshot_name: SnapshotName = "pre_winrepair"
    stage_free_gb: float = Field(default=15.0, gt=0, allow_inf_nan=False)
    system_free_gb: float = Field(default=25.0, gt=0, allow_inf_nan=False)

    _free_space_is_not_a_boolean = field_validator("stage_free_gb", "system_free_gb", mode="before")(_refuse_a_boolean)


class NodeSettings(BaseModel):
    """Where the node keeps its own state (repair receipts).

    ``state_dir`` must be an absolute POSIX path; "", a relative path and a leading "~" are refused.

    Example:
        >>> NodeSettings().state_dir.name
        'pve-winrepair'
    """

    model_config = _SECTION_CONFIG

    state_dir: Path = Path("/var/lib/pve-winrepair")

    @field_validator("state_dir", mode="before")
    @classmethod
    def _state_dir_is_an_absolute_posix_path(cls, value: object) -> object:
        # Checked before pydantic builds the Path: "" would become Path("."), so receipts would land in
        # whatever cwd a run starts from and a later run elsewhere could not find them. A relative path
        # and a leading "~" (never expanded here) fail the same way. PurePosixPath keeps the check the
        # same on every OS: the directory is on a Proxmox node, whatever machine validates the file.
        text = value.as_posix() if isinstance(value, PurePath) else value
        if isinstance(text, str | int) and not PurePosixPath(str(text)).is_absolute():
            # The value is not repeated: the reason names the rule, the location names the key.
            raise ValueError("must be an absolute path on the node (starting with /)")
        return value


class Settings(BaseModel):
    """All node CLI settings, one model per configuration section.

    Example:
        >>> Settings().repair.stage_free_gb
        15.0
    """

    model_config = _SECTION_CONFIG

    ssh: SshSettings = Field(default_factory=SshSettings)
    guest: GuestSettings = Field(default_factory=GuestSettings)
    repair: RepairSettings = Field(default_factory=RepairSettings)
    node: NodeSettings = Field(default_factory=NodeSettings)


__all__ = [
    "GuestSettings",
    "NodeSettings",
    "RepairSettings",
    "Settings",
    "SnapshotName",
    "SshSettings",
]
