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

import os
from ipaddress import IPv4Network
from pathlib import Path, PurePath
from typing import TYPE_CHECKING, Annotated, Final

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator

from pve_winrepair.domain.ssh_paths import jump_key_problem, known_hosts_problem

if TYPE_CHECKING:
    from collections.abc import Mapping

#: A Windows account name as the guest's sshd takes it: no domain part, no spaces.
_USER_PATTERN: Final[str] = r"^[A-Za-z0-9_.-]{1,64}$"
#: A node host as ssh takes it: a DNS name or an IPv4 address. A letter or digit first, so ssh can never
#: read it as an option; no space, ';' or '@', so it can never become a second word or carry a user.
NODE_HOST_PATTERN: Final[str] = r"^$|^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$"
#: The node's login user: like _USER_PATTERN, but never starting with '-' (ssh would read "-x@host" as an option).
_NODE_USER_PATTERN: Final[str] = r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$"
#: A Proxmox snapshot name: a letter first, 2 to 40 characters (PVE's CONFIGID_RE needs at least two).
_SNAPSHOT_PATTERN: Final[str] = r"^[A-Za-z][A-Za-z0-9_-]{1,39}$"
#: A scheduled task name as ``verify-runners --task`` accepts it.
_TASK_PATTERN: Final[str] = r"^[A-Za-z0-9_.-]{1,64}$"
#: The largest count ``verify-runners --expected`` accepts (six digits).
_MAX_EXPECTED_RUNNERS: Final[int] = 999_999

_SECTION_CONFIG: Final[ConfigDict] = ConfigDict(frozen=True, extra="forbid", coerce_numbers_to_str=True)
#: A section's text field as the section reads it: a number is coerced to its digits, anything else
#: that is no string is refused. ``subnet`` is read through it before it becomes a network.
_SECTION_TEXT: Final[TypeAdapter[str]] = TypeAdapter(str, config=ConfigDict(coerce_numbers_to_str=True))

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


def _unless(problem: str | None, value: str) -> str:
    """``value`` unchanged when ``problem`` is None, else a ValueError carrying ``problem``.

    The value is not repeated: the reason names the rule, the location names the key.

    Example:
        >>> _unless(None, "/kh")
        '/kh'
        >>> _unless("must not be empty", "")
        Traceback (most recent call last):
        ...
        ValueError: must not be empty
    """
    if problem is not None:
        raise ValueError(problem)
    return value


class SshSettings(BaseModel):
    """How the node reaches a guest over ssh.

    ``known_hosts_file`` must not be empty or hold whitespace or ``"``, which ssh would misread; its ``%``
    tokens stay ssh's, since the guest ssh is a direct argv (a per-guest ``known_hosts_%h`` is legitimate).

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
    # Kept as written: ssh expands a leading "~" itself, so the node passes the text unchanged. What
    # ssh would misread is refused instead (ssh_paths): its option parser splits the value at whitespace.
    known_hosts_file: str = "~/.ssh/known_hosts"

    @field_validator("known_hosts_file")
    @classmethod
    def _known_hosts_file_is_one_ssh_path(cls, value: str) -> str:
        return _unless(known_hosts_problem(value, through_jump=False), value)


def _subnet(value: object) -> IPv4Network | None:
    """The ``subnet`` setting as a network, or None for "" (not configured); a network is kept as it is.

    The setting is text, as every other text field of a section is (:data:`_SECTION_TEXT`): a number
    is read as its digits, which never name a network.

    Raises:
        pydantic.ValidationError: ``value`` is neither text nor a number.
        ValueError: The text is no IPv4 network in CIDR or netmask form with no host bits set.

    Example:
        >>> _subnet("192.0.2.0/255.255.255.0"), _subnet("")
        (IPv4Network('192.0.2.0/24'), None)
    """
    if isinstance(value, IPv4Network):
        return value
    text = _SECTION_TEXT.validate_python(value)
    if text == "":
        return None
    # A bare address would parse as a /32; the setting names a LAN, so the prefix is required.
    if "/" not in text:
        raise ValueError("must be an IPv4 network in CIDR or netmask form (a.b.c.d/n or a.b.c.d/m.m.m.m), or empty")
    try:
        return IPv4Network(text, strict=True)
    except ValueError:
        # Neither the input nor ipaddress's message (which repeats it) goes into the reason.
        raise ValueError("must be an IPv4 network in CIDR or netmask form with no host bits set, or empty") from None


class GuestSettings(BaseModel):
    """What the node expects of a guest.

    ``subnet`` takes an IPv4 network in CIDR or netmask form (``192.0.2.0/24`` or
    ``192.0.2.0/255.255.255.0``) with no host bits set, or "" for "not configured" (None here).

    Example:
        >>> GuestSettings.model_validate({"subnet": "192.0.2.0/24"}).subnet
        IPv4Network('192.0.2.0/24')
        >>> GuestSettings().subnet is None
        True
    """

    model_config = _SECTION_CONFIG

    subnet: IPv4Network | None = None
    runner_tasks: tuple[TaskName, ...] = ()
    expected_runners: int = Field(default=0, ge=0, le=_MAX_EXPECTED_RUNNERS)

    _expected_runners_is_not_a_boolean = field_validator("expected_runners", mode="before")(_refuse_a_boolean)
    _subnet_is_a_strict_ipv4_network = field_validator("subnet", mode="before")(_subnet)


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


def default_state_dir(os_name: str = os.name, environ: Mapping[str, str] = os.environ) -> str:
    r"""Where receipts live when ``[node] state_dir`` is not set, per OS.

    /var/lib/pve-winrepair on POSIX, %LOCALAPPDATA%\pve-winrepair on Windows, and
    "" on Windows when LOCALAPPDATA is unset, so the validator refuses it by name instead of a guess.

    Args:
        os_name: The ``os.name`` to answer for: ``"nt"`` is Windows, anything else POSIX.
        environ: The environment LOCALAPPDATA is read from on Windows.

    Returns:
        The default state directory for that OS, as text.

    Example:
        >>> default_state_dir("posix", {})
        '/var/lib/pve-winrepair'
        >>> default_state_dir("nt", {"LOCALAPPDATA": r"C:\Users\op\AppData\Local"})
        'C:\\Users\\op\\AppData\\Local\\pve-winrepair'
    """
    if os_name != "nt":
        return "/var/lib/pve-winrepair"
    local = environ.get("LOCALAPPDATA", "")
    return f"{local}\\pve-winrepair" if local else ""


class NodeSettings(BaseModel):
    """Where this machine keeps its state (repair receipts), and how the tool reaches the node.

    ``state_dir`` must be an absolute path on the machine running the tool (default: :func:`default_state_dir`);
    "", a relative path and a leading "~" are refused.
    ``host`` is the PVE node to drive over ssh, a DNS name or an IPv4 address; "" means this machine is the node.
    ``ssh_user`` is the account the tool logs in to the node as; it never starts with "-".
    ``ssh_key`` is the private key file this machine logs in to the node with; "" means not configured.
    It travels inside the ``ProxyCommand`` to a guest, so ``"`` and ``%`` are refused; a space is quoted.
    ``known_hosts_file`` is the known_hosts file the node's host key is checked against, passed to ssh as written;
    it must not be empty or hold whitespace, ``"`` or ``%`` (the jump would expand a ``%`` token twice).

    Example:
        >>> NodeSettings().state_dir.name
        'pve-winrepair'
    """

    model_config = _SECTION_CONFIG

    # validate_default: the Windows default is "" when LOCALAPPDATA is unset, and must be refused like a typed "".
    state_dir: Path = Field(default_factory=lambda: Path(default_state_dir()), validate_default=True)
    host: str = Field(default="", pattern=NODE_HOST_PATTERN)
    ssh_user: str = Field(default="root", pattern=_NODE_USER_PATTERN)
    # Kept as written, like [ssh] key: ssh reads the path itself on the machine running the tool. A
    # '"' or '%' is refused: no quoting carries either through the ProxyCommand (see ssh_paths).
    ssh_key: str = ""
    # Passed as written, like [ssh] known_hosts_file: ssh expands a leading "~" on the machine running the tool.
    # Refused: whitespace and '"' (ssh misreads them), and '%', which the jump to a guest expands once more.
    known_hosts_file: str = "~/.ssh/known_hosts"

    @field_validator("state_dir", mode="before")
    @classmethod
    def _state_dir_is_absolute_here(cls, value: object) -> object:
        # Checked before pydantic builds the Path: "" would become Path("."), so receipts would land in
        # whatever cwd a run starts from and a later run elsewhere could not find them. A relative path
        # and a leading "~" (never expanded here) fail the same way. Absolute on THIS OS: receipts live on
        # the machine running the tool, the node or a workstation (C1 decision), and a POSIX path on
        # Windows lacks its drive. Path("") is Path("."), which is relative, so the unset Windows default
        # and a typed "" are refused here like any other relative path.
        text = str(value) if isinstance(value, PurePath) else value
        if isinstance(text, str | int) and not Path(str(text)).is_absolute():
            # The value is not repeated: the reason names the rule, the location names the key.
            hint = r" (the Windows default %LOCALAPPDATA%\pve-winrepair needs LOCALAPPDATA)" if os.name == "nt" else ""
            raise ValueError(f"must be an absolute path on this machine{hint}")
        return value

    @field_validator("ssh_key")
    @classmethod
    def _ssh_key_survives_the_jump(cls, value: str) -> str:
        return _unless(jump_key_problem(value), value)

    @field_validator("known_hosts_file")
    @classmethod
    def _known_hosts_file_survives_the_jump(cls, value: str) -> str:
        return _unless(known_hosts_problem(value, through_jump=True), value)


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
    "NODE_HOST_PATTERN",
    "GuestSettings",
    "NodeSettings",
    "RepairSettings",
    "Settings",
    "SnapshotName",
    "SshSettings",
    "default_state_dir",
]
