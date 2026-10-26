"""Application ports - Protocol definitions the adapters satisfy structurally (PEP 544).

Each function port defines a ``__call__`` method whose signature exactly matches the
corresponding adapter function. :class:`GuestPort` and :class:`NodePort` describe the guest and
the node the drivers reach (the ssh adapter's ``Guest`` and the node adapter's ``Node``); their data
members are read-only properties, because those adapters are frozen dataclasses and a read-only
field does not satisfy a plain (mutable) Protocol attribute. :class:`MediaSource` is where a run's
installation media are and how they reach the guest (the media adapter's ``LocalMedia``).

System Role:
    Sits between domain and adapters.  Infrastructure types (``Config``)
    are imported under ``TYPE_CHECKING`` only so that
    import-linter layer contracts remain satisfied at runtime.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from ipaddress import IPv4Address
    from pathlib import Path

    # The finished process is only a type here; nothing in this module runs one.
    from subprocess import CompletedProcess  # nosec B404

    from lib_layered_config import Config

    from ..domain.enums import DeployTarget, OutputFormat
    from ..domain.envelope import GuestAnswer, PayloadT
    from ..domain.guest_answers import GuestCommand
    from ..domain.guest_tool import PackedTool, Pushed
    from ..domain.node_link import NodeLink
    from ..domain.receipt import RepairReceipt
    from ..domain.settings import Settings, SshSettings
    from ..domain.vm_config import SnapshotResult, VmConfigRead


class TransferTimeoutError(RuntimeError):
    """A copy into the guest did not finish within its timeout.

    Raised rather than returned as a failed process: only a copy that ran out of time is helped by
    a longer ``[repair] stage_timeout_minutes``, so the caller must tell it from any other failure.
    """


class GetConfig(Protocol):
    """Load layered configuration with application defaults."""

    def __call__(
        self, *, profile: str | None = ..., start_dir: str | None = ..., dotenv_path: str | None = ...
    ) -> Config: ...


class GetDefaultConfigPath(Protocol):
    """Return the path to the bundled default configuration file."""

    def __call__(self) -> Path: ...


class DeployConfiguration(Protocol):
    """Deploy default configuration to specified target layers."""

    def __call__(
        self,
        *,
        targets: Sequence[DeployTarget],
        force: bool = ...,
        profile: str | None = ...,
        set_permissions: bool | None = ...,
        dir_mode: int | None = ...,
        file_mode: int | None = ...,
        permission_overrides: Mapping[str, object] | None = ...,
    ) -> list[Path]: ...


class DisplayConfig(Protocol):
    """Display the provided configuration in the requested format."""

    def __call__(
        self, config: Config, *, output_format: OutputFormat = ..., section: str | None = ..., profile: str | None = ...
    ) -> None: ...


class InitLogging(Protocol):
    """Initialize lib_log_rich runtime with the provided configuration.

    ``dotenv_path`` is the ``.env`` the configuration was loaded with, or None for the one the
    configuration's provenance names.
    A refused logging setting raises ``InvalidLoggingConfigError`` only after logging has been
    started with its defaults, so the caller never has to start it a second time.
    """

    def __call__(self, config: Config, *, dotenv_path: str | None = None) -> None: ...


class CheckLoggingConfig(Protocol):
    """Refuse ``config``'s logging settings as ``InitLogging`` would, leaving the running runtime alone.

    For a configuration loaded after logging is running; a refused setting raises
    ``InvalidLoggingConfigError`` and logging keeps running with the settings it started with.
    """

    def __call__(self, config: Config) -> None: ...


class LoadSettings(Protocol):
    """Validate the node CLI's sections of a loaded configuration into typed settings.

    Raises ``SettingsError`` (one ``<section>.<field>: <reason>`` or ``<section>: <reason>`` line per
    problem) for a value the settings refuse or a top-level section nothing reads.
    """

    def __call__(self, config: Config, /) -> Settings: ...


class MakeNode(Protocol):
    """The PVE node a command drives: this machine (no link), or a remote node over ssh; guests use ``[ssh]``."""

    def __call__(self, ssh: SshSettings, link: NodeLink | None, /) -> NodePort: ...


class MakeReceipts(Protocol):
    """The receipt store kept in the given ``[node] state_dir``, or the one ``--receipt`` file when one is given."""

    def __call__(self, state_dir: Path, file: Path | None, /) -> ReceiptStore: ...


class GuestPort(Protocol):
    """One guest as the drivers reach it: push or stage the packed tool, ask it, run raw commands."""

    @property
    def ip(self) -> str:
        """The guest's address."""
        ...

    @property
    def tool_path(self) -> str:
        """The tool copy this guest's calls run: its content address, or the verified profile copy."""
        ...

    @property
    def packed(self) -> PackedTool:
        """The packed tool on this node and its content address on the guest."""
        ...

    def push_tool(self) -> Pushed:
        """Put the packed tool at its content address on the guest."""
        ...

    def stage_tool(self) -> GuestPort:
        """Copy the tool to the ssh user's profile, verify it, and return a guest whose calls run that copy."""
        ...

    def remove_profile_copy(self) -> str | None:
        """Delete the profile copy; None once done, else why not (never raises)."""
        ...

    def ask(self, command: GuestCommand, payload: type[PayloadT], *args: str, timeout: float) -> GuestAnswer[PayloadT]:
        """Run one subcommand of the tool and return its typed answer (ok or refused; a probe never refuses)."""
        ...

    def ssh(self, *remote: str, timeout: float) -> CompletedProcess[str]:
        """Run a raw remote command; the caller checks the result."""
        ...

    def copy_to(self, sources: Sequence[str], dest: str, *, timeout: float) -> CompletedProcess[str]:
        """Copy ``sources`` recursively into the guest directory ``dest``; the caller checks the result.

        Raises:
            TransferTimeoutError: The copy did not finish within ``timeout``.
        """
        ...


class MediaSource(Protocol):
    """The installation media of one run: where they are, and how they reach the guest's stage root."""

    def check(self) -> str | None:
        """Why the media cannot be used (missing, empty or unreachable), or None when they can."""
        ...

    def copy_into(self, guest: GuestPort, dest: str, *, timeout: float) -> CompletedProcess[str]:
        """Copy every entry of the media directory into the guest directory ``dest``; the caller checks the result.

        Raises:
            TransferTimeoutError: The copy did not finish within ``timeout``.
        """
        ...


class NodePort(Protocol):
    """The PVE node a driver runs on: how it runs ``qm``, reads a VM's configuration, waits, and reaches a guest."""

    @property
    def clock(self) -> Callable[[], float]:
        """The wall clock, in seconds."""
        ...

    @property
    def sleep(self) -> Callable[[float], None]:
        """Wait the given number of seconds."""
        ...

    def qm(self, *args: str, timeout: int = 600) -> CompletedProcess[str]:
        """Run ``qm`` on this node."""
        ...

    def check_link(self) -> str | None:
        """Why the linked node cannot be used, or None (also when there is no link)."""
        ...

    def vm_config(self, vmid: int) -> VmConfigRead:
        """``qm config <vmid>``, parsed; the exit code says whether the call succeeded."""
        ...

    def snapshots(self, vmid: int) -> frozenset[str]:
        """The snapshot names of ``vmid`` (``qm listsnapshot``), without PVE's ``current`` marker."""
        ...

    def snapshot(self, vmid: int, name: str, description: str) -> SnapshotResult:
        """Snapshot ``vmid`` as ``name`` (``qm snapshot``): exit code, stderr, and whether PVE froze the guest fs."""
        ...

    def guest(self, ip: IPv4Address) -> GuestPort:
        """The guest at ``ip``."""
        ...

    def media(self, directory: str, *, from_node: bool) -> MediaSource:
        """The media in ``directory``: on the node when ``from_node`` and the node is remote, else on this machine."""
        ...


class ReceiptStore(Protocol):
    """Where a repair leaves the build its prepare step measured, one receipt per VM, for apply to verify.

    Every failure to write, read or remove a receipt is a ``ReceiptError`` naming the file.
    """

    def write(self, receipt: RepairReceipt) -> Path:
        """Replace the receipt of ``receipt.vmid``; return where it is kept."""
        ...

    def read(self, vmid: int) -> RepairReceipt | None:
        """The receipt of ``vmid``; None when there is none, ``ReceiptError`` when it is unreadable or invalid."""
        ...

    def other_vm(self, vmid: int) -> int | None:
        """The VM the receipt at ``path(vmid)`` names when that is not ``vmid``.

        None when there is no receipt there or it names ``vmid``; None as well when the store's own per-VM
        file cannot be read or parsed. A ``ReceiptError`` when the operator named the file (``--receipt``)
        and it exists but is no valid receipt: it may be any file, so it is left alone.
        """
        ...

    def path(self, vmid: int) -> Path:
        """Where the receipt of ``vmid`` is kept."""
        ...

    def delete(self, vmid: int) -> None:
        """Remove the receipt of ``vmid``; an absent one is fine, one that cannot be removed a ``ReceiptError``.

        An operator-named file (``--receipt``) that is no valid receipt is never removed: ``ReceiptError``.
        """
        ...


__all__ = [
    "CheckLoggingConfig",
    "DeployConfiguration",
    "DisplayConfig",
    "GetConfig",
    "GetDefaultConfigPath",
    "GuestPort",
    "InitLogging",
    "LoadSettings",
    "MakeNode",
    "MakeReceipts",
    "MediaSource",
    "NodePort",
    "ReceiptStore",
    "TransferTimeoutError",
]
