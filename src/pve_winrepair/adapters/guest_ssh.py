r"""Talk to the winrepair guest tool over ssh: push it, run one subcommand, read its JSON envelope.

The ssh and scp side of a guest call, run ON the PVE node by the repair and apply-and-verify
drivers: :class:`Guest` builds every argv (:func:`ssh_options` from the ``[ssh]`` settings), runs it
through its runner, and hands the finished process to
:func:`~pve_winrepair.domain.envelope.parse_envelope`, which owns the answer contract and the error
types.

The tool lives on the guest under a content address,
``C:\winrepair\winrepair_guest-<first 16 hex of its sha256>.ps1``. A SYSTEM upgrade run executes
the file it was launched with for hours, and a re-run of a driver pushes again; a fixed name would
be overwritten under that live run. With a content address the same bytes are already there (the
push copies nothing in) and a new version gets a new name, so a push never writes a file a run
executes.

``C:\winrepair`` is locked to SYSTEM and Administrators before the tool is ever copied into it: a
directory created under ``C:\`` is open to every local user until then, and the tool runs as an
elevated admin and as SYSTEM. The tool itself does the locking (``lock-dirs``), so every push first
puts it in the ssh user's profile, which only SYSTEM, Administrators and that user can write, checks
the copy's bytes against the node's digest, and runs it from there (see :func:`push_tool`). After
the apply reboot the apply-and-verify driver runs the tool from such a verified profile copy only
(:meth:`Guest.stage_tool`), never from ``C:\winrepair``, whose lock the upgrade may have changed.

Settings:
    The key, the user and the host-key options come from the ``[ssh]`` section
    (:class:`~pve_winrepair.domain.settings.SshSettings`). A guest whose sshd refuses the configured
    key is reached by overriding it for that run through the environment:
    ``PVE_WINREPAIR___SSH__KEY=<path>``. The packed tool ships inside this package (:data:`TOOL_DIR`).
"""

from __future__ import annotations

import hashlib
import re

# ssh and scp are the one boundary this module crosses; run() below says why its argv is safe.
import subprocess  # nosec B404
from contextlib import contextmanager
from dataclasses import dataclass, replace
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING

from pve_winrepair.domain.envelope import (
    READ_FAILURES,
    Envelope,
    Fields,
    GuestCallError,
    GuestNoAnswerError,
    GuestProtocolError,
    GuestPushError,
    Runner,
    parse_envelope,
    snippet,
    tool_argv,
)
from pve_winrepair.domain.guest_tool import PackedTool, Pushed

if TYPE_CHECKING:
    from collections.abc import Generator, Sequence

    from pve_winrepair.domain.settings import SshSettings

__all__ = [
    "CERTUTIL",
    "GUEST_TOOL_DIR",
    "LOCK_TIMEOUT",
    "PUSH_TIMEOUT",
    "REMOTE_TIMEOUT",
    "TOOL_DIR",
    "TOOL_NAME",
    "Guest",
    "guest_tool",
    "packed_tool",
    "push_tool",
    "remove_staged",
    "run",
    "ssh_options",
    "stage_tool",
]


TOOL_NAME = "winrepair_guest.ps1"
# The packed tool ships inside this package; resolved from this file, never by importing the root
# package for its __file__ (an adapter importing the composition root breaks the layer contract).
TOOL_DIR = Path(__file__).resolve().parent / "guest_tool"
GUEST_TOOL_DIR = "C:\\winrepair"
# 64 bits of the sha256: a collision between two tool versions is not a practical concern, and the
# name stays short enough to read in a task's action line.
_TOOL_HASH_CHARS = 16
PUSH_TIMEOUT = 300.0
REMOTE_TIMEOUT = 60.0
# The pushed copy's first run may bootstrap uv and Python on the guest before it answers.
LOCK_TIMEOUT = 300.0
# Options fixed for every guest, either side of the two host-key options (ssh_options keeps that
# order). BatchMode plus publickey: a rejected key fails at once instead of hanging an unattended
# run on a password prompt.
_AUTH_OPTS = (
    "-o", "BatchMode=yes",
    "-o", "PreferredAuthentications=publickey",
)  # fmt: skip
_TIMEOUT_OPTS = (
    "-o", "ConnectTimeout=20",
    "-o", "ServerAliveInterval=30",
)  # fmt: skip


# The guest's own hasher, by full path for the same reason as the domain's POWERSHELL. Its hex
# line is the one part of its output that is not localised; older builds print it as spaced byte
# pairs.
CERTUTIL = r"%SystemRoot%\System32\certutil.exe"
_SHA256_LINE = re.compile(r"[0-9A-Fa-f]{64}")


def run(cmd: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
    """Run a command, capturing stdout and stderr SEPARATELY as UTF-8 text.

    Separate on purpose: ssh's own warnings go to stderr and must never splice into the
    envelope line on stdout.
    """
    # An argv list, never a shell, and every word bound for the guest passed check_argument.
    return subprocess.run(  # noqa: S603 - argv list, no shell  # nosec B603
        list(cmd),
        capture_output=True,
        text=True,
        timeout=timeout,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def ssh_options(ssh: SshSettings) -> tuple[str, ...]:
    """The ``-o`` options of every ssh and scp call to a guest.

    ``strict_host_key_checking`` maps to ``StrictHostKeyChecking=yes`` or ``no``: guests are cloned
    and rebuilt, so a fleet that accepts a changed host key sets it to false. ``known_hosts_file``
    is passed as written, never expanded here: ssh expands a leading ``~`` itself, against the HOME
    of the account that runs it. Keep it a real file, never ``/dev/null``: that makes every connect a
    first connect, and ssh then prints "Permanently added" on every call.

    Example:
        >>> from pve_winrepair.domain.settings import SshSettings
        >>> ssh_options(SshSettings(strict_host_key_checking=False, known_hosts_file="~/.ssh/kh"))[4:8]
        ('-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=~/.ssh/kh')
    """
    checking = "yes" if ssh.strict_host_key_checking else "no"
    return (
        *_AUTH_OPTS,
        "-o",
        f"StrictHostKeyChecking={checking}",
        "-o",
        f"UserKnownHostsFile={ssh.known_hosts_file}",
        *_TIMEOUT_OPTS,
    )


def _ssh_argv(ip: str, ssh: SshSettings, remote: Sequence[str]) -> list[str]:
    return ["ssh", "-i", ssh.key, *ssh_options(ssh), f"{ssh.user}@{ip}", *remote]


def _scp_argv(ip: str, ssh: SshSettings, sources: Sequence[str], dest: str, *, recursive: bool) -> list[str]:
    return [
        "scp",
        "-q",
        "-i",
        ssh.key,
        *ssh_options(ssh),
        *(["-r"] if recursive else []),
        *sources,
        f"{ssh.user}@{ip}:{dest}",
    ]


def _call(runner: Runner, argv: Sequence[str], timeout: float, what: str) -> subprocess.CompletedProcess[str]:
    """Run ``argv``; a timeout or a failure to start is :class:`GuestNoAnswerError`."""
    try:
        return runner(argv, timeout)
    except subprocess.TimeoutExpired as exc:
        raise GuestNoAnswerError(f"{what}: timed out after {timeout:g} s") from exc
    except OSError as exc:
        raise GuestNoAnswerError(f"{what}: could not run {argv[0]}: {exc}") from exc


def guest_tool(guest: Guest, command: str, *args: str, timeout: float) -> Envelope:
    """Run one subcommand of the tool copy at ``guest.tool_path`` and return its envelope (ok or refused).

    Raises:
        UnsafeArgumentError: Before ssh, see :func:`check_argument`.
        GuestPushError: The packed tool is missing on this node, so its guest path is unknown.
        GuestNoAnswerError, GuestInternalError, GuestProtocolError: See :func:`parse_envelope`.
    """
    argv = _ssh_argv(guest.ip, guest.ssh_settings, tool_argv(guest.tool_path, command, args))
    return parse_envelope(command, _call(guest.runner, argv, timeout, f"guest tool {command}"))


def packed_tool(directory: Path) -> PackedTool:
    r"""Hash ``directory/winrepair_guest.ps1`` into its guest path ``C:\winrepair\winrepair_guest-<sha>.ps1``.

    Raises:
        GuestPushError: The packed tool is missing or unreadable.
    """
    source = directory / TOOL_NAME
    try:
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
    except OSError as exc:
        raise GuestPushError(
            f"{source} is missing: the package is missing its guest tool - reinstall pve-winrepair ({exc})"
        ) from exc
    stem = TOOL_NAME.removesuffix(".ps1")
    return PackedTool(source, f"{GUEST_TOOL_DIR}\\{stem}-{digest[:_TOOL_HASH_CHARS]}.ps1", digest)


def _remote(
    runner: Runner, ip: str, ssh: SshSettings, remote: Sequence[str], what: str
) -> subprocess.CompletedProcess[str]:
    """One raw ``cmd.exe`` command of the push; no answer at all is a push failure naming ``what``."""
    try:
        return _call(runner, _ssh_argv(ip, ssh, remote), REMOTE_TIMEOUT, what)
    except GuestNoAnswerError as exc:
        raise GuestPushError(str(exc)) from exc


def _checked(proc: subprocess.CompletedProcess[str], what: str) -> None:
    if proc.returncode != 0:
        raise GuestPushError(f"{what} failed rc={proc.returncode}: {snippet(proc.stderr or proc.stdout)}")


def _lock_tool_dir(runner: Runner, ip: str, ssh: SshSettings, staged: str, dest: str) -> bool:
    """Run lock-dirs from the profile copy ``staged``; return whether ``dest`` is already in place.

    Raises:
        GuestPushError: It refused, gave no answer, or crashed (the guest traceback is chained).
        GuestProtocolError: Its answer broke the envelope contract.
    """
    command = "lock-dirs"
    argv = _ssh_argv(ip, ssh, tool_argv(staged, command, ("--tool", dest)))
    try:
        envelope = parse_envelope(command, _call(runner, argv, LOCK_TIMEOUT, f"guest tool {command}"))
    except READ_FAILURES as exc:
        raise GuestPushError(f"{command} before the push: {exc}") from exc
    if envelope.gate("verdict", "OK") != "OK":
        raise GuestPushError(f"{command} refused, nothing was copied in: {envelope.data.text_or_none('reason')}")
    return envelope.data.flag("tool_present")


def _guest_sha256(runner: Runner, ip: str, ssh: SshSettings, path: str) -> str:
    """The sha256 of the guest file ``path``, read with the guest's certutil."""
    what = f"hashing {path}"
    proc = _remote(runner, ip, ssh, (CERTUTIL, "-hashfile", path, "SHA256"), what)
    _checked(proc, what)
    found = {"".join(line.split()).lower() for line in proc.stdout.splitlines()}
    digests = {line for line in found if _SHA256_LINE.fullmatch(line)}
    if len(digests) != 1:
        raise GuestPushError(f"{what}: certutil printed no single SHA256 line: {snippet(proc.stdout)!r}")
    return digests.pop()


def _verify(runner: Runner, ip: str, ssh: SshSettings, path: str, tool: PackedTool) -> None:
    """Refuse unless the guest file ``path`` (the profile copy or the copy in place) is exactly ``tool``."""
    digest = _guest_sha256(runner, ip, ssh, path)
    if digest != tool.sha256:
        label = "the profile copy" if path == tool.staged else "the copy in place"
        raise GuestPushError(
            f"{label} {path} hashes to {digest} on the guest, expected {tool.sha256} (the node's "
            f"{tool.source.name}): refused, it is not run"
        )


def remove_staged(runner: Runner, ip: str, ssh: SshSettings, staged: str) -> str | None:
    """Delete the profile copy ``staged``; None once done, else why not. Never raises."""
    removing = f"removing the profile copy {staged}"
    try:
        _checked(_remote(runner, ip, ssh, ("del", "/Q", staged), removing), removing)
    except GuestPushError as exc:
        return f"the profile copy {staged} was left in the ssh user's profile: {exc}"
    return None


@contextmanager
def _removed_on_failure(runner: Runner, ip: str, ssh: SshSettings, staged: str) -> Generator[None, None, None]:
    """Delete the profile copy when the body fails, naming a delete that failed too in the error."""
    try:
        yield
    except GuestCallError as exc:
        exc.cleanup_failure = remove_staged(runner, ip, ssh, staged)
        raise
    except BaseException:
        remove_staged(runner, ip, ssh, staged)
        raise


def stage_tool(
    ip: str, tool: PackedTool, *, ssh: SshSettings, runner: Runner = run, timeout: float = PUSH_TIMEOUT
) -> str:
    """Copy ``tool`` to the ssh user's profile and check its bytes there; return its (relative) name.

    The copy is hashed on the guest against the node's digest before anything runs it, so a
    profile that is not what it should be cannot hand an elevated run other bytes. On any failure
    the copy is deleted again (see :func:`remove_staged`); on success the caller deletes it.

    Raises:
        GuestPushError: The copy failed, its hash could not be read, or it is not ``tool``.
    """
    staged = tool.staged
    with _removed_on_failure(runner, ip, ssh, staged):
        try:
            proc = _call(runner, _scp_argv(ip, ssh, [str(tool.source)], staged, recursive=False), timeout, "push")
        except GuestNoAnswerError as exc:
            raise GuestPushError(str(exc)) from exc
        _checked(proc, f"pushing {TOOL_NAME} to the ssh user's profile")
        _verify(runner, ip, ssh, staged, tool)
    return staged


def push_tool(
    ip: str, tool: PackedTool, *, ssh: SshSettings, runner: Runner = run, timeout: float = PUSH_TIMEOUT
) -> Pushed:
    r"""Put ``tool`` at its content address on the guest, into a ``C:\winrepair`` locked beforehand.

    The tool first goes to the ssh user's profile under its plain name (ssh and scp start there, and
    only SYSTEM, Administrators and that user may write it), is hashed there against the node's
    digest (:func:`stage_tool`), and runs ``lock-dirs`` from there: that creates ``C:\winrepair``
    with the lock in place before anything is copied in, and checks a tool already at the content
    address against its name. Only then is the profile copy copied in, beside the final name, and
    renamed into place, so a cut copy never sits under a name a run executes; the copy in place is
    hashed once more before anyone runs it. The profile copy is deleted on every path.

    The final name is never written while it exists: a live SYSTEM run may be executing it, and
    the same name means the same bytes (lock-dirs checked them).

    Raises:
        GuestPushError: A step failed, a hash did not match, or lock-dirs refused; nothing was copied
            into ``C:\winrepair`` unless lock-dirs passed.
    """
    dest = tool.guest_path
    staged = stage_tool(ip, tool, ssh=ssh, runner=runner, timeout=timeout)
    part = dest + ".part"
    with _removed_on_failure(runner, ip, ssh, staged):
        present = _lock_tool_dir(runner, ip, ssh, staged, dest)
        if not present:
            copying = f"copying {staged} to {part}"
            _checked(_remote(runner, ip, ssh, ("copy", "/Y", "/B", staged, part), copying), copying)
            renaming = f"renaming {part} into place"
            _checked(_remote(runner, ip, ssh, ("move", "/Y", part, dest), renaming), renaming)
        _verify(runner, ip, ssh, dest, tool)
    return Pushed(dest, copied=not present, staged_left=remove_staged(runner, ip, ssh, staged))


@dataclass(frozen=True)
class Guest:
    """One guest as the drivers reach it: address, ssh settings, where the packed tool is, and the runner.

    The runner is the seam the tests use; production runs :func:`run`.
    """

    ip: str
    ssh_settings: SshSettings
    tool_dir: Path = TOOL_DIR
    runner: Runner = run
    # Set only on the Guest :meth:`stage_tool` returns: its calls run that verified profile copy.
    profile_copy: str | None = None

    # The cache behind :attr:`packed`. Exposed through a plain property because pyright does not
    # accept a cached_property where GuestPort declares a read-only property.
    @cached_property
    def _packed(self) -> PackedTool:
        return packed_tool(self.tool_dir)

    @property
    def packed(self) -> PackedTool:
        """The packed tool, hashed once per Guest so every call names the copy this Guest pushed.

        Raises:
            GuestPushError: The packed tool is missing (see :func:`packed_tool`).
        """
        return self._packed

    @property
    def tool_path(self) -> str:
        """The copy this Guest's tool calls run: the content address, or the verified profile copy."""
        return self.profile_copy or self.packed.guest_path

    def push_tool(self) -> Pushed:
        """See :func:`push_tool`."""
        return push_tool(self.ip, self.packed, ssh=self.ssh_settings, runner=self.runner)

    def stage_tool(self) -> Guest:
        r"""Copy the tool to the ssh user's profile and verify it (:func:`stage_tool`); calls run that copy.

        Returns:
            This guest, with every tool call running the verified profile copy instead of the one in
            ``C:\winrepair``. Delete the copy with :meth:`remove_profile_copy` when done.
        """
        staged = stage_tool(self.ip, self.packed, ssh=self.ssh_settings, runner=self.runner)
        guest = replace(self, profile_copy=staged)
        guest.__dict__["_packed"] = self.packed  # the digest just verified, not a re-read of the node file
        return guest

    def remove_profile_copy(self) -> str | None:
        """Delete the profile copy this Guest runs; None once done, else why not (never raises)."""
        return remove_staged(self.runner, self.ip, self.ssh_settings, self.packed.staged)

    def tool(self, command: str, *args: str, timeout: float) -> Envelope:
        """See :func:`guest_tool`; runs the copy at :attr:`tool_path`."""
        return guest_tool(self, command, *args, timeout=timeout)

    def probe(self, command: str, *args: str, timeout: float) -> Fields:
        """Run a subcommand that never refuses (a pure probe) and return its data.

        Raises:
            GuestProtocolError: It refused anyway.
        """
        envelope = self.tool(command, *args, timeout=timeout)
        if not envelope.ok:
            raise GuestProtocolError(f"probe {command} refused (exit {envelope.exit_code}); it never should")
        return envelope.data

    def ssh(self, *remote: str, timeout: float) -> subprocess.CompletedProcess[str]:
        """Run a raw remote command (``hostname``, ``mkdir``); the caller checks the result.

        A timeout or an ssh that cannot start comes back as a failed process (rc 255), the code
        ssh itself uses for a connection failure, so a readiness poll simply tries again.
        """
        argv = _ssh_argv(self.ip, self.ssh_settings, remote)
        try:
            return _call(self.runner, argv, timeout, "ssh")
        except GuestNoAnswerError as exc:
            return subprocess.CompletedProcess(argv, 255, "", str(exc))

    def copy_to(self, sources: Sequence[str], dest: str, *, timeout: float) -> subprocess.CompletedProcess[str]:
        """``scp -r`` ``sources`` into the guest directory ``dest``; the caller checks the result.

        Like :meth:`ssh`, a timeout or an scp that cannot start comes back as a failed process
        (rc 255) naming why, so the caller reports a failed transfer rather than crashing.
        """
        argv = _scp_argv(self.ip, self.ssh_settings, sources, dest, recursive=True)
        try:
            return _call(self.runner, argv, timeout, "media transfer")
        except GuestNoAnswerError as exc:
            return subprocess.CompletedProcess(argv, 255, "", str(exc))
