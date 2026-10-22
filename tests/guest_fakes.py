"""A fake ssh/scp runner for the host-driver tests, answering with the guest tool's REAL envelopes.

The drivers reach the guest only through the ssh adapter's runner seam (the function that runs ssh
and scp). :class:`FakeRunner` stands in for it: it records every argv and answers each guest tool
subcommand from a queue of replies. The replies are built with the guest's own ``envelope.build``
over the guest's own data models (``probes.StateLog``, ``upgrade.LaunchReport``, ...), so a field
renamed on the guest side breaks these tests instead of passing against a hand-typed dict.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from pve_winrepair_guest.envelope import Outcome, build, internal_error, render
from pve_winrepair_guest.probes import StateLog, state_verdict
from pve_winrepair_guest.upgrade import DirectoryLock, LockDirsReport

#: The account the fakes expect ssh and scp to log in as (``SshSettings.user``).
USER = "admin"
GUEST_IP = "192.0.2.10"
LAN_IP = "192.0.2.50"
# What would stop, restart or reconfigure the VM, or take a snapshot of it.
MUTATING_QM = frozenset({"shutdown", "stop", "start", "set", "snapshot", "rollback", "reboot"})
# A real file standing in for the packed tool: the drivers hash it to name its guest copy.
TOOL_DIR = Path(__file__).resolve().parent / "fixtures" / "packed_tool"


def expected_guest_path(source: Path) -> str:
    r"""Where the driver must put ``source`` on the guest, computed here independently of the ssh adapter.

    ``C:\winrepair\winrepair_guest-<first 16 hex of its sha256>.ps1``.
    """
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    return f"C:\\winrepair\\winrepair_guest-{digest[:16]}.ps1"


TOOL_PATH = expected_guest_path(TOOL_DIR / "winrepair_guest.ps1")


def locked(*, present: bool, stage_root: str | None = None) -> LockDirsReport:
    r"""lock-dirs' answer for a guest whose ``C:\winrepair`` (and stage root) it locked or found locked."""
    dirs = (DirectoryLock("C:\\winrepair", "ALREADY_LOCKED"),)
    if stage_root is not None:
        dirs += (DirectoryLock(stage_root, "CREATED"),)
    return LockDirsReport(TOOL_PATH, present, "ab" * 32 if present else None, dirs, "OK", None)


@dataclass(frozen=True)
class Reply:
    """What one fake ssh/scp call returns."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


def answer(command: str, data: object, *, ok: bool = True) -> Reply:
    """The tool's envelope for ``data``: exit 0 when ``ok``, else exit 1 (refused)."""
    return Reply(0 if ok else 1, render(build(command, Outcome(ok=ok, data=data))) + "\r\n")


def crashed(command: str, error: BaseException) -> Reply:
    """The tool's internal-error envelope (exit 2)."""
    return Reply(2, render(internal_error(command, error)) + "\r\n", "Traceback ...")


def route(cmd: Sequence[str]) -> str:
    """The key a call is answered under: ``qm``, ``scp``, the tool subcommand, or the raw remote verb."""
    if cmd[0] in ("qm", "scp"):
        return cmd[0]
    at = next(i for i, token in enumerate(cmd) if token.startswith(f"{USER}@"))
    remote = list(cmd[at + 1 :])
    if remote[0].endswith("powershell.exe"):
        return remote[6]
    if remote[0].endswith("certutil.exe"):
        return "certutil"
    return remote[0]


def certutil_output(digest: str, path: str = "winrepair_guest.ps1") -> str:
    """What ``certutil -hashfile <path> SHA256`` prints on a German guest: header, hex line, footer.

    Only the hex line is a contract (it is not localised); the rest is there so a parser that keys
    on English text fails here. The footer's u-umlaut is built from its codepoint (ASCII sources).
    """
    done = f"CertUtil: -hashfile-Befehl wurde erfolgreich ausgef{chr(0xFC)}hrt."
    return f"SHA256-Hash von {path}:\r\n{digest}\r\n{done}\r\n"


def hashes_to(source: Path) -> Responder:
    """certutil on a guest whose every hashed file holds ``source``'s bytes (the push went right)."""
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    return lambda cmd: Reply(0, certutil_output(digest, cmd[-2]))


Responder = Callable[[list[str]], Reply]
Answer = Reply | BaseException | Responder


class FakeRunner:
    """Records argv and answers per route; the last reply of a queue repeats.

    A reply may be an exception (``subprocess.TimeoutExpired``, ``OSError``), raised as the real
    ``subprocess.run`` would, or a function of the argv that returns the reply (a stateful fake).
    """

    def __init__(self) -> None:
        self.replies: dict[str, list[Answer]] = {}
        self.calls: list[list[str]] = []
        self.timeouts: list[float] = []

    def on(self, key: str, *replies: Answer) -> FakeRunner:
        """Queue ``replies`` for ``key``."""
        self.replies.setdefault(key, []).extend(replies)
        return self

    def __call__(self, cmd: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(cmd))
        self.timeouts.append(timeout)
        key = route(cmd)
        queue = self.replies.get(key)
        if not queue:
            raise AssertionError(f"unexpected call {key!r}: {list(cmd)}")
        reply = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(reply, BaseException):
            raise reply
        if not isinstance(reply, Reply):
            reply = reply(list(cmd))
        return subprocess.CompletedProcess(list(cmd), reply.returncode, reply.stdout, reply.stderr)


def lock_dirs_reply(cmd: list[str]) -> Reply:
    """lock-dirs on a guest whose tool is in place: its directory (and a named stage root) locked."""
    stage_root = cmd[cmd.index("--stage-root") + 1] if "--stage-root" in cmd else None
    return answer("lock-dirs", locked(present=True, stage_root=stage_root))


def tool_on_the_guest(runner: FakeRunner) -> FakeRunner:
    """Answer a push for a guest that already has this tool version in its locked ``C:\\winrepair``.

    Every push copies the tool to the ssh user's profile and runs lock-dirs from there; the copy into
    ``C:\\winrepair`` is skipped because lock-dirs found the verified tool already in place.
    """
    return (
        runner.on("scp", Reply(0))
        .on("certutil", hashes_to(TOOL_DIR / "winrepair_guest.ps1"))
        .on("lock-dirs", lock_dirs_reply)
        .on("del", Reply(0))
    )


class FakeClock:
    """A clock that only moves when something sleeps."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.slept: list[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def state_log(*lines: str, present: bool = True) -> StateLog:
    r"""The guest's ``state`` probe data for a log holding ``lines`` (verdict parsed the guest's way)."""
    verdict, marker = state_verdict(lines)
    return StateLog(r"C:\upgrade-state.log", present, verdict, marker, len(lines), tuple(lines))


class FakePve:
    """``qm`` on a node with one VM: tracks its power state so stop/start sequences read back."""

    def __init__(self, status: str = "running") -> None:
        self.status = status
        self.config = "scsi0: local-zfs:vm-1-disk-0,size=64G\ntpmstate0: local-zfs:vm-1-disk-1,size=4M\n"

    def __call__(self, cmd: list[str]) -> Reply:
        verb = cmd[1]
        if verb in ("shutdown", "start"):
            self.status = "stopped" if verb == "shutdown" else "running"
            return Reply(0)
        interfaces = [{"ip-addresses": [{"ip-address-type": "ipv4", "ip-address": LAN_IP}]}]
        answers = {
            "status": f"status: {self.status}\n",
            "config": self.config,
            "listsnapshot": "`-> current                                        You are here!\n",
            "guest": json.dumps(interfaces),
        }
        if verb in answers:
            return Reply(0, answers[verb])
        if verb in ("agent", "snapshot", "set"):
            return Reply(0)
        raise AssertionError(f"unexpected qm call: {cmd}")


def call_labels(calls: list[list[str]]) -> list[str]:
    """Each call as ``qm <verb>``, ``scp`` or ``guest <tool subcommand or raw verb>``, in order."""
    labels: list[str] = []
    for cmd in calls:
        if cmd[0] == "qm":
            labels.append(f"qm {cmd[1]}")
        elif cmd[0] == "scp":
            labels.append("scp")
        else:
            labels.append(f"guest {route(cmd)}")
    return labels
