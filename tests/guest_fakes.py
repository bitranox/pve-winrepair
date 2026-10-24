"""A fake ssh/scp runner for the host-driver tests, answering with the guest tool's REAL envelopes.

The drivers reach the guest only through the ssh adapter's runner seam (the function that runs ssh
and scp). :class:`FakeRunner` stands in for it: it records every argv and answers each guest tool
subcommand from a queue of replies. The replies are built with the guest's own ``envelope.build``
over the guest's own data models (``probes.StateLog``, ``upgrade.LaunchReport``, ...), so a field
renamed on the guest side breaks these tests instead of passing against a hand-typed dict.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
from click.testing import CliRunner
from lib_layered_config import Config
from pwshpy import ServiceState

from pve_winrepair.adapters.cli.main import main
from pve_winrepair.adapters.guest_ssh import Guest
from pve_winrepair.adapters.node import Node
from pve_winrepair.composition import AppServices, build_production, build_testing
from pve_winrepair.domain.receipt import BuildPair, RepairReceipt
from pve_winrepair.domain.settings import SshSettings
from pve_winrepair_guest.envelope import Outcome, Report, build, internal_error, render
from pve_winrepair_guest.probes import (
    BuildInfo,
    BuildReport,
    Drive,
    DriveReport,
    NicMacReport,
    ServicingReport,
    SetupReport,
    StagedOs,
    StagedVerdict,
    StateLog,
    state_verdict,
)
from pve_winrepair_guest.upgrade import (
    DirectoryAction,
    DirectoryLock,
    LaunchReport,
    LaunchVerdict,
    LaunchWait,
    LaunchWaitStatus,
    LockDirsReport,
    LockDirsVerdict,
    PrepareGate,
    PrepareReport,
    TaskCleanup,
    TaskCleanupAction,
    WimImage,
)
from pve_winrepair_guest.wu import (
    QuiesceReport,
    QuiesceVerdict,
    RestoreReport,
    RestoreVerdict,
    SearchProbe,
    SearchStatus,
    ServiceRow,
    ServiceStart,
    StartMode,
    StartWrite,
    StopIssued,
    StopWait,
    WmiServiceState,
    WriteResult,
)

if TYPE_CHECKING:
    from pve_winrepair.domain.envelope import Runner

#: The account the fakes expect ssh and scp to log in as (``SshSettings.user``).
USER = "admin"
#: The guest key the fakes' ssh and scp name; never read, the runner is fake.
KEY = "/keys/test.key"
SSH = SshSettings(key=KEY, user=USER)
GUEST_IP = "192.0.2.10"
LAN_IP = "192.0.2.50"
# What would stop, restart or reconfigure the VM, or take a snapshot of it.
MUTATING_QM = frozenset({"shutdown", "stop", "start", "set", "snapshot", "rollback", "reboot"})
#: The MAC of the fake VM's one NIC (``net0`` of :class:`FakePve`), as PVE writes it.
VM_MAC = "BC:24:11:0A:0B:0C"
# A real file standing in for the packed tool: the drivers hash it to name its guest copy.
TOOL_DIR = Path(__file__).resolve().parent / "fixtures" / "packed_tool"


def expected_guest_path(source: Path) -> str:
    r"""Where the driver must put ``source`` on the guest, computed here independently of the ssh adapter.

    ``C:\winrepair\winrepair_guest-<first 16 hex of its sha256>.ps1``.
    """
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    return f"C:\\winrepair\\winrepair_guest-{digest[:16]}.ps1"


TOOL_PATH = expected_guest_path(TOOL_DIR / "winrepair_guest.ps1")


def make_guest(runner: Runner, tool_dir: Path | None = None) -> Guest:
    """The guest at :data:`GUEST_IP`, reached with :data:`SSH` through ``runner``."""
    return Guest(GUEST_IP, ssh_settings=SSH, tool_dir=tool_dir or TOOL_DIR, runner=runner)


def make_node(runner: Runner, clock: FakeClock | None = None) -> Node:
    """A node reaching its guests with :data:`SSH` through ``runner``; ``clock`` (default: a fresh one) waits."""
    clock = clock or FakeClock()
    return Node(ssh=SSH, runner=runner, clock=clock.time, sleep=clock.sleep, tool_dir=TOOL_DIR)


def locked(*, present: bool, stage_root: str | None = None) -> LockDirsReport:
    r"""lock-dirs' answer for a guest whose ``C:\winrepair`` (and stage root) it locked or found locked."""
    dirs = (DirectoryLock(path="C:\\winrepair", action=DirectoryAction.ALREADY_LOCKED),)
    if stage_root is not None:
        dirs += (DirectoryLock(path=stage_root, action=DirectoryAction.CREATED),)
    return LockDirsReport(
        tool=TOOL_PATH,
        tool_present=present,
        tool_sha256="ab" * 32 if present else None,
        directories=dirs,
        verdict=LockDirsVerdict.OK,
        reason=None,
    )


@dataclass(frozen=True)
class Reply:
    """What one fake ssh/scp call returns."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


def answer(command: str, data: Report | Mapping[str, object], *, ok: bool = True) -> Reply:
    """The tool's envelope for ``data``: exit 0 when ``ok``, else exit 1 (refused).

    ``data`` is one of the guest's own reports, or a hand-typed payload for an answer that breaks
    the contract (a missing field, a renamed one), which no guest model can be made to carry.
    """
    if isinstance(data, Report):
        line = render(build(command, Outcome(ok=ok, data=data)))
    else:
        # The envelope's own layout, as render writes it: json.dumps with its default separators.
        line = json.dumps({"ok": ok, "command": command, "data": dict(data), "skipped": []}, ensure_ascii=True)
    return Reply(0 if ok else 1, line + "\r\n")


#: What nic-macs reports on the guest that is the fake VM: its NIC (lower case here, so both sides
#: must be normalised) plus a Hyper-V vEthernet adapter the VM config does not list - the check is
#: membership, never equality.
NIC_MACS = answer("nic-macs", NicMacReport(macs=("00:15:5D:01:02:03", VM_MAC.lower())))


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
        # The profile probe runs an encoded script, not the tool: it has no subcommand to route by.
        return PROFILE_ACL if "-EncodedCommand" in remote else remote[6]
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

#: The route the profile probe (the ssh user's profile descriptor, read before a copy goes there) is
#: answered under.
PROFILE_ACL = "profile-acl"
#: The ssh user's SID and profile directory the default probe reply reports.
PROFILE_SID = "S-1-5-21-1-2-3-1001"
PROFILE_PATH = "C:\\Users\\admin"
#: A profile only SYSTEM, Administrators and the ssh user may write; an app capability SID may only
#: traverse it.
PROFILE_SDDL = (
    f"O:{PROFILE_SID}G:{PROFILE_SID}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{PROFILE_SID})"
    "(A;;0x100020;;;S-1-15-3-1024-1-2-3)"
)


def profile_reply(sddl: str = PROFILE_SDDL, *, user: str = PROFILE_SID, path: str = PROFILE_PATH) -> Reply:
    """What the profile probe prints: one compressed JSON object, as ``ConvertTo-Json -Compress`` writes it."""
    return Reply(0, json.dumps({"path": path, "user": user, "sddl": sddl}, separators=(",", ":")) + "\r\n")


#: Answered on every runner unless a test queues its own: a guest whose profile only trusted
#: principals can write, so a push or stage proceeds past the probe.
DEFAULT_REPLIES: Mapping[str, Answer] = {PROFILE_ACL: profile_reply()}


class FakeRunner:
    """Records argv and answers per route; the last reply of a queue repeats.

    A route with nothing queued is answered from :data:`DEFAULT_REPLIES` (the profile probe), else
    the call is unexpected. A reply may be an exception (``subprocess.TimeoutExpired``,
    ``OSError``), raised as the real ``subprocess.run`` would, or a function of the argv that
    returns the reply (a stateful fake).
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
        queue = self.replies.get(key) or ([DEFAULT_REPLIES[key]] if key in DEFAULT_REPLIES else None)
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
    return StateLog(
        path=r"C:\upgrade-state.log",
        present=present,
        verdict=verdict,
        marker=marker,
        line_count=len(lines),
        tail=tuple(lines),
    )


class FakePve:
    """``qm`` on a node with one VM: tracks its power state so stop/start sequences read back.

    ``stuck``: a VM whose power state never changes - ``qm shutdown`` and ``qm start`` answer 0 and
    ``qm status`` keeps reporting ``status`` - for a wait that must give up.
    """

    def __init__(self, status: str = "running", *, stuck: bool = False, snapshot_output: str = "") -> None:
        self.status = status
        self.stuck = stuck
        self.snapshot_output = snapshot_output
        self.config = (
            "scsi0: local-zfs:vm-1-disk-0,size=64G\n"
            "tpmstate0: local-zfs:vm-1-disk-1,size=4M\n"
            f"net0: virtio={VM_MAC},bridge=vmbr0,firewall=1\n"
        )

    def __call__(self, cmd: list[str]) -> Reply:
        verb = cmd[1]
        if verb in ("shutdown", "start"):
            if not self.stuck:
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
        if verb == "snapshot":
            return Reply(0, self.snapshot_output)
        if verb in ("agent", "set"):
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


# --- whole runs: a guest every step of a repair or an apply answers OK -----------------------
# Shared by the use-case tests and the CLI tests, so one fake guest decides both.

GIB = 1024**3


def quiesce_report(verdict: str, *, running: tuple[str, ...] = ()) -> QuiesceReport:
    """quiesce-wu's answer with ``verdict`` (its value text); ``running`` names the services still running."""
    state = WmiServiceState.RUNNING if running else WmiServiceState.STOPPED
    rows = (ServiceRow(name="wuauserv", start_mode=StartMode.DISABLED, state=state),)
    return QuiesceReport(
        previous_start_modes={"wuauserv": StartMode.MANUAL, "UsoSvc": StartMode.AUTO},
        writes=(StartWrite(service="wuauserv", value=ServiceStart.DISABLED, result=WriteResult.WRITTEN, error=None),),
        stops=(StopIssued(service="wuauserv", state=ServiceState.STOP_PENDING, error=None),),
        wait=StopWait(waited_s=10.0, timed_out=False, still_running=running),
        services=rows,
        not_disabled=(),
        still_running=running,
        verdict=QuiesceVerdict(verdict),
    )


def drive_report(**free_gib: float) -> DriveReport:
    """drives' answer: one fixed drive per keyword, with that many GiB free."""
    return DriveReport(
        drives=tuple(
            # float(): an int keyword (C=60) must reach the wire as 60.0, as a real drive reports it.
            Drive(letter=letter, free_bytes=int(gib * GIB), size_bytes=int(gib * GIB) * 2, free_gb=round(float(gib), 1))
            for letter, gib in sorted(free_gib.items())
        )
    )


def servicing_report(total: int) -> ServicingReport:
    """servicing-active's answer with ``total`` servicing processes."""
    return ServicingReport(counts={"TiWorker": total, "TrustedInstaller": 0}, total=total, active=total > 0)


IMAGE = WimImage(
    index=1,
    name="Windows 11 Pro",
    edition="Professional",
    build=26200,
    spbuild=8973,
    languages=("de-DE",),
    default_language="de-DE",
)
RUNNING_BUILD = BuildInfo(current_build="26200", ubr=7462, build="26200.7462")
#: InstallDate (epoch seconds) of the guest before the repair, and after an upgrade that applied.
INSTALL_DATE = 1_761_206_400
INSTALL_DATE_AFTER = 1_761_300_000
#: What ``build`` reports on the guest before the upgrade: :data:`RUNNING_BUILD` and its InstallDate.
BUILD_BEFORE = BuildReport(current_build="26200", ubr=7462, build="26200.7462", install_date=INSTALL_DATE)


def prepare_report(gate: str, reason: str | None = None, *, tpm: bool | None = True) -> PrepareReport:
    """prepare's answer for :data:`IMAGE` staged on ``D:\\upgrade``: ``gate`` PASS or FAIL with ``reason``."""
    passed = PrepareGate(gate) is PrepareGate.PASSED
    return PrepareReport(
        stage_root="D:\\upgrade",
        readonly_cleared=12,
        readonly_failed=0,
        wim="D:\\upgrade\\sources\\install.wim",
        gate=PrepareGate(gate),
        reason=reason,
        image=IMAGE,
        running=RUNNING_BUILD,
        waiver_readback=1 if passed else None,
        tpm_present=tpm if passed else None,
        drives=(),
    )


DISARMED = TaskCleanup(action=TaskCleanupAction.DISARM, ended=None, disabled=False, deleted=True, error=None)


def launch_report(
    verdict: str,
    reason: str | None = None,
    *,
    wait: str | None = "LAUNCHED",
    setuphost: int | None = 1,
    cleanup: TaskCleanup = DISARMED,
) -> LaunchReport:
    """launch's answer with ``verdict`` and ``wait`` (their value texts): the SYSTEM task points at the pushed tool."""
    return LaunchReport(
        task="OVMRepairUpgrade",
        command=f"powershell -File {TOOL_PATH} upgrade-run",
        stale_log_removed=False,
        registered=True,
        wait=None if wait is None else LaunchWait(status=LaunchWaitStatus(wait), waited_s=42.0, last_error=None),
        setuphost=setuphost,
        state=state_log("launching: setup.exe"),
        task_cleanup=cleanup,
        verdict=LaunchVerdict(verdict),
        reason=reason,
    )


ALIVE = answer("setup-alive", SetupReport(count=1, alive=True))
GONE = answer("setup-alive", SetupReport(count=0, alive=False))
NO_LOG = answer("state", state_log(present=False))
DONE_OK = answer("state", state_log("launching: setup.exe", "STATE=DONE-OK setup exit=0x00000000"))


def agent_runner(pve: FakePve, **overrides: Answer) -> FakeRunner:
    """A healthy agent guest with no run on it: every step of a full repair answers OK."""
    answers: dict[str, list[Answer]] = {
        "qm": [pve],
        "lock-dirs": [lock_dirs_reply],
        "certutil": [hashes_to(TOOL_DIR / "winrepair_guest.ps1")],
        "del": [Reply(0)],
        "setup-alive": [GONE],
        "state": [NO_LOG, NO_LOG, DONE_OK],
        "quiesce-wu": [answer("quiesce-wu", quiesce_report("OK"))],
        "servicing-active": [answer("servicing-active", servicing_report(0))],
        "drives": [answer("drives", drive_report(C=60.0, D=200.0))],
        "scp": [Reply(0)],
        "prepare": [answer("prepare", prepare_report("PASS"))],
        "build": [answer("build", BUILD_BEFORE)],
        "nic-macs": [NIC_MACS],
        "launch": [answer("launch", launch_report("OK"))],
    }
    answers.update({key: [value] for key, value in overrides.items()})
    runner = FakeRunner()
    for key, replies in answers.items():
        runner.on(key, *replies)
    return runner


NEWOS = r"C:\$WINDOWS.~BT\NewOS\Windows\System32\winload.efi"
TIMED_OUT = SearchProbe(status=SearchStatus.TIMEOUT, pending=None, titles=(), error=None, timeout_s=180.0)


def restore_report(verdict: str, still: tuple[str, ...] = (), search: SearchProbe = TIMED_OUT) -> RestoreReport:
    """restore-wu's answer with ``verdict`` (its value text); ``still`` names the services left disabled."""
    rows = tuple(
        ServiceRow(
            name=name,
            start_mode=StartMode.DISABLED if name in still else StartMode.MANUAL,
            state=WmiServiceState.STOPPED,
        )
        for name in ("wuauserv", "UsoSvc")
    )
    return RestoreReport(
        writes=(StartWrite(service="wuauserv", value=ServiceStart.MANUAL, result=WriteResult.WRITTEN, error=None),),
        services=rows,
        still_disabled=still,
        verdict=RestoreVerdict(verdict),
        search=search,
    )


def apply_runner(pve: FakePve, alive: Reply, state: Reply) -> FakeRunner:
    """A guest one apply away from the target: down-level staged, NewOS present."""
    return (
        tool_on_the_guest(FakeRunner())
        .on("qm", pve)
        .on("build", answer("build", BUILD_BEFORE), answer("build", BUILD_AFTER))
        .on("setup-alive", alive)
        .on("state", state)
        .on("staged-os", answer("staged-os", StagedOs(path=NEWOS, present=True, verdict=StagedVerdict.REARMABLE)))
        .on("hostname", Reply(0, "GUEST\r\n"))
        .on("nic-macs", NIC_MACS)
        .on("restore-wu", answer("restore-wu", restore_report("RESTORED")))
    )


#: The guest after an upgrade to :data:`IMAGE` that applied: the image's build, a new InstallDate.
BUILD_AFTER = BuildReport(current_build="26200", ubr=8973, build="26200.8973", install_date=INSTALL_DATE_AFTER)
#: The receipt a repair of VM 1 leaves for :data:`IMAGE` staged on a guest that ran :data:`BUILD_BEFORE`.
RECEIPT = RepairReceipt(
    vmid=1,
    image_build=IMAGE.build,
    image_spbuild=IMAGE.spbuild,
    build_before=BuildPair(build=26200, ubr=7462),
    install_date_before=INSTALL_DATE,
    written_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc),
)


# --- the CLI: ``main()`` over the testing composition, with the fake node injected ----------------


@dataclass(frozen=True)
class CliRun:
    """How one ``main()`` run ended: its exit code and what it wrote to stdout and stderr."""

    exit_code: int
    stdout: str
    stderr: str


def cli_config(tmp_path: Path) -> dict[str, dict[str, object]]:
    """The node CLI sections for a run on the fake node: :data:`SSH`, a media dir, a state dir in ``tmp_path``.

    The media directory holds only ``setup.exe``; the state directory does not exist yet (the first
    receipt creates it). On Windows that state directory is ``C:\\...``, which the node refuses: a
    test whose run loads it carries :data:`NEEDS_A_POSIX_STATE_DIR`.
    """
    media = tmp_path / "media"
    media.mkdir(exist_ok=True)
    (media / "setup.exe").write_bytes(b"MZ")
    return {
        "ssh": {"key": KEY, "user": USER},
        "guest": {"subnet": "192.0.2.0/24"},
        "repair": {"media_dir": str(media)},
        "node": {"state_dir": str(tmp_path / "state")},
    }


#: Marks a test whose CLI run loads ``[node] state_dir`` from :func:`cli_config`. The node's state
#: directory is an absolute POSIX path on every OS (``NodeSettings`` refuses anything else, because
#: the directory is on a Proxmox node), and the only place this test can put it is ``tmp_path``,
#: which on Windows is ``C:\\...``: there the run ends with exit 78 before the command starts.
NEEDS_A_POSIX_STATE_DIR = pytest.mark.os_posix


def run_cli(
    argv: Sequence[str], config: Mapping[str, object], runner: Runner, *, production_logging: bool = False
) -> CliRun:
    """Run ``pve-winrepair <argv>`` through the real ``main()`` with ``config`` and a node on ``runner``.

    The configuration is injected as the template's CLI tests inject it (``get_config``), the node
    through ``build_testing(make_node=...)``: it gets the ``[ssh]`` settings the command read, the
    fake runner, a fake clock and the 83-byte stand-in tool. ``production_logging`` starts logging
    as a node does (lib_log_rich with its stdlib bridge on the root logger) from ``config``'s
    ``[lib_log_rich]`` section, instead of the testing composition's quiet runtime.
    """
    loaded = Config(dict(config), {})
    clock = FakeClock()

    def get_config(**_kwargs: object) -> Config:
        return loaded

    def make_node(ssh: SshSettings) -> Node:
        return Node(ssh=ssh, runner=runner, clock=clock.time, sleep=clock.sleep, tool_dir=TOOL_DIR)

    def services() -> AppServices:
        testing = dataclasses.replace(build_testing(make_node=make_node), get_config=get_config)
        if not production_logging:
            return testing
        production = build_production()
        return dataclasses.replace(
            testing, init_logging=production.init_logging, check_logging_config=production.check_logging_config
        )

    with CliRunner().isolation() as (stdout, stderr, _output):
        exit_code = main(list(argv), services_factory=services)
    # CliRunner's text streams write each "\n" as os.linesep, as a Windows stdout does: undo that.
    out, err = (stream.getvalue().decode("utf-8").replace(os.linesep, "\n") for stream in (stdout, stderr))
    return CliRun(exit_code, out, err)


def json_envelope(stdout: str) -> dict[str, object]:
    """The --json envelope: the WHOLE of stdout must parse as one object, so nothing else went there."""
    parsed: object = json.loads(stdout)
    assert isinstance(parsed, dict)
    return cast("dict[str, object]", parsed)


def envelope_steps(envelope: dict[str, object]) -> list[dict[str, object]]:
    """The envelope's ``steps``, each a step object."""
    steps = envelope["steps"]
    assert isinstance(steps, list)
    return cast("list[dict[str, object]]", steps)


#: A ``[lib_log_rich]`` section that logs as a node does at the default verbosity (console INFO on
#: stderr), with no system sink and no queue, so the console lines are written before ``main()``
#: returns and nothing reaches the machine's journal.
NODE_LOGGING: dict[str, object] = {
    "service": "pve-winrepair-test",
    "environment": "test",
    "console_level": "INFO",
    "console_stream": "stderr",
    "backend_level": "WARNING",
    "enable_journald": False,
    "enable_eventlog": False,
    "enable_graylog": False,
    "queue_enabled": False,
}
