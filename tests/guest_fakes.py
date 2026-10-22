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
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

from click.testing import CliRunner
from lib_layered_config import Config

from pve_winrepair.adapters.cli.main import main
from pve_winrepair.adapters.guest_ssh import Guest
from pve_winrepair.adapters.node import Node
from pve_winrepair.composition import AppServices, build_production, build_testing
from pve_winrepair.domain.settings import SshSettings
from pve_winrepair_guest.envelope import Outcome, build, internal_error, render
from pve_winrepair_guest.probes import (
    BuildInfo,
    Drive,
    DriveReport,
    ServicingReport,
    SetupReport,
    StagedOs,
    StateLog,
    state_verdict,
)
from pve_winrepair_guest.upgrade import (
    DirectoryLock,
    LaunchReport,
    LaunchWait,
    LockDirsReport,
    PrepareReport,
    TaskCleanup,
)
from pve_winrepair_guest.wim import WimImage
from pve_winrepair_guest.wu import (
    QuiesceReport,
    RestoreReport,
    SearchProbe,
    ServiceRow,
    StartWrite,
    StopIssued,
    StopWait,
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
    """``qm`` on a node with one VM: tracks its power state so stop/start sequences read back.

    ``stuck``: a VM whose power state never changes - ``qm shutdown`` and ``qm start`` answer 0 and
    ``qm status`` keeps reporting ``status`` - for a wait that must give up.
    """

    def __init__(self, status: str = "running", *, stuck: bool = False) -> None:
        self.status = status
        self.stuck = stuck
        self.config = "scsi0: local-zfs:vm-1-disk-0,size=64G\ntpmstate0: local-zfs:vm-1-disk-1,size=4M\n"

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


# --- whole runs: a guest every step of a repair or an apply answers OK -----------------------
# Shared by the use-case tests and the CLI tests, so one fake guest decides both.

GIB = 1024**3


def quiesce_report(verdict: str, *, running: tuple[str, ...] = ()) -> QuiesceReport:
    """quiesce-wu's answer with ``verdict``; ``running`` names the services still running."""
    rows = (ServiceRow("wuauserv", "Disabled", "Running" if running else "Stopped"),)
    return QuiesceReport(
        previous_start_modes={"wuauserv": "Manual", "UsoSvc": "Auto"},
        writes=(StartWrite("wuauserv", 4, "WRITTEN", None),),
        stops=(StopIssued("wuauserv", 0, None),),
        wait=StopWait(10.0, False, running),
        services=rows,
        not_disabled=(),
        still_running=running,
        verdict=verdict,
    )


def drive_report(**free_gib: float) -> DriveReport:
    """drives' answer: one fixed drive per keyword, with that many GiB free."""
    return DriveReport(
        drives=tuple(
            Drive(letter, int(gib * GIB), int(gib * GIB) * 2, round(gib, 1)) for letter, gib in sorted(free_gib.items())
        )
    )


def servicing_report(total: int) -> ServicingReport:
    """servicing-active's answer with ``total`` servicing processes."""
    return ServicingReport(counts={"TiWorker": total, "TrustedInstaller": 0}, total=total, active=total > 0)


IMAGE = WimImage(1, "Windows 11 Pro", "Professional", 26200, 8973, ("de-DE",), "de-DE")
RUNNING_BUILD = BuildInfo("26200", 7462, "26200.7462")


def prepare_report(gate: str, reason: str | None = None, *, tpm: bool | None = True) -> PrepareReport:
    """prepare's answer for :data:`IMAGE` staged on ``D:\\upgrade``: ``gate`` PASS or FAIL with ``reason``."""
    passed = gate == "PASS"
    return PrepareReport(
        "D:\\upgrade",
        12,
        0,
        "D:\\upgrade\\sources\\install.wim",
        gate,
        reason,
        IMAGE,
        RUNNING_BUILD,
        1 if passed else None,
        tpm if passed else None,
        (),
    )


DISARMED = TaskCleanup("DISARM", None, False, True, None)


def launch_report(
    verdict: str,
    reason: str | None = None,
    *,
    wait: str | None = "LAUNCHED",
    setuphost: int | None = 1,
    cleanup: TaskCleanup = DISARMED,
) -> LaunchReport:
    """launch's answer with ``verdict``: the SYSTEM task points at the pushed tool."""
    return LaunchReport(
        "OVMRepairUpgrade",
        f"powershell -File {TOOL_PATH} upgrade-run",
        False,
        True,
        None if wait is None else LaunchWait(wait, 42.0, None),
        setuphost,
        state_log("launching: setup.exe"),
        cleanup,
        verdict,
        reason,
    )


ALIVE = answer("setup-alive", SetupReport(1, True))
GONE = answer("setup-alive", SetupReport(0, False))
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
        "launch": [answer("launch", launch_report("OK"))],
    }
    answers.update({key: [value] for key, value in overrides.items()})
    runner = FakeRunner()
    for key, replies in answers.items():
        runner.on(key, *replies)
    return runner


NEWOS = r"C:\$WINDOWS.~BT\NewOS\Windows\System32\winload.efi"
TIMED_OUT = SearchProbe("TIMEOUT", None, (), None, 180.0)


def restore_report(verdict: str, still: tuple[str, ...] = (), search: SearchProbe = TIMED_OUT) -> RestoreReport:
    """restore-wu's answer with ``verdict``; ``still`` names the services left disabled."""
    rows = tuple(
        ServiceRow(name, "Disabled" if name in still else "Manual", "Stopped") for name in ("wuauserv", "UsoSvc")
    )
    return RestoreReport(
        writes=(StartWrite("wuauserv", 3, "WRITTEN", None),),
        services=rows,
        still_disabled=still,
        verdict=verdict,
        search=search,
    )


def apply_runner(pve: FakePve, alive: Reply, state: Reply) -> FakeRunner:
    """A guest one apply away from the target: down-level staged, NewOS present."""
    return (
        tool_on_the_guest(FakeRunner())
        .on("qm", pve)
        .on("build", answer("build", BuildInfo("26200", 7462, "26200.7462")), answer("build", BUILD_AFTER))
        .on("setup-alive", alive)
        .on("state", state)
        .on("staged-os", answer("staged-os", StagedOs(NEWOS, True, "REARMABLE")))
        .on("hostname", Reply(0, "GUEST\r\n"))
        .on("restore-wu", answer("restore-wu", restore_report("RESTORED")))
    )


BUILD_AFTER = BuildInfo("26200", 8973, "26200.8973")


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
    receipt creates it).
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
    return CliRun(exit_code, stdout.getvalue().decode("utf-8"), stderr.getvalue().decode("utf-8"))


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
