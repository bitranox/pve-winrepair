"""``pve-winrepair repair``: run an in-place repair upgrade of one guest on this node.

Thin: it reads the settings, refuses what :mod:`.runs` checks before any call, builds the
:class:`~pve_winrepair.application.repair.RepairRequest`, runs the use case on the composition's node
and receipt store, and prints the result (exit 0 repaired or staged, 1 refused, 2 internal; 78 when
the configuration does not load or validate).

Contents:
    * :func:`cli_repair` - the ``repair`` command.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import lib_log_rich.runtime
import rich_click as click

from pve_winrepair.application.repair import RepairRequest, run_repair

from ..constants import CLICK_CONTEXT_SETTINGS
from ..context import get_cli_context
from ..param_types import Ipv4Address, PositiveFiniteFloat, StorageId, WindowsDrive
from ..typed_click import option
from .runs import (
    PreflightError,
    RunCommand,
    check_node,
    echo_step,
    finish,
    load_run_settings,
    refused,
    resolve_snapshot_name,
)

if TYPE_CHECKING:
    from ipaddress import IPv4Address

    from pve_winrepair.domain.enums import DriveLetter

__all__ = ["cli_repair"]


@click.command("repair", context_settings=CLICK_CONTEXT_SETTINGS)
@option("--vmid", type=click.IntRange(min=1), required=True, help="The guest's VMID on this node.")
@option(
    "--snapshot-name",
    default=None,
    help=(
        "Snapshot taken before the media are staged; one of that name that exists is reused. A missing vTPM "
        "is added before it, and on a running guest reached through the agent the Windows Update hold too. "
        "Default: [repair] snapshot_name."
    ),
)
@option("--hours", type=PositiveFiniteFloat(), default=6.0, show_default=True, help="Polling deadline, in hours.")
@option("--json", "as_json", is_flag=True, default=False, help="Print a JSON envelope on stdout.")
@option(
    "--stage-only",
    is_flag=True,
    default=False,
    help="Stage the media and hold Windows Update, but neither gate the WIM nor launch setup (verdict STAGED).",
)
@option(
    "--ip",
    type=Ipv4Address(),
    default=None,
    help=(
        "Guest IPv4 address, for a guest with no QEMU agent. Implies the offline snapshot: stop, snapshot, "
        "start. The guest there must have a NIC MAC of the VM's qm config, or the run is refused."
    ),
)
@option(
    "--stage-root",
    type=WindowsDrive(),
    default=None,
    help="Drive to stage the media on, e.g. C: or D:. Default: a non-system fixed drive with room, else C:.",
)
@option(
    "--tpm-storage",
    type=StorageId(),
    default=None,
    help="PVE storage ID for a new vTPM volume. Default: the storage the guest's own disk is on.",
)
@click.pass_context
def cli_repair(
    ctx: click.Context,
    *,
    vmid: int,
    snapshot_name: str | None,
    hours: float,
    as_json: bool,
    stage_only: bool,
    ip: IPv4Address | None,
    stage_root: DriveLetter | None,
    tpm_storage: str | None,
) -> None:
    """Repair a guest whose cumulative update fails, by an in-place repair upgrade.

    Refuse a live upgrade run, hold Windows Update (on a running guest reached through the agent),
    ensure a vTPM, snapshot, stage the installation media from [repair] media_dir, hold Windows Update
    again, gate the image, record the receipt, launch setup from a SYSTEM task and poll to its
    verdict. Each step goes to stderr as it happens. Exit 0 when repaired or staged, 1 when refused,
    2 on an internal error or a bad option, 78 when the configuration does not load.
    """
    cli_ctx = get_cli_context(ctx)
    settings = load_run_settings(ctx, cli_ctx)
    with lib_log_rich.runtime.bind(job_id="cli-repair", extra={"command": "repair", "vmid": vmid}):
        try:
            check_node(settings)
            request = RepairRequest(
                vmid=vmid,
                snapshot_name=resolve_snapshot_name(settings.repair, snapshot_name),
                hours=hours,
                stage_only=stage_only,
                ip=ip,
                stage_root=stage_root,
                tpm_storage=tpm_storage,
            )
        except PreflightError as refusal:
            finish(ctx, refused(vmid, refusal, wu_held=False), command=RunCommand.REPAIR, vmid=vmid, as_json=as_json)
        result = run_repair(
            request,
            cli_ctx.services.make_node(settings.ssh, None),
            repair=settings.repair,
            guest=settings.guest,
            receipts=cli_ctx.services.make_receipts(settings.node.state_dir),
            on_step=echo_step,
        )
        finish(ctx, result, command=RunCommand.REPAIR, vmid=vmid, as_json=as_json)
