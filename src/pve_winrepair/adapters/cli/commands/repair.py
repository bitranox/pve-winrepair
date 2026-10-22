"""``pve-winrepair repair``: run an in-place repair upgrade of one guest on this node.

Thin: it reads the settings, refuses what :mod:`.runs` checks before any call, builds the
:class:`~pve_winrepair.application.repair.RepairRequest`, runs the use case on the composition's node
and receipt store, and prints the result (exit 0 repaired or staged, 1 refused, 2 internal; 78 when
the configuration does not load or validate).

Contents:
    * :func:`cli_repair` - the ``repair`` command.
"""

from __future__ import annotations

import lib_log_rich.runtime
import rich_click as click

from pve_winrepair.application.repair import RepairRequest, run_repair

from ..constants import CLICK_CONTEXT_SETTINGS
from ..context import get_cli_context
from ..typed_click import option
from .runs import (
    PreflightError,
    check_node,
    echo_step,
    finish,
    load_run_settings,
    operator_progress,
    refused,
    resolve_snapshot_name,
)

__all__ = ["cli_repair"]


@click.command("repair", context_settings=CLICK_CONTEXT_SETTINGS)
@option("--vmid", type=click.IntRange(min=1), required=True, help="The guest's VMID on this node.")
@option(
    "--snapshot-name",
    default=None,
    help="Snapshot taken before anything changes on the guest. Default: [repair] snapshot_name.",
)
@option("--hours", type=float, default=6.0, show_default=True, help="Polling deadline, in hours.")
@option("--json", "as_json", is_flag=True, default=False, help="Print a JSON envelope on stdout.")
@option("--stage-only", is_flag=True, default=False, help="Stage and verify the media, but do not launch setup.")
@option(
    "--ip",
    default=None,
    help="Guest address, for a guest with no QEMU agent. Implies the offline snapshot: stop, snapshot, start.",
)
@option(
    "--stage-root",
    default=None,
    help="Drive to stage the media on, e.g. C: or D:. Default: a non-system fixed drive with room, else C:.",
)
@option(
    "--tpm-storage",
    default=None,
    help="PVE storage for a new vTPM volume. Default: the storage the guest's own disk is on.",
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
    ip: str | None,
    stage_root: str | None,
    tpm_storage: str | None,
) -> None:
    """Repair a guest whose cumulative update fails, by an in-place repair upgrade.

    Snapshot, ensure a vTPM, stage the installation media from [repair] media_dir, gate the image,
    launch setup from a SYSTEM task and poll to its verdict. Each step goes to stderr as it happens.
    Exit 0 when repaired or staged, 1 when refused, 2 on an internal error, 78 when the
    configuration does not load.
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
            finish(ctx, refused(vmid, refusal, wu_held=False), command="repair", vmid=vmid, as_json=as_json)
        with operator_progress():
            result = run_repair(
                request,
                cli_ctx.services.make_node(settings.ssh),
                repair=settings.repair,
                guest=settings.guest,
                receipts=cli_ctx.services.make_receipts(settings.node.state_dir),
                on_step=echo_step,
            )
        finish(ctx, result, command="repair", vmid=vmid, as_json=as_json)
