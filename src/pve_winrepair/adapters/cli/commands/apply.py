"""``pve-winrepair apply``: apply a staged repair upgrade and verify the build its repair run recorded.

Thin: it reads the settings, refuses what :mod:`.runs` checks before any call (a remote node that
cannot be used included), builds the :class:`~pve_winrepair.application.apply.ApplyRequest`, runs the
use case on the composition's node (this machine, or the one ``--node`` names) and receipt store,
and prints the result (exit 0 verified, 1 refused, 2 internal; 78 when the configuration does not
load or validate).

Contents:
    * :func:`cli_apply` - the ``apply`` command.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import lib_log_rich.runtime
import rich_click as click

from pve_winrepair.application.apply import ApplyRequest, run_apply

from ..constants import CLICK_CONTEXT_SETTINGS
from ..context import get_cli_context
from ..param_types import Ipv4Address, NodeHost, PositiveFiniteFloat
from ..typed_click import option
from .runs import (
    PreflightError,
    RunCommand,
    check_link,
    check_node,
    echo_step,
    finish,
    load_run_settings,
    refused,
    resolve_link,
)

if TYPE_CHECKING:
    from ipaddress import IPv4Address

__all__ = ["cli_apply"]


@click.command("apply", context_settings=CLICK_CONTEXT_SETTINGS)
@option("--vmid", type=click.IntRange(min=1), required=True, help="The guest's VMID on the node.")
@option(
    "--ip",
    type=Ipv4Address(),
    required=True,
    help="The guest's IPv4 address. It must have a NIC MAC of the VM's qm config, or the run is refused.",
)
@option(
    "--node",
    type=NodeHost(),
    default=None,
    help="PVE node to drive over ssh, guests reached through it. Default: [node] host; empty: this machine.",
)
@option(
    "--receipt",
    type=click.Path(dir_okay=False, readable=False, path_type=Path, resolve_path=True),
    default=None,
    help="Receipt file on this machine, instead of receipt-<vmid>.json in [node] state_dir.",
)
@option(
    "--apply-minutes",
    type=PositiveFiniteFloat(),
    default=90.0,
    show_default=True,
    help="How long the apply phase may take before it is reported as overrun.",
)
@option("--json", "as_json", is_flag=True, default=False, help="Print a JSON envelope on stdout.")
@click.pass_context
def cli_apply(
    ctx: click.Context,
    *,
    vmid: int,
    ip: IPv4Address,
    node: str | None,
    receipt: Path | None,
    apply_minutes: float,
    as_json: bool,
) -> None:
    """Apply the upgrade a repair run staged, and verify the build it recorded.

    Refuses unless the guest's upgrade run finished OK, reboots it cleanly into the new OS, waits
    for it to answer ssh, checks its build against the repair's receipt (in [node] state_dir, or the
    --receipt file), and lifts the Windows Update hold. Exit 0 when verified, 1 when refused, 2 on an
    internal error or a bad option, 78 when the configuration does not load.
    """
    cli_ctx = get_cli_context(ctx)
    settings = load_run_settings(ctx, cli_ctx)
    with lib_log_rich.runtime.bind(job_id="cli-apply", extra={"command": "apply", "vmid": vmid}):
        try:
            check_node(settings, receipt)
            node_port = cli_ctx.services.make_node(settings.ssh, resolve_link(settings, node))
            check_link(node_port)
        except PreflightError as refusal:
            # The repair run held Windows Update and only a verified apply lifts it.
            finish(ctx, refused(vmid, refusal, wu_held=True), command=RunCommand.APPLY, vmid=vmid, as_json=as_json)
        result = run_apply(
            ApplyRequest(vmid=vmid, ip=ip, apply_minutes=apply_minutes),
            node_port,
            receipts=cli_ctx.services.make_receipts(settings.node.state_dir, receipt),
            on_step=echo_step,
        )
        finish(ctx, result, command=RunCommand.APPLY, vmid=vmid, as_json=as_json)
