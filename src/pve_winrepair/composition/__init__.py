"""Composition root wiring adapters to application ports.

``build_production`` wires the real adapters: the node runs ``qm``, ssh and scp for real and the
repair receipts are files under ``[node] state_dir``. ``build_testing`` wires the in-memory
configuration and logging adapters; the node it builds refuses to run anything unless a test
passes its own ``make_node`` (a node on a fake runner), so no test reaches a real ``qm`` or ssh.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, NoReturn

from ..adapters.config.deploy import deploy_configuration
from ..adapters.config.display import display_config

# Configuration services
from ..adapters.config.loader import get_config, get_default_config_path
from ..adapters.config.settings import load_settings

# Logging services
from ..adapters.logging.setup import check_logging_config, init_logging

# The node and its receipts
from ..adapters.node import Node
from ..adapters.receipts import FileReceiptStore

# Static conformance assertions - pyright verifies that each adapter function
# structurally satisfies its corresponding Protocol at type-check time.
if TYPE_CHECKING:
    from collections.abc import Sequence

    from ..application.ports import (
        CheckLoggingConfig,
        DeployConfiguration,
        DisplayConfig,
        GetConfig,
        GetDefaultConfigPath,
        InitLogging,
        LoadSettings,
        MakeNode,
        MakeReceipts,
    )
    from ..domain.node_link import NodeLink
    from ..domain.settings import SshSettings

    _assert_get_config: GetConfig = get_config
    _assert_get_default_config_path: GetDefaultConfigPath = get_default_config_path
    _assert_deploy_configuration: DeployConfiguration = deploy_configuration
    _assert_display_config: DisplayConfig = display_config
    _assert_init_logging: InitLogging = init_logging
    _assert_check_logging_config: CheckLoggingConfig = check_logging_config
    _assert_load_settings: LoadSettings = load_settings
    _assert_make_node: MakeNode = Node
    _assert_make_receipts: MakeReceipts = FileReceiptStore


@dataclass(frozen=True, slots=True)
class AppServices:
    """Frozen container holding all application port implementations."""

    get_config: GetConfig
    get_default_config_path: GetDefaultConfigPath
    deploy_configuration: DeployConfiguration
    display_config: DisplayConfig
    init_logging: InitLogging
    check_logging_config: CheckLoggingConfig
    load_settings: LoadSettings
    make_node: MakeNode
    make_receipts: MakeReceipts


def build_production() -> AppServices:
    """Wire production adapters into an AppServices container."""
    return AppServices(
        get_config=get_config,
        get_default_config_path=get_default_config_path,
        deploy_configuration=deploy_configuration,
        display_config=display_config,
        init_logging=init_logging,
        check_logging_config=check_logging_config,
        load_settings=load_settings,
        make_node=Node,
        make_receipts=FileReceiptStore,
    )


def _refuse_to_run(cmd: Sequence[str], _timeout: float) -> NoReturn:
    """The testing node's runner: a test that runs the node without injecting one gets this error."""
    raise RuntimeError(f"build_testing runs no command ({cmd[0]}): pass make_node to build_testing")


def _refusing_node(ssh: SshSettings, link: NodeLink | None) -> Node:
    """A node on :func:`_refuse_to_run`, so an unprepared test never reaches a real ``qm`` or ssh."""
    return Node(ssh=ssh, link=link, runner=_refuse_to_run)


def build_testing(*, make_node: MakeNode | None = None, make_receipts: MakeReceipts | None = None) -> AppServices:
    """Wire in-memory adapters into an AppServices container.

    Args:
        make_node: The node the commands run on (a node on a fake runner); default: one that
            refuses to run anything.
        make_receipts: The receipt store; default: the file store, in whatever ``[node] state_dir``
            the test configures or the ``--receipt`` file the run names.

    Returns:
        AppServices container with in-memory adapters.
    """
    from ..adapters.memory import (  # noqa: PLC0415 - deferred: keeps in-memory test doubles out of the production import path
        check_logging_config_in_memory,
        deploy_configuration_in_memory,
        display_config_in_memory,
        get_config_in_memory,
        get_default_config_path_in_memory,
        init_logging_in_memory,
    )

    return AppServices(
        get_config=get_config_in_memory,
        get_default_config_path=get_default_config_path_in_memory,
        deploy_configuration=deploy_configuration_in_memory,
        display_config=display_config_in_memory,
        init_logging=init_logging_in_memory,
        check_logging_config=check_logging_config_in_memory,
        load_settings=load_settings,
        make_node=make_node or _refusing_node,
        make_receipts=make_receipts or FileReceiptStore,
    )


__all__ = [
    "AppServices",
    "build_production",
    "build_testing",
    "check_logging_config",
    "deploy_configuration",
    "display_config",
    "get_config",
    "get_default_config_path",
    "init_logging",
    "load_settings",
]
