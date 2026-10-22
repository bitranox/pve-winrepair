"""Send email CLI command.

Provides the send-email command with HTML and attachment support.
"""

from __future__ import annotations

import functools
from pathlib import Path

import lib_log_rich.runtime
import rich_click as click

from ...config_load import require_config
from ...constants import CLICK_CONTEXT_SETTINGS
from ...context import get_cli_context
from ...typed_click import option
from ._common import (
    EmailConfigOverrides,
    execute_with_email_error_handling,
    load_and_validate_email_config,
    smtp_config_options,
)


@click.command("send-email", context_settings=CLICK_CONTEXT_SETTINGS)
@option(
    "--to",
    "recipients",
    multiple=True,
    required=False,
    help="Recipient email address (can specify multiple; uses config default if not specified)",
)
@option("--subject", required=True, help="Email subject line")
@option("--body", default="", help="Plain-text email body")
@option("--body-html", default="", help="HTML email body (sent as multipart with plain text)")
@option("--from", "from_address", default=None, help="Override sender address (uses config default if not specified)")
@option(
    "--attachment",
    "attachments",
    multiple=True,
    type=click.Path(path_type=str),
    help="File to attach (can specify multiple)",
)
@option(
    "--raise-on-missing-attachments/--no-raise-on-missing-attachments",
    default=None,
    help="Override missing attachment handling",
)
@smtp_config_options
@click.pass_context
def cli_send_email(
    ctx: click.Context,
    *,
    recipients: tuple[str, ...],
    subject: str,
    body: str,
    body_html: str,
    from_address: str | None,
    attachments: tuple[str, ...],
    smtp_hosts: tuple[str, ...],
    smtp_username: str | None,
    smtp_password: str | None,
    use_starttls: bool | None,
    timeout: float | None,
    raise_on_missing_attachments: bool | None,
    raise_on_invalid_recipient: bool | None,
) -> None:
    """Send an email using configured SMTP settings.

    \f
    Example:
        >>> from click.testing import CliRunner
        >>> runner = CliRunner()
        >>> # Real invocation tested in test_cli_email.py
    """
    cli_ctx = get_cli_context(ctx)
    config = require_config(ctx, cli_ctx)
    resolved_recipients = list(recipients) if recipients else None
    extra = {"command": "send-email", "recipients": resolved_recipients, "subject": subject}

    with lib_log_rich.runtime.bind(job_id="cli-send-email", extra=extra):
        overrides = EmailConfigOverrides.from_cli_options(
            smtp_hosts=smtp_hosts,
            smtp_username=smtp_username,
            smtp_password=smtp_password,
            use_starttls=use_starttls,
            timeout=timeout,
            raise_on_missing_attachments=raise_on_missing_attachments,
            raise_on_invalid_recipient=raise_on_invalid_recipient,
        )
        email_config = load_and_validate_email_config(
            config, cli_ctx.services.load_email_config_from_dict, overrides=overrides
        )
        attachment_paths = [Path(p) for p in attachments] if attachments else None

        # No "Sending email" line here: the transport logs it with the resolved sender and recipients.
        execute_with_email_error_handling(
            operation=functools.partial(
                cli_ctx.services.send_email,
                config=email_config,
                recipients=resolved_recipients,
                subject=subject,
                body=body,
                body_html=body_html,
                from_address=from_address,
                attachments=attachment_paths,
            ),
            recipients=resolved_recipients,
            message_type="Email",
            catches_file_not_found=True,
        )


__all__ = ["cli_send_email"]
