"""Names shared by the ``failing_command`` fixture and the tests that assert on what it raises.

A conftest is not imported by name, so the fixture's command name and message live here: the
fixture builds its command from them and the tests compare against the same values.
"""

from __future__ import annotations

__all__ = ["FAILING_COMMAND", "FAILING_MESSAGE"]

#: The name the ``failing_command`` fixture registers; no shipped command is called this.
FAILING_COMMAND = "test-only-fail"
#: The message of the ``RuntimeError`` that command raises.
FAILING_MESSAGE = "I should fail"
