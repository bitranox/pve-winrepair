"""The ssh path values no quoting carries: refused at config load, never escaped per layer.

A known_hosts file reaches ssh as ``-o UserKnownHostsFile=<path>``, and the node's also inside the
``ProxyCommand`` that jumps to a guest. Each refused character fails at the first ssh today, later and
less clearly than a refusal at load:

* whitespace: ssh's own option parser splits a ``UserKnownHostsFile`` value at whitespace (``ssh -vvv``
  opened two files), and quoting inside the option on Windows would need a nested, backslash-escaped
  quote through CreateProcess that was never measured;
* ``"``: the Windows ``ProxyCommand`` double-quotes each path word, so a quote inside one ends it;
* ``%``: ssh expands ``%`` tokens in ``UserKnownHostsFile`` itself (``ssh -G -o UserKnownHostsFile=/kh%h
  pve1`` printed ``/khpve1``), and the outer ssh expands a ``ProxyCommand`` once more, so even a doubled
  ``%%`` reached the inner ssh as ``%h`` (measured, OpenSSH 10.2p1). A known_hosts file read by a direct
  guest ssh keeps its tokens: a per-guest ``known_hosts_%h`` is legitimate there.

The node key is a separate ``-i`` word, so a space in it is quoted like any word and stays allowed; ""
means not configured, which the command that needs the key refuses later.
"""

from __future__ import annotations

from typing import Final

__all__ = ["jump_key_problem", "known_hosts_problem"]

_PERCENT: Final[str] = "must not contain %: ssh expands it as a token, once more through the jump to a guest"
_QUOTE: Final[str] = "must not contain a double quote"


def known_hosts_problem(path: str, *, through_jump: bool) -> str | None:
    """Why ssh would misread ``path`` as a known_hosts file, or None when it is usable.

    Args:
        path: The known_hosts file as configured, before ssh expands a leading ``~``.
        through_jump: True when the path also travels inside the ``ProxyCommand`` to a guest, where a
            ``%`` is expanded twice; False for a direct ssh, where ssh's own tokens are wanted.

    Returns:
        The reason, which never repeats ``path``, or None.

    Example:
        >>> known_hosts_problem("~/.ssh/known_hosts", through_jump=True) is None
        True
        >>> known_hosts_problem("/a b/kh", through_jump=True)
        'must not contain whitespace: ssh splits the value into several files'
        >>> known_hosts_problem("~/.ssh/known_hosts_%h", through_jump=False) is None
        True
    """
    if not path:
        return "must not be empty"
    if any(char.isspace() for char in path):
        return "must not contain whitespace: ssh splits the value into several files"
    if '"' in path:
        return _QUOTE
    if through_jump and "%" in path:
        return _PERCENT
    return None


def jump_key_problem(path: str) -> str | None:
    """Why the node key ``path`` cannot travel inside the ``ProxyCommand``, or None when it can.

    Args:
        path: The node's private key file as configured; "" (not configured) is not refused here.

    Returns:
        The reason, which never repeats ``path``, or None.

    Example:
        >>> jump_key_problem("/home/a b/node.key") is None
        True
        >>> jump_key_problem("/k%h/node.key")
        'must not contain %: ssh expands it as a token, once more through the jump to a guest'
    """
    if '"' in path:
        return _QUOTE
    if "%" in path:
        return _PERCENT
    return None
