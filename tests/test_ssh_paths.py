"""Tests for the ssh path rules: the known_hosts and node-key characters no quoting carries."""

from __future__ import annotations

import pytest

from pve_winrepair.domain.ssh_paths import jump_key_problem, known_hosts_problem


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        ("", "must not be empty"),
        ("/a b/kh", "must not contain whitespace: ssh splits the value into several files"),
        ("/a\tb", "must not contain whitespace: ssh splits the value into several files"),
        ('/a"b', "must not contain a double quote"),
        ("/kh%h", "must not contain %: ssh expands it as a token, once more through the jump to a guest"),
    ],
)
def test_a_node_known_hosts_path_no_quoting_carries_is_refused(path: str, reason: str) -> None:
    assert known_hosts_problem(path, through_jump=True) == reason


def test_a_guest_known_hosts_path_keeps_its_ssh_tokens() -> None:
    assert known_hosts_problem("~/.ssh/known_hosts_%h", through_jump=False) is None


@pytest.mark.parametrize("path", ["~/.ssh/known_hosts", r"C:\Users\operator\kh", "/keys/known_hosts_node"])
def test_an_ordinary_known_hosts_path_is_usable(path: str) -> None:
    assert known_hosts_problem(path, through_jump=True) is None


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        ('C:\\a"b', "must not contain a double quote"),
        ("/k%h/node.key", "must not contain %: ssh expands it as a token, once more through the jump to a guest"),
    ],
)
def test_a_node_key_no_quoting_carries_is_refused(path: str, reason: str) -> None:
    assert jump_key_problem(path) == reason


@pytest.mark.parametrize("path", ["", "/home/a b/node.key", r"C:\Users\srv admin\keys\node.key"])
def test_an_empty_or_spaced_node_key_is_not_refused_here(path: str) -> None:
    assert jump_key_problem(path) is None
