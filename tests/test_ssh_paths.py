"""Tests for the ssh path rules: the known_hosts and node-key characters no quoting carries."""

from __future__ import annotations

import pytest

from pve_winrepair.domain.ssh_paths import jump_key_problem, key_path_problem, known_hosts_problem


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


#: Every ASCII control character, DEL included, beside the whitespace ones a known_hosts path already refuses.
_CONTROLS = [chr(code) for code in (*range(0x20), 0x7F)]


@pytest.mark.parametrize("char", _CONTROLS, ids=[f"0x{ord(c):02x}" for c in _CONTROLS])
def test_a_key_path_holding_a_control_character_is_refused(char: str) -> None:
    reason = key_path_problem(f"C:{char}keys{chr(0x5C)}guest.key")
    assert reason is not None
    assert reason.startswith("must not contain a control character")
    assert jump_key_problem(f"/keys/node{char}.key") == reason


@pytest.mark.parametrize("char", [chr(0x08), chr(0x00), chr(0x7F)], ids=["backspace", "nul", "del"])
def test_a_known_hosts_path_holding_a_non_space_control_character_is_refused(char: str) -> None:
    assert str(known_hosts_problem(f"/kh{char}x", through_jump=False)).startswith("must not contain a control")


@pytest.mark.parametrize("path", ["", "/home/a b/guest.key", r"C:\Users\operator\.ssh\id_guest", "/k%h/key"])
def test_a_guest_key_path_without_a_control_character_is_usable(path: str) -> None:
    assert key_path_problem(path) is None
