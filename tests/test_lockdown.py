"""Tests for lockdown: the DACL that keeps non-admins away from what the SYSTEM task executes.

The pure checks run on readings built here. The pywin32 wiring (``create_locked_dir``,
``inspect_lock_target``, ``read_acl``, ``token_user_sid``) runs against ``FakeSecurity`` and
``FakeFiles``, in-memory stand-ins for ``win32security`` and ``win32file`` with the same member
names, so the flags, SIDs and masks handed to the real API are pinned.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from win32_fakes import (
    FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT,
    SE_DACL_PROTECTED,
    Descriptor,
    FakeApi,
    FakeFiles,
    FakeSecurity,
    Node,
    Sid,
    Win32Error,
    descriptor,
)

from pve_winrepair_guest import lockdown
from pve_winrepair_guest.lockdown import Ace, AclReading, LockTarget

if TYPE_CHECKING:
    import os

SYSTEM, ADMINS, RUNNER, USERS = "S-1-5-18", "S-1-5-32-544", "S-1-5-21-1-2-3-1001", "S-1-5-11"
PLANTER = "S-1-5-21-1-2-3-1002"
REPARSE_DIR = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT
OPEN_REPARSE_POINT = 0x00200000
TRUSTED = frozenset({SYSTEM, ADMINS, RUNNER})
FULL = 0x1F01FF
INHERIT = 0x3  # OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
READ_EXECUTE = 0x1200A9
MODIFY = 0x1301BF


def _locked_dir(path: str = r"C:\winrepair", owner: str = ADMINS) -> AclReading:
    return AclReading(path, owner, True, (Ace(SYSTEM, 0, INHERIT, FULL), Ace(ADMINS, 0, INHERIT, FULL)))


# --- the pure checks ----------------------------------------------------------------------------


def test_a_locked_directory_has_no_problem() -> None:
    assert lockdown.acl_problems(_locked_dir(), trusted=TRUSTED, container=True) == ()


def test_an_authenticated_users_modify_ace_is_a_problem() -> None:
    # The Windows default a directory under a drive root inherits.
    aces = (*(_locked_dir().aces or ()), Ace(USERS, 0, 0x1B, MODIFY))
    reading = AclReading(r"D:\upgrade", ADMINS, False, aces)
    problems = lockdown.acl_problems(reading, trusted=TRUSTED, container=True)
    assert any(USERS in p for p in problems)
    assert any("inherits" in p for p in problems)


def test_a_read_only_ace_for_others_is_no_problem() -> None:
    reading = AclReading(r"D:\upgrade\setup.exe", RUNNER, False, (Ace(USERS, 0, 0x10, READ_EXECUTE),))
    assert lockdown.acl_problems(reading, trusted=TRUSTED, container=False) == ()


@pytest.mark.parametrize("right", [0x2, 0x4, 0x40, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000])
def test_any_write_right_for_others_is_a_problem(right: int) -> None:
    reading = AclReading(r"D:\upgrade\setup.exe", RUNNER, False, (Ace(USERS, 0, 0, right),))
    assert lockdown.acl_problems(reading, trusted=TRUSTED, container=False) != ()


def test_a_deny_ace_for_others_is_no_problem() -> None:
    reading = AclReading(r"D:\upgrade\setup.exe", RUNNER, False, (Ace(USERS, 1, 0, FULL),))
    assert lockdown.acl_problems(reading, trusted=TRUSTED, container=False) == ()


def test_an_untrusted_owner_is_a_problem_because_an_owner_can_rewrite_the_dacl() -> None:
    problems = lockdown.acl_problems(_locked_dir(owner=USERS), trusted=TRUSTED, container=True)
    assert any("owned by S-1-5-11" in p for p in problems)


def test_a_null_dacl_is_a_problem() -> None:
    problems = lockdown.acl_problems(AclReading("x", ADMINS, True, None), trusted=TRUSTED, container=False)
    assert any("NULL DACL" in p for p in problems)


def test_an_unrecognised_ace_type_is_a_problem() -> None:
    reading = AclReading("x", ADMINS, False, (Ace(SYSTEM, 9, 0, FULL),))
    assert lockdown.acl_problems(reading, trusted=TRUSTED, container=False) != ()


@pytest.mark.parametrize(
    "aces",
    [
        (Ace(SYSTEM, 0, INHERIT, FULL),),
        (Ace(SYSTEM, 0, INHERIT, FULL), Ace(ADMINS, 0, 0, FULL)),
        (Ace(SYSTEM, 0, INHERIT, FULL), Ace(ADMINS, 0, INHERIT, READ_EXECUTE)),
    ],
    ids=["no-admins", "admins-not-inherited", "admins-not-full"],
)
def test_a_directory_must_grant_both_full_and_inheritable(aces: tuple[Ace, ...]) -> None:
    reading = AclReading(r"C:\winrepair", ADMINS, True, aces)
    assert lockdown.acl_problems(reading, trusted=TRUSTED, container=True) != ()


def test_the_lock_sids_are_system_and_administrators_never_a_name() -> None:
    assert lockdown.LOCK_SIDS == (SYSTEM, ADMINS)


# --- the content address ----------------------------------------------------------------------


def _tool(tmp_path: Path, content: bytes = b"# packed\n") -> Path:
    digest = hashlib.sha256(content).hexdigest()
    path = tmp_path / f"winrepair_guest-{digest[:16]}.ps1"
    path.write_bytes(content)
    return path


def test_a_tool_whose_bytes_match_its_name_passes(tmp_path: Path) -> None:
    path = _tool(tmp_path)
    digest, problem = lockdown.content_address(str(path))
    assert (digest, problem) == (hashlib.sha256(b"# packed\n").hexdigest(), None)


def test_a_tool_replaced_under_its_name_is_refused(tmp_path: Path) -> None:
    path = _tool(tmp_path)
    path.write_bytes(b"# not what the driver pushed\n")
    _digest, problem = lockdown.content_address(str(path))
    assert problem is not None
    assert "does not match its name" in problem


def test_a_tool_without_a_content_address_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "winrepair_guest.ps1"
    path.write_bytes(b"x")
    assert lockdown.content_address(str(path))[1] is not None


# --- the pywin32 wiring, over an in-memory win32security ------------------------------------------


LOCK_ACES = [((0, INHERIT), FULL, Sid(SYSTEM)), ((0, INHERIT), FULL, Sid(ADMINS))]


def test_create_locked_dir_creates_the_directory_with_the_lock_already_in_place() -> None:
    # No moment exists in which the directory carries the drive root's inherited DACL: a local
    # user who opened it then would keep that access through the handle after any later lock.
    security, files = FakeSecurity(), FakeFiles()
    assert lockdown.create_locked_dir(security, files, r"C:\winrepair") is True
    created = files.created[r"C:\winrepair"]
    assert created.control & SE_DACL_PROTECTED
    assert created.dacl is not None and created.dacl.aces == LOCK_ACES
    security.objects[r"C:\winrepair"] = created
    assert lockdown.exact_lock_problems(lockdown.read_acl(security, r"C:\winrepair")) == ()


def test_a_directory_made_without_a_descriptor_would_inherit_the_open_dacl() -> None:
    # Control for the fake: what os.mkdir gives a directory under a drive root.
    security, files = FakeSecurity(), FakeFiles()
    files.CreateDirectory(r"D:\upgrade", None)
    security.objects[r"D:\upgrade"] = files.created[r"D:\upgrade"]
    problems = lockdown.exact_lock_problems(lockdown.read_acl(security, r"D:\upgrade"))
    assert any("still inherits" in p for p in problems)
    assert any(f"lets {USERS} write" in p for p in problems)


def test_create_locked_dir_reports_a_name_that_exists_as_not_created() -> None:
    files = FakeFiles({r"C:\winrepair": Node(REPARSE_DIR, PLANTER, target=r"C:\Windows")})
    assert lockdown.create_locked_dir(FakeSecurity(), files, r"C:\winrepair") is False
    assert files.created == {}


def test_create_locked_dir_reports_a_failure_as_oserror() -> None:
    files = FakeFiles(missing=frozenset({r"E:\upgrade"}))
    with pytest.raises(OSError, match=r"cannot create E:\\upgrade") as caught:
        lockdown.create_locked_dir(FakeSecurity(), files, r"E:\upgrade")
    assert isinstance(caught.value.__cause__, Win32Error)


class _BindingRefuses(FakeSecurity):
    """win32security whose C binding refuses an argument before Windows sees the call."""

    def __init__(self, error: Exception) -> None:
        super().__init__()
        self.binding_error = error

    def SECURITY_DESCRIPTOR(self) -> Descriptor:  # noqa: N802 - mirrors the pywin32 / COM member name
        error = self.binding_error

        class _Refusing(Descriptor):
            def SetSecurityDescriptorControl(self, interest: int, bits: int, /) -> None:  # noqa: N802 - mirrors the pywin32 / COM member name
                raise error

        return _Refusing(None, None, 0)

    def GetNamedSecurityInfo(self, name: str, kind: int, info: int, /) -> Descriptor:  # noqa: N802 - mirrors the pywin32 / COM member name
        raise self.binding_error


@pytest.mark.parametrize(
    "error",
    [OverflowError("Python int too large to convert to C long"), TypeError("an integer is required")],
    ids=["overflow", "type"],
)
def test_a_binding_refusal_is_reported_as_oserror_so_lock_dirs_refuses_cleanly(error: Exception) -> None:
    security, files = _BindingRefuses(error), FakeFiles()
    with pytest.raises(OSError, match="cannot create") as created:
        lockdown.create_locked_dir(security, files, r"D:\upgrade")
    assert created.value.__cause__ is error
    assert files.created == {}
    with pytest.raises(OSError, match="cannot read the DACL") as read:
        lockdown.read_acl(security, r"D:\upgrade")
    assert read.value.__cause__ is error


def test_a_followed_junction_would_have_looked_like_a_plain_directory() -> None:
    # Control for the fake: opened the ordinary way, the junction reads as its target.
    files = FakeFiles({r"C:\winrepair": Node(REPARSE_DIR, PLANTER, target=r"C:\Windows")})
    handle = files.CreateFile(r"C:\winrepair", 0x80, 0x3, None, 3, 0x02000000, None)
    assert files.GetFileInformationByHandle(handle)[0] == FILE_ATTRIBUTE_DIRECTORY


def test_inspect_lock_target_reads_the_directory_and_each_ancestor_without_following_links() -> None:
    files = FakeFiles({"D:\\": Node(REPARSE_DIR, ADMINS, target="E:\\")})
    target = lockdown.inspect_lock_target(FakeSecurity(), files, r"D:\upgrade")
    assert target == LockTarget(r"D:\upgrade", ("D:\\",), True, ADMINS)
    assert [h.path for h in files.opened] == ["D:\\", r"D:\upgrade"]
    assert all(h.flags & OPEN_REPARSE_POINT and h.closed for h in files.opened)


def test_inspect_lock_target_reports_a_junction_and_its_own_owner() -> None:
    files = FakeFiles({r"C:\winrepair": Node(REPARSE_DIR, PLANTER, target=r"C:\Windows")})
    target = lockdown.inspect_lock_target(FakeSecurity(), files, r"C:\winrepair")
    assert target == LockTarget(r"C:\winrepair", (r"C:\winrepair",), True, PLANTER)


def test_inspect_lock_target_reports_an_unreadable_path_as_oserror() -> None:
    with pytest.raises(OSError, match=r"cannot inspect D:\\upgrade") as caught:
        lockdown.inspect_lock_target(FakeSecurity(), FakeFiles(missing=frozenset({r"D:\upgrade"})), r"D:\upgrade")
    assert isinstance(caught.value.__cause__, Win32Error)


def test_a_real_directory_owned_by_administrators_or_system_is_a_safe_lock_target() -> None:
    for owner in (ADMINS, SYSTEM):
        assert lockdown.lock_target_problems(LockTarget(r"C:\winrepair", (), True, owner)) == ()


def test_every_unsafe_property_of_a_lock_target_is_named() -> None:
    target = LockTarget(r"D:\upgrade", ("D:\\", r"D:\upgrade"), False, RUNNER)
    problems = lockdown.lock_target_problems(target)
    assert problems == (
        r"D:\upgrade lies below a reparse point at D:\, so a lock could land on another tree",
        r"D:\upgrade is a reparse point (a junction or link), so a lock would land on its target",
        r"D:\upgrade is not a directory",
        rf"D:\upgrade is owned by {RUNNER}, not SYSTEM or Administrators: another account created it",
    )


def test_read_acl_reports_an_unreadable_path_as_oserror() -> None:
    with pytest.raises(OSError, match="nicht finden"):
        lockdown.read_acl(FakeSecurity(), r"D:\missing")


def test_read_acl_reads_a_null_dacl_as_none() -> None:
    security = FakeSecurity()
    security.objects["x"] = descriptor(Sid(USERS), None, 0)
    assert lockdown.read_acl(security, "x") == AclReading("x", USERS, False, None)


def test_token_user_sid_reads_this_process_token() -> None:
    assert lockdown.token_user_sid(FakeSecurity(user=RUNNER), FakeApi()) == RUNNER


# --- the lock, exactly, and the tree below it ----------------------------------------


def test_a_directory_with_the_lock_reads_back_as_exactly_locked() -> None:
    for owner in (ADMINS, SYSTEM):
        assert lockdown.exact_lock_problems(_locked_dir(owner=owner)) == ()


@pytest.mark.parametrize(
    ("reading", "fragment"),
    [
        (AclReading(r"D:\upgrade", ADMINS, False, _locked_dir().aces), "still inherits"),
        (_locked_dir(owner=RUNNER), f"owned by {RUNNER}"),
        (AclReading(r"D:\upgrade", ADMINS, True, None), "NULL DACL"),
        # A read-only grant is harmless to acl_problems, but it is not the lock.
        (
            AclReading(r"D:\upgrade", ADMINS, True, (*(_locked_dir().aces or ()), Ace(USERS, 0, 0, READ_EXECUTE))),
            "carries 3 ACEs",
        ),
        (AclReading(r"D:\upgrade", ADMINS, True, (Ace(SYSTEM, 0, INHERIT, FULL),)), "carries 1 ACE"),
        (
            AclReading(r"D:\upgrade", ADMINS, True, (Ace(SYSTEM, 0, INHERIT, FULL), Ace(SYSTEM, 0, INHERIT, FULL))),
            f"does not grant {ADMINS}",
        ),
        (
            AclReading(r"D:\upgrade", ADMINS, True, (Ace(SYSTEM, 0, INHERIT, FULL), Ace(ADMINS, 0, 0x1, FULL))),
            f"ACE for {ADMINS} is not",
        ),
        (
            AclReading(r"D:\upgrade", ADMINS, True, (Ace(SYSTEM, 0, INHERIT, MODIFY), Ace(ADMINS, 0, INHERIT, FULL))),
            f"ACE for {SYSTEM} is not",
        ),
        (
            AclReading(r"D:\upgrade", ADMINS, True, (Ace(SYSTEM, 1, INHERIT, FULL), Ace(ADMINS, 0, INHERIT, FULL))),
            f"ACE for {SYSTEM} is not",
        ),
    ],
    ids=["inherits", "owner", "null-dacl", "extra-read-ace", "one-ace", "no-admins", "flags", "mask", "deny"],
)
def test_anything_but_the_exact_lock_is_named(reading: AclReading, fragment: str) -> None:
    problems = lockdown.exact_lock_problems(reading)
    assert any(fragment in p for p in problems), problems


def test_walk_tree_yields_every_entry_below_the_root_but_not_the_root(tmp_path: Path) -> None:
    (tmp_path / "sources" / "sub").mkdir(parents=True)
    (tmp_path / "setup.exe").write_bytes(b"MZ")
    (tmp_path / "sources" / "a.dll").write_bytes(b"MZ")
    (tmp_path / "sources" / "sub" / "b.dll").write_bytes(b"MZ")
    entries = {Path(e.path).relative_to(tmp_path).as_posix(): e for e in lockdown.walk_tree(str(tmp_path))}
    assert set(entries) == {"setup.exe", "sources", "sources/a.dll", "sources/sub", "sources/sub/b.dll"}
    assert entries["sources"].directory and not entries["setup.exe"].directory
    assert not any(e.reparse for e in entries.values())


def test_walk_tree_reports_a_link_and_does_not_descend_into_it(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    (outside / "deep").mkdir(parents=True)
    (outside / "deep" / "evil.dll").write_bytes(b"MZ")
    root = tmp_path / "upgrade"
    root.mkdir()
    (root / "sources").symlink_to(outside, target_is_directory=True)
    entries = list(lockdown.walk_tree(str(root)))
    assert [(Path(e.path).name, e.reparse) for e in entries] == [("sources", True)]


def test_walk_tree_does_not_enter_a_directory_whose_attributes_say_reparse_point(tmp_path: Path) -> None:
    # A Windows junction: a directory to stat, no symlink before 3.12, marked only by its attributes.
    (tmp_path / "sources" / "deep").mkdir(parents=True)
    (tmp_path / "sources" / "deep" / "evil.dll").write_bytes(b"MZ")
    (tmp_path / "setup.exe").write_bytes(b"MZ")
    junction = (tmp_path / "sources").stat().st_ino

    def attributes(info: os.stat_result) -> int:
        return FILE_ATTRIBUTE_REPARSE_POINT if info.st_ino == junction else 0

    entries = sorted(
        (Path(e.path).name, e.reparse, e.directory) for e in lockdown.walk_tree(str(tmp_path), attributes=attributes)
    )
    assert entries == [("setup.exe", False, False), ("sources", True, True)]
