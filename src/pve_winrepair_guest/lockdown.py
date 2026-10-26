r"""Keep non-admins away from what the SYSTEM upgrade task executes.

The task runs the packed tool from ``C:\winrepair`` and ``setup.exe`` from the stage root as
SYSTEM, and setup.exe loads what lies beside it. A directory created under a drive root inherits
``Authenticated Users: Modify`` (the Windows default), so without this any local user could
replace or plant a file there and have SYSTEM run it. ``lock-dirs`` therefore creates both
directories with a DACL restricted to SYSTEM and Administrators already in place (there is no
moment in which they are open), before anything is copied in; ``launch`` checks they still carry
exactly that DACL, walks the tree below them, and checks the tool's bytes against the sha256 its
name carries.

Principals are named by SID, never by name: on a German-language Windows "Administrators" is
"Administratoren" and a by-name grant fails. The ACL is built and read through pywin32's native
calls, not by parsing ``icacls`` output, which is localised too.

Contents:
    * :func:`create_locked_dir`, :func:`inspect_lock_target`, :func:`read_acl` - the pywin32 calls,
      over an injected :class:`Win32Security` and :class:`Win32File` (the seams the tests fake).
    * :func:`walk_tree` - every entry below a locked directory, without following a reparse point.
    * :func:`acl_problems`, :func:`exact_lock_problems`, :func:`content_address`,
      :func:`lock_scope_problem`, :func:`lock_target_problems` - the pure checks.
    * :class:`Ace`, :class:`AclReading`, :class:`LockTarget`, :class:`TreeEntry` - what was read back.
"""

from __future__ import annotations

import hashlib
import ntpath
import os
import re
import stat
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

from pydantic import BaseModel, ConfigDict

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

__all__ = [
    "ADMINISTRATORS_SID",
    "LOCK_SIDS",
    "SYSTEM_SID",
    "TOOL_DIR",
    "Ace",
    "AclReading",
    "LockTarget",
    "TreeEntry",
    "Win32File",
    "Win32Security",
    "acl_problems",
    "content_address",
    "create_locked_dir",
    "exact_lock_problems",
    "inspect_lock_target",
    "lock_scope_problem",
    "lock_target_problems",
    "read_acl",
    "walk_tree",
]

SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"
LOCK_SIDS = (SYSTEM_SID, ADMINISTRATORS_SID)
# winnt.h / accctrl.h values; fixed by the Windows ABI.
SE_FILE_OBJECT = 1
OWNER_SECURITY_INFORMATION = 0x1
DACL_SECURITY_INFORMATION = 0x4
SE_DACL_PROTECTED = 0x1000
ERROR_ALREADY_EXISTS = 183
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
READ_CONTROL = 0x20000
FILE_READ_ATTRIBUTES = 0x80
FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000  # needed to open a directory at all
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000  # open a junction or link itself, not its target
ACL_REVISION = 2
ACCESS_ALLOWED_ACE_TYPE = 0
ACCESS_DENIED_ACE_TYPE = 1
OBJECT_INHERIT_ACE = 0x1
CONTAINER_INHERIT_ACE = 0x2
FILE_ALL_ACCESS = 0x1F01FF
# Every right that lets a principal change what runs: write/append data (on a directory: add a
# file or subdirectory), extended attributes, attributes, delete a child, delete, change the DACL,
# take ownership, and the generic write/all bits.
WRITE_RIGHTS = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000
# The guest path guestcall pushes the tool to: winrepair_guest-<first 16 hex of its sha256>.ps1.
TOOL_DIR = "C:\\winrepair"
_CONTENT_ADDRESS = re.compile(r"winrepair_guest-([0-9a-f]{16})\.ps1")
# The only stage root the driver stages into (repair_vm's <letter>:\upgrade).
_STAGE_ROOT = re.compile(r"[A-Za-z]:\\upgrade", re.IGNORECASE)
# Every directory handle here opens the object itself, never what a reparse point leads to.
_OPEN_FLAGS = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
# Inspection opens carry no data right, so they neither block nor are blocked by other handles.
_SHARE = FILE_SHARE_READ | FILE_SHARE_WRITE
_INSPECT_ACCESS = READ_CONTROL | FILE_READ_ATTRIBUTES


# --- the pywin32 surface used here ----------------------------------------------------------------


class Sid(Protocol):
    """A ``PySID``; only ever handed back to win32security."""


class Acl(Protocol):
    """The ``PyACL`` members used here."""

    def AddAccessAllowedAceEx(self, revision: int, aceflags: int, access: int, sid: Sid, /) -> None:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Append an access-allowed ACE with inheritance flags."""
        ...

    def GetAceCount(self) -> int:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Return the number of ACEs."""
        ...

    def GetAce(self, index: int, /) -> tuple[object, ...]:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Return ``((type, flags), mask, ..., sid)``: the SID is last for every ACE type."""
        ...


class SecurityDescriptor(Protocol):
    """The ``PySECURITY_DESCRIPTOR`` members used here."""

    def GetSecurityDescriptorOwner(self) -> Sid:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Return the owner SID."""
        ...

    def GetSecurityDescriptorDacl(self) -> Acl | None:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Return the DACL; None for a NULL DACL (everyone has full access)."""
        ...

    def GetSecurityDescriptorControl(self) -> tuple[int, int]:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Return (control bits, revision)."""
        ...

    def SetSecurityDescriptorDacl(self, present: int, dacl: Acl | None, defaulted: int, /) -> None:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Set the DACL of a descriptor being built."""
        ...

    def SetSecurityDescriptorControl(self, interest: int, bits: int, /) -> None:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Set the ``bits`` among the control bits ``interest`` (SE_DACL_PROTECTED here)."""
        ...


class SecurityAttributes(Protocol):
    """The ``PySECURITY_ATTRIBUTES`` member used here: the descriptor a new object gets.

    Typed ``object`` because it is only ever assigned a descriptor built here and handed back to
    win32file.
    """

    SECURITY_DESCRIPTOR: object


class Win32Security(Protocol):
    """The ``win32security`` members used here (pywin32 is Windows-only, absent on the dev host)."""

    @property
    def error(self) -> type[Exception]:
        """``pywintypes.error``, which every call here raises (it is not an OSError)."""
        ...

    def ACL(self) -> Acl:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Return a new, empty ACL."""
        ...

    def SECURITY_DESCRIPTOR(self) -> SecurityDescriptor:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Return a new, empty security descriptor."""
        ...

    def SECURITY_ATTRIBUTES(self) -> SecurityAttributes:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Return new security attributes, to carry a descriptor into a create call."""
        ...

    def ConvertStringSidToSid(self, sid: str, /) -> Sid:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Parse ``S-1-...`` into a SID."""
        ...

    def ConvertSidToStringSid(self, sid: Sid, /) -> str:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Render a SID as ``S-1-...``."""
        ...

    def GetSecurityInfo(self, handle: object, object_type: int, info: int, /) -> SecurityDescriptor:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Read parts of the security descriptor of the object behind an open handle."""
        ...

    def GetNamedSecurityInfo(self, name: str, object_type: int, info: int, /) -> SecurityDescriptor:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Read parts of an object's security descriptor."""
        ...


class Win32File(Protocol):
    """The ``win32file`` members used here."""

    def CreateFile(  # noqa: N802, PLR0913, PLR0917 - mirrors the win32file name and its fixed positional signature
        self,
        name: str,
        access: int,
        share: int,
        security: object,
        disposition: int,
        flags: int,
        template: object,
        /,
    ) -> object:
        """Open a file or directory and return its handle."""
        ...

    def CreateDirectory(self, name: str, security: SecurityAttributes, /) -> None:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Create a directory with the given security attributes."""
        ...

    def GetFileInformationByHandle(self, handle: object, /) -> tuple[object, ...]:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Return ``(attributes, ...)`` of the object behind the handle."""
        ...

    def CloseHandle(self, handle: object, /) -> None:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Close a handle."""
        ...


# --- readings and checks --------------------------------------------------------------------------


class Ace(BaseModel):
    """One ACE as read back.

    Attributes:
        sid: The principal, as ``S-1-...``.
        kind: The ACE type (0 allowed, 1 denied, anything else is not recognised here).
        flags: The inheritance flags.
        mask: The access mask.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    sid: str
    kind: int
    flags: int
    mask: int


class AclReading(BaseModel):
    """An object's owner and DACL.

    Attributes:
        path: The object.
        owner: Its owner SID (an owner can always rewrite the DACL).
        protected: The DACL does not inherit from the parent.
        aces: The ACEs in order, or None for a NULL DACL.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    owner: str
    protected: bool
    aces: tuple[Ace, ...] | None


class LockTarget(BaseModel):
    """A directory lock-dirs is about to lock (or launch to trust), read without following a reparse point.

    Attributes:
        path: The directory.
        reparse_points: The directory itself and every ancestor on its path that is a reparse
            point (a junction, a symbolic link, a mount point), in path order; () for none.
        directory: The object is a directory.
        owner: Its owner SID.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    reparse_points: tuple[str, ...]
    directory: bool
    owner: str


class TreeEntry(BaseModel):
    """One file or directory below a locked directory, as listed without following a reparse point.

    Attributes:
        path: Its full path.
        reparse: It is a reparse point (a junction, a symbolic link, a mount point); a walk does
            not descend into it.
        directory: It is a directory.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    reparse: bool
    directory: bool


def _foreign_writers(reading: AclReading, trusted: frozenset[str]) -> list[str]:
    aces = reading.aces or ()
    writers = {a.sid for a in aces if a.kind == ACCESS_ALLOWED_ACE_TYPE and a.mask & WRITE_RIGHTS}
    unknown = {a.sid for a in aces if a.kind not in (ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE)}
    problems = [f"{reading.path} lets {sid} write" for sid in sorted(writers - trusted)]
    problems += [f"{reading.path} has an unrecognised ACE type for {sid}" for sid in sorted(unknown)]
    return problems


def _missing_grants(reading: AclReading) -> list[str]:
    inherit = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    problems = [] if reading.protected else [f"{reading.path} still inherits ACEs from its parent"]
    for sid in LOCK_SIDS:
        granted = any(
            a.sid == sid
            and a.kind == ACCESS_ALLOWED_ACE_TYPE
            and a.mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS
            and a.flags & inherit == inherit
            for a in reading.aces or ()
        )
        if not granted:
            problems.append(f"{reading.path} does not grant {sid} inheritable full control")
    return problems


def acl_problems(reading: AclReading, *, trusted: frozenset[str], container: bool) -> tuple[str, ...]:
    """Why ``reading`` does not keep untrusted principals from changing the object, or ().

    Only rights that could change what runs count: a read-only ACE for Users is harmless, and a
    deny ACE grants nothing.

    Args:
        reading: The owner and DACL as read back.
        trusted: SIDs that may own and write it (SYSTEM, Administrators, the admin running the check).
        container: A directory this module locked: its DACL must also be protected and grant
            SYSTEM and Administrators inheritable full control, as :func:`create_locked_dir` gives it.

    Returns:
        One sentence per problem.
    """
    problems: list[str] = []
    if reading.owner not in trusted:
        problems.append(f"{reading.path} is owned by {reading.owner}, which can rewrite its DACL")
    if reading.aces is None:
        problems.append(f"{reading.path} has a NULL DACL: everyone has full access")
    problems += _foreign_writers(reading, trusted)
    if container:
        problems += _missing_grants(reading)
    return tuple(problems)


_LOCK_INHERIT = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE


def _not_the_lock_ace(path: str, ace: Ace) -> str | None:
    exact = ace.kind == ACCESS_ALLOWED_ACE_TYPE and ace.flags == _LOCK_INHERIT and ace.mask == FILE_ALL_ACCESS
    if exact:
        return None
    return (
        f"{path}: the ACE for {ace.sid} is not the lock's allow, full control, inherited by files and "
        f"directories (type {ace.kind}, flags {ace.flags:#x}, mask {ace.mask:#x})"
    )


def exact_lock_problems(reading: AclReading) -> tuple[str, ...]:
    """Why ``reading`` is not exactly the DACL :func:`create_locked_dir` gives a directory, or ().

    Exactly: owned by SYSTEM or Administrators, protected, and two ACEs, one per lock SID, each
    allowing full control and inherited by files and directories. :func:`acl_problems` lets a
    harmless extra grant (Users: read) pass; this does not, because what is checked here is that
    the directory is still in the state the lock left it in, which only an administrator can
    change.

    Returns:
        One sentence per problem.
    """
    problems = list(acl_problems(reading, trusted=frozenset(LOCK_SIDS), container=True))
    aces = reading.aces or ()
    if reading.aces is not None and len(aces) != len(LOCK_SIDS):
        plural = "" if len(aces) == 1 else "s"
        problems.append(f"{reading.path} carries {len(aces)} ACE{plural}, the lock writes {len(LOCK_SIDS)}")
    problems += [problem for ace in aces if (problem := _not_the_lock_ace(reading.path, ace))]
    return tuple(problems)


def lock_scope_problem(tool: str, stage_root: str | None) -> str | None:
    r"""Why ``tool``'s directory or ``stage_root`` must not be locked or trusted, or None.

    lock-dirs replaces both DACLs with a protected SYSTEM-and-Administrators one, which Windows
    propagates to everything below. Named anywhere else - a tool at ``C:\``, a stage root of
    ``C:\Windows`` - that would cut every other account out of a whole tree. So only the two
    directories the driver itself fills are accepted: ``C:\winrepair`` holding a content-addressed
    tool, and ``<letter>:\upgrade``. With ``stage_root`` None only the tool is checked: lock-dirs
    locks the tool's directory alone when it names no stage root.
    """
    if ntpath.dirname(tool).casefold() != TOOL_DIR.casefold() or not _CONTENT_ADDRESS.fullmatch(ntpath.basename(tool)):
        return f"{tool} is not a winrepair_guest-<sha16>.ps1 in {TOOL_DIR}, the only tool directory locked"
    if stage_root is not None and not _STAGE_ROOT.fullmatch(stage_root):
        return f"{stage_root} is not a <letter>:\\upgrade stage root, the only stage root locked"
    return None


def lock_target_problems(target: LockTarget) -> tuple[str, ...]:
    r"""Why ``target`` must not be locked (lock-dirs) or trusted (launch), or ().

    The names alone do not decide what a lock reaches. A local non-admin may create
    ``C:\winrepair`` or ``<letter>:\upgrade`` before the driver does (a directory under a drive root
    is open to Authenticated Users by default), as a junction to ``C:\Windows``: a DACL written
    through it would cut every other account out of that tree. A real directory that account
    created is owned by it, and an owner can rewrite the DACL after the lock. So the directory
    and its path must hold no reparse point, and it must be owned by SYSTEM or Administrators,
    which is what an elevated admin's mkdir gives it (measured on two test guests).
    """
    problems = [
        f"{target.path} lies below a reparse point at {point}, so a lock could land on another tree"
        for point in target.reparse_points
        if point != target.path
    ]
    if target.path in target.reparse_points:
        problems.append(f"{target.path} is a reparse point (a junction or link), so a lock would land on its target")
    if not target.directory:
        problems.append(f"{target.path} is not a directory")
    if target.owner not in LOCK_SIDS:
        owner = f"{target.path} is owned by {target.owner}"
        problems.append(f"{owner}, not SYSTEM or Administrators: another account created it")
    return tuple(problems)


def content_address(path: str) -> tuple[str, str | None]:
    """Hash the tool at ``path`` and check it against the sha256 prefix its name carries.

    The driver pushed exactly these bytes under this name; a file that hashes otherwise was
    replaced on the guest and must not run as SYSTEM.

    Returns:
        (the file's sha256 hex, a problem or None).

    Raises:
        OSError: The file cannot be read.
    """
    sha = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            sha.update(block)
    digest = sha.hexdigest()
    match = _CONTENT_ADDRESS.fullmatch(ntpath.basename(path))
    if match is None:
        return digest, f"{path} is not a content-addressed tool name (winrepair_guest-<sha16>.ps1)"
    if not digest.startswith(match.group(1)):
        return digest, f"{path} does not match its name: its sha256 is {digest}"
    return digest, None


# --- the pywin32 calls ----------------------------------------------------------------------------

# What pywin32's C binding raises when it refuses an argument before Windows sees the call (an int
# outside a C long, a wrong type). The directory is then simply not created, which lock-dirs must
# report as a refusal like any other (FAILED, exit 1, nothing copied in), not escape as an internal
# error.
_BINDING_ERRORS: tuple[type[Exception], ...] = (OverflowError, TypeError, ValueError)


def _ancestors(path: str) -> list[str]:
    r"""Every directory above ``path``, from its drive root down: ``C:\a\b`` -> ``C:\``, ``C:\a``."""
    drive, rest = ntpath.splitdrive(path)
    parts = [part for part in rest.split("\\") if part]
    root = drive + "\\"
    return [root] + [ntpath.join(root, *parts[:depth]) for depth in range(1, len(parts))]


def _open(files: Win32File, path: str, access: int) -> object:
    return files.CreateFile(path, access, _SHARE, None, OPEN_EXISTING, _OPEN_FLAGS, None)


def _attributes(files: Win32File, handle: object) -> int:
    value = files.GetFileInformationByHandle(handle)[0]
    if not isinstance(value, int):
        raise TypeError(f"unexpected file attributes from pywin32: {value!r}")
    return value


def _target(security: Win32Security, files: Win32File, handle: object, path: str) -> LockTarget:
    """The object behind ``handle`` (opened without following a reparse point) as a LockTarget."""
    attributes = _attributes(files, handle)
    owner = security.GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION)
    return LockTarget(
        path=path,
        reparse_points=(path,) if attributes & FILE_ATTRIBUTE_REPARSE_POINT else (),
        directory=bool(attributes & FILE_ATTRIBUTE_DIRECTORY),
        owner=security.ConvertSidToStringSid(owner.GetSecurityDescriptorOwner()),
    )


def _reparse_ancestors(files: Win32File, path: str) -> tuple[str, ...]:
    found: list[str] = []
    for ancestor in _ancestors(path):
        handle = _open(files, ancestor, FILE_READ_ATTRIBUTES)
        try:
            if _attributes(files, handle) & FILE_ATTRIBUTE_REPARSE_POINT:
                found.append(ancestor)
        finally:
            files.CloseHandle(handle)
    return tuple(found)


def inspect_lock_target(security: Win32Security, files: Win32File, path: str) -> LockTarget:
    """Read ``path`` and every directory above it without following a reparse point; changes nothing.

    Raises:
        OSError: An object on the path could not be opened or read.
    """
    try:
        ancestors = _reparse_ancestors(files, path)
        handle = _open(files, path, _INSPECT_ACCESS)
        try:
            target = _target(security, files, handle, path)
        finally:
            files.CloseHandle(handle)
    except (security.error, *_BINDING_ERRORS) as exc:
        raise OSError(f"cannot inspect {path} before locking it: {exc}") from exc
    return LockTarget(
        path=path, reparse_points=ancestors + target.reparse_points, directory=target.directory, owner=target.owner
    )


def _file_attributes(info: os.stat_result) -> int:
    if sys.platform == "win32":
        return info.st_file_attributes
    return 0


def walk_tree(root: str, *, attributes: Callable[[os.stat_result], int] = _file_attributes) -> Iterator[TreeEntry]:
    """Every file and directory below ``root`` (not ``root`` itself), lazily, depth first.

    A reparse point is listed but never entered: a junction inside the tree would otherwise lead
    the walk, and setup.exe, into a tree the lock never reached. A junction is a directory to
    ``stat`` and no symlink to ``is_symlink`` before Python 3.12, so the reparse bit of its
    Windows attributes is what marks it. Plain Python over ``os.scandir``, whose entries carry
    the attributes, so a listing costs no extra open per file.

    Args:
        root: The directory to walk.
        attributes: Reads the Windows file attributes of an entry's own stat (0 elsewhere); the
            tests pass one that marks a real directory as a reparse point.

    Raises:
        OSError: A directory in the tree could not be listed.
    """
    pending = [root]
    while pending:
        with os.scandir(pending.pop()) as listing:
            for entry in listing:
                info = entry.stat(follow_symlinks=False)
                reparse = entry.is_symlink() or bool(attributes(info) & FILE_ATTRIBUTE_REPARSE_POINT)
                directory = stat.S_ISDIR(info.st_mode)
                yield TreeEntry(path=entry.path, reparse=reparse, directory=directory)
                if directory and not reparse:
                    pending.append(entry.path)


def _lock_acl(security: Win32Security) -> Acl:
    acl = security.ACL()
    for sid in LOCK_SIDS:
        principal = security.ConvertStringSidToSid(sid)
        acl.AddAccessAllowedAceEx(ACL_REVISION, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE, FILE_ALL_ACCESS, principal)
    return acl


def _lock_attributes(security: Win32Security) -> SecurityAttributes:
    """Security attributes carrying the lock: a protected DACL of the two lock ACEs, by SID."""
    descriptor = security.SECURITY_DESCRIPTOR()
    descriptor.SetSecurityDescriptorDacl(1, _lock_acl(security), 0)
    descriptor.SetSecurityDescriptorControl(SE_DACL_PROTECTED, SE_DACL_PROTECTED)
    attributes = security.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    return attributes


def create_locked_dir(security: Win32Security, files: Win32File, path: str) -> bool:
    """Create ``path`` with SYSTEM and Administrators full control, inherited, protected, from birth.

    The DACL comes with the CreateDirectory call itself. Created first and locked afterwards, the
    directory would carry the drive root's inherited ``Authenticated Users: Modify`` in between,
    and a local user who opened it then keeps that access through the handle: a later DACL change
    does not revoke an open handle, and opens relative to it are checked against what it was
    granted. Protected, so nothing from the parent flows in; inheritable, so every file and
    directory created below gets the same two ACEs. The owner is left to the token's default (an
    elevated admin's: Administrators, measured for mkdir on two test guests); the caller
    checks it on the result.

    Returns:
        True when the directory was created; False when something already has that name (a
        directory, a file, or a junction, which this never follows).

    Raises:
        OSError: It could not be created (a missing drive, access denied), or pywin32's binding
            refused an argument (OverflowError, TypeError, ValueError).
    """
    try:
        files.CreateDirectory(path, _lock_attributes(security))
    except security.error as exc:
        if exc.args[:1] == (ERROR_ALREADY_EXISTS,):
            return False
        raise OSError(f"cannot create {path}: {exc}") from exc
    except _BINDING_ERRORS as exc:
        raise OSError(f"cannot create {path}: {exc}") from exc
    return True


def _ace(security: Win32Security, entry: tuple[object, ...]) -> Ace:
    # Every part is checked here: the model would coerce a non-int (a "3" or a 3.0) rather than
    # refuse it, and a shape pywin32 never documented must not read as a real ACE.
    match entry:
        case ((int() as kind, int() as flags), int() as mask, *_):
            sid = entry[-1]
        case _:
            raise OSError(f"unexpected ACE shape from pywin32: {entry!r}")
    # pywin32 returns the ACCESS_MASK (a DWORD) as a signed C long, so a mask with the high bit set
    # (a generic right) is negative; the bit tests read the same, a refusal would print -0x1fff0000.
    return Ace(sid=security.ConvertSidToStringSid(cast("Sid", sid)), kind=kind, flags=flags, mask=mask & 0xFFFFFFFF)


def read_acl(security: Win32Security, path: str) -> AclReading:
    """Read ``path``'s owner and DACL.

    Raises:
        OSError: They could not be read.
    """
    try:
        descriptor = security.GetNamedSecurityInfo(
            path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
        )
        owner = security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())
        control, _revision = descriptor.GetSecurityDescriptorControl()
        dacl = descriptor.GetSecurityDescriptorDacl()
        count = 0 if dacl is None else dacl.GetAceCount()
        aces = None if dacl is None else tuple(_ace(security, dacl.GetAce(i)) for i in range(count))
    except (security.error, *_BINDING_ERRORS) as exc:
        raise OSError(f"cannot read the DACL of {path}: {exc}") from exc
    return AclReading(path=path, owner=owner, protected=bool(control & SE_DACL_PROTECTED), aces=aces)
