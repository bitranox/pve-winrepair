"""In-memory stand-ins for the pywin32 modules the guest tool calls (pywin32 exists only on Windows).

The member names are pywin32's own, so the code under test runs its real call sequence; the
fakes record what it asked for and answer like Windows would.
"""

from __future__ import annotations

from dataclasses import dataclass, field

ADMINS = "S-1-5-32-544"
RUNNER = "S-1-5-21-1-2-3-1001"


class Win32Error(Exception):
    """Stands in for pywintypes.error, which derives from Exception and NOT from OSError."""


C_LONG_MIN, C_LONG_MAX = -(2**31), 2**31 - 1


def c_long(*values: int) -> None:
    """Refuse what pywin32's ``PyArg_ParseTuple`` "l" refuses: an int outside a 32-bit C long.

    pywin32 312 parses the integer arguments of the security calls as C longs ("l"); on Windows a
    C long is 32 bits, so 0x80000004 raised exactly this on two test guests (pywin32 312,
    Python 3.10).
    """
    for value in values:
        if not C_LONG_MIN <= value <= C_LONG_MAX:
            raise OverflowError("Python int too large to convert to C long")


FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT = 0x10, 0x400
ERROR_PATH_NOT_FOUND, ERROR_ALREADY_EXISTS = 3, 183
SE_DACL_PROTECTED, INHERITED_ACE = 0x1000, 0x10
SYSTEM, USERS = "S-1-5-18", "S-1-5-11"
FULL, MODIFY = 0x1F01FF, 0x1301BF
FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS = 0x00200000, 0x02000000
READ_CONTROL = 0x20000


@dataclass
class Node:
    """One filesystem object: its attributes, its owner, and where it leads if it is a link."""

    attributes: int = FILE_ATTRIBUTE_DIRECTORY
    owner: str = ADMINS
    target: str | None = None


@dataclass
class Handle:
    """A PyHANDLE from CreateFile: what was asked for and the object it reached."""

    path: str
    access: int
    share: int
    flags: int
    attributes: int
    owner: str
    closed: bool = False


class FakeFiles:
    """win32file over a table of paths; a path not in it is an ordinary Admins-owned directory.

    Like Windows, CreateFile follows a reparse point unless FILE_FLAG_OPEN_REPARSE_POINT is given:
    the handle then reaches the link's target, whose attributes carry no reparse bit. Also like
    Windows, opening a directory without FILE_FLAG_BACKUP_SEMANTICS fails with access denied.
    """

    def __init__(self, nodes: dict[str, Node] | None = None, *, missing: frozenset[str] = frozenset()) -> None:
        self.nodes = dict(nodes or {})
        self.missing = missing
        self.opened: list[Handle] = []
        # Each directory CreateDirectory made, with the descriptor it came into existence with.
        self.created: dict[str, Descriptor] = {}

    def node(self, path: str) -> Node:
        return self.nodes.get(path, Node())

    def CreateFile(  # noqa: N802, PLR0917 - mirrors the win32file name and its fixed positional signature
        self,
        name: str,
        access: int,
        share: int,
        security: object,
        disposition: int,
        flags: int,
        template: object,
        /,
    ) -> Handle:
        c_long(access, share, disposition, flags)
        assert (security, disposition, template) == (None, 3, None)  # OPEN_EXISTING
        if name in self.missing:
            raise Win32Error(2, "CreateFile", "Das System kann die angegebene Datei nicht finden.")
        node = self.node(name)
        if node.target is not None and not flags & FILE_FLAG_OPEN_REPARSE_POINT:
            node = self.node(node.target)
        if node.attributes & FILE_ATTRIBUTE_DIRECTORY and not flags & FILE_FLAG_BACKUP_SEMANTICS:
            raise Win32Error(5, "CreateFile", "Zugriff verweigert")
        handle = Handle(name, access, share, flags, node.attributes, node.owner)
        self.opened.append(handle)
        return handle

    def CreateDirectory(self, name: str, security: object, /) -> None:  # noqa: N802 - mirrors the pywin32 / COM member name
        """Like Windows: a name that exists fails with 183; without a descriptor the directory gets
        the drive root's inherited, unprotected DACL (Authenticated Users may modify it)."""
        if name in self.nodes or name in self.created:
            raise Win32Error(ERROR_ALREADY_EXISTS, "CreateDirectory", "Eine Datei ist bereits vorhanden.")
        if name in self.missing:
            raise Win32Error(ERROR_PATH_NOT_FOUND, "CreateDirectory", "Der Pfad wurde nicht gefunden.")
        given = security.SECURITY_DESCRIPTOR if isinstance(security, Attributes) else None
        if isinstance(given, Descriptor) and given.dacl is not None:
            # The token's default owner, as an elevated admin's create gets (measured: Administrators).
            self.created[name] = Descriptor(Sid(ADMINS), given.dacl, given.control)
        else:
            inherited = Acl(
                [((0, INHERITED_ACE), FULL, Sid(SYSTEM)), ((0, INHERITED_ACE), FULL, Sid(ADMINS)),
                 ((0, INHERITED_ACE), MODIFY, Sid(USERS))]
            )  # fmt: skip
            self.created[name] = Descriptor(Sid(ADMINS), inherited, 0)
        self.nodes[name] = Node()

    def GetFileInformationByHandle(self, handle: object, /) -> tuple[object, ...]:  # noqa: N802 - mirrors the pywin32 / COM member name
        assert isinstance(handle, Handle) and not handle.closed
        return (handle.attributes, "ctime", "atime", "wtime", 7, 0, 0, 1, 0, 0)

    def CloseHandle(self, handle: object, /) -> None:  # noqa: N802 - mirrors the pywin32 / COM member name
        assert isinstance(handle, Handle) and not handle.closed
        handle.closed = True


@dataclass(frozen=True)
class Sid:
    """A PySID: only its ``S-1-...`` text matters here."""

    text: str


@dataclass
class Acl:
    """A PyACL holding standard ACEs as ``((type, flags), mask, sid)``."""

    aces: list[tuple[tuple[int, int], int, Sid]] = field(default_factory=list[tuple[tuple[int, int], int, Sid]])

    def AddAccessAllowedAceEx(self, revision: int, aceflags: int, access: int, sid: object, /) -> None:  # noqa: N802 - mirrors the pywin32 / COM member name
        assert revision == 2  # ACL_REVISION
        assert isinstance(sid, Sid)
        self.aces.append(((0, aceflags), access, sid))

    def GetAceCount(self) -> int:  # noqa: N802 - mirrors the pywin32 / COM member name
        return len(self.aces)

    def GetAce(self, index: int, /) -> tuple[object, ...]:  # noqa: N802 - mirrors the pywin32 / COM member name
        return self.aces[index]


@dataclass
class Descriptor:
    """A PySECURITY_DESCRIPTOR: owner, DACL (None = NULL DACL) and control bits."""

    owner: Sid | None
    dacl: Acl | None
    control: int

    def GetSecurityDescriptorOwner(self) -> Sid:  # noqa: N802 - mirrors the pywin32 / COM member name
        assert self.owner is not None
        return self.owner

    def SetSecurityDescriptorDacl(self, present: int, dacl: object, defaulted: int, /) -> None:  # noqa: N802 - mirrors the pywin32 / COM member name
        c_long(present, defaulted)
        assert dacl is None or isinstance(dacl, Acl)
        self.dacl = dacl if present else None

    def SetSecurityDescriptorControl(self, interest: int, bits: int, /) -> None:  # noqa: N802 - mirrors the pywin32 / COM member name
        c_long(interest, bits)
        self.control = (self.control & ~interest) | (bits & interest)

    def GetSecurityDescriptorDacl(self) -> Acl | None:  # noqa: N802 - mirrors the pywin32 / COM member name
        return self.dacl

    def GetSecurityDescriptorControl(self) -> tuple[int, int]:  # noqa: N802 - mirrors the pywin32 / COM member name
        return self.control, 1


@dataclass
class Attributes:
    """A PySECURITY_ATTRIBUTES: the descriptor a new object is created with."""

    SECURITY_DESCRIPTOR: object = None


def descriptor(owner: Sid, dacl: Acl | None, control: int) -> Descriptor:
    """A security descriptor to plant under a path."""
    return Descriptor(owner, dacl, control)


class FakeApi:
    """win32api: only the current-process pseudo handle."""

    def GetCurrentProcess(self) -> object:  # noqa: N802 - mirrors the pywin32 / COM member name
        return "process"


class FakeSecurity:
    """win32security over a dict of paths and one process token; records the calls made."""

    error = Win32Error
    TOKEN_QUERY = 8
    TokenUser = 1

    def __init__(self, *, user: str = RUNNER, account: tuple[str, str] = ("admin", "WIN-HOST")) -> None:
        self.user = user
        self.account = account
        self.objects: dict[str, Descriptor] = {}
        self.calls: list[str] = []

    def ACL(self) -> Acl:  # noqa: N802 - mirrors the pywin32 / COM member name
        return Acl()

    def SECURITY_DESCRIPTOR(self) -> Descriptor:  # noqa: N802 - mirrors the pywin32 / COM member name
        return Descriptor(None, None, 0)

    def SECURITY_ATTRIBUTES(self) -> Attributes:  # noqa: N802 - mirrors the pywin32 / COM member name
        return Attributes()

    def ConvertStringSidToSid(self, sid: str, /) -> Sid:  # noqa: N802 - mirrors the pywin32 / COM member name
        return Sid(sid)

    def ConvertSidToStringSid(self, sid: object, /) -> str:  # noqa: N802 - mirrors the pywin32 / COM member name
        assert isinstance(sid, Sid)
        return sid.text

    def GetSecurityInfo(self, handle: object, kind: int, info: int, /) -> Descriptor:  # noqa: N802 - mirrors the pywin32 / COM member name
        c_long(kind, info)
        assert isinstance(handle, Handle) and not handle.closed
        assert (kind, info) == (1, 0x1)  # SE_FILE_OBJECT; OWNER_SECURITY_INFORMATION
        assert handle.access & READ_CONTROL
        return Descriptor(Sid(handle.owner), None, 0)

    def GetNamedSecurityInfo(self, name: str, kind: int, info: int, /) -> Descriptor:  # noqa: N802 - mirrors the pywin32 / COM member name
        c_long(kind, info)
        assert (kind, info) == (1, 0x5)  # SE_FILE_OBJECT; OWNER | DACL_SECURITY_INFORMATION
        if name not in self.objects:
            raise Win32Error(2, "GetNamedSecurityInfo", "Das System kann die angegebene Datei nicht finden.")
        return self.objects[name]

    def OpenProcessToken(self, process: object, access: int, /) -> object:  # noqa: N802 - mirrors the pywin32 / COM member name
        self.calls.append(f"open {process} {access}")
        return "token"

    def GetTokenInformation(self, token: object, kind: int, /) -> tuple[Sid, int]:  # noqa: N802 - mirrors the pywin32 / COM member name
        self.calls.append(f"info {token} {kind}")
        return Sid(self.user), 0

    def LookupAccountSid(self, system: str | None, sid: object, /) -> tuple[str, str, int]:  # noqa: N802 - mirrors the pywin32 / COM member name
        return self.account[0], self.account[1], 1
