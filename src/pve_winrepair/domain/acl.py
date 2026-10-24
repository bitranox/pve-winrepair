"""Who may write a directory, read from its SDDL security descriptor.

Every guest tool call the node makes from the ssh user's profile copy runs in an elevated ssh
session. The copy's bytes are hashed before it runs, but a principal that can write the profile
could swap the file between the hash and the run. So the node reads the profile directory's
descriptor first and refuses unless only trusted principals can write it (see
:func:`write_problems`).

The parser covers the descriptor text ``Get-Acl`` prints (``O:``, ``G:``, ``D:``, ``S:``
components; hex or two-letter rights; SID strings or two-letter aliases). Anything it does not
understand is :class:`SddlError`, and any ACE kind other than allow and deny is reported as a
problem rather than judged: the check fails closed.

Reference: the "Security Descriptor String Format" and "ACE Strings" pages of the Windows SDK
documentation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

__all__ = [
    "TRUSTED_WELL_KNOWN",
    "WRITE_RIGHTS",
    "AceFlag",
    "AceKind",
    "SddlAce",
    "SddlError",
    "SddlReading",
    "parse_sddl",
    "trusted_writers",
    "write_problems",
]

# LocalSystem, BUILTIN\Administrators, CREATOR OWNER. CREATOR OWNER is trusted because on a file
# created in the directory it becomes that file's creator: here the ssh user who copies the tool.
TRUSTED_WELL_KNOWN: frozenset[str] = frozenset({"S-1-5-18", "S-1-5-32-544", "S-1-3-0"})

# Every right that lets a principal change what is in the directory or what a copy there holds:
# add file 0x2, add subdirectory 0x4, write EA 0x10, delete child 0x40, write attributes 0x100,
# DELETE 0x10000, WRITE_DAC 0x40000, WRITE_OWNER 0x80000, GENERIC_ALL 0x10000000, GENERIC_WRITE
# 0x40000000. Synchronize plus traverse (0x100020), which app capability SIDs hold, is not a write.
WRITE_RIGHTS: int = 0x500D0156

# Only the trusted aliases are resolved: every other principal stays as written and is untrusted,
# so a missing alias can only make the check stricter.
_ALIASES = {"SY": "S-1-5-18", "BA": "S-1-5-32-544", "CO": "S-1-3-0"}

# The alias SDDL gives the machine's built-in Administrator (relative ID 500, DOMAIN_USER_RID_ADMIN).
# Get-Acl prints that account's own SID this way, so on its profile the owner and the user's ACE read
# LA, never the SID the probe reports. It is trusted only for an ssh user whose SID ends in -500.
_LOCAL_ADMIN_ALIAS = "LA"
_ADMINISTRATOR_RID = "500"

_RIGHT_CODES = {
    "GA": 0x10000000,
    "GW": 0x40000000,
    "GR": 0x80000000,
    "GX": 0x20000000,
    "FA": 0x1F01FF,
    "FW": 0x120116,
    "FR": 0x120089,
    "FX": 0x1200A0,
    "SD": 0x10000,
    "RC": 0x20000,
    "WD": 0x40000,
    "WO": 0x80000,
    "CC": 0x1,
    "DC": 0x2,
    "LC": 0x4,
    "SW": 0x8,
    "RP": 0x10,
    "WP": 0x20,
    "DT": 0x40,
    "LO": 0x80,
    "CR": 0x100,
}

_COMPONENT = re.compile(r"([OGDS]):")
_SID = re.compile(r"S-1(?:-[0-9]+)+|[A-Z]{2}")
# The ACL flags as a closed alternation: a greedy [A-Z_]* would swallow the "S" of a following "S:".
_ACL_FLAGS = re.compile(r"(?:NO_ACCESS_CONTROL|P|AI|AR)*")
_HEX_RIGHTS = re.compile(r"0[xX][0-9A-Fa-f]{1,8}")
_NESTING = {"(": 1, ")": -1}
_ACE_FIELDS = 6  # kind;flags;rights;object guid;inherit object guid;sid (a callback ACE adds a seventh)


class SddlError(ValueError):
    """The descriptor text is malformed, or uses a form this parser does not support."""


class AceKind(str, Enum):
    """How an ACE is judged: allow and deny are; every other kind (audit, object, callback) is OTHER."""

    ALLOW = "A"
    DENY = "D"
    OTHER = "other"


class AceFlag(str, Enum):
    """The two-letter ACE flags SDDL writes."""

    CONTAINER_INHERIT = "CI"
    OBJECT_INHERIT = "OI"
    NO_PROPAGATE = "NP"
    INHERIT_ONLY = "IO"
    INHERITED = "ID"
    SUCCESSFUL_ACCESS = "SA"
    FAILED_ACCESS = "FA"
    TRUST_PROTECTED_FILTER = "TP"
    CRITICAL = "CR"


_KINDS = {AceKind.ALLOW.value: AceKind.ALLOW, AceKind.DENY.value: AceKind.DENY}
_FLAGS = {flag.value: flag for flag in AceFlag}


@dataclass(frozen=True)
class SddlAce:
    """One ACE of a parsed descriptor.

    Attributes:
        kind: Allow, deny, or another kind (reported, never judged).
        code: The kind as written (``A``, ``D``, ``AU``, ``XA``, ...), for messages.
        flags: The ACE flags.
        flags_text: The flags as written (``OICI``), for messages.
        rights: The rights mask.
        sid: The trustee's SID, the trusted aliases resolved.
    """

    kind: AceKind
    code: str
    flags: frozenset[AceFlag]
    flags_text: str
    rights: int
    sid: str


@dataclass(frozen=True)
class SddlReading:
    """A parsed descriptor: the owner ("" when absent), whether a DACL is in force, the DACL's ACEs."""

    owner: str
    dacl_present: bool
    aces: tuple[SddlAce, ...]


def _sid(text: str) -> str:
    if not _SID.fullmatch(text):
        raise SddlError(f"not a SID: {text!r}")
    return _ALIASES.get(text, text)


def _rights(text: str) -> int:
    if _HEX_RIGHTS.fullmatch(text):
        return int(text, 16)
    if not text or len(text) % 2:
        raise SddlError(f"unsupported rights {text!r}")
    mask = 0
    for i in range(0, len(text), 2):
        code = text[i : i + 2]
        if code not in _RIGHT_CODES:
            raise SddlError(f"unknown rights code {code!r}")
        mask |= _RIGHT_CODES[code]
    return mask


def _flags(flags: str) -> frozenset[AceFlag]:
    """The two-letter ACE flags, read in pairs: a substring test would find "IO" inside "CIOI"."""
    codes = tuple(flags[i : i + 2] for i in range(0, len(flags), 2))
    if len(flags) % 2 or not all(code in _FLAGS for code in codes):
        raise SddlError(f"unknown ACE flags {flags!r}")
    return frozenset(_FLAGS[code] for code in codes)


def _ace(body: str) -> SddlAce:
    fields = body.split(";", _ACE_FIELDS)
    # Only a callback ACE carries a seventh field; on an allow or deny ACE one is malformed.
    if len(fields) < _ACE_FIELDS or (fields[0] in _KINDS and len(fields) > _ACE_FIELDS):
        raise SddlError(f"an ACE needs {_ACE_FIELDS} fields: ({body})")
    code, flags, rights, _object, _inherit, sid = fields[:_ACE_FIELDS]
    if not re.fullmatch(r"[A-Z]{1,2}", code):
        raise SddlError(f"unknown ACE kind {code!r}")
    return SddlAce(
        kind=_KINDS.get(code, AceKind.OTHER),
        code=code,
        flags=_flags(flags),
        flags_text=flags,
        rights=_rights(rights),
        sid=_sid(sid),
    )


def _ace_end(text: str, start: int) -> int:
    """The index just past the ``)`` closing the ACE that opens at ``start`` (callback ACEs nest)."""
    depth = 0
    for i in range(start, len(text)):
        depth += _NESTING.get(text[i], 0)
        if depth == 0:
            return i + 1
    raise SddlError("an ACE is not closed")


def _acl(text: str, at: int) -> tuple[str, tuple[SddlAce, ...], int]:
    """The ACL flags and ACEs from ``at``, and where they end."""
    matched = _ACL_FLAGS.match(text, at)  # never None: the pattern matches the empty string
    flags = matched.group(0) if matched else ""
    aces: list[SddlAce] = []
    at += len(flags)
    while at < len(text) and text[at] == "(":
        end = _ace_end(text, at)
        aces.append(_ace(text[at + 1 : end - 1]))
        at = end
    return flags, tuple(aces), at


def _owner_or_group(text: str, at: int) -> tuple[str, int]:
    match = _SID.match(text, at)
    if match is None:
        raise SddlError(f"no SID after the component at {at}")
    return _sid(match.group(0)), match.end()


def parse_sddl(text: str) -> SddlReading:
    """Parse a descriptor string such as ``(Get-Acl -LiteralPath .).Sddl`` prints.

    Raises:
        SddlError: It is empty, a component repeats, or something is malformed or unsupported.

    Example:
        >>> reading = parse_sddl("O:BAG:SYD:P(A;OICI;FA;;;SY)(A;;0x1200a9;;;BU)")
        >>> reading.owner, reading.dacl_present, [ace.sid for ace in reading.aces]
        ('S-1-5-32-544', True, ['S-1-5-18', 'BU'])
    """
    seen: dict[str, str] = {}
    dacl: tuple[str, tuple[SddlAce, ...]] | None = None
    at = 0
    while at < len(text):
        component = _COMPONENT.match(text, at)
        if component is None or component.group(1) in seen:
            raise SddlError(f"expected a new O:, G:, D: or S: component at {at}")
        tag = component.group(1)
        if tag in "OG":
            seen[tag], at = _owner_or_group(text, component.end())
            continue
        flags, aces, at = _acl(text, component.end())
        seen[tag] = flags
        if tag == "D":
            dacl = (flags, aces)
    if not seen:
        raise SddlError("an empty descriptor")
    present = dacl is not None and "NO_ACCESS_CONTROL" not in dacl[0]
    return SddlReading(seen.get("O", ""), present, dacl[1] if dacl is not None else ())


def trusted_writers(user_sid: str) -> frozenset[str]:
    """The principals that may write the ssh user's profile: SYSTEM, Administrators, CREATOR OWNER, the user.

    For the built-in Administrator (a SID whose last sub-authority is 500, the shipped default
    ``[ssh] user``) the alias ``LA`` is that same account, so it is trusted too; for any other user
    ``LA`` stays an untrusted principal.

    Example:
        >>> sorted(trusted_writers("S-1-5-21-1-2-3-500") - TRUSTED_WELL_KNOWN)
        ['LA', 'S-1-5-21-1-2-3-500']
        >>> sorted(trusted_writers("S-1-5-21-1-2-3-1001") - TRUSTED_WELL_KNOWN)
        ['S-1-5-21-1-2-3-1001']
    """
    trusted = TRUSTED_WELL_KNOWN | {user_sid}
    if user_sid.rsplit("-", 1)[-1] == _ADMINISTRATOR_RID:
        trusted |= {_LOCAL_ADMIN_ALIAS}
    return trusted


def _ace_problem(ace: SddlAce, trusted: frozenset[str]) -> str | None:
    if ace.kind is AceKind.DENY:  # a deny ACE only removes rights
        return None
    if ace.kind is AceKind.OTHER:
        return f"an ACE of kind {ace.code} for {ace.sid} is not judged (only allow and deny are)"
    if ace.sid in trusted or not ace.rights & WRITE_RIGHTS:
        return None
    # Inherit-only reaches the directory itself never; it still reaches a copy created there when
    # files inherit it (OI). A container-only inherit-only ACE reaches neither.
    if AceFlag.INHERIT_ONLY in ace.flags and AceFlag.OBJECT_INHERIT not in ace.flags:
        return None
    return f"{ace.sid} may write: allow {ace.rights:#x} (flags {ace.flags_text or 'none'})"


def write_problems(reading: SddlReading, *, trusted: frozenset[str]) -> tuple[str, ...]:
    """One line per way a principal outside ``trusted`` can write the directory or a copy placed in it.

    Example:
        >>> write_problems(parse_sddl("O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FW;;;BU)"), trusted=TRUSTED_WELL_KNOWN)
        ('BU may write: allow 0x120116 (flags OICI)',)
    """
    problems: list[str] = []
    if reading.owner not in trusted:
        problems.append(f"the owner {reading.owner or '(none)'} is not trusted (an owner can rewrite the ACL)")
    if not reading.dacl_present:
        problems.append("no DACL is in force, so everyone has every right")
    problems += [problem for ace in reading.aces if (problem := _ace_problem(ace, trusted)) is not None]
    return tuple(problems)
