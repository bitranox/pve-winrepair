"""Privacy gate: no private site data in the tracked tree, its path names or the packed guest tool.

The repository is public, so this file must not carry the names it forbids, in clear or encoded.
Two kinds of check run:

* Generic patterns (always active, CI included): a private-range address prefix, ``vm-`` and
  ``lxc-`` host names, a key file named after a user and a host, and a credentials directory. They
  reveal nothing about any site and match case-insensitively, since host names do.
* The exact private tokens, read from a JSON list that is never committed: the file named by
  ``PVE_WINREPAIR_PRIVACY_TOKENS_FILE`` when that variable is set, else the gitignored
  ``.privacy-tokens.json`` at the checkout root. Shape: an object with keys from ``hosts``,
  ``vmids``, ``words`` and ``paths``, each a list of non-empty strings. A malformed list, or a
  variable naming a missing file, is an ERROR; only the default file being absent skips these tests
  (CI has no list, so CI skips them by design; a local skip means the list is missing).

The gate finds only the tokens written down. A new private name goes into BOTH copies of the list:
the gitignored one in the checkout and the maintainer's tracked canonical copy kept outside this
repository.

What is scanned: every entry ``git ls-files`` lists, as the bytes a commit stores (the index blob,
so a symlink's target too), then every untracked file that is not ignored
(``git ls-files -o --exclude-standard``, read from the worktree, a symlink as its target), and the
worktree copy of every tracked file changed but not staged (``git ls-files -m``; a deleted one has
none): bmk's ``make push`` runs the tests and THEN ``git add -A``, which commits those too. A
content finding says which version hit, ``(index)`` or ``(worktree)``. Each is scanned in
every rendering (UTF-8, else latin-1; plus UTF-16-LE at both byte alignments whenever the bytes
hold a NUL), and every listed path name. ``uv.lock``'s content is skipped (machine-written hashes
and sizes; a size can equal a VM id) but its name is scanned. A gitlink's content is another
repository; only its name is scanned here. ANY file carrying a pwshpy payload block or
``$PwshPySha`` line (the packed guest tool, or another script in its runner layout) is scanned
without its base64, which can spell a token by chance and changes on every repack; the payload is
scanned DECODED, member by member (the packed tool's index copy by its own tests, every other copy
with the tree). A payload that cannot be decoded is an error, never a skip.

A finding never prints the matched text, nor a file or member NAME (a name can hold the token its
content also holds): it names the path's index, the version, the line and the pattern or the
token's list position (``path[7] (worktree):3: token words[2]``; a hit in the name itself is
``path[7]: token words[2]``). ``path[i]`` counts the tracked entries in ``git ls-files -s`` order
first, then the untracked ones in ``git ls-files -o --exclude-standard`` order; a modified file's
worktree copy keeps its tracked entry's index. A payload member is ``member[j]``, its 0-based
position in the archive. A failing tree or payload test says how to print a name locally
(:func:`lookup_hint`). The list object prints only its counts.
pytest's long tracebacks print every shown frame's arguments, and ``-l`` its locals: every helper
holding scanned text or list content hides its frame (``__tracebackhide__``), and a refused payload
is re-raised as a message-only :class:`PayloadError` with its chain dropped.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pack_guest
import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

TOKENS_FILE = ".privacy-tokens.json"
TOKENS_VARIABLE = "PVE_WINREPAIR_PRIVACY_TOKENS_FILE"
TOKEN_KEYS = ("hosts", "vmids", "words")
KEYS = (*TOKEN_KEYS, "paths")
SKIP_REASON = "no private token list: site-specific check not run"
# Machine-written hashes and sizes, no prose: a size could equal a VM id.
CONTENT_EXCLUDED = frozenset({"uv.lock"})
GITLINK = "160000"  # the index mode of a submodule entry: its object is a commit, not a blob
# The character class in the last pattern keeps this file's own source from matching it.
GENERIC = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"192\.168\.",
        r"\bvm-[a-z]",
        r"\blxc-[a-z]",
        r"\b[\w.-]+@[\w.-]+\.key\b",
        r"/scripts/credential[s]/",
    )
)


class PrivacyListError(ValueError):
    """The private token list is unreadable or malformed: an error, never a reason to skip."""


class PayloadError(ValueError):
    """The packed tool's payload is refused; the message names the reason, never the text."""


@dataclass(frozen=True, repr=False)
class PrivateList:
    """The private tokens, each with the label a finding prints in its place."""

    tokens: tuple[tuple[str, str], ...]  # (label "words[2]", lower-case token) for hosts/vmids/words
    paths: tuple[tuple[str, str], ...]  # (label "paths[1]", lower-case substring)

    def __repr__(self) -> str:
        """Per-key counts only.

        pytest prints a failing test's arguments (the ``private`` fixture value among them) and the
        operands of a failing assert; the dataclass default repr would publish every token there.
        """
        counts = Counter(label.split("[", 1)[0] for label, _ in (*self.tokens, *self.paths))
        return "PrivateList(" + ", ".join(f"{key}={counts[key]}" for key in KEYS) + ")"


def _parse(path: Path) -> object:
    # "from None" for the decode errors: a chained traceback ends in json's own frame, whose
    # argument is the whole list text, and pytest prints that argument. Hidden: with -l pytest
    # prints this frame's locals, and a UnicodeDecodeError's repr carries the list's bytes.
    __tracebackhide__ = True
    try:
        return json.loads(path.read_bytes().decode("utf-8"))
    except OSError as exc:
        raise PrivacyListError(f"{path}: cannot read the private token list ({exc.strerror})") from exc
    except UnicodeDecodeError as exc:
        raise PrivacyListError(f"{path}: the private token list is not UTF-8 (byte {exc.start})") from None
    except json.JSONDecodeError as exc:
        raise PrivacyListError(f"{path}: not valid JSON ({exc.msg}, line {exc.lineno})") from None


def _entries(path: Path, key: str, values: object) -> tuple[tuple[str, str], ...]:
    # pytest prints the arguments of the frame that raised; ``values`` holds the tokens.
    __tracebackhide__ = True
    if not isinstance(values, list):
        raise PrivacyListError(f"{path}: {key} must be a list of non-empty strings")
    found: list[tuple[str, str]] = []
    for n, value in enumerate(cast("list[object]", values), start=1):
        if not isinstance(value, str) or not value.strip():
            raise PrivacyListError(f"{path}: {key} must be a list of non-empty strings")
        found.append((f"{key}[{n}]", value.strip().lower()))
    return tuple(found)


def load_private_list(path: Path) -> PrivateList:
    """Read and validate a private token list.

    Args:
        path: The JSON list.

    Returns:
        The tokens and path substrings, lower-cased, each labelled by key and 1-based position.

    Raises:
        PrivacyListError: The file is unreadable, not JSON, not an object, has an unknown key, a
            non-list value, a non-string or empty entry, or holds no token under any key.
    """
    __tracebackhide__ = True  # with -l pytest prints locals: ``data`` holds every token
    data = _parse(path)
    if not isinstance(data, dict):
        raise PrivacyListError(f"{path}: the list must be a JSON object with keys from {', '.join(sorted(KEYS))}")
    entries = cast("dict[str, object]", data)
    unknown = sorted(set(entries) - set(KEYS))
    if unknown:
        raise PrivacyListError(f"{path}: unknown key(s) {', '.join(unknown)}; allowed: {', '.join(sorted(KEYS))}")
    # A loop, not a comprehension: before Python 3.12 a comprehension runs in a frame of its own,
    # which no __tracebackhide__ reaches, and with -l pytest prints its locals - ``entries`` too.
    parsed: dict[str, tuple[tuple[str, str], ...]] = {}
    for key in KEYS:
        parsed[key] = _entries(path, key, entries.get(key, []))
    tokens = tuple(entry for key in TOKEN_KEYS for entry in parsed[key])
    if not tokens and not parsed["paths"]:
        raise PrivacyListError(f"{path}: the list holds no token, so it would check nothing")
    return PrivateList(tokens=tokens, paths=parsed["paths"])


def private_list() -> PrivateList | None:
    """The private token list in force, or None when the default file is absent.

    Returns:
        The list named by ``PVE_WINREPAIR_PRIVACY_TOKENS_FILE``, else the checkout's
        ``.privacy-tokens.json``; None only when the variable is unset and that file is absent.

    Raises:
        PrivacyListError: The list is malformed, or the variable names a missing file.
    """
    named = os.environ.get(TOKENS_VARIABLE)
    if named:
        return load_private_list(Path(named))
    default = pack_guest.PROJECT / TOKENS_FILE
    if not default.exists():
        return None
    return load_private_list(default)


def renderings(data: bytes) -> list[str]:
    """Every text reading of ``data`` the scan checks.

    UTF-16-LE is added on any NUL byte, not only when UTF-8 decoding fails: UTF-16-LE of ASCII text
    behind an ASCII header is valid UTF-8, so a decode-failure trigger would never read it as UTF-16.

    Args:
        data: A file's bytes.

    Returns:
        UTF-8 (else latin-1), plus UTF-16-LE at both byte alignments when ``data`` holds a NUL.
    """
    __tracebackhide__ = True
    try:
        found = [data.decode("utf-8")]
    except UnicodeDecodeError:
        found = [data.decode("latin-1")]
    if b"\0" in data:
        found += [data.decode("utf-16-le", "replace"), data[1:].decode("utf-16-le", "replace")]
    return found


@functools.lru_cache(maxsize=8)
def _token_patterns(private: PrivateList) -> tuple[tuple[str, re.Pattern[str]], ...]:
    # A token is bounded by any non-alphanumeric, "_" included: "name_key" hits for "name", while a
    # VM id inside a longer number does not. One pattern per token: an empty alternation would match
    # the empty string everywhere, and an alternation would report only one of two overlapping tokens.
    return tuple(
        (label, re.compile(r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])")) for label, token in private.tokens
    )


def _occurrences(text: str, needle: str) -> Iterator[int]:
    __tracebackhide__ = True
    start = text.find(needle)
    while start >= 0:
        yield start
        start = text.find(needle, start + 1)


def _line(text: str, offset: int) -> int:
    __tracebackhide__ = True
    return text.count("\n", 0, offset) + 1


def _hits(text: str, private: PrivateList | None) -> list[tuple[int, str]]:
    __tracebackhide__ = True
    found = [(_line(text, m.start()), f"pattern {p.pattern}") for p in GENERIC for m in p.finditer(text)]
    if private is None:
        return found
    lowered = text.lower()
    found += [
        (_line(lowered, m.start()), f"token {label}")
        for label, pattern in _token_patterns(private)
        for m in pattern.finditer(lowered)
    ]
    found += [
        (_line(lowered, at), f"token {label}")
        for label, needle in private.paths
        for at in _occurrences(lowered, needle)
    ]
    return found


def findings(name: str, text: str, private: PrivateList | None) -> list[str]:
    """The findings in one text, deduplicated, never quoting what matched.

    Args:
        name: The label printed before each finding (``path[3] (index)``, ``member[2]``): never a
            file name, which can hold a token.
        text: The text to scan.
        private: The private tokens, or None for the generic patterns alone.

    Returns:
        ``<name>:<line>: pattern <regex>`` and ``<name>:<line>: token <key>[<n>]`` lines, by line.
    """
    __tracebackhide__ = True
    return [f"{name}:{line}: {what}" for line, what in sorted(set(_hits(text, private)))]


def file_findings(name: str, data: bytes, private: PrivateList | None) -> list[str]:
    """The findings in every rendering of a file's bytes, deduplicated.

    A rendering that carries a pwshpy payload block or ``$PwshPySha`` line, in ANY file (the packed
    guest tool or another script in pwshpy's runner layout), is scanned as its wrapper plus its
    DECODED payload: the base64 can spell a token by chance, and a deflated member hides one.

    Args:
        name: The label printed before each finding (see :func:`findings`).
        data: The file's bytes.
        private: The private tokens, or None for the generic patterns alone.

    Returns:
        The findings of :func:`findings` over each of :func:`renderings` without its payload, then
        ``<name>: member[<j>]...`` for its decoded payload (:func:`payload_findings`), first
        occurrence kept.

    Raises:
        PayloadError: A rendering carries a payload that is refused, never skipped.
    """
    __tracebackhide__ = True
    found: list[str] = []
    for text in renderings(data):
        wrapper = pack_guest.wrapper_without_payload(text)
        found += findings(name, wrapper, private)
        if wrapper != text:  # a payload block or a sha line was stripped: decode what it carries
            found += [f"{name}: {finding}" for finding in payload_findings(text, private)]
    return list(dict.fromkeys(found))


def path_findings(index: int, name: str, private: PrivateList | None) -> list[str]:
    """The findings in a path name, labelled by its index so the name itself is never printed.

    Args:
        index: The path's position in the scanned listing.
        name: The path name.
        private: The private tokens, or None for the generic patterns alone.

    Returns:
        ``path[<index>]: pattern <regex>`` and ``path[<index>]: token <key>[<n>]`` lines.
    """
    __tracebackhide__ = True
    return _name_findings(f"path[{index}]", name, private)


def _name_findings(label: str, name: str, private: PrivateList | None) -> list[str]:
    __tracebackhide__ = True  # ``name`` is the scanned name
    return list(dict.fromkeys(f"{label}: {what}" for _, what in sorted(_hits(name, private))))


def payload_findings(text: str, private: PrivateList | None) -> list[str]:
    """The findings in each member name and member content of a packed script's decoded payload.

    Args:
        text: The packed script.
        private: The private tokens, or None for the generic patterns alone.

    Returns:
        ``member[<j>]: ...`` for a hit in a member's name and ``member[<j>]:<line>: ...`` for one in
        its content (:func:`file_findings`), j being the member's 0-based position in the archive:
        the name is never printed.

    Raises:
        PayloadError: The payload is refused (see :func:`pack_guest.decode_payload`).
    """
    __tracebackhide__ = True
    members = decoded_payload(text)
    found: list[str] = []
    for j, (name, data) in enumerate(members.items()):
        found += [*_name_findings(f"member[{j}]", name, private), *file_findings(f"member[{j}]", data, private)]
    return found


def decoded_payload(text: str) -> dict[str, bytes]:
    """The members of a packed script's payload, refused with a message that never quotes ``text``.

    pytest's long traceback prints each shown frame's arguments, ``-l`` its locals: here and in
    ``decode_payload`` that is the whole artefact, which saferepr cuts to its head and tail, so a
    refused block appended at the end would print. This frame is hidden and the chain dropped.

    Args:
        text: The packed script.

    Returns:
        Each archive member name mapped to its bytes.

    Raises:
        PayloadError: Not exactly one payload and one sha line, malformed base64 or zip, or a sha
            mismatch; the message is ``decode_payload``'s, which names the reason only.
    """
    __tracebackhide__ = True
    try:
        return pack_guest.decode_payload(text)
    except ValueError as exc:
        raise PayloadError(str(exc)) from None


def _git() -> str:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is not on PATH: the privacy gate cannot list the tracked files")
    return git


def _git_run(project: Path, *args: str, stdin: bytes = b"") -> bytes:
    __tracebackhide__ = True  # ``stdin`` can hold file content (a staged test blob)
    # Inherited GIT_* variables (a hook's GIT_DIR, a pathspec mode) would make git answer for
    # another repository or another pathspec rule; LC_ALL=C keeps its output unlocalised.
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}
    env["LC_ALL"] = "C"
    return subprocess.run(  # noqa: S603 - fixed argv: git, resolved by shutil.which, run on a given checkout
        [_git(), "-C", str(project), *args],
        input=stdin,
        capture_output=True,
        check=True,
        env=env,
    ).stdout


def _index(project: Path) -> list[tuple[str, str, str]]:
    """Every index entry as (mode, object id, name), in ``git ls-files`` order, unmerged stages included."""
    __tracebackhide__ = True
    listing = _git_run(project, "ls-files", "-z", "-s").decode("utf-8", "surrogateescape")
    entries: list[tuple[str, str, str]] = []
    for record in filter(None, listing.split("\0")):
        meta, name = record.split("\t", 1)
        mode, object_id, _stage = meta.split(" ")
        entries.append((mode, object_id, name))
    return entries


def _blobs(project: Path, object_ids: Sequence[str]) -> dict[str, bytes]:
    """The bytes of each blob, read from git's object store in one ``git cat-file --batch``."""
    __tracebackhide__ = True
    out = _git_run(project, "cat-file", "--batch", stdin="".join(f"{i}\n" for i in object_ids).encode("ascii"))
    found: dict[str, bytes] = {}
    at = 0
    for object_id in object_ids:
        end = out.index(b"\n", at)
        header = out[at:end].split(b" ")
        if len(header) != 3 or header[1] != b"blob":  # "<id> missing", or not a blob
            raise RuntimeError(f"git cannot read the index blob {object_id}: the scan would miss it")
        size = int(header[2])
        found[object_id] = out[end + 1 : end + 1 + size]
        at = end + 1 + size + 1  # cat-file ends each object with a newline
    return found


def _listed(project: Path, *args: str) -> list[str]:
    """The names ``git ls-files -z <args>`` prints, in its order."""
    __tracebackhide__ = True
    return list(filter(None, _git_run(project, "ls-files", "-z", *args).decode("utf-8", "surrogateescape").split("\0")))


def _worktree_bytes(path: Path) -> bytes | None:
    """What ``git add`` would store for ``path``: a symlink's target, a file's bytes; None for neither."""
    __tracebackhide__ = True
    if path.is_symlink():
        return os.fsencode(path.readlink())  # git stores a symlink as its target
    if path.is_file():
        return path.read_bytes()
    return None  # absent, or "<dir>/": a nested repository, which its own scan covers


def _untracked(project: Path) -> list[tuple[str, bytes]]:
    """Every untracked, not-ignored path as (name, worktree bytes), in ``git ls-files -o`` order."""
    __tracebackhide__ = True
    found: list[tuple[str, bytes]] = []
    for name in _listed(project, "-o", "--exclude-standard"):
        data = None if name in CONTENT_EXCLUDED else _worktree_bytes(project / name)
        found.append((name, data or b""))
    return found


def _modified(project: Path) -> dict[str, bytes]:
    """The worktree bytes of every tracked file changed but not staged (``git ls-files -m``).

    bmk's ``make push`` runs ``git add -A`` after the tests, so it commits these worktree bytes, not
    the index blob :func:`_staged` reads. A deleted file is listed too but has no worktree content
    (``git add -A`` stages the deletion), so it is skipped, as are ``uv.lock`` and a gitlink's
    directory. An unmerged path is listed once per stage; the dict keeps it once.
    """
    __tracebackhide__ = True
    found: dict[str, bytes] = {}
    for name in _listed(project, "-m"):
        data = None if name in CONTENT_EXCLUDED else _worktree_bytes(project / name)
        if data is not None:
            found[name] = data
    return found


def _tracked(project: Path = pack_guest.PROJECT) -> list[tuple[str, bytes]]:
    """Every index entry (:func:`_staged`), then every untracked, not-ignored path, as (name, bytes).

    The untracked, not-ignored paths follow (``git ls-files -o --exclude-standard`` order, read from
    the worktree): bmk's ``make push`` runs the tests and then ``git add -A``, which commits them. So
    positions ``0..n-1`` are the ``git ls-files`` positions of the n index entries and position
    ``n + k`` is the k-th untracked path. An untracked file comes as it is (:func:`file_findings`
    scans any file carrying a payload as its wrapper plus its decoded payload), and ``uv.lock``'s
    content stays excluded. The worktree copies of modified tracked files (:func:`_modified`) are
    not listed here: they keep their index entry's position.
    """
    __tracebackhide__ = True
    return _staged(project) + _untracked(project)


def _staged(project: Path) -> list[tuple[str, bytes]]:
    """Every index entry as (name, bytes to scan), in ``git ls-files`` order.

    The bytes are what a commit of the index stores, read from the INDEX: a staged file deleted or
    restored in the worktree, a dangling symlink and a symlink's target (the blob of a mode-120000
    entry) are all scanned. No entry is dropped, so a position here is the position in
    ``git ls-files``. A gitlink (mode 160000, a submodule) comes with empty bytes: its content is
    another repository, which its own scan covers; its name is still scanned. ``uv.lock`` comes with
    empty bytes too (its content is excluded, its name is not); the packed tool comes as its wrapper
    without the payload, whose base64 is never scanned as text.
    """
    __tracebackhide__ = True
    entries = _index(project)
    readable = [i for mode, i, name in entries if mode != GITLINK and name not in CONTENT_EXCLUDED]
    blobs = _blobs(project, list(dict.fromkeys(readable)))
    artefact = pack_guest.ARTEFACT.as_posix()
    tracked: list[tuple[str, bytes]] = []
    for mode, object_id, name in entries:
        if mode == GITLINK or name in CONTENT_EXCLUDED:
            tracked.append((name, b""))
        elif name == artefact:
            wrapper = pack_guest.wrapper_without_payload(blobs[object_id].decode("utf-8"))
            tracked.append((name, wrapper.encode("utf-8")))
        else:
            tracked.append((name, blobs[object_id]))
    return tracked


def _artefact_text() -> str:
    """The packed tool as the index stores it, the same bytes :func:`_tracked` scans."""
    __tracebackhide__ = True
    return _git_run(pack_guest.PROJECT, "cat-file", "blob", f":{pack_guest.ARTEFACT.as_posix()}").decode("utf-8")


def _worktree_findings(index: int, data: bytes, private: PrivateList | None) -> list[str]:
    """The findings in the worktree copy of path ``index``, each labelled ``path[<index>] (worktree)``.

    A copy carrying a payload (an unstaged repack of the packed tool, or any other script in
    pwshpy's runner layout) is scanned as its wrapper plus its DECODED payload (:func:`file_findings`);
    a refused payload raises :class:`PayloadError`, never a skip.
    """
    __tracebackhide__ = True
    return file_findings(f"path[{index}] (worktree)", data, private)


def _tree_findings(private: PrivateList | None, project: Path = pack_guest.PROJECT) -> list[str]:
    """Path and content findings by position, content tagged with the version that hit.

    An index entry's content is labelled ``path[<i>] (index)``; the worktree copy of a modified
    tracked file (:func:`_modified`) is scanned too, labelled ``path[<i>] (worktree)`` with its
    entry's position, as is every untracked path. No label carries the name: a name can hold the
    token its content holds (:func:`lookup_hint` says how to print one locally).
    """
    __tracebackhide__ = True
    staged, untracked, modified = _staged(project), _untracked(project), _modified(project)
    assert staged or untracked, "the scan listed no tracked file: it examined nothing"
    found: list[str] = []
    for i, (name, data) in enumerate(staged):
        found += [*path_findings(i, name, private), *file_findings(f"path[{i}] (index)", data, private)]
        if name in modified:
            found += _worktree_findings(i, modified.pop(name), private)
    for i, (name, data) in enumerate(untracked, start=len(staged)):
        found += [*path_findings(i, name, private), *_worktree_findings(i, data, private)]
    return found


def lookup_hint(project: Path = pack_guest.PROJECT) -> str:
    """How to print a finding's path or member name locally; a failing log never names it.

    Args:
        project: The checkout the positions refer to.

    Returns:
        The command for ``path[i]`` (tracked entries first, then untracked) and ``member[j]``.
    """
    tracked = len(_index(project))
    return (
        f"path[i] is line i+1 of `git ls-files -s` when i < {tracked}, else line i-{tracked}+1 of "
        "`git ls-files -o --exclude-standard`; print it locally, e.g. `git ls-files -s | sed -n '<i+1>p'`. "
        "member[j] is entry j (0-based) of the packed tool's payload: "
        "`.venv/bin/python -c \"import sys; sys.path[:0] = ['scripts']; import pack_guest as p; "
        "print(list(p.decode_payload((p.PROJECT / p.ARTEFACT).read_text(encoding='utf-8')))[<j>])\"`"
    )


@pytest.fixture
def private() -> PrivateList:
    found = private_list()
    if found is None:
        pytest.skip(SKIP_REASON)
    return found


def _planted(tmp_path: Path) -> PrivateList:
    path = tmp_path / "tokens.json"
    path.write_text(
        json.dumps(
            {"hosts": ["planted-host7"], "vmids": ["98765"], "words": ["plantedword"], "paths": ["/planted/dir/"]}
        ),
        encoding="utf-8",
    )
    return load_private_list(path)


def _zipped(members: dict[str, bytes], *, compression: int = zipfile.ZIP_STORED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _wrapped(raw: bytes) -> str:
    """A minimal script in pwshpy's runner layout carrying the zip bytes ``raw``, its sha256 matching."""
    blob = base64.b64encode(raw).decode("ascii")
    return f"$PwshPySha = '{hashlib.sha256(raw).hexdigest()}'\n$PwshPyPayload = @'\n{blob}\n'@\nInvoke-It\n"


def _packed(members: dict[str, bytes], *, compression: int = zipfile.ZIP_STORED) -> str:
    """A minimal script in pwshpy's runner layout carrying ``members`` as its payload."""
    return _wrapped(_zipped(members, compression=compression))


def _encrypted(name: str, data: bytes) -> bytes:
    """A one-member zip whose member is flagged encrypted (general purpose bit 0) in both headers."""
    raw = bytearray(_zipped({name: data}))
    raw[raw.find(b"PK\x03\x04") + 6] |= 0x01  # the local header's flags
    raw[raw.find(b"PK\x01\x02") + 8] |= 0x01  # the central directory header's flags
    return bytes(raw)


def _bad_crc(name: str, data: bytes) -> bytes:
    """A one-member zip whose recorded CRC-32 is wrong in both headers: reading the member fails."""
    raw = bytearray(_zipped({name: data}))
    raw[raw.find(b"PK\x03\x04") + 14] ^= 0xFF  # the local header's CRC-32
    raw[raw.find(b"PK\x01\x02") + 16] ^= 0xFF  # the central directory header's CRC-32
    return bytes(raw)


# --- the real tree --------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_the_scan_examines_the_tree_and_the_payload() -> None:
    # Counted into locals: a failing assert on len(...) would print the scanned contents.
    entries = len(_tracked())
    members = len(decoded_payload(_artefact_text()))
    assert entries >= 100
    assert members == 8


@pytest.mark.os_agnostic
def test_no_tracked_file_or_path_matches_a_generic_pattern() -> None:
    found = _tree_findings(None)
    assert found == [], lookup_hint()


@pytest.mark.os_agnostic
def test_no_tracked_file_or_path_carries_a_private_token(private: PrivateList) -> None:
    found = _tree_findings(private)
    assert found == [], lookup_hint()


@pytest.mark.os_agnostic
def test_the_packed_payload_matches_no_generic_pattern() -> None:
    # Into a local: a failing assert over the call would print its argument, the artefact text.
    found = payload_findings(_artefact_text(), None)
    assert found == [], lookup_hint()


@pytest.mark.os_agnostic
def test_the_packed_payload_carries_no_private_token(private: PrivateList) -> None:
    found = payload_findings(_artefact_text(), private)
    assert found == [], lookup_hint()


def _scanned_artefact_shape() -> tuple[bool, bool, bool]:
    """(holds the payload here-string, holds the sha line, is non-empty) of the scanned artefact."""
    __tracebackhide__ = True  # its locals hold the scanned wrapper text
    scanned = dict(_tracked())[pack_guest.ARTEFACT.as_posix()].decode("utf-8")
    return "$PwshPyPayload = @'" in scanned, "$PwshPySha = '" in scanned, bool(scanned.strip())


@pytest.mark.os_agnostic
def test_the_artefact_is_scanned_without_its_base64_payload() -> None:
    # The wrapper still names the variables; their definitions (the here-string, the sha) are gone.
    # Booleans from a hidden helper: a failing assert, or -l, would print the scanned text.
    has_payload, has_sha, has_wrapper = _scanned_artefact_shape()
    assert not has_payload
    assert not has_sha
    assert has_wrapper, "the wrapper of the packed tool was not scanned"


# --- planted positives (a tmp_path list, so these run in CI too) ---------------------------


@pytest.mark.os_agnostic
def test_a_planted_token_and_a_planted_address_are_found(tmp_path: Path) -> None:
    planted = "line one\nkey for plantedword here\nnet " + "192." + "168.1.1\n"
    found = findings("planted.txt", planted, _planted(tmp_path))
    assert sorted(found) == ["planted.txt:2: token words[1]", "planted.txt:3: pattern 192\\.168\\."]


@pytest.mark.os_agnostic
def test_tokens_and_generic_host_names_match_in_any_case(tmp_path: Path) -> None:
    planted = "PLANTED-HOST7 runs\nnamed " + "VM" + "-Guest\n"
    found = findings("planted.txt", planted, _planted(tmp_path))
    assert found == ["planted.txt:1: token hosts[1]", "planted.txt:2: pattern \\bvm-[a-z]"]


@pytest.mark.os_agnostic
def test_an_underscore_bounds_a_token(tmp_path: Path) -> None:
    assert findings("k.txt", "id=98765_disk", _planted(tmp_path)) == ["k.txt:1: token vmids[1]"]


@pytest.mark.os_agnostic
def test_a_planted_token_in_utf16_behind_an_odd_length_header_is_found(tmp_path: Path) -> None:
    # 7 ASCII header bytes put the UTF-16 text at an odd offset: only the second alignment reads it.
    # "utf-16-le" (no BOM) keeps every byte ASCII, so the data is valid UTF-8: this fails when the
    # UTF-16 renderings are added only on a UTF-8 decode error instead of on any NUL byte.
    data = b"MSWIM\0\0" + "<NAME>plantedword</NAME>".encode("utf-16-le")
    assert data.decode("utf-8")  # the precondition the test exists for
    assert file_findings("planted.bin", data, _planted(tmp_path)) == ["planted.bin:1: token words[1]"]


@pytest.mark.os_agnostic
def test_a_planted_token_in_undecodable_bytes_is_found_as_latin1(tmp_path: Path) -> None:
    data = b"\xff\xfe junk /planted/dir/x"
    assert file_findings("planted.bin", data, _planted(tmp_path)) == ["planted.bin:1: token paths[1]"]


@pytest.mark.os_agnostic
def test_a_planted_token_in_a_decoded_payload_member_is_found(tmp_path: Path) -> None:
    packed = _packed({"pkg/clean.py": b"x = 1\n", "pkg/leak.py": b"# one\nHOST = 'planted-host7'\n"})
    assert payload_findings(packed, _planted(tmp_path)) == ["member[1]:2: token hosts[1]"]
    assert payload_findings(packed, None) == []


@pytest.mark.os_agnostic
def test_a_planted_payload_member_name_is_found_without_printing_it(tmp_path: Path) -> None:
    packed = _packed({"pkg/clean.py": b"x = 1\n", "pkg/plantedword.py": b"x = 2\n"})
    assert payload_findings(packed, _planted(tmp_path)) == ["member[1]: token words[1]"]


@pytest.mark.os_agnostic
def test_a_list_with_only_paths_loads_and_matches_no_empty_token(tmp_path: Path) -> None:
    path = tmp_path / "tokens.json"
    path.write_text(json.dumps({"paths": ["/planted/dir/"]}), encoding="utf-8")
    only_paths = load_private_list(path)
    assert findings("ok.txt", "plain text, no private path", only_paths) == []
    assert findings("bad.txt", "see /planted/dir/x", only_paths) == ["bad.txt:1: token paths[1]"]


@pytest.mark.os_agnostic
def test_a_planted_path_name_is_found_without_printing_it(tmp_path: Path) -> None:
    assert path_findings(7, "docs/plantedword_notes.md", _planted(tmp_path)) == ["path[7]: token words[1]"]


@pytest.mark.os_agnostic
def test_a_second_payload_block_is_refused_not_skipped(tmp_path: Path) -> None:
    # The wrapper scan strips EVERY payload block; a decode of only the first would let a second
    # block escape both checks.
    packed = _packed({"pkg/clean.py": b"x = 1\n"}) + "$PwshPyPayload = @'\nAAAA\n'@\n"
    with pytest.raises(PayloadError, match="exactly one") as raised:
        payload_findings(packed, _planted(tmp_path))
    # The chain is dropped: a chained traceback would print decode_payload's text argument.
    assert raised.value.__cause__ is None
    assert raised.value.__suppress_context__


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    "raw",
    [_encrypted("pkg/plantedword.py", b"x = 1\n"), _bad_crc("pkg/plantedword.py", b"x = 1\n")],
    ids=["encrypted", "bad-crc"],
)
def test_an_unreadable_member_is_refused_with_a_fixed_message(raw: bytes) -> None:
    # zipfile names the member in these errors (RuntimeError "File '<name>' is encrypted", BadZipFile
    # "Bad CRC-32 for file '<name>'"), and a member name can hold a token: no message may carry it.
    with pytest.raises(ValueError, match="not a readable zip archive") as raised:
        pack_guest.decode_payload(_wrapped(raw))
    assert "plantedword" not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__suppress_context__


@pytest.mark.os_agnostic
@pytest.mark.parametrize(("version", "label"), [("untracked", "worktree"), ("staged", "index")])
def test_any_script_carrying_a_payload_is_scanned_decoded(repo: Path, tmp_path: Path, version: str, label: str) -> None:
    # Not only the packed guest tool: any script in pwshpy's runner layout. A deflated member hides
    # its token from a text scan of the script, so only a decode finds it.
    text = _packed({"pkg/leak.py": b"# one\nHOST = 'planted-host7'\n"}, compression=zipfile.ZIP_DEFLATED)
    assert findings("x.ps1", text, _planted(tmp_path)) == []  # the precondition: unreadable as text
    script = repo / "tools" / "x.ps1"
    script.parent.mkdir()
    script.write_bytes(text.encode("utf-8"))
    if version == "staged":
        _git_run(repo, "add", "tools/x.ps1")
    assert _tree_findings(_planted(tmp_path), repo) == [f"path[1] ({label}): member[0]:2: token hosts[1]"]


# --- what a commit stores: the index, not the worktree (a scratch repository) ---------------


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A fresh repository with one clean staged file; nothing is committed (the index is the subject)."""
    path = tmp_path / "repo"
    path.mkdir()
    _git_run(path, "init", "-q")
    (path / "clean.txt").write_bytes(b"nothing private\n")
    _git_run(path, "add", "clean.txt")
    return path


def _stage(repo: Path, mode: str, name: str, data: bytes) -> None:
    """Put an index entry of ``mode`` holding ``data`` under ``name``, with no worktree file."""
    object_id = _git_run(repo, "hash-object", "-w", "--stdin", stdin=data).decode("ascii").strip()
    _git_run(repo, "update-index", "--add", "--cacheinfo", f"{mode},{object_id},{name}")


@pytest.mark.os_agnostic
def test_a_dangling_symlink_name_is_scanned(repo: Path, tmp_path: Path) -> None:
    _stage(repo, "120000", "docs/plantedword-link", b"nowhere")
    assert _tree_findings(_planted(tmp_path), repo) == ["path[1]: token words[1]"]


@pytest.mark.os_agnostic
def test_a_symlink_target_is_scanned_as_its_blob(repo: Path, tmp_path: Path) -> None:
    _stage(repo, "120000", "link", b"/planted/dir/x")
    assert _tree_findings(_planted(tmp_path), repo) == ["path[1] (index):1: token paths[1]"]


@pytest.mark.os_agnostic
def test_a_staged_file_deleted_from_the_worktree_is_scanned(repo: Path, tmp_path: Path) -> None:
    (repo / "leak.txt").write_bytes(b"host planted-host7\n")
    _git_run(repo, "add", "leak.txt")
    (repo / "leak.txt").unlink()
    assert _tree_findings(_planted(tmp_path), repo) == ["path[1] (index):1: token hosts[1]"]


@pytest.mark.os_agnostic
def test_staged_content_is_scanned_when_the_worktree_is_restored(repo: Path, tmp_path: Path) -> None:
    (repo / "leak.txt").write_bytes(b"host planted-host7\n")
    _git_run(repo, "add", "leak.txt")
    (repo / "leak.txt").write_bytes(b"nothing private\n")
    assert _tree_findings(_planted(tmp_path), repo) == ["path[1] (index):1: token hosts[1]"]


@pytest.mark.os_agnostic
def test_a_gitlink_name_is_scanned_and_its_commit_is_not_read(repo: Path, tmp_path: Path) -> None:
    # The object id names a commit in another repository: reading it here would fail.
    _git_run(repo, "update-index", "--add", "--cacheinfo", f"{GITLINK},{'1' * 40},plantedword-sub")
    assert _tree_findings(_planted(tmp_path), repo) == ["path[1]: token words[1]"]


@pytest.mark.os_agnostic
def test_positions_are_those_of_git_ls_files(repo: Path) -> None:
    _stage(repo, "120000", "a-dangling-link", b"nowhere")
    (repo / "z.txt").write_bytes(b"z\n")
    _git_run(repo, "add", "z.txt")
    (repo / "z.txt").unlink()
    listed = _git_run(repo, "ls-files", "-z").decode("utf-8").split("\0")[:-1]
    assert [name for name, _ in _tracked(repo)] == listed == ["a-dangling-link", "clean.txt", "z.txt"]


# --- what `git add -A` adds: untracked, not-ignored files (bmk's push stages them after the tests) ---


@pytest.mark.os_agnostic
def test_an_untracked_file_is_scanned(repo: Path, tmp_path: Path) -> None:
    (repo / "notes.txt").write_bytes(b"host planted-host7\n")
    assert _tree_findings(_planted(tmp_path), repo) == ["path[1] (worktree):1: token hosts[1]"]


@pytest.mark.os_agnostic
def test_an_ignored_untracked_file_is_not_scanned(repo: Path, tmp_path: Path) -> None:
    (repo / ".gitignore").write_bytes(b"notes.txt\n")
    (repo / "notes.txt").write_bytes(b"host planted-host7\n")
    assert _tree_findings(_planted(tmp_path), repo) == []


@pytest.mark.os_agnostic
def test_untracked_paths_are_indexed_after_the_tracked_ones(repo: Path, tmp_path: Path) -> None:
    (repo / "b.txt").write_bytes(b"b\n")
    (repo / "a-plantedword.txt").write_bytes(b"a\n")
    listed = _git_run(repo, "ls-files", "-z", "-o", "--exclude-standard").decode("utf-8").split("\0")[:-1]
    assert [name for name, _ in _tracked(repo)] == ["clean.txt", *listed] == ["clean.txt", "a-plantedword.txt", "b.txt"]
    assert _tree_findings(_planted(tmp_path), repo) == ["path[1]: token words[1]"]


@pytest.mark.os_posix
def test_an_untracked_symlink_is_scanned_as_its_target(repo: Path, tmp_path: Path) -> None:
    # git stores a symlink as its target text, which is what `git add -A` would commit.
    (repo / "link").symlink_to("/planted/dir/x")
    assert _tree_findings(_planted(tmp_path), repo) == ["path[1] (worktree):1: token paths[1]"]


# --- what `git add -A` commits of a tracked file: its worktree copy, staged or not ----------


@pytest.mark.os_agnostic
def test_an_unstaged_worktree_edit_of_a_tracked_file_is_scanned(repo: Path, tmp_path: Path) -> None:
    (repo / "clean.txt").write_bytes(b"nothing private\nhost planted-host7\n")
    assert _tree_findings(_planted(tmp_path), repo) == ["path[0] (worktree):2: token hosts[1]"]
    (repo / "clean.txt").write_bytes(b"nothing private\n")
    assert _tree_findings(_planted(tmp_path), repo) == []


@pytest.mark.os_agnostic
def test_a_worktree_copy_keeps_its_entry_position(repo: Path, tmp_path: Path) -> None:
    # git ls-files sorts: b.txt is path[0], clean.txt path[1]; the modified copy of clean.txt is
    # labelled path[1] too, and the untracked file stays path[2] beside it.
    (repo / "b.txt").write_bytes(b"b\n")
    _git_run(repo, "add", "b.txt")
    (repo / "clean.txt").write_bytes(b"host planted-host7\n")
    (repo / "c-plantedword.txt").write_bytes(b"c\n")
    found = _tree_findings(_planted(tmp_path), repo)
    assert found == ["path[1] (worktree):1: token hosts[1]", "path[2]: token words[1]"]


@pytest.mark.os_agnostic
def test_an_unstaged_repack_is_scanned_with_its_payload_decoded(repo: Path, tmp_path: Path) -> None:
    artefact = repo / pack_guest.ARTEFACT
    artefact.parent.mkdir(parents=True)
    artefact.write_bytes(_packed({"pkg/clean.py": b"x = 1\n"}).encode("utf-8"))
    _git_run(repo, "add", pack_guest.ARTEFACT.as_posix())
    artefact.write_bytes(_packed({"pkg/leak.py": b"# one\nHOST = 'planted-host7'\n"}).encode("utf-8"))
    found = _tree_findings(_planted(tmp_path), repo)
    assert found == ["path[1] (worktree): member[0]:2: token hosts[1]"]


# --- a failing privacy test prints no token -------------------------------------------------


@pytest.mark.os_agnostic
def test_a_private_list_prints_counts_never_tokens(tmp_path: Path) -> None:
    planted = _planted(tmp_path)
    assert repr(planted) == "PrivateList(hosts=1, vmids=1, words=1, paths=1)"
    assert str(planted) == repr(planted)


# Each probe models a real test: the tree scan, the payload scan, and a direct decode_payload call
# (test_pack_guest and test_artefact make one on the committed artefact). Results go into locals
# first, as the real tests do: an assert over a call would print the call's text argument.
_PROBE = """
import os
from pathlib import Path

import pack_guest
import test_privacy_gate as gate
from test_privacy_gate import private


def _text():
    return Path(os.environ["PROBE_TEXT"]).read_bytes().decode("utf-8")


def test_tree(private):
    found = gate._tree_findings(private, Path(os.environ["PROBE_REPO"]))
    assert found == []


def test_payload(private):
    found = gate.payload_findings(_text(), private)
    assert found == []


def test_packer():
    members = len(pack_guest.decode_payload(_text()))
    assert members == 1
"""
_PLANTED_TOKENS = ("planted-host7", "98765", "plantedword", "/planted/dir/")
_PLANTED_JSON = json.dumps(
    {"hosts": ["planted-host7"], "vmids": ["98765"], "words": ["plantedword"], "paths": ["/planted/dir/"]}
)
_LEAK = " ".join(_PLANTED_TOKENS)
# A refused block at the END: saferepr keeps a long argument's head and tail, so the tail prints.
_SECOND_BLOCK = _packed({"pkg/clean.py": b"x = 1\n"}) + f"$PwshPyPayload = @'\n{_LEAK}\n'@\n"
# One block and one sha line, but "-" is not base64: the older "not base64" refusal.
# A name holding every planted token (the content holds them too): a content finding labelled by
# the name would print it, the path index hides it.
_LEAK_NAME = "plantedword/planted/dir/planted-host7-98765.txt"
_NAMED_MEMBER = _packed({"pkg/" + _LEAK_NAME: _LEAK.encode("utf-8") + b"\n"})
_NOT_BASE64 = f"$PwshPySha = '{'0' * 64}'\n$PwshPyPayload = @'\n{_LEAK}\n'@\nInvoke-It\n"
# A valid block and sha whose one member, named with every planted token, cannot be read: zipfile
# names the member in its error, and its own frames carry the name as an argument and a local.
_ENCRYPTED_MEMBER = _wrapped(_encrypted("pkg/" + _LEAK_NAME, _LEAK.encode("utf-8")))
_BAD_CRC_MEMBER = _wrapped(_bad_crc("pkg/" + _LEAK_NAME, _LEAK.encode("utf-8")))


@dataclass(frozen=True)
class _LeakCase:
    probe: str  # the probe test to run
    tokens_json: str  # the list the child reads
    text: str  # the packed script the payload probes read
    outcome: str  # pytest's summary for the run
    name: str = "leak.txt"  # the staged file the tree probe finds


_LEAK_CASES = {
    "a-finding": _LeakCase("test_tree", _PLANTED_JSON, "", "1 failed"),
    "a-malformed-list": _LeakCase(
        "test_tree", '{"hosts": ["planted-host7"], "vmids": ["98765"], "words": ["plantedword", ""]}', "", "1 error"
    ),
    "invalid-json": _LeakCase(
        "test_tree", '{"hosts": ["planted-host7"], "vmids": ["98765"], "words": ["plantedword"]', "", "1 error"
    ),
    "a-second-payload-block": _LeakCase("test_payload", _PLANTED_JSON, _SECOND_BLOCK, "1 failed"),
    "a-second-payload-block-decoded-directly": _LeakCase("test_packer", _PLANTED_JSON, _SECOND_BLOCK, "1 failed"),
    "a-payload-not-base64": _LeakCase("test_payload", _PLANTED_JSON, _NOT_BASE64, "1 failed"),
    "a-payload-not-base64-decoded-directly": _LeakCase("test_packer", _PLANTED_JSON, _NOT_BASE64, "1 failed"),
    "a-token-named-file-whose-content-hits": _LeakCase("test_tree", _PLANTED_JSON, "", "1 failed", _LEAK_NAME),
    "a-token-named-member-whose-content-hits": _LeakCase("test_payload", _PLANTED_JSON, _NAMED_MEMBER, "1 failed"),
    "an-encrypted-member": _LeakCase("test_payload", _PLANTED_JSON, _ENCRYPTED_MEMBER, "1 failed"),
    "an-encrypted-member-decoded-directly": _LeakCase("test_packer", _PLANTED_JSON, _ENCRYPTED_MEMBER, "1 failed"),
    "a-member-with-a-bad-crc": _LeakCase("test_payload", _PLANTED_JSON, _BAD_CRC_MEMBER, "1 failed"),
    "a-member-with-a-bad-crc-decoded-directly": _LeakCase("test_packer", _PLANTED_JSON, _BAD_CRC_MEMBER, "1 failed"),
}


def _run_probe(repo: Path, tmp_path: Path, case: _LeakCase, options: Sequence[str]) -> str:
    """Run one probe test in a child pytest and return its whole output, lower-cased."""
    (repo / case.name).parent.mkdir(parents=True, exist_ok=True)
    (repo / case.name).write_bytes(_LEAK.encode("utf-8") + b"x\n")
    _git_run(repo, "add", case.name)
    (tmp_path / "tokens.json").write_text(case.tokens_json, encoding="utf-8")
    (tmp_path / "packed.ps1").write_bytes(case.text.encode("utf-8"))
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    (tmp_path / "test_probe.py").write_text(_PROBE, encoding="utf-8")
    here = Path(__file__).resolve().parent
    env = {k: v for k, v in os.environ.items() if not k.startswith("COV_CORE_")}
    env |= {
        "PYTHONPATH": os.pathsep.join(
            str(p) for p in (here, pack_guest.PROJECT / "scripts", pack_guest.PROJECT / "src")
        ),
        TOKENS_VARIABLE: str(tmp_path / "tokens.json"),
        "PROBE_REPO": str(repo),
        "PROBE_TEXT": str(tmp_path / "packed.ps1"),
    }
    argv = [sys.executable, "-m", "pytest", "-c", str(tmp_path / "pytest.ini"), "-p", "no:cacheprovider", *options]
    run = subprocess.run(  # noqa: S603 - fixed argv: this interpreter running pytest on a generated probe
        [*argv, f"{tmp_path / 'test_probe.py'}::{case.probe}"],
        capture_output=True,
        env=env,
        cwd=tmp_path,
        check=False,
    )
    return (run.stdout + run.stderr).decode("utf-8", "replace").lower()


@pytest.mark.os_agnostic
@pytest.mark.parametrize("options", [("-vv", "--tb=long"), ("-vv", "--tb=long", "-l")], ids=["tb-long", "showlocals"])
@pytest.mark.parametrize("case", list(_LEAK_CASES.values()), ids=list(_LEAK_CASES))
def test_a_failing_run_prints_no_token(repo: Path, tmp_path: Path, case: _LeakCase, options: tuple[str, ...]) -> None:
    """A failing privacy test, run with the strictest tracebacks (frame arguments; with -l, locals)."""
    output = _run_probe(repo, tmp_path, case, options)
    assert case.outcome in output, "the probe did not run to the expected outcome"
    leaked = [n for n, token in enumerate(_PLANTED_TOKENS, start=1) if token in output]
    assert leaked == [], "planted token number(s) printed by the failing run"


# --- known negatives ------------------------------------------------------------------------


@pytest.mark.os_agnostic
def test_public_numbers_and_names_are_not_findings(tmp_path: Path) -> None:
    text = "Proxmox VE build 26200 CVE-2025-987650 port 65535 vm-1-disk-0"
    assert findings("ok.txt", text, _planted(tmp_path)) == []


@pytest.mark.os_agnostic
def test_a_file_without_a_nul_has_one_rendering_and_a_nul_adds_two() -> None:
    assert renderings(b"plain") == ["plain"]
    assert len(renderings(b"a\0b\0")) == 3


# --- the list itself ------------------------------------------------------------------------


@pytest.mark.os_agnostic
@pytest.mark.parametrize(
    ("content", "message"),
    [
        ('{"host": ["x"]}', "unknown key(s) host; allowed: hosts, paths, vmids, words"),
        ('{"words": [1]}', "words must be a list of non-empty strings"),
        ('{"words": [""]}', "words must be a list of non-empty strings"),
        ('{"words": "x"}', "words must be a list of non-empty strings"),
        ("[]", "the list must be a JSON object with keys from hosts, paths, vmids, words"),
        ("{}", "the list holds no token, so it would check nothing"),
        ('{"words": [], "paths": []}', "the list holds no token, so it would check nothing"),
        ("not json", "not valid JSON (Expecting value, line 1)"),
    ],
)
def test_a_malformed_list_is_an_error_not_a_skip(tmp_path: Path, content: str, message: str) -> None:
    path = tmp_path / "tokens.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(PrivacyListError) as raised:
        load_private_list(path)
    assert str(raised.value) == f"{path}: {message}"


@pytest.mark.os_agnostic
def test_the_variable_names_another_list_and_a_missing_one_is_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _planted(tmp_path)
    monkeypatch.setenv(TOKENS_VARIABLE, str(tmp_path / "tokens.json"))
    assert private_list() == _planted(tmp_path)
    missing = tmp_path / "absent.json"
    monkeypatch.setenv(TOKENS_VARIABLE, str(missing))
    with pytest.raises(PrivacyListError) as raised:
        private_list()
    assert str(raised.value).startswith(f"{missing}: cannot read the private token list (")
