# Changelog

All notable changes to this project will be documented in this file following
the [Keep a Changelog](https://keepachangelog.com/) format.


## [Unreleased]

### Removed

- Python 3.10 support: the package and the guest tool need Python 3.11 or newer. On a node or
  guest that has only 3.10, uv fetches a 3.11 or newer interpreter on the next run. The CI lane
  for 3.10 goes with it, and so does its pinned filelock 4.1.0, which carried open advisories
  that no 3.10-compatible release fixes.

## [2.0.0] 2026-10-28 23:38:06

A major release because a configuration 1.0.0 ran with can now stop with exit 78 before any call:
an unknown top-level section, and the other new load-time refusals listed under Changed. On
Windows the default `[node] state_dir` moved to `%LOCALAPPDATA%\pve-winrepair`; to keep the receipts 1.0.0
wrote, set `state_dir` to where they are (`/var/lib/pve-winrepair` on the drive 1.0.0 ran from,
for example `C:\var\lib\pve-winrepair`). Run `pve-winrepair config`
after upgrading: it names every refused setting and section.

### Added

- `docs/installation-media.md`: how to pick installation media for a repair - reading the guest's
  edition, install language and build over ssh, which Microsoft page or licensing portal offers
  which edition, downloading, verifying and unpacking the ISO on the node, checking image 1 with
  DISM before staging, and adding the current cumulative update to an ISO older than the guest.
- `repair` and `apply` can run on a workstation (Linux, macOS or Windows) and drive a remote PVE
  node over ssh. `[node] host`, or `--node HOST` for one run, names the node; `--node ""` runs on
  this machine although `[node] host` is set. The tool logs in to the node as `[node] ssh_user`
  (default `root`) with `[node] ssh_key`, checks the node's host key strictly against
  `[node] known_hosts_file` (default `~/.ssh/known_hosts`), runs `qm` there, and reaches the
  guests through the node with a `ProxyCommand` that logs in with the node key, so the guest key
  is never offered to the node. A node that does not answer, refuses the key or its host key, or
  has no `qm` is refused before any VM call (exit 1), and so is a node named without
  `[node] ssh_key`. README "From a workstation" walks through it. These `[node]` keys are checked
  when the configuration loads, even when no node is used, and a refused value stops the tool
  with exit 78: `host` (letters, digits, `.` and `-`, so `_` is refused), `ssh_user` (1 to 64
  letters, digits, `_`, `.` and `-`, not starting with `-`), `ssh_key` (no `"`, `%` or control
  character) and `known_hosts_file` (not empty; no whitespace, `"`, `%` or control character).
- `repair --media node|local` and `[repair] media_source` (default `"node"`): `node` stages
  `[repair] media_dir` on the node, `local` stages `[repair] local_media_dir` from the machine
  running the tool. With a remote node, `node` has the node's own scp copy the media into the
  guest, logging in with the guest key from this machine's ssh-agent, forwarded for that copy
  only. Before any VM call the run refuses unconfigured, missing or empty media (for a remote
  `node`, a directory holding only names starting with `.` counts as empty, since its copy skips
  them) and, for a remote `node`, no reachable ssh-agent, an agent holding no key, or a node that
  did not receive it.
  A `media_source` other than `node` or `local` stops the tool when the configuration loads
  (exit 78), even for a run that passes `--media`.
- `[repair] stage_timeout_minutes` (default 90, a whole number from 1 to 1440): how long the media
  copy to the guest may take; it was a fixed 90 minutes. A value outside that range stops the tool
  when the configuration loads (exit 78).
- `repair --receipt FILE` and `apply --receipt FILE`: one receipt file on this machine instead of
  `receipt-<vmid>.json` in `[node] state_dir`, made absolute against the current directory with
  its symbolic links resolved. `repair` refuses (exit 1), before any VM call, a file that holds
  another VM's receipt or that exists but is no valid receipt; that file is left as it is.

### Changed

- Requires `lib_log_rich>=8.1.1` (was 6.5.7). With the raised floor, a `[lib_log_rich]
  console_theme` other than `classic`, `dark`, `neon` or `pastel` stops the tool when the
  configuration loads (exit 78), and a section with several invalid settings reports every one
  of them. A 1.0.0 install that resolved lib_log_rich below 7.0.1 accepted an unknown theme and
  reported only the first invalid setting; an unknown console stream, format preset, Graylog
  protocol or queue policy already stopped 1.0.0. The shipped defaults are all valid.
- An unknown key in `[lib_log_rich]`, or in its `payload_limits` table, is refused: every command
  that reads the configuration stops with exit 78 and one line such as
  `Error: lib_log_rich.custom_field: Extra inputs are not permitted`. A 1.0.0 install that
  resolved lib_log_rich below 8.0.0 dropped such a key silently, so a misspelled logging setting
  left its default in place; the raised lib_log_rich floor makes the refusal certain, and
  pve-winrepair reports it like its own configuration problems.
- The guest tool runs on `pwshpy==1.8.0` (was 1.6.0). `launch` registers its SYSTEM task through
  pwshpy's `register_scheduled_task` with task settings (no trigger, start and keep running on
  battery, 72 h limit, a second start ignored, hard terminate and start on demand allowed)
  instead of driving the Task Scheduler COM API itself; the task it registers is unchanged. The
  task cleanup's read-back looks the task up by name in its folder instead of walking every
  folder, so a task elsewhere that this account cannot read no longer makes the cleanup refuse.
  An elevated run of the packed tool on Windows now keeps an empty git configuration file at
  `pwshpy\empty.gitconfig` below the account's data directory, and refuses to start (exit 127)
  when another account could change it.
- Every guest tool answer is validated once, strictly, into a typed model per subcommand, closed
  to unknown fields. A malformed answer still ends the run as an internal error (exit 2), but its
  message now reads `guest tool <cmd>: the answer breaks the contract: <field>: <reason>` and no
  longer quotes the guest's value; a `nic-macs` value that is not a MAC address now reads that way
  too, instead of `nic-macs: '<value>' is not a MAC address`. An envelope with extra top-level keys,
  an exit-2 envelope without its `error`/`error_type`, a `prepare` that passes with no image, and a
  Windows Update search whose `pending` count contradicts its status are now refused the same way.
- The guest tool builds its answers from pydantic models and pins `pydantic==2.14.1` in its own
  dependency header; the JSON it prints is byte-identical.
- A malformed `--stage-root` (empty, `1:`, `CD`, `C:\upgrade`, a non-ASCII letter) is a usage
  error (exit 2) before anything runs, instead of exit 1 after the snapshot and staging steps.
  Omitting the option still measures the stage drive.
- A `qm status` answer that names neither `running` nor `stopped` (a VM this node does not have,
  a failed call) refuses the run at once with exit 1 instead of being read as "not running". A
  wait for a status keeps polling through such a read until its bound and then names the last
  failure.
- The guest tool refuses a Win32_Service start mode or state outside the documented set in
  `quiesce-wu` and `restore-wu` (exit 2) instead of passing it through as text, and skips a
  `docker ps` line whose name or status is not text.
- A guest agent address whose type is neither `ipv4` nor `ipv6` ends the run as an internal error
  instead of being skipped.
- New load-time refusals (exit 78, before any call) that a configuration accepted by 1.0.0 can
  hit:
  - `[ssh] known_hosts_file` that is empty, or holds whitespace or `"`. ssh's option parser split a
    spaced value into several files, and an empty one made every ssh fail. A `%` token stays
    allowed there.
  - `[ssh] key` or `[ssh] known_hosts_file` holding a control character, such as the tab a Windows
    path like `"C:\temp\..."` gets in a double-quoted TOML string. Before, ssh failed on a file
    that does not exist, for the guest key only once the run reached the guest.
  - On Windows, `[node] state_dir` without a drive, such as the former default
    `/var/lib/pve-winrepair`: the directory must be absolute on the machine running the tool. The
    Windows default is now `%LOCALAPPDATA%\pve-winrepair`, and with `LOCALAPPDATA` unset and no
    `state_dir` the setting is refused by name. On POSIX the rule is unchanged (a relative path,
    `""` and a leading `~` were refused before); the message now reads `must be an absolute path on
    this machine`.
  - A top-level section other than `[ssh]`, `[guest]`, `[repair]`, `[node]`, `[lib_log_rich]` and
    `[lib_layered_config]`, from any layer and written as a table (`[repiar]`) or an array of tables
    (`[[repiar]]`): one `Error: <section>: not a section pve-winrepair reads
    (...)` line each, beside the lines for refused values, in `config`, `repair` and `apply`.
    1.0.0 ignored such a section, so a misspelt `[repiar]` was skipped without a word, and a `.env`
    line written with the environment prefix (`PVE_WINREPAIR___SSH__KEY=...`, which the loader
    reads as a section `pve_winrepair`) set nothing; that section's line adds that `.env` lines take
    `SECTION__KEY` without the `PVE_WINREPAIR___` prefix. A top-level key that is no table, such as
    a `.env` line without `__`, is not refused. The settings do not use it, but a `LOG_*` line
    (`LOG_CONSOLE_LEVEL=DEBUG`) still takes effect: pve-winrepair copies a `.env`'s `LOG_*` lines
    into the environment, where lib_log_rich reads them. Any other such key sets nothing and stops
    nothing, as in 1.0.0: a TOML key written above its section's header (`key = "/k"` before
    `[ssh]`), and a section joined to its key by one underscore instead of two (`SSH_KEY=/k` in a
    `.env`, `PVE_WINREPAIR___SSH_KEY=/k` in the environment).
- `repair` refuses (exit 1), before any VM call, a `receipt-<vmid>.json` in `[node] state_dir`
  that holds another VM's receipt; before, it removed it, and that VM's `apply` then had no
  receipt. A per-VM file that is no valid receipt is still removed, like any previous receipt, once
  the run has found no live upgrade run; a new receipt is written only when the image passes the WIM
  gate.
- `repair` refuses (exit 1) when `qm config` fails at the vTPM step, quoting qm's output, before
  the VM is shut down or changed. Before, and in 1.0.0, the failed read was taken as a config
  with no TPM: without `--tpm-storage` the run stopped with "cannot determine storage", and with
  `--tpm-storage` it shut the guest down and added a vTPM it may already have had.
- The WIM gate fails media whose image index 1 names no SPBUILD (missing or not a number), with
  that as its reason. Before, and in 1.0.0, it read as SPBUILD 0: media of a newer build passed
  into a receipt naming `<build>.0`, which `apply` then refused to verify after the upgrade, and
  media of the running build failed as "older than running".
- `config` checks the `[ssh]`, `[guest]`, `[repair]` and `[node]` settings the way `repair` and
  `apply` load them: after showing the values it prints one `Error: <section>.<key>: <reason>` line
  per refused value and exits 78. Before, and in 1.0.0, it showed such a value and exited 0, and
  only `repair` or `apply` refused it.

### Fixed

- ssh, scp, ssh-keygen and ssh-add no longer read the caller's stdin, so a shell loop such as
  `while read v; do pve-winrepair repair --vmid "$v"; done < list` runs every VM in the list
  (before, the first VM's ssh read the rest of the list; with or without `--node`).
- A `lock-dirs` refusal prints an ACE's access mask as the unsigned value Windows stores
  (`mask 0xe0010000`); before, a mask holding a generic right read negative (`mask -0x1fff0000`).
  Which ACEs are refused is unchanged.
- A `repair` that ends with Windows Update held and nothing to apply (`--stage-only`, or a poll
  ending `STATE=DONE-FAIL`, `WORKER_GONE` or `TIMEOUT`) prints its last step once, with the hold
  note. Before, and in 1.0.0, it printed that step twice on stderr, the second time with the note.
  The `--json` steps are unchanged.
- A media copy that timed out or could not start says `media transfer` once, as in
  `media transfer failed: timed out after 5400 s (...)` and
  `media transfer failed rc=255: could not run scp: <reason>`. Before, and in 1.0.0, the refusal
  named it twice (`media transfer failed rc=255: media transfer: timed out after 5400 s`).
- The README's persistent install (`uv tool install --exclude-newer "7 days" ...`) carries the
  same four `--exclude-newer-package ...=false` exemptions as the pinned wrapper. Before, it
  exempted nothing, so uv refused any pve-winrepair release less than a week old.


## [1.0.0] 2026-10-23 22:06:16

The first public release, 1.0.0. The tool was developed in a private repository before it; that
history is not published, so this changelog starts here.

### Added

- `pve-winrepair repair --vmid N`: repairs a Windows guest whose cumulative update fails, by an
  in-place repair upgrade. It snapshots the guest before anything on it changes, adds a vTPM when
  the guest has none, stages the installation media from `[repair] media_dir`, checks the image,
  launches setup from a SYSTEM scheduled task and polls it to its verdict. `--stage-only` stages
  the media and holds Windows Update, but neither gates the WIM nor launches setup; `--ip`
  reaches a guest that has no QEMU guest agent.
- `pve-winrepair apply --vmid N --ip ADDR`: applies the upgrade a repair staged. It refuses unless
  the guest's upgrade run finished OK, reboots the guest into the new OS, waits for ssh, checks the
  guest's build against the repair receipt and lifts the Windows Update hold.
- A repair receipt per guest in `[node] state_dir`: the repair records the build that `prepare`
  read from the staged image, and `apply` accepts only that build. The receipt is replaced
  atomically and readable by its owner only.
- `pve-winrepair guest-tool path` and `guest-tool sha256`: the packed guest tool this install
  pushes to the guests, and its sha256 with the content address it is stored under on a guest.
- The guest tool, packed with pwshpy into one PowerShell file, called over ssh and answering each
  call with one JSON envelope (exit 0 ok, 1 refused, 2 internal error). Its verbs: `build`,
  `drives`, `nic-macs`, `state`, `staged-os`, `servicing-active`, `setup-alive`,
  `detect-lp-defect`, `verify-runners`, `quiesce-wu`, `restore-wu`, `lock-dirs`, `prepare`,
  `launch` and `upgrade-run`.
- Layered configuration in `/etc/pve-winrepair/config.toml` with the sections `[ssh]`, `[guest]`,
  `[repair]` and `[node]`; a key can be overridden for one run through
  `PVE_WINREPAIR___<SECTION>__<KEY>`. An unknown key or a refused value stops the command and
  names `<section>.<key>`.
- `repair` and `apply` exit 0 when done, 1 when refused, 2 on an internal error and 78 when the
  configuration does not load.
- `repair --ip` and `apply` bind the guest at `--ip` to the VM: one of the MACs in `qm config
  <vmid>` must be among the adapters the guest tool's `nic-macs` reports, else the run is refused
  before anything acts on the VM (on a stopped VM: before anything is staged at that address).
- The receipt also records the guest's build and InstallDate before the upgrade. For media that
  carry the build the guest already runs, `apply` requires InstallDate to change across the apply
  reboot, else REVERTED_OR_UNCHANGED.
- A `--stage-only` run (verdict STAGED) says on its last step that Windows Update is still held and
  how to lift it.
- The profile check trusts the SDDL alias `LA` when the ssh user is the built-in Administrator
  (a SID ending in -500), the default `[ssh] user`.
- `--hours` and `--apply-minutes` accept only finite numbers above 0, `--tpm-storage` only a PVE
  storage ID and `--ip` only an IPv4 address; anything else is a usage error before any call.
- ssh and scp to the guests pass `-o IdentitiesOnly=yes`, so only the configured key is offered.
- `docs/windows-guest-ssh.md`: how to prepare a Windows guest for the node's ssh key - installing
  OpenSSH Server, writing `administrators_authorized_keys` with the right encoding and ACL, and
  checking the login from the node.
