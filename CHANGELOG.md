# Changelog

All notable changes to this project will be documented in this file following
the [Keep a Changelog](https://keepachangelog.com/) format.


## [Unreleased]

### Changed

- Requires `lib_log_rich>=7.0.1` (was 6.5.7). The `[lib_log_rich]` settings are checked when the
  configuration loads: a `console_theme` other than `classic`, `dark`, `neon` or `pastel`, or an
  unknown console stream, format preset, Graylog protocol or queue policy, now stops the tool with
  a configuration error (exit 78). Before, an unknown theme was accepted and the console printed
  without colours. The shipped defaults are all valid.
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
- A `[lib_log_rich]` section with several invalid settings reports every one of them, not only
  the first.


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
