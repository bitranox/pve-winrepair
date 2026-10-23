# Changelog

All notable changes to this project will be documented in this file following
the [Keep a Changelog](https://keepachangelog.com/) format.


## [Unreleased]

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
  `drives`, `state`, `staged-os`, `servicing-active`, `setup-alive`, `detect-lp-defect`,
  `verify-runners`, `quiesce-wu`, `restore-wu`, `lock-dirs`, `prepare`, `launch` and
  `upgrade-run`.
- Layered configuration in `/etc/pve-winrepair/config.toml` with the sections `[ssh]`, `[guest]`,
  `[repair]` and `[node]`; a key can be overridden for one run through
  `PVE_WINREPAIR___<SECTION>__<KEY>`. An unknown key or a refused value stops the command and
  names `<section>.<key>`.
- `repair` and `apply` exit 0 when done, 1 when refused, 2 on an internal error and 78 when the
  configuration does not load.
