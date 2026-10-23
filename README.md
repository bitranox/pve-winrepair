# pve-winrepair

<!-- Badges -->
[![CI](https://github.com/bitranox/pve-winrepair/actions/workflows/default_cicd_public.yml/badge.svg)](https://github.com/bitranox/pve-winrepair/actions/workflows/default_cicd_public.yml)
[![CodeQL](https://github.com/bitranox/pve-winrepair/actions/workflows/codeql.yml/badge.svg)](https://github.com/bitranox/pve-winrepair/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/pve-winrepair.svg)](https://pypi.org/project/pve-winrepair/)
[![Python](https://img.shields.io/pypi/pyversions/pve-winrepair.svg)](https://pypi.org/project/pve-winrepair/)
[![Code Style: Ruff](https://img.shields.io/badge/Code%20Style-Ruff-46A3FF?logo=ruff&labelColor=000)](https://docs.astral.sh/ruff/)

Repair a Windows guest on Proxmox VE whose cumulative updates keep failing, with an offline
in-place repair upgrade driven from the node.

## What it does

Some Windows installations get into a state where no cumulative update installs any more: the
component store is damaged, or an orphaned language pack blocks every update at the same step.
DISM and SFC rarely get such a guest back. An in-place repair upgrade does. setup.exe from
installation media of the same edition replaces the component store instead of patching it, and
keeps the applications, settings and data.

`pve-winrepair` runs that upgrade from the Proxmox node over ssh, without anyone logging in to the
guest. It takes two commands. `pve-winrepair repair --vmid N` prepares and starts the upgrade:

1. It refuses a guest on which an upgrade run is still live. With `--ip`, it first refuses a guest
   that is not the VM: one of the MACs of the VM's `netN` devices in `qm config` must be among the
   guest's network adapters (the guest tool's `nic-macs`). On a running VM that is checked before
   anything acts on the VM. A stopped VM cannot be asked before it boots, so there the order is:
   vTPM added if missing, offline snapshot and start, all on the VM `--vmid` names, then the MAC
   check. On every `--ip` run the check runs again after the boot, before anything is staged or
   launched at that address.
2. It holds Windows Update (the service start types set to Disabled, then read back), so no further
   update lands in the broken store. On a running guest reached through the QEMU agent this happens
   first, and `repair` then waits up to 20 minutes for running servicing to finish. A guest reached
   with `--ip`, or one that was stopped, is held only after the media are staged, and gets no
   servicing wait.
3. It adds a v2.0 vTPM when the guest has none, because setup refuses a machine without any TPM.
   That needs a clean ACPI shutdown; the guest is never force-stopped.
4. It takes a Proxmox snapshot, `pre_winrepair` by default. With the guest agent, PVE freezes the
   filesystem first; without one (`--ip`), the guest is shut down and snapshotted powered off.
5. It creates the staging directory `<drive>:\upgrade` on the first fixed drive other than `C:`, in
   letter order, with `[repair] stage_free_gb` free (or on the drive `--stage-root` names). With no
   such drive it uses `C:\upgrade`, but only when `C:` has room for both the media and the upgrade.
   Whichever drive it stages on, `C:` always needs `[repair] system_free_gb` free for the upgrade
   itself. The directory is created already locked to SYSTEM and Administrators, and the installation
   media are then copied from the node into it. A staging directory that exists already and is
   exactly locked is reused, and the copy goes over what is in it: files of other media stay. Remove
   it (`rd /s /q X:\upgrade`, as an administrator) before staging different media.
6. It gates on the WIM: `sources\install.wim` must be readable and its image 1 must not be older than
   the build the guest runs (the build number first, then the servicing build). The image's build,
   with the build and the InstallDate the guest runs at that moment, goes into a receipt on the node.
7. It launches setup.exe from a SYSTEM scheduled task (ssh kills a process tree that outlives its
   connection, and setup runs for hours) and polls the run's own state log until it reports
   `STATE=DONE-OK` or `STATE=DONE-FAIL`.

setup.exe runs with `/noreboot`, so the guest keeps running the old OS with the new one staged.
`pve-winrepair apply --vmid N --ip IP` finishes the job:

1. It refuses unless the guest at `--ip` is the VM (a MAC of its `qm config`, as for `repair --ip`),
   the upgrade run finished OK and the staged new OS is still there.
2. It shuts the guest down cleanly and starts it again, which boots into the new OS.
3. It waits for ssh, then checks the guest's build against the receipt the repair wrote. When the
   media carried the very build the guest ran before, a rolled-back upgrade ends on that same build,
   so the guest's InstallDate, which an in-place upgrade writes anew, must also differ from the one
   in the receipt.
4. It releases the Windows Update hold, and only once the build matches.

## Requirements

On the Proxmox VE node:

- Run as root: the commands call `qm`.
- [uv](https://docs.astral.sh/uv/). It also fetches a Python 3.10 or newer when the node has none.
- A directory with the installation media, unpacked as on the ISO: `setup.exe` and
  `sources\install.wim` at its top level. Use media of the guest's edition and language; setup keeps
  the applications only then. The WIM gate refuses media older than the guest's build.

On the Windows guest (Windows 10 or 11):

- OpenSSH Server with key authentication for an administrator account, and `cmd.exe` as the ssh
  default shell (the Windows default). [Preparing a Windows guest for SSH key
  access](docs/windows-guest-ssh.md) walks through the install, the key file and its ACL.
- The QEMU guest agent. Without it, pass the guest's address with `--ip`; the snapshot is then taken
  with the guest powered off.
- Internet access the first time the guest tool runs as a given user, SYSTEM included: it installs
  `uv` for that user when the guest has no uv that user can trust, downloads a uv-managed Python
  into that user's own profile (an elevated run uses no other Python), and resolves its own pinned
  dependencies (`pwshpy==1.6.0`, `pywin32==312`) from PyPI at that moment. Proxy variables are
  ignored in an elevated run, so the guest needs direct access. See [SECURITY.md](SECURITY.md) for
  what that trusts.
- Free space: by default 15 GiB on the staging drive for the media and 25 GiB on `C:` (`[repair]
  stage_free_gb` and `system_free_gb`).

## Install and run

Run a fixed version with `uvx`, which installs nothing permanently on the node:

```bash
uvx pve-winrepair@1.0.0 --version
```

For regular use, put a small wrapper on the node that pins the version and passes a supply-chain
cooldown, for example as `/usr/local/sbin/pve-winrepair`:

```bash
#!/usr/bin/env bash
# pve-winrepair, pinned. Upgrade by raising PVE_WINREPAIR_VERSION.
set -euo pipefail
readonly PVE_WINREPAIR_VERSION="1.0.0"
exec uv tool run \
    --exclude-newer "7 days" \
    --exclude-newer-package pve-winrepair=false \
    --exclude-newer-package lib-layered-config=false \
    --exclude-newer-package lib-log-rich=false \
    --exclude-newer-package lib-cli-exit-tools=false \
    --from "pve-winrepair==${PVE_WINREPAIR_VERSION}" \
    pve-winrepair "$@"
```

With `--exclude-newer "7 days"` uv ignores every release younger than a week, transitive
dependencies included, so a hijacked release that gets pulled within that week never reaches the
node. A wheel carries no `[tool.uv]` settings, so the cooldown has to be on the command line. The
four packages exempted with `=false` come from the same author and are released together with this
one: a new pve-winrepair can need a library release from the same day, which the cooldown would
hold back.

A persistent install works too (`uv tool install --exclude-newer "7 days" pve-winrepair`);
[INSTALL.md](INSTALL.md) lists the other ways.

## Quick start

1. Write `/etc/pve-winrepair/config.toml` on the node. A minimal one:

   ```toml
   [ssh]
   key = "/root/.ssh/id_guest"     # the private key the node logs in to the guests with
   user = "admin"                  # an administrator account on the guest

   [guest]
   subnet = "192.0.2.0/24"         # the LAN the node reaches the guests on

   [repair]
   media_dir = "/var/lib/vz/winmedia/win11"   # holds setup.exe and sources\install.wim
   ```

2. Check what the tool reads: `pve-winrepair config`.
3. Repair the guest and wait for the verdict, which takes an hour or more:

   ```bash
   pve-winrepair repair --vmid 100
   ```

4. When it ends with `vm 100: STATE=DONE-OK`, apply the upgrade:

   ```bash
   pve-winrepair apply --vmid 100 --ip 192.0.2.10
   ```

   It ends with `vm 100: VERIFIED` once the new build is in place and Windows Update is released.

## CLI reference

Options given before the command apply to every command: `--version`, `--profile NAME`, `--set
SECTION.KEY=VALUE` (repeatable), `--env-file PATH`, `--traceback` / `--no-traceback`.

| Command                                  | What it does                                                                            |
|------------------------------------------|-----------------------------------------------------------------------------------------|
| `repair --vmid N`                        | vTPM, snapshot, stage the media, gate the WIM, launch setup and poll to a verdict       |
| `apply --vmid N --ip IP`                 | Reboot into the staged OS, verify the build against the receipt, release Windows Update |
| `guest-tool path`                        | Print the path of the packed guest tool this install pushes                             |
| `guest-tool sha256`                      | Print its sha256 and the content address it gets on a guest                             |
| `config`                                 | Show the merged configuration and where each value came from                            |
| `config-deploy --target app\|host\|user` | Write the defaults into a layer, winrepair keys commented out ([CONFIG.md](CONFIG.md))  |
| `config-generate-examples`               | Write lib_layered_config's example files for every layer location                       |
| `info`                                   | Print the package metadata                                                              |

`repair` options:

| Option              | Default                  | Meaning                                                                                             |
|---------------------|--------------------------|-----------------------------------------------------------------------------------------------------|
| `--vmid N`          | required                 | The guest's VMID on this node                                                                       |
| `--snapshot-name S` | `[repair] snapshot_name` | The snapshot to take; an existing snapshot of that name is reused                                   |
| `--hours H`         | `6.0`                    | How long to poll for the verdict; a finite number above 0                                           |
| `--stage-only`      | off                      | Stage the media and hold Windows Update, but neither gate the WIM nor launch setup (verdict STAGED) |
| `--ip IP`           | from the agent           | The guest's IPv4 address, for a guest without the QEMU agent; implies the powered-off snapshot      |
| `--stage-root X:`   | measured                 | The drive to stage on; by default a non-system fixed drive with room, else `C:`                     |
| `--tpm-storage S`   | the guest disk's storage | The PVE storage ID for a new vTPM volume                                                            |
| `--json`            | off                      | Print a JSON envelope on stdout                                                                     |

`apply` takes `--vmid N` and `--ip IP` (both required), `--apply-minutes M` (default `90.0`: how long
the apply phase may take before it counts as overrun; a finite number above 0) and `--json`. A value
these options refuse is a usage error (exit 2) before any call.

Both commands print each step on stderr as it happens. stdout carries only the result: one line
`vm <vmid>: <verdict>`, or with `--json` an envelope like this one:

```json
{"ok": false, "command": "apply", "vmid": 100, "verdict": "ERROR", "steps": [{"step": "error", "ok": false, "message": "...", "wu_held": true}]}
```

Exit codes of `repair` and `apply`:

| Code | Meaning                                                                                              |
|------|------------------------------------------------------------------------------------------------------|
| 0    | `repair`: STATE=DONE-OK or STAGED; `apply`: VERIFIED                                                 |
| 1    | Refused: a check said no, or the run ended STATE=DONE-FAIL, WORKER_GONE or TIMEOUT                   |
| 2    | Internal error (the node and the guest tool disagree); also a usage error on the command line        |
| 78   | The configuration does not load or a setting is invalid; one `Error: <section>.<key>: ...` line each |

The `config` commands have their own codes (22 for an unknown `--section`, 13 when `config-deploy`
may not write); [CONFIG.md](CONFIG.md) has them.

## Configuration

The settings live in `/etc/pve-winrepair/config.toml` on the node. [CONFIG.md](CONFIG.md) explains
every key, the other layers and the environment overrides.

| Key                              | Default                    | Meaning                                                |
|----------------------------------|----------------------------|--------------------------------------------------------|
| `[ssh] key`                      | `""` (required)            | Private key the node logs in to the guests with        |
| `[ssh] user`                     | `"Administrator"`          | Administrator account on the guest                     |
| `[ssh] strict_host_key_checking` | `true`                     | Refuse an unknown or changed guest host key            |
| `[ssh] known_hosts_file`         | `"~/.ssh/known_hosts"`     | known_hosts file for the guests                        |
| `[guest] subnet`                 | `""`                       | The LAN the guest's address is picked from (set it)    |
| `[guest] runner_tasks`           | `[]`                       | Values for the guest tool's `verify-runners --task`    |
| `[guest] expected_runners`       | `0`                        | Value for the guest tool's `verify-runners --expected` |
| `[repair] media_dir`             | `""` (required)            | Directory with the unpacked installation media         |
| `[repair] snapshot_name`         | `"pre_winrepair"`          | Snapshot taken before the repair                       |
| `[repair] stage_free_gb`         | `15.0`                     | Free GiB the staging drive needs                       |
| `[repair] system_free_gb`        | `25.0`                     | Free GiB `C:` needs                                    |
| `[node] state_dir`               | `"/var/lib/pve-winrepair"` | Where the repair receipts are kept                     |

Any key can be overridden for one run with `PVE_WINREPAIR___<SECTION>__<KEY>`. The usual case is a
guest that refuses the configured key:

```bash
PVE_WINREPAIR___SSH__KEY=/root/.ssh/id_other_guest pve-winrepair repair --vmid 100
```

## Guest tool

The work on the guest is done by one PowerShell file, `winrepair_guest.ps1`: Python sources packed
with [pwshpy](https://github.com/bitranox/pwshpy) and shipped inside the package. `pve-winrepair
guest-tool path` prints where it is, `pve-winrepair guest-tool sha256` its sha256 and its address
on a guest.

### How it gets onto the guest

On the guest the tool lives under a content address,
`C:\winrepair\winrepair_guest-<first 16 hex of its sha256>.ps1`. A push never overwrites a file of
that name. The same name means the same bytes, so a re-run cannot replace the file a live SYSTEM run
is executing, and a new version gets a new name beside the old one.

`C:\winrepair` is locked before the tool goes in, and the tool does the locking itself, so every push
runs in this order:

1. The node reads the security descriptor of the ssh user's profile directory, where ssh and scp
   start, and refuses unless only SYSTEM, Administrators and the ssh user can write it. Anyone else
   could swap the copy between its hash check and its run. Nothing is copied when this refuses.
2. scp copies the tool into the profile under its plain name. The guest hashes that copy
   (`certutil -hashfile <copy> SHA256`) and the node refuses unless it matches its own sha256.
3. That copy runs `lock-dirs`, which creates `C:\winrepair` with the lock already in place, or finds
   it exactly locked, and checks a tool already at the content address against its name.
4. Only when no tool is there yet, the profile copy is copied to `<content address>.part` inside the
   locked directory, renamed into place and hashed once more.
5. The profile copy is deleted, on every path. A delete that fails is reported (`staged_left` on the
   `push_tool` step) and does not fail the push.

After the apply reboot, `apply` does steps 1 and 2 only and runs the tool from the verified profile
copy: the upgrade may have changed the lock on `C:\winrepair`, and nothing runs as SYSTEM from it any
more. `apply` reports that lock as the informational `winrepair_lock` step and deletes the profile
copy at the end (`remove_profile_copy`).

### What is locked when

Whatever the SYSTEM task executes (the tool, setup.exe and everything setup.exe loads from the
staging directory) is locked to SYSTEM and Administrators before it is copied in, never after. A
directory created under a drive root is open to every local user, so a file copied in before the
lock could be replaced, or a DLL planted beside setup.exe, and no later lock could tell.

| When                                                 | What                                                                                              |
|------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| every push, before the tool is copied in             | `lock-dirs`, run from the profile copy, creates `C:\winrepair` locked                             |
| `repair`, after choosing the drive, before the media | `lock-dirs --stage-root X:\upgrade` creates the staging directory locked                          |
| `launch`                                             | verifies both locks and every entry below them; writes no DACL                                    |
| `apply`, after the reboot                            | `lock-dirs --no-create` reports the lock on `C:\winrepair` (`winrepair_lock`), runs nothing there |

`lock-dirs` creates an absent directory with the lock in the create call itself (a protected DACL:
SYSTEM and Administrators with full control, inherited below), so there is no moment in which a
local user could open it. An existing directory is never re-locked. It is reused when it is exactly
locked and nothing below it is owned or writable by a non-admin; otherwise it is refused with the
fix: remove it as an administrator (`rd /s /q <dir>`) and run again. A junction or other reparse
point, at the directory or anywhere below it, is refused too. `launch` checks all of that again
before it registers the task, plus the tool's bytes against its name.

### What a run leaves on the guest

- `C:\winrepair\winrepair_guest-<sha16>.ps1`, one per tool version pushed, and a `.part` beside one
  if a push was cut mid-copy (the next push of that version overwrites it).
- `C:\upgrade-state.log`, the upgrade run's state log, ending in `STATE=DONE-OK` or
  `STATE=DONE-FAIL`. Each launch replaces it.
- `X:\upgrade\`, the staged media, and `X:\upgrade-logs\`, where setup copies its logs.
- The pack wrapper's extraction cache `%LOCALAPPDATA%\pwshpy-pack\` for the ssh user and for SYSTEM,
  `uv` under `%USERPROFILE%\.local\bin\` if the wrapper installed it, and uv's cache and Python.
- The scheduled task `\OVMRepairUpgrade`, only when a run reports it was left behind; the step names
  the commands that remove it.

After a finished repair, remove `C:\winrepair`, `C:\upgrade-state.log` and the staging directories.

### Reading a run

- Every step has `step` and `ok`; the last one says how the run ended. When the guest tool crashed,
  the error step carries `guest_stderr`, the last lines of its traceback.
- `wu_held: true` on the last step means this run left Windows Update held: after a refusal, a crash,
  a poll ending STATE=DONE-FAIL, WORKER_GONE (setup's process went away and no verdict appeared) or
  TIMEOUT, or a `--stage-only` run (verdict STAGED, exit 0: its last step `staged` says so, since it
  writes no receipt and `apply` cannot follow it). [Safety and recovery](#safety-and-recovery) shows
  how to release it.
- A `guest_identity` step (runs with `--ip`, and `apply`) names the MACs the guest at that address
  shares with the VM's `qm config`; when it shares none, the run is refused before the VM is touched
  and the step lists both sides.
- `apply` refuses the reboot with RUN_LIVE (setup is still running), RUN_UNFINISHED (the run
  started, setup is gone and no verdict was written: it was cut off, check the guest), RUN_FAILED
  (`STATE=DONE-FAIL`) or NO_RUN (no state log). REVERTED_OR_UNCHANGED means the guest came back on
  a build other than the receipt's, or, for media of the build it already ran, with an unchanged
  InstallDate: setup rolled back, or the apply was cut off. Windows Update stays held.
- The `restore_wu` step passes on the verified start types alone. Its `search` field reports a
  bounded Windows Update search and is informational. TIMEOUT means the search was abandoned after
  180 s, which is normal on the first boot after the apply while servicing runs; run `restore-wu`
  again later to list the pending updates.
- `detect-lp-defect` right after a repair reads UNKNOWN: setup starts a fresh, empty log, which
  proves nothing either way. The proof of a repair is the next cumulative update installing.

### The repair receipt

`repair` records the build of the staged image in `<state_dir>/receipt-<vmid>.json`
(`/var/lib/pve-winrepair/receipt-100.json` for VM 100 with the default `state_dir`), after the WIM
gate and before it launches setup, together with the build and InstallDate the guest ran then
(`build_before`, `install_date_before`). `apply` reads it before it touches the guest, refuses to
run without one or with one that lacks a field, and accepts only that build; for same-build media
it also requires a changed InstallDate. That an in-place upgrade always rewrites InstallDate is
not yet measured on a real upgrade: should it not, every same-build repair ends
REVERTED_OR_UNCHANGED and its Windows Update hold has to be released by hand. A repair removes the VM's previous receipt once it is sure
no run is live, so a run that stops before the WIM gate, or a `--stage-only` run, leaves none. The
file is replaced atomically and only its owner can read it (0600, in a 0700 directory when
`pve-winrepair` creates the directory).

## Guest tool subcommands

Every subcommand prints one JSON envelope `{"ok", "command", "data", "skipped"}` and exits 0 (ok),
1 (refused: its own gate said no, or it could not decide) or 2 (internal error, still with an
envelope). The drivers call them; an operator can run one by hand on the guest, as an elevated
admin:

```
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\winrepair\winrepair_guest-<sha16>.ps1 detect-lp-defect --json
```

| Subcommand                                                      | What it answers                                                                                                                                                                   | Exit 1 when                   |
|-----------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------|
| `detect-lp-defect`                                              | is this guest affected by the orphaned language pack: AFFECTED, CLEAN or UNKNOWN                                                                                                  | UNKNOWN                       |
| `drives`                                                        | free bytes per fixed drive (an unparsable volume is skipped)                                                                                                                      | never (2 when no drive reads) |
| `verify-runners [--task NAME]... [--expected N]`                | did the runner containers and their boot tasks come back after a reboot: OK, SHORT or UNKNOWN; bare (no `--task`, `--expected 0`) it checks no task and accepts any count         | SHORT or UNKNOWN              |
| `build`                                                         | CurrentBuild, UBR and InstallDate (epoch seconds; an in-place upgrade writes it anew)                                                                                             | never                         |
| `staged-os`                                                     | is the staged NewOS still there: REARMABLE (apply) or RERUN (a rollback deleted it)                                                                                               | never (2 when it cannot look) |
| `servicing-active`                                              | are TiWorker / TrustedInstaller running                                                                                                                                           | never                         |
| `setup-alive`                                                   | is SetupHost running                                                                                                                                                              | never                         |
| `state [--log PATH]`                                            | the upgrade state log and its last `STATE=DONE-OK` / `STATE=DONE-FAIL` marker                                                                                                     | never                         |
| `nic-macs`                                                      | the MAC address of every network adapter, `AA:BB:CC:DD:EE:FF`, sorted (an adapter without one is skipped)                                                                         | never (2 when no MAC reads)   |
| `quiesce-wu`                                                    | hold Windows Update (Start=4, issue stops, bounded wait) and verify: OK, FAIL or UNKNOWN                                                                                          | FAIL or UNKNOWN               |
| `restore-wu`                                                    | restore the start types and verify: RESTORED, STILL_DISABLED or UNKNOWN; plus a bounded search probe                                                                              | STILL_DISABLED or UNKNOWN     |
| `prepare --stage-root X:\upgrade`                               | clear read-only, gate on the WIM, write the compat waiver: PASS or FAIL                                                                                                           | FAIL                          |
| `lock-dirs --tool PATH [--stage-root X:\upgrade] [--no-create]` | create `C:\winrepair` (and the stage root) already locked, before anything is copied in; with `--no-create` an absent one is reported ABSENT and nothing is created: OK or FAILED | FAILED                        |
| `launch --stage-root X:\upgrade --tool PATH [--state-log]`      | verify the locks, then upgrade-run as a SYSTEM task: OK, SUSPECT, NO_START, FAILED, TASK_LEFT                                                                                     | anything but OK               |
| `upgrade-run --stage-root X:\upgrade [--state-log]`             | the SYSTEM task's command: setup.exe, the state log, the marker: DONE-OK or DONE-FAIL                                                                                             | DONE-FAIL                     |

## Safety and recovery

### The snapshot and rolling back

`repair` takes the snapshot `[repair] snapshot_name` before the media are staged or setup runs, and
never deletes it. An existing snapshot of that name is reused, not replaced. On a running guest with
the agent, the Windows Update hold and a needed vTPM come before the snapshot, so the snapshot
already contains both; the tool may already sit in `C:\winrepair` too, because the live-run check
that comes first runs it.

If the repaired guest is worse off, roll back on the node with `qm rollback <vmid> pre_winrepair`.
A snapshot taken after the hold brings back a guest with Windows Update still held, so release it as
described below. Delete the snapshot (`qm delsnapshot <vmid> pre_winrepair`) once the guest has
installed its next cumulative update.

### Windows Update stays held until the build is verified

Only a successful `apply` releases the hold. A start type left Disabled stops the machine from ever
patching again, so release the hold by hand when you abandon a repair, and after a `--stage-only`
run unless a full `repair` and `apply` follow. Every step that leaves it held says how:

> Windows Update is still held - to lift it if this repair is abandoned, copy the guest tool
> (`pve-winrepair guest-tool path`) to the ssh user's profile, check that certutil -hashfile
> \<copy\> SHA256 on the guest matches `pve-winrepair guest-tool sha256`, and run restore-wu from
> that copy, never from a C:\winrepair that lock-dirs refused

From the node, for example:

```bash
scp -i /root/.ssh/id_guest "$(pve-winrepair guest-tool path)" admin@192.0.2.10:winrepair_guest.ps1
ssh -i /root/.ssh/id_guest admin@192.0.2.10 certutil -hashfile winrepair_guest.ps1 SHA256
pve-winrepair guest-tool sha256
ssh -i /root/.ssh/id_guest admin@192.0.2.10 powershell.exe -NoProfile -ExecutionPolicy Bypass -File winrepair_guest.ps1 restore-wu --json
```

Run the last command only when the two hashes match, and delete the copy afterwards.

### A live setup is never interrupted

Both commands refuse a guest whose upgrade run is still live. On a running guest with the agent,
`repair` waits up to 20 minutes for running servicing to finish before anything stops the guest, and
its `servicing_idle` step says so when it gave up.

## Development

```bash
make test           # the full local gate: ruff, pyright, import-linter, bandit, pip-audit, pytest
make custom pack    # repack the guest tool after any change under src/pve_winrepair_guest/
```

The packed `src/pve_winrepair/adapters/guest_tool/winrepair_guest.ps1` is committed, and a test
fails when it is not a fresh pack of the current guest sources.

A privacy gate (`tests/test_privacy_gate.py`) keeps site data out of the public tree. Its generic
patterns always run. The exact names of a site come from a token list that is never committed:
`.privacy-tokens.json` at the checkout root (gitignored), or the file named by
`PVE_WINREPAIR_PRIVACY_TOKENS_FILE`. Without a list those tests skip, which is expected in CI.

More in [DEVELOPMENT.md](DEVELOPMENT.md) and the
[module reference](docs/systemdesign/module_reference.md).

## Further documentation

- [Configuration](CONFIG.md)
- [Install guide](INSTALL.md)
- [Preparing a Windows guest for SSH key access](docs/windows-guest-ssh.md)
- [Development handbook](DEVELOPMENT.md)
- [Contributor guide](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Module reference](docs/systemdesign/module_reference.md)
- [License](LICENSE)
