# Preparing a Windows guest for SSH key access

`pve-winrepair` reaches every guest over ssh, logging in with the key in `[ssh] key` as an
administrator: from the Proxmox node when it runs there, or from a workstation through the node.
So before the first `repair`, the guest needs a running OpenSSH server and that key's public half
in the place sshd looks for an administrator's key. This page sets that up on Windows 10,
Windows 11 and Windows Server 2019 or newer.

Run every guest command below in Windows PowerShell 5.1, started with "Run as administrator".

## 1. Install and start the OpenSSH server

See whether the server is installed:

```powershell
Get-WindowsCapability -Online -Name OpenSSH.Server*
Get-Service sshd
```

Check both. `Get-WindowsCapability` reports only the Windows feature. A server installed from the
Win32-OpenSSH MSI shows `State : NotPresent` there while `Get-Service sshd` lists it as running, so
the capability state alone does not tell you sshd is missing. If `Get-Service sshd` finds no
service, install the feature:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```

This downloads the feature from Windows Update. On a guest that cannot reach Windows Update (offline,
or a WSUS server that does not offer Features on Demand), install it from the Features on Demand
media of the guest's build, or install the MSI from the
[Win32-OpenSSH releases](https://github.com/PowerShell/Win32-OpenSSH/releases) on GitHub. This page
does not walk through either.

Start the service and make it start at boot:

```powershell
Set-Service sshd -StartupType Automatic
Start-Service sshd
Get-Service sshd
```

The last line should read `Running`.

The capability install creates an inbound firewall rule named `OpenSSH-Server-In-TCP` for TCP port
22. An MSI install, or an administrator, may have created one under another name, so look for a
rule by port rather than only by name:

```powershell
Get-NetFirewallPortFilter -Protocol TCP | Where-Object LocalPort -eq 22 | Get-NetFirewallRule |
    Format-Table Name, DisplayName, Enabled, Direction, Action
```

You need an inbound rule that is `Enabled True` with action `Allow`. If none exists, create the one
the capability would have created:

```powershell
New-NetFirewallRule -Name OpenSSH-Server-In-TCP -DisplayName 'OpenSSH Server (sshd)' `
    -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

If a rule exists but is disabled, enable it by its name (`Enable-NetFirewallRule -Name <name>`).

## 2. Put the public key on the guest

pve-winrepair logs in as `[ssh] user`, which is `Administrator` by default and must be a member of
the local Administrators group: the repair runs elevated work on the guest.

For a member of Administrators, sshd does not read the key from the user's own
`C:\Users\<user>\.ssh\authorized_keys`. The default `C:\ProgramData\ssh\sshd_config` ends with this
block, which sends every administrator to one shared file:

```text
Match Group administrators
       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
```

The group name in that block is written in English and still applies on a localised Windows, where
the group itself is called something else. Keep the block as it is.

Add the public key (the `.pub` file next to the private key in `[ssh] key`, one line that
starts with `ssh-ed25519` or `ssh-rsa`) to `C:\ProgramData\ssh\administrators_authorized_keys`,
one key per line. If the file already exists, its last line must end with a line break, or the new
key is glued onto that line and both keys break (some editors save a file whose last line has no
line break); read it back afterwards with `Get-Content $keys` and look for one key per line. Paste the whole line between
the single quotes:

```powershell
$keys = "$env:ProgramData\ssh\administrators_authorized_keys"
Add-Content -Path $keys -Value 'ssh-ed25519 AAAA... root@node' -Encoding ascii
```

Write the file as plain ASCII, as this command does. In Windows PowerShell 5.1, `>`, `>>` and
`Out-File` write UTF-16 (the file starts with the bytes `FF FE`), and `Set-Content -Encoding utf8`
puts a byte order mark (`EF BB BF`) in front of the first line. sshd may then not match the key,
and the login fails with "Permission denied (publickey)". `-Encoding ascii` does not fix a file that
is already UTF-16: `Add-Content` keeps appending in the encoding the file already has. Check the
first bytes:

```powershell
([IO.File]::ReadAllBytes($keys) | Select-Object -First 3 | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
```

Anything but `FF FE` or `EF BB BF` is fine: `73 73 68` is the text `ssh`, and a first line holding
another key type or a `#` comment starts with other bytes. If you see `FF FE` or `EF BB BF`, write
the file again in ASCII: `Set-Content -Path $keys -Value (Get-Content $keys) -Encoding ascii`.

The first bytes say nothing about lines appended later with `>>`, which can be UTF-16 in a file
that starts in ASCII. A UTF-16 line holds zero bytes, so this should print `False`:

```powershell
[IO.File]::ReadAllBytes($keys) -contains 0
```

sshd ignores that file unless only SYSTEM and the Administrators group have access to it. Remove
the inherited entries and grant both full control by SID:

```powershell
$keys = "$env:ProgramData\ssh\administrators_authorized_keys"
icacls.exe $keys /inheritance:r /grant '*S-1-5-18:F' /grant '*S-1-5-32-544:F'
"icacls exit code: $LASTEXITCODE"
```

The first line sets `$keys` again, so the block also works in a new PowerShell window: run with an
empty `$keys`, icacls would only print its usage and a non-zero exit code.

`S-1-5-18` is SYSTEM and `S-1-5-32-544` is Administrators. Grant by SID, never by group name: on a
German Windows the group is `Administratoren`, a grant to `Administrators` fails with exit code 1332
(no mapping between account names and security IDs), and icacls changes nothing. That is why the
exit code is printed; anything other than 0 means the ACL was not set.

Read the ACL back:

```powershell
icacls.exe $keys
(Get-Acl -LiteralPath $keys).Sddl
```

icacls should list exactly two entries, SYSTEM and Administrators, each `(F)`, in the guest's own
language. The SDDL should look like `O:BAG:...D:PAI(A;;FA;;;SY)(A;;FA;;;BA)`: the `P` means
inheritance is off, and the only ACEs are for `SY` (SYSTEM) and `BA` (Administrators).

A user who is not an administrator keeps their key in their own `C:\Users\<user>\.ssh\authorized_keys`.
pve-winrepair cannot use such an account.

## 3. Check the login from the node

The machine that runs pve-winrepair keeps the guests' host keys in `[ssh] known_hosts_file` and,
with the default `strict_host_key_checking = true`, refuses a guest whose key is not in that file
yet. Record the key once, with the same file and the same address pve-winrepair will use (the
address the QEMU guest agent reports, or the one you pass with `--ip`).

On the guest, print its host key fingerprint:

```powershell
ssh-keygen -l -f "$env:ProgramData\ssh\ssh_host_ed25519_key.pub"
```

On the node, log in once and let ssh add the key, then compare what it stored with the guest's
fingerprint. When pve-winrepair runs on a workstation, do this on the workstation through the node,
as [From a workstation](../README.md#from-a-workstation) shows:

```bash
ssh -i /root/.ssh/id_guest -o BatchMode=yes -o PreferredAuthentications=publickey \
    -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new \
    -o UserKnownHostsFile=~/.ssh/known_hosts Administrator@192.0.2.10 whoami
ssh-keygen -l -F 192.0.2.10 -f ~/.ssh/known_hosts
```

`~/.ssh/known_hosts` is the default `[ssh] known_hosts_file`. Use your own key path, user and guest
address, and if you set `known_hosts_file` to another file, use that file in both commands:
pve-winrepair looks for the key nowhere else. `whoami` prints the account as
`<computer>\administrator`; a password prompt cannot appear, because `BatchMode=yes` turns it into a
failure.

The key is compared after the login that stored it. That login sends the guest nothing secret: a
key login proves the key without handing it over. So comparing afterwards is safe as long as you do
it before pve-winrepair, or any other login, relies on the stored key. If the two fingerprints
differ, remove the entry (`ssh-keygen -R 192.0.2.10 -f ~/.ssh/known_hosts`) and find out why before
going on.

The settings that have to match what you just did, all in `[ssh]` (details in
[CONFIG.md](../CONFIG.md#ssh)):

- `key`: the private key the tool logs in with, a file on the machine it runs on. Required.
- `user`: the administrator account, `Administrator` by default.
- `known_hosts_file`: the file the host key went into above.
- `strict_host_key_checking`: keep it `true`.

One guest that refuses the configured key can be reached with another key for one run, without
changing the file:

```bash
PVE_WINREPAIR___SSH__KEY=/root/.ssh/id_other_guest pve-winrepair repair --vmid 100
```

## 4. Turn off password logins

Do this only after the key login in step 3 works. Then a password guess against sshd gets nowhere.
In `C:\ProgramData\ssh\sshd_config`, set:

```text
PasswordAuthentication no
```

The shipped file has this line commented out as `#PasswordAuthentication yes`. Remove the `#` and
change the value. The setting has to come before the `Match Group administrators` block, which
applies to every line after it. Then restart sshd so it reads the file again:

```powershell
Restart-Service sshd
Get-Service sshd
```

The last line should read `Running`: a typing error in `sshd_config` can keep sshd from starting.
Then repeat the key login from step 3.

Do not set a different default shell for sshd (the `DefaultShell` value under
`HKLM:\SOFTWARE\OpenSSH`). pve-winrepair needs `cmd.exe`, the Windows default; see
[Troubleshooting](#the-default-shell-must-stay-cmdexe).

## Troubleshooting

### "Permission denied (publickey)"

sshd did not accept the key. Usual causes:

- The key is in the wrong file. For an administrator it must be in
  `C:\ProgramData\ssh\administrators_authorized_keys`; a key in the user's own `.ssh\authorized_keys`
  is never read.
- The ACL of `administrators_authorized_keys` grants something besides SYSTEM and Administrators
  (an inherited `Users` or `Authenticated Users` entry, for example), and sshd ignores the file.
  Read it back as in step 2.
- The user is wrong: `[ssh] user` names an account that is not in the Administrators group, or not
  the one whose key you installed.
- The key file is UTF-16 or starts with a byte order mark, which sshd may not read. That happens
  when it was written with `>`, `>>`, `Out-File` or `Set-Content -Encoding utf8` in Windows
  PowerShell 5.1. Check its bytes and write it again in ASCII, as in step 2.
- The key file holds a broken line: a line wrapped by an editor, two keys glued onto one line, or a
  private key pasted in place of the public one.

Microsoft's OpenSSH documentation places sshd's log in the Windows event log under Applications and
Services Logs, OpenSSH, Operational; the reason for a refused key should be there.

### The default shell must stay cmd.exe

pve-winrepair sends its guest commands for `cmd.exe` to run. It names PowerShell and certutil by
`%SystemRoot%\System32\...` paths, which only `cmd.exe` expands, and it deletes its staged copy with
`del`, a `cmd.exe` built-in. Its argument checks also assume `cmd.exe` quoting. If sshd's
`DefaultShell` is set to PowerShell or another shell, every guest call fails. From how those
commands are built, expect an error about a path starting `%SystemRoot%` that is not found, since
PowerShell does not expand that form.

Check that no default shell is set (no output means `cmd.exe`):

```powershell
Get-ItemProperty -Path HKLM:\SOFTWARE\OpenSSH -Name DefaultShell -ErrorAction SilentlyContinue
```

To go back to `cmd.exe`, remove the value and restart sshd:

```powershell
Remove-ItemProperty -Path HKLM:\SOFTWARE\OpenSSH -Name DefaultShell
Restart-Service sshd
```

### "the ssh user's profile ... can be written by others"

Before it copies the guest tool, pve-winrepair reads the security descriptor of the ssh user's
profile directory (where ssh and scp start) and refuses unless only SYSTEM, Administrators and the
ssh user can write it. Anyone else could swap the copy between its hash check and its run, so
nothing is copied. The refusal names each principal that may write and the rights it holds, for
example:

```text
the ssh user's profile C:\Users\Administrator can be written by others, so a copy placed there
could be swapped before it runs: BU may write: allow 0x120116 (flags OICI) - fix the profile's
ACL (only SYSTEM, Administrators and the ssh user may write it); nothing was copied
```

The principal is written as a SID or a two-letter SDDL alias: `BU` is the Users group, `AU`
Authenticated Users, `WD` Everyone. To see the same descriptor, log in as the ssh user and run:

```powershell
(Get-Acl -LiteralPath $env:USERPROFILE).Sddl
```

A healthy profile reads like `O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-21-...)`,
with full control for `SY`, `BA` and the user's own SID only. For the built-in Administrator account
the user's entries read `LA` instead of a SID, and `CO` (CREATOR OWNER) is accepted too. A read-only
entry such as `(A;;0x100020;;;S-1-15-3-...)` is fine: it carries no write right.

Remove the entry the refusal names with `icacls`, by SID as in step 2. For `BU` (the Users group,
`S-1-5-32-545`):

```powershell
icacls.exe $env:USERPROFILE /remove:g '*S-1-5-32-545'
"icacls exit code: $LASTEXITCODE"
```

`/remove` removes only an entry set on the profile itself. One the profile inherits from
`C:\Users` (marked `(I)` in icacls' listing, `ID` among the entry's flags in the SDDL) stays, and
icacls still exits 0; run `icacls.exe $env:USERPROFILE /inheritance:d` first, which turns the
inherited entries into the profile's own, and the `/remove` above then takes it out. Read the
descriptor back afterwards: the exit code does not show whether anything was removed. The
full rules are in [README.md](../README.md#how-it-gets-onto-the-guest).

## Microsoft documentation

- [Get started with OpenSSH Server for Windows](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse)
- [Key-based authentication in OpenSSH for Windows](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement)
- [OpenSSH Server configuration for Windows](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration)
