# Getting the right installation media

`repair` runs setup.exe from a directory of Windows installation media, unpacked as on the ISO, so
that `setup.exe` and `sources\install.wim` sit at its top level (`[repair] media_dir` on the node,
or `local_media_dir` with `--media local`). Setup keeps the applications, settings and data only
when the media fit the guest, and the tool itself refuses media whose build is older than the
guest's. This page shows how to read what the guest needs, where Microsoft publishes the matching
media, and how to put them on the node.

## 1. What the media must match

| Property     | Must be                                            | If it is not                                         |
|--------------|----------------------------------------------------|------------------------------------------------------|
| Edition      | the guest's `EditionID` among the WIM's images     | setup offers no upgrade that keeps applications      |
| Language     | the guest's install language                       | setup offers no upgrade that keeps applications      |
| Architecture | x64 media for an `AMD64` guest, Arm64 for `ARM64`  | setup cannot upgrade it                              |
| Build        | image 1's build and servicing build >= the guest's | the tool's WIM gate refuses before it launches setup |
| Image format | `sources\install.wim`, not `sources\install.esd`   | the WIM gate refuses: `install.wim missing`          |

The WIM gate reads image 1 only. On Microsoft's multi-edition ISOs every image carries the same
build, so image 1 stands for all of them. If you build your own `install.wim` (section 6), make the
guest's edition image 1.

## 2. Read the guest's values

Over ssh from the node, with the login the tool uses (`cmd.exe` is the guest's ssh shell):

```bash
ssh -i ~/.ssh/id_guest admin@192.0.2.10 'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v EditionID & reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuild & reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v UBR & reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v DisplayVersion & reg query HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language /v InstallLanguage & echo %PROCESSOR_ARCHITECTURE%'
```

The answer looks like this:

```text
    EditionID    REG_SZ    Professional
    CurrentBuild    REG_SZ    26200
    UBR    REG_DWORD    0x1f5b
    DisplayVersion    REG_SZ    25H2
    InstallLanguage    REG_SZ    0407
AMD64
```

- `EditionID` is the edition: `Core` is Home, `Professional` is Pro, an `N` suffix is the N
  edition (`ProfessionalN`).
- `CurrentBuild` and `UBR` are the build the WIM gate compares against. `reg` prints `UBR` in hex:
  `0x1f5b` is 8027, so this guest runs 26200.8027.
- `InstallLanguage` is the language Windows was installed in, as a hex LCID: `0407` is German,
  `0409` English (United States), `0809` English (United Kingdom). A display language added later
  does not change it, and the media must match this one, not the display language.

These are registry values, so the commands read the same on a guest of any display language.

## 3. Where Microsoft publishes the media

| Guest                                                                                      | Source                                                                                                                               |
|--------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| Windows 11 Home, Pro, Education, Pro Education, Pro for Workstations, and their N editions | [Download Windows 11](https://www.microsoft.com/software-download/windows11), "Download Windows 11 Disk Image (ISO) for x64 devices" |
| Windows 10 Home, Pro and their N editions                                                  | [Download Windows 10 Disc Image (ISO File)](https://www.microsoft.com/software-download/windows10ISO), version 22H2                  |
| Enterprise, Enterprise LTSC, IoT Enterprise                                                | the licensing portal of your agreement: the Microsoft 365 admin center (volume licensing downloads) or Visual Studio subscriptions   |

- Take the ISO from the "Disk Image (ISO)" section. The Media Creation Tool writes an ISO whose
  `sources` folder holds `install.esd` instead of `install.wim`, which the WIM gate refuses.
- The Windows 11 and Windows 10 ISOs are multi-edition: one ISO per language holds every edition its
  row names, but not Home Single Language (`CoreSingleLanguage`). Section 5 lists what a given ISO
  holds.
- Pick the ISO language that matches `InstallLanguage`. "English International" is English (United
  Kingdom), not English (United States).
- The download link Microsoft generates is valid for 24 hours. The page lists a SHA-256 hash per
  language; compare it before you use the file.
- If the Windows 10 page offers only the Media Creation Tool, open it from a Linux or macOS browser:
  Microsoft shows the ISO download to browsers that do not run on Windows.
- The Evaluation Center's images install evaluation editions (`ServerStandardEval`, for example),
  which do not match a licensed guest. Do not use them to repair one.

## 4. Download, verify and unpack on the node

Generate the download link in a browser, then fetch the ISO on the node with it. Quote the link: it
carries `&` characters.

```bash
cd /var/lib/vz/template/iso
curl -fL -o Win11_German_x64.iso 'https://software.download.prss.microsoft.com/...'
sha256sum Win11_German_x64.iso      # compare with the hash on Microsoft's page
```

Unpack it into the media directory. Mount the ISO read-only and copy its content; no extra
software is needed on the node:

```bash
mkdir -p /var/lib/vz/winmedia/win11
iso_mnt=$(mktemp -d)
mount -o loop,ro /var/lib/vz/template/iso/Win11_German_x64.iso "$iso_mnt"
cp -a "$iso_mnt"/. /var/lib/vz/winmedia/win11/
umount "$iso_mnt" && rmdir "$iso_mnt"
chmod -R u+w /var/lib/vz/winmedia/win11      # the ISO's files are read-only
ls /var/lib/vz/winmedia/win11/setup.exe /var/lib/vz/winmedia/win11/sources/install.wim
```

Keep one directory per language and version, and point `[repair] media_dir` (or `--set
repair.media_dir=...` for one run) at the one that fits the guest. For `--media local`, unpack the
same way on the workstation into `[repair] local_media_dir`.

## 5. Check the media against the guest before staging

Copying the media into the guest takes a while, and the WIM gate only reads them after that. Look
at image 1 first, on any Windows machine:

```bat
dism /Get-WimInfo /WimFile:D:\winmedia\win11\sources\install.wim /Index:1
```

The build in `Version` (`10.0.26200` reads as 26200) and `ServicePack Build` must be at least the
guest's `CurrentBuild` and `UBR`. Run it again without `/Index` to list the editions, then with the
guest's index to see its `Languages`.
On Linux, `wiminfo install.wim 1` from wimtools (wimlib) reports the same fields; install it on a
workstation, not on the Proxmox node.

## 6. When the media are older than the guest

Microsoft refreshes the public ISOs only now and then, so a guest that still installs some updates
often runs a newer servicing build than the ISO, and the WIM gate refuses it. Two ways out:

- Media from your licensing portal, if it offers a later refresh of the same version. Check its
  build with section 5.
- Bring the ISO's image up to the guest's build: put the guest's edition into a WIM of its own and
  add the current cumulative update to it, on a Windows machine with DISM, as an administrator.
  Download the update's `.msu` from the [Microsoft Update Catalog](https://www.catalog.update.microsoft.com/);
  for Windows 11 24H2 (build 26100) and later the catalog may list a checkpoint update beside it. Put both into
  the same folder, where DISM finds the checkpoint.

```bat
dism /Get-WimInfo /WimFile:D:\winmedia\win11\sources\install.wim
dism /Export-Image /SourceImageFile:D:\winmedia\win11\sources\install.wim /SourceIndex:5 /DestinationImageFile:C:\work\install.wim
mkdir C:\work\mount
dism /Mount-Image /ImageFile:C:\work\install.wim /Index:1 /MountDir:C:\work\mount
dism /Image:C:\work\mount /Add-Package /PackagePath:C:\work\cu\windows11.0-kb0000000-x64.msu
dism /Unmount-Image /MountDir:C:\work\mount /Commit
dism /Get-WimInfo /WimFile:C:\work\install.wim /Index:1
```

Use the index the first command lists for the guest's edition (`5` here). The exported WIM holds
that edition alone, as image 1, which is the image the WIM gate reads. Check that the last command
shows a `ServicePack Build` at least the guest's `UBR`, then replace `sources\install.wim` in the media directory with
`C:\work\install.wim`. If `/Add-Package` fails, run `dism /Unmount-Image /MountDir:C:\work\mount
/Discard` before you try again.
