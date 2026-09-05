# LinuxLocker — universal in-place LUKS2 disk encryption for Linux

[![CI](https://github.com/doug445/LinuxLocker/actions/workflows/lint.yml/badge.svg)](https://github.com/doug445/LinuxLocker/actions/workflows/lint.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform: x86_64 | aarch64](https://img.shields.io/badge/platform-x86__64%20%7C%20aarch64-lightgrey.svg)](#requirements)
[![KDF: argon2id](https://img.shields.io/badge/KDF-argon2id-blue.svg)](#kdf-profiles--argon2id-only)
[![Boot: GRUB | systemd-boot | UKI](https://img.shields.io/badge/boot-GRUB%20%7C%20systemd--boot%20%7C%20UKI-informational.svg)](docs/BOOTLOADERS.md)

Add **full-disk encryption (FDE) to a Linux install you already have.**
LinuxLocker encrypts the root filesystem of an already-installed system in
place — without reinstalling, and without a second copy of your data. One
tool, any distro family it can chroot into, x86_64 and ARM alike: Fedora,
RHEL, Rocky, AlmaLinux, Debian, Ubuntu, Linux Mint, Pop!_OS, Raspberry Pi OS,
Arch, Manjaro, EndeavourOS and openSUSE. Converts LUKS1 to a LUKS2 container. 

> ### ⚠️ Running Fedora Asahi Remix, or any Linux on Apple Silicon (M1/M2/M3/M4)?
>
> **Use [AsahiLocker](https://github.com/doug445/AsahiLocker) instead — not this
> tool.** Same job, with the Fedora Asahi Remix boot guards LinuxLocker
> deliberately drops. Apple Silicon boots iBoot → m1n1 → U-Boot → GRUB, and its
> stub partitions are read by the Apple firmware itself; nothing here
> understands that chain.
>
> You do not have to remember this. `linuxlocker.sh` and `luks-deploy.sh` both
> detect Fedora Asahi Remix — from `VARIANT_ID`, an Asahi kernel, m1n1 boot
> components, or an Apple Silicon device tree — and **exit before touching any
> device**, with a link to AsahiLocker. The check runs against the live
> environment *and* against the partition you select, because an Asahi disk can
> be read from another machine.

`luks-deploy.sh` converts your existing root (or data) partition into a LUKS2
container holding that same filesystem. Your files and the filesystem UUID
survive; the partition simply gains an encryption layer. It then rewrites every
piece of boot configuration that has to change — `crypttab`, `fstab`, GRUB
defaults and their `grub.d` drop-ins, BLS and systemd-boot entries wherever
the ESP is, `/etc/kernel/cmdline` and `cmdline.d`, `cmdline.txt`,
`extlinux.conf`, `refind_linux.conf`, `limine.conf`, initramfs generator
config, **all** initramfs images — and refuses to let you reboot until a full
verification gate passes. A `root=PARTUUID=` or `root=/dev/…` that names the
raw partition is rewritten to the mapper in every one of those.

`/boot` stays unencrypted, and that is a design decision, not a gap: a target
whose `/boot` lives on the root filesystem under GRUB is refused before
anything is touched, and a volume that GRUB *already* unlocks (an existing
encrypted `/boot`) is recognised and offered only what GRUB can take — see
[Why is `/boot` left unencrypted?](#why-is-boot-left-unencrypted).

The front door, `linuxlocker.sh`, first **identifies the live environment's OS
and package manager**, installs any tools the run needs, and only then hands
off to the encrypter — which resolves filesystem-specific tools the moment it
knows what the target actually uses.

> **This is destructive-by-nature tooling.** It rewrites a live root
> filesystem. Read [`docs/INSTALL.md`](docs/INSTALL.md) before running
> anything, and have a verified backup. See [Risks](#risks--read-this).

---

## Quick start

```bash
# 1. On the installed system: get the kit onto a USB drive
git clone https://github.com/doug445/LinuxLocker.git

# 2. Boot ANY live Linux for your machine (the target distro's own live ISO
#    is the safest choice) with that USB plugged in.

# 3. From the live environment:
sudo ./LinuxLocker/bin/linuxlocker.sh          # detects OS, installs deps,
                                               # runs the encrypter

# 4. Reboot, enter your passphrase, then finish up on the encrypted system:
sudo ./LinuxLocker/bin/post-encryption-setup.sh
```

The deploy script auto-detects your disk layout, target OS, filesystem and
boot machinery, and shows you what it found. You confirm the selection, type
`ENCRYPT`, and choose a passphrase. Everything after that is automated,
including recovery if a step fails partway.

`--dry-run` runs the entire read-only half — detection, cross-checks, KDF
benchmark, the exact `cryptsetup` command it would issue — and exits before
the point of no return.

---

## Supported systems

Behaviour is keyed off what is **actually installed on the target**, never off
the distro's name — so derivatives inherit support from their family.

| Family | Package manager | Initramfs | Boot config handled |
|---|---|---|---|
| Fedora / RHEL / Rocky / Alma | dnf / yum | dracut | GRUB defaults, **BLS entries** (grubby or direct patch), `/etc/kernel/cmdline`, `rd.luks.*` args |
| Debian / Ubuntu / Mint / Pop!_OS | apt | initramfs-tools | `crypttab` with `initramfs` flag, `update-grub` (installs `cryptsetup-initramfs` in the chroot if missing) |
| Raspberry Pi OS | apt | initramfs-tools | `cmdline.txt` `root=` rewrite, `auto_initramfs=1`, crypttab-driven unlock |
| Arch / Manjaro / EndeavourOS | pacman | mkinitcpio | `HOOKS` gets `encrypt` (busybox) or `sd-encrypt` (systemd), `cryptdevice=`/`rd.luks.*` args, grub-mkconfig |
| openSUSE | zypper | dracut | GRUB defaults + grub2-mkconfig, `rd.luks.*` args |
| ARM boards with U-Boot distro-boot | — | any of the above | `extlinux.conf` `APPEND` rewrite |

Alpine, Void and Gentoo are recognised by the dependency installer; their boot
stacks are handled to the extent they use the machinery above.

### systemd-boot, Unified Kernel Images and Secure Boot

Handled as of **1.2.0**, having previously been refused outright.

| Boot stack | What happens |
|---|---|
| **systemd-boot**, Type #1 entries | Detected from the loader binary on the ESP, not guessed from `/boot/loader/entries`. Entries are patched; check V13 confirms something bootable points at the encrypted root. Works with the ESP at `/efi`, `/boot/efi` or `/boot`, with or without a separate XBOOTLDR partition. |
| **Unified Kernel Image** (`EFI/Linux/*.efi`) | The `.efi` is **rebuilt** with the post-encryption kernel command line, using whichever backend the target actually uses: an `mkinitcpio` preset with `_uki=`, `kernel-install` with `layout=uki`, `dracut --uki-file`, or `ukify`. Check V11 reads the rebuilt `.cmdline` section back and fails the run if the LUKS arguments are not in it. |
| **Secure Boot** + UKI | The rebuilt `.efi` is **re-signed** with `sbctl` or `sbsign`. Check V12 fails the run if Secure Boot is enabled and any UKI came out unsigned. |
| **Secure Boot**, no UKI (shim + GRUB, shim + systemd-boot) | No interaction. The initramfs is not part of the verified chain, and nothing here touches shim, the bootloader binary or `vmlinuz`. |

Signing has to be explicit, because distro automation does not fire from a
chroot: Arch's `zz-sbctl.hook` is a **libalpm** hook, so `mkinitcpio -P` run by
hand rebuilds the UKI and leaves it unsigned — which a Secure Boot machine then
refuses to load. LinuxLocker signs it itself and verifies the signature before
allowing the reboot.

A UKI target is still **refused before the shrink** in two cases: no rebuild
backend exists, or Secure Boot is on and no signing backend exists. Both are
overridable with `LUKS_ALLOW_UKI=1`.

This is verified by 45 fixture assertions in CI across every ESP layout, backend
and signer combination — verified end to end on Manjaro w/ systemd-boot/UKI. 
[BOOTLOADERS.md](docs/BOOTLOADERS.md) has the full detail, the environment 
knobs, and the hardware checklist.

### Filesystems

Everything gnome-disks can format is classified; a filesystem is supported
**in place** when it can be shrunk by 32 MiB for the LUKS2 header (or already
has that much slack). Full matrix and workarounds:
[`docs/FILESYSTEMS.md`](docs/FILESYSTEMS.md).

| In place | How |
|---|---|
| ext4 / ext3 / ext2 | `resize2fs` shrink → encrypt → grow |
| btrfs | online `btrfs filesystem resize` (subvolume layouts auto-detected) |
| xfs | cannot shrink — accepted only with ≥ 32 MiB pre-existing slack |
| f2fs | `resize.f2fs` (needs f2fs-tools ≥ 1.16 to shrink) |
| ntfs | `ntfsresize` (data partitions) |
| vfat | `fatresize` (data partitions) |
| exfat / udf / swap | not in place — see [`docs/FILESYSTEMS.md`](docs/FILESYSTEMS.md) |

---

## What the run does

1. **Detects** partitions (scored menu, live-USB disk deprioritised), target
   OS (`/etc/os-release`), filesystem, subvolumes, and the boot partitions —
   resolved **from the target's own fstab**, not guessed.
2. **Installs missing tools** with the live distro's package manager (dnf,
   apt, pacman, zypper, apk, xbps, emerge).
3. **Shrinks** the filesystem by 32 MiB (idempotently — a re-run detects the
   gap and skips).
4. **Encrypts in place**: `cryptsetup reencrypt --encrypt` with AES-256-XTS,
   argon2id, sha512, checksum resilience.
5. **Verifies** the LUKS header, opens the container, checks the inner
   filesystem type and UUID are unchanged, grows the filesystem back.
6. **Rewrites boot configuration** for whatever this target uses, then
   rebuilds **every** initramfs image in a chroot, self-repairing images that
   come out without `cryptsetup` or `dm-crypt`.
7. **Rebuilds and re-signs the Unified Kernel Image**, if the target boots one —
   after the kernel command line is final, then signed with `sbctl`/`sbsign`
   when Secure Boot is enabled.
8. **Gates the reboot** behind a verification pass over every applicable
   component — a check that doesn't apply to this target is reported as SKIP,
   never silently passed.

### Idempotent modes — re-run it any time

| The script finds | What happens |
|---|---|
| plain filesystem | normal encryption run |
| LUKS2 header with `online-reencrypt` flag | a previous run was interrupted → finishes it (`--resume-only`, with automatic `cryptsetup repair` after a hard kill), then redoes config |
| complete LUKS2 header | shows a truncated `luksDump`, then offers: **tune** (launches `luks-tune.sh` to raise the KDF), **config** (redo boot config + verification), or **quit** |
| LUKS1 header | offers in-place **conversion to LUKS2** (`cryptsetup convert`), then re-costs each keyslot to argon2id using the same three profiles. A volume that **GRUB itself** unlocks (encrypted `/boot`) is recognised from the GRUB images on the disk and the volume's own layout: conversion is refused unless that GRUB demonstrably reads LUKS2, and the argon2id re-cost is offered only when it embeds the argon2 module — at 1 GiB, with the unlock estimate multiplied by GRUB's slowdown |
| no `/etc/fstab` inside | offers **data-partition mode**: encrypt + recovery key + header backup, no boot config |

---

## KDF profiles — argon2id only

Three presets. All argon2id; there is deliberately no pbkdf2 profile, and the
`fast` profile is a **hard floor** — the tool refuses to write anything
cheaper, with no override flag. **LinuxLocker hardens; it never weakens.** It
does not write a KDF below the floor, and `luks-tune.sh` does not re-cost a
keyslot to anything cheaper than the keyslot already has. If you genuinely
want a weaker keyslot, that is a manual `cryptsetup luksConvertKey` you run
yourself, outside this tool — no script here will do it for you.

| Profile | Memory | Iterations | Unlock time* | argon2id CPU-seconds |
|---|---|---|---|---|
| aggressive | 4 GiB | 10 | **~16 s** | **35.3 s** (measured, 56 boots) |
| moderate *(default)* | 2 GiB | 8 | **~8 s** | ~14.6 s (extrapolated) |
| fast | 1 GiB | 9 | **~4 s** | ~9.4 s (extrapolated) |

\* **Reference machine: ASUS ZenBook UX534FTC — Intel Core i7-10510U
(4 cores / 8 threads, 1.80 GHz base, 4.90 GHz turbo), 16 GiB RAM, NVMe,
`powersave` governor, Linux 6.18 LTS, cryptsetup 2.8.7.** AES-XTS throughput on
this box is 2188 MiB/s encrypt / 2267 MiB/s decrypt at a 512-bit key, so the
cipher is never the bottleneck — the KDF is the whole of the wait.

**How these were measured.** The `aggressive` row is not an estimate: that
machine runs `aggressive` in production, and systemd records the cost of every
unlock. Across **56 real boots**, the journal's per-unit resource accounting for
`systemd-cryptsetup@…service` reports a mean of **35.73 CPU seconds** (median
35.34, min 34.65, max 39.05) at a 4 GiB memory peak:

```bash
journalctl -g 'Consumed .* CPU time over' | grep cryptsetup
# ...service: Consumed 35.366s CPU time over 28.681s wall clock time, 4G memory peak.
```

CPU time is the honest signal here. The unit's *wall clock* time also covers the
human typing the passphrase, which is why it ranges from 22 s to over 3 minutes
across those same boots and cannot be compared between machines. CPU time is
pure argon2id — typing consumes none of it.

The **unlock time** column is wall clock: how long you actually wait after the
last keystroke. It was measured directly, by formatting loop-backed LUKS2
volumes with each profile's pinned parameters and timing
`cryptsetup open --test-passphrase` (best of three: 16.4 s / 8.2 s / 4.2 s).
That reconciles with the journal at a CPU-to-wall ratio of ~2.2 — argon2id at
4 GiB is memory-bandwidth bound, so four threads do not buy four times the
speed. The other two rows' CPU-second figures are extrapolated from the measured
`aggressive` cost, using ratios confirmed independently with the reference
`argon2` CLI at the same parameters (32.3 s / 13.2 s / 8.5 s).

For scale: `cryptsetup`'s own auto-tuning on this machine picks argon2id at
727 MiB and 4 iterations to hit its 2000 ms default target. The `fast` **floor**
is over three times that much work.

None of this is configuration. The installer benchmarks **the machine it is
running on** and shows live estimates in the menu; these numbers exist so you
know what shape of answer to expect, and they will differ on your hardware —
roughly linearly with single-thread performance and memory bandwidth.

Two guards run before anything is written:

- **The floor**: nothing below `fast` (1 GiB × 9) is accepted — cryptsetup's
  own default is argon2id at ~1 GiB tuned to 2000 ms, and this tool exists to
  beat a bare `luksFormat`, not to undercut it.
- **The stock-strength check**: the installer measures what `cryptsetup`
  would have chosen unaided on *this* machine and, if a named profile falls
  short (very fast hardware), raises the iteration count 25% past stock.
  Pinned `LUKS_PBKDF_*` values below stock are fatal instead — pinning exists
  for fleet reproducibility, so the tool never silently edits pinned numbers.

The `aggressive` profile needs ~6 GiB of free RAM at every unlock — the
installer warns on small-memory machines (Raspberry Pi class) and refuses any
profile whose memory cost exceeds the machine's RAM outright.

Already encrypted? `sudo ./bin/luks-tune.sh` (or `linuxlocker.sh tune`) is an
ncurses UI that re-costs existing keyslots — shows the measured unlock time
and what each cost buys against a GPU fleet, backs the header up first, and
never touches data, passphrases, or keyslot existence. It also converts
leftover pbkdf2 keyslots to argon2id.

On a volume that **GRUB itself unlocks** (an encrypted `/boot` you set up
elsewhere), `luks-tune.sh` recognises that and still gives it the strongest
KDF that GRUB can open: argon2id — memory-hard, GPU-resistant — whenever the
GRUB image embeds the argon2 module (stock GRUB 2.12 does not; a 2.14 build
does), at up to **1 GiB**, which is what argon2id can take as one contiguous
allocation from the x86 UEFI firmware heap. The unlock estimate it shows is
honest about where that unlock runs: GRUB is single-threaded, so the figure is
the kernel-side estimate times **8.5** (measured on one machine;
`LUKS_GRUB_KDF_FACTOR` overrides it). Nothing here sets an encrypted `/boot` up
or re-embeds a GRUB image.

---

## What's in here

| Path | What it is |
|------|------------|
| `bin/linuxlocker.sh` | **Start here.** Detects the live OS + package manager, installs core dependencies, dispatches to the other scripts (`deploy` / `tune` / `post` / `bundle`). |
| `bin/luks-deploy.sh` | **The main event.** In-place LUKS2 encryption, run from a live USB. Auto-detects everything, resolves boot partitions from the target's fstab, self-repairs failed initramfs steps, fixes SELinux labels, and gates the reboot behind verification. Fully resumable. |
| `bin/lib-deps.sh` | Shared OS / package-manager detection, dependency installer, and the Fedora Asahi Remix guard (sourced, not run). |
| `bin/lib-uki.sh` | UKI / systemd-boot / Secure Boot support (sourced, not run): finds `EFI/Linux/*.efi` across every ESP layout, picks the rebuild backend and the signer, rebuilds and signs, and reads the `.cmdline` and `.initrd` sections back out of a PE binary. `UKI_DRY=1` prints the commands instead of running them. |
| `bin/lib-boot.sh` | Kernel command-line carriers and encrypted-`/boot` recognition (sourced, not run). One transform for every file format that carries a command line — BLS/systemd-boot entries in any ESP layout, `extlinux.conf`, `cmdline.txt`, `/etc/kernel/cmdline`, `cmdline.d`, `refind_linux.conf`, `limine.conf`, GRUB defaults and `grub.d` drop-ins — rewriting `root=`/`resume=` to the mapper, adding the unlock arguments, stripping and restoring the splash, without touching a line it does not understand. Also reads the GRUB images on a disk to tell whether GRUB itself unlocks a volume and whether it can read LUKS2 / open argon2id. |
| `bin/luks-tune.sh` | ncurses KDF re-costing for existing LUKS2 volumes. Pins `--hash sha512` so a re-cost cannot walk a slot's AF hash back to cryptsetup's `sha256` default. `--dry-run` prints the command and changes nothing. |
| `bin/post-encryption-setup.sh` | Run once on the newly-encrypted system: recovery bundle, snapper subvolumes (btrfs roots), splash-argument restore, verification. Idempotent. |
| `bin/save-luks-recovery-bundle.sh` | Labeled recovery bundle: fresh header backup + crypttab/fstab/boot state + a README with distro-specific repair commands. **Key material — never attach it to a bug report.** |
| `bin/linuxlocker-diag.sh` | **Read-only diagnostic bundle for bug reports**, as Markdown you can paste straight into an issue: tool inventory, `lsblk -f`, Secure Boot state, the target's boot configuration, the baked-in `.cmdline` of every UKI and its signature status, what LinuxLocker's own detection thinks it found, public LUKS header metadata, and the relevant journal lines. UUIDs truncated by default. Also reachable as `linuxlocker.sh diag`. |
| `extras/` | Optional: `luks-fetch-cache`, a disk-encryption status readout for fastfetch (LUKS **and** BitLocker volumes — KDF, cipher, protectors; public header metadata only). Its `install.sh` also installs fastfetch itself if missing. |
| `tests/loopback-core-test.sh` | CI-safe loopback test of the whole core: shrink guards, reencrypt, resume, hard-kill repair, recovery keys, the ext4 path, and LUKS1→LUKS2 conversion. Touches no real disk, and runs on every push against x86_64 **and** aarch64 runners. |
| `tests/uki-fixture-test.sh` | CI-safe fixture test of the UKI / systemd-boot / Secure Boot logic: every ESP layout, every rebuild backend, every signer, the refusal matrix, `.cmdline` round-trips through a real PE binary, and the Asahi guard. Needs no root and no disk. Run it as root on a UKI machine and section 10 also self-checks detection against that real system. |
| `tests/cmdline-fixture-test.sh` | CI-safe fixture test of `lib-boot.sh`: every command-line carrier format round-trips, `root=PARTUUID=`/`root=/dev/…` rewriting, idempotency, `grub.d` overrides, CRLF and comment tolerance, and the encrypted-`/boot` recogniser against stock-2.12 and argon2-2.14 image signatures. Needs no root and no disk. |
| `docs/` | [ABOUT](docs/ABOUT.md) · [INSTALL](docs/INSTALL.md) · [FILESYSTEMS](docs/FILESYSTEMS.md) · [RECOVERY](docs/RECOVERY.md) |
| `SECURITY.md` | What is in scope, what is not, and **what never to attach to a bug report** — the artefacts this tool produces can be the keys themselves. |
| `.github/rulesets/` | Branch and tag protection as JSON, not as settings someone clicked once: `main` and every `v*` tag are protected from deletion and force-push. |

---

## Crypto parameters

- **Cipher**: `aes-xts-plain64`, 512-bit key (AES-256-XTS) — the modern
  default for disk encryption, hardware-accelerated on both x86_64 (AES-NI)
  and aarch64 (ARMv8 Crypto Extensions).
- **KDF**: argon2id, pinned per profile (`--pbkdf-force-iterations`, no
  time-benchmark drift between fleet machines).
- **Hash**: sha512 (AF splitter + LUKS2 digest).
- **Resilience**: `checksum` — the in-place re-encryption is journaled, so
  power loss mid-run is recoverable by re-running the script.

## Environment knobs (fleet / non-interactive use)

```
LUKS_PROFILE=aggressive|moderate|fast      pick a KDF preset, skip the menu
LUKS_PBKDF_MEMORY / _ITER / _PARALLEL      pin exact KDF numbers (floor-checked)
LUKS_TARGET_ROOT / _BOOT / _EFI            pin partitions, skip the menus
LUKS_PASSPHRASE_FILE=<path>                non-interactive passphrase
LUKS_RECOVERY_KEY=yes|no                   recovery keyslot without prompting
LUKS_MAPPER_NAME=<name>                    device-mapper name (default root_crypt)
LUKS_KEEP_SPLASH=1                         don't strip rhgb/quiet/splash
LUKS_DRY_RUN=1  (or --dry-run)             plan only, change nothing
LUKS_SKIP_VERSION_CHECK=1                  bypass the cryptsetup >= 2.4 floor
LUKS_ALLOW_UKI=1                           proceed past the two UKI refusals
LUKS_UKI_REGEN=<backend>                   force the UKI rebuild backend:
                                           mkinitcpio|kernel-install|dracut|ukify
LUKS_UKI_SIGN=<backend>                    force the signer: sbctl|sbsign|none
LUKS_SB_KEY / LUKS_SB_CERT                 explicit sbsign key + certificate
LUKS_SKIP_UKI_SIGN=1                       rebuild the UKI but do not sign it
LUKS_SB_STATE=enabled|disabled             override Secure Boot autodetection
LUKS_GRUB_KDF_FACTOR=<x>                   unlock-time multiplier for a volume GRUB
                                           itself unlocks (default 8.5, measured)
LUKS_GRUB_ARGON2_MAX_KIB=<n>               argon2id ceiling for such a volume
                                           (default 1 GiB — the x86 UEFI heap)
```

The UKI and Secure Boot knobs are documented in full, with detection order and
key-discovery paths, in [BOOTLOADERS.md](docs/BOOTLOADERS.md).

## Requirements

- A live/rescue Linux environment for the target machine (the target distro's
  own live ISO is the safest bet). The script hard-refuses to run from the
  installed system without a typed override.
- `cryptsetup` ≥ 2.4 in the live environment (in-place reencryption).
- On a UKI target: `binutils` (for `objcopy`) in the live environment, so the
  `.cmdline` and `.initrd` sections can be read back and verified. Without it
  those checks report SKIP rather than passing silently.
- AC power for laptops — the script checks and warns.
- **A verified backup.** In-place encryption is irreversible the moment it
  starts.

## How this differs from encrypting by hand

The manual route — `cryptsetup reencrypt` followed by editing `crypttab`,
`fstab`, the kernel cmdline and your bootloader's config yourself — works, and
there are guides for it. What this kit adds is the part those guides leave to
you, and the part that differs on every distro:

| | Manual `cryptsetup reencrypt` | LinuxLocker |
|---|---|---|
| Partition selection | You identify root/boot/EFI yourself | Auto-detected and fstype-checked; boot and ESP resolved from the **target's own fstab**, and your pick cross-checked against it |
| Filesystem shrink | You pick the right resize tool and the right size | Per-filesystem handler (ext2/3/4, btrfs, xfs, f2fs, ntfs, vfat), 32 MiB gap, idempotent re-run detection |
| Which distro is this? | You already know, and follow the matching guide | Detected from the target's own artefacts — derivatives inherit support without being named |
| KDF parameters | `cryptsetup` auto-benchmarks — machine-dependent, and picks sha256 | Pinned argon2id + sha512, identical on every box, chosen from a menu benchmarked on your hardware, with a hard floor |
| Boot config | You edit `crypttab`, `fstab`, cmdline, GRUB defaults, BLS entries, `cmdline.txt` or `extlinux.conf` by hand | All of them rewritten, for whichever ones this target actually uses |
| Initramfs | `dracut -f` / `mkinitcpio -P` / `update-initramfs -u`, and hope the module is in | **Every** image rebuilt in a chroot, then checked for `cryptsetup`/`dm-crypt` and self-repaired if missing |
| UKI / Secure Boot | You discover after the reboot that the `.efi` still has the old command line baked in, or that rebuilding it broke the signature | The `.efi` is rebuilt with the right backend after the cmdline is final, re-signed with `sbctl`/`sbsign`, and its `.cmdline` section read back to prove it |
| Did it work? | You find out at reboot | Verification gate refuses the reboot until it passes; a check that does not apply reports SKIP, never a silent pass |
| Interrupted run | You debug the header state yourself | Detected and resumed automatically; `cryptsetup repair` path handled |
| Undo / recovery | Whatever you thought to save | Header backups plus a labeled bundle of every changed file, with distro-specific repair commands |

If you want to understand what it changes before trusting it, `--dry-run`
prints every action, including the exact `cryptsetup` invocation, and changes
nothing.

---

## Risks — read this

- Power loss or a crash **mid-encryption** leaves a half-encrypted disk. The
  LUKS2 journal + checksum resilience make this recoverable — re-run the
  script — but only if you don't panic-format anything first.
- A wrong partition selection is catastrophic. The script cross-checks your
  selection against the target's own fstab and makes you type `ENCRYPT`, but
  the final authority is you.
- Forgetting the passphrase — or setting it with Caps Lock on, which
  `cryptsetup`'s type-it-twice check cannot catch — with no recovery key
  enrolled means the data is gone. The script guards the second case by
  requiring a lower-case `yes` immediately before the passphrase prompt:
  it cannot be typed with Caps Lock on. That is the feature working as
  designed.
- On systems where **GRUB itself** unlocks the disk (encrypted `/boot`,
  `cryptomount`), a LUKS2 header its GRUB cannot read or an argon2id keyslot
  its GRUB cannot open makes the system unbootable. Such volumes are
  recognised from the GRUB images and refused or capped accordingly; nothing
  here sets up an encrypted `/boot`.

---

## Frequently asked questions

### Can I encrypt Linux after installation, without reinstalling?

Yes — that is the entire point of this tool. `cryptsetup reencrypt --encrypt`
converts an existing filesystem into a LUKS2 container in place. LinuxLocker
automates that plus every boot-configuration change it forces, and refuses to
let you reboot until the result verifies.

### Will my files, filesystem UUID and snapshots survive?

Yes. The partition gains an encryption layer; the filesystem inside it is the
same filesystem, with the same UUID. btrfs subvolumes and snapshots come
through untouched. The script re-reads the inner filesystem type and UUID after
encryption and fails the run if either changed.

### Which distributions are supported?

Support is keyed off what is **actually installed on the target**, never off the
distro's name, so derivatives inherit it from their family: Fedora / RHEL /
Rocky / AlmaLinux (dnf, dracut, BLS), Debian / Ubuntu / Mint / Pop!\_OS (apt,
initramfs-tools), Arch / Manjaro / EndeavourOS (pacman, mkinitcpio), openSUSE
(zypper, dracut), and Raspberry Pi OS. Alpine, Void and Gentoo are recognized by
the dependency installer. See [Supported systems](#supported-systems).

### Does it work on a Raspberry Pi or another ARM board?

Yes. Raspberry Pi OS is handled as a first-class target — the `root=` line in
`cmdline.txt` is rewritten and `auto_initramfs=1` set — and ARM boards using
U-Boot distro-boot get their `extlinux.conf` `APPEND` line rewritten. Note that
the `aggressive` KDF profile wants ~6 GiB of free RAM at every unlock; the
installer warns on small-memory machines and refuses outright any profile whose
memory cost exceeds the machine's RAM.

### Why does it have to run from a live USB?

Because it rewrites the filesystem it would otherwise be running from. The
script hard-refuses to run from the installed system without a typed override.
Any live or rescue Linux for your machine works; the target distro's own live
ISO is the safest choice, since its `cryptsetup` and filesystem tools already
match the target.

### Why argon2id only, and never pbkdf2?

pbkdf2 is CPU-only, which is exactly what a GPU cracking fleet is good at.
argon2id is memory-hard, so an attacker has to buy RAM per guess, not just
cores. All three profiles are argon2id, and the cheapest of them is a hard
floor with no override flag — the tool exists to beat a bare `luksFormat`, not
to undercut it. `luks-tune.sh` also converts leftover pbkdf2 keyslots on
volumes you encrypted earlier.

### Why is `/boot` left unencrypted?

Because the root keyslot is where the strength lives. The initramfs unlocks
root with the full argon2id cost — up to 4 GiB of memory per guess, which is
what holds a GPU fleet to a handful of parallel attempts. An encrypted `/boot`
would have to be opened by GRUB instead, and GRUB cannot deliver that: it takes
argon2id's memory as **one contiguous allocation** from the firmware heap,
which on x86 UEFI has never reliably meant more than **1 GiB** (4 GiB overflows
GRUB outright), and whether it can open argon2id at all depends on the build
(stock GRUB 2.12 prints *Argon2 not supported*). A `/boot` keyslot would
therefore be the cheapest way into the machine — a quarter of the memory cost
of an aggressive root — and every unlock would run single-threaded in GRUB,
about 8.5× the initramfs time for the same parameters. Fitting the KDF to the
bootloader trades a strong defence for a partial one; leaving `/boot` clear
keeps the strong one.

So LinuxLocker **recognises** encrypted `/boot` and **never sets it up**:

- A target whose `/boot` lives on the root filesystem under GRUB or extlinux is
  **refused before the shrink**, with the reason and the fix (a separate,
  unencrypted `/boot` partition — 1 GiB is plenty). The old behaviour encrypted
  it and reported success on a machine whose GRUB could no longer find a kernel.
- A volume GRUB *already* unlocks is detected from the GRUB images on the disk
  (the embedded early config names the UUID it `cryptomount`s) and from the
  volume's own layout. On it, `luks-tune.sh` and the LUKS1 conversion offer
  only what that GRUB can take: LUKS2 only if the image reads it, argon2id only
  if the image embeds the argon2 module, 1 GiB at most, and unlock estimates
  multiplied by GRUB's slowdown.

Apple Silicon under U-Boot's EFI has been measured allocating 2 GiB; that is
AsahiLocker's territory and out of scope here. Details:
[BOOTLOADERS.md](docs/BOOTLOADERS.md#encrypted-boot).

### What happens if the encryption is interrupted — power loss, a crash, a closed lid?

LUKS2 re-encryption is journaled with checksum resilience. Re-run the script:
it detects the `online-reencrypt` flag, runs `cryptsetup repair` first if the
journal is dirty, finishes the re-encryption, and then redoes the configuration
work. The one way to lose the disk here is to panic-format it before re-running.

### Does it work with systemd-boot, or a Unified Kernel Image?

Yes, both, as of 1.2.0.

**systemd-boot** is detected from the loader binary on the ESP rather than
inferred from `/boot/loader/entries`, so it works with the ESP mounted at
`/efi`, `/boot/efi` or `/boot`, with or without a separate XBOOTLDR partition.
Type #1 entries get the LUKS arguments, and check V13 refuses the reboot unless
something systemd-boot can actually boot points at the encrypted root.

**A UKI** is rebuilt. The kernel command line and the initramfs are baked into
the `.efi`, so editing `/etc/kernel/cmdline` and rebuilding the standalone
initramfs — which is all any generic guide does — changes nothing about what the
firmware loads. LinuxLocker detects which tool owns the `.efi` on your target
(an `mkinitcpio` preset with `_uki=`, `kernel-install` with `layout=uki`,
`dracut --uki-file`, or `ukify`), rebuilds it **after** the kernel command line
is final, and then reads the `.cmdline` section back out to prove the LUKS
arguments are in there. That last check, V11, is the one whose absence made the
old failure silent.

It still refuses before touching the disk if no rebuild backend exists, or if
Secure Boot is on and nothing can sign the result. See
[BOOTLOADERS.md](docs/BOOTLOADERS.md).

### Does it work with Secure Boot enabled?

Yes, and it handles the part that is easy to get wrong.

Without a UKI — shim + GRUB, or shim + systemd-boot — there is nothing to do:
the initramfs is not part of the verified chain, and LinuxLocker never touches
shim, the bootloader binary or `vmlinuz`. Rebuilding the initramfs is invisible
to Secure Boot.

With a UKI, the `.efi` **is** the signed object, so rebuilding it invalidates the
signature and the firmware will refuse to load the result. LinuxLocker re-signs
it with `sbctl` or `sbsign`, then verifies the signature before allowing the
reboot (check V12). This matters more than it sounds: on Arch and Manjaro,
signing normally happens through `zz-sbctl.hook`, which is a **libalpm** hook —
it fires on pacman transactions, *not* when something runs `mkinitcpio -P`
directly. Any tool that rebuilds your UKI without being a package manager leaves
it unsigned unless it signs it deliberately.

`pesign`/NSS signing is detected but not implemented: the certificate nickname
and NSS database cannot be discovered reliably from a chroot, and a silently
unsigned `.efi` is exactly the failure this is meant to prevent. Those targets
are refused with an explanation.

### Can it unlock with a TPM, or with no passphrase at all?

No. LinuxLocker enrolls a passphrase and, optionally, a recovery keyslot. TPM2
enrollment, PCR sealing and network-bound unlock are features it does not
implement — you type the passphrase at boot. Secure Boot signing (above) is a
separate thing and *is* handled.

### I run Fedora Asahi Remix on an Apple Silicon Mac. Can I use this?

No — use **[AsahiLocker](https://github.com/doug445/AsahiLocker)**. It does the
same job with the Apple Silicon boot guards LinuxLocker deliberately drops.
Both `linuxlocker.sh` and `luks-deploy.sh` detect Fedora Asahi Remix and exit
with a link before touching any device, so running the wrong one by mistake
costs you nothing.

### Can I run it unattended across several machines?

Yes. Every prompt has an `LUKS_*` environment variable behind it — see
[Environment knobs](#environment-knobs-fleet--non-interactive-use). Pin
`LUKS_PBKDF_MEMORY` / `_ITER` / `_PARALLEL` for reproducible KDF cost across a
fleet rather than per-machine benchmark drift; pinned values below the floor are
fatal rather than silently raised, precisely so the numbers you pinned are the
numbers you get.

### Can I encrypt a second data disk instead of the root?

Yes. If the selected partition has no `/etc/fstab` inside it, the script offers
**data-partition mode**: encrypt, enroll a recovery key, back up the header, and
skip all boot configuration.

### My root is xfs — can it be encrypted in place?

Only if it already has at least 32 MiB of free space **at the end of the
partition**, because xfs cannot be shrunk. The script checks for that slack and
declines rather than guessing. [`docs/FILESYSTEMS.md`](docs/FILESYSTEMS.md) has
the full matrix and the workarounds for xfs, exfat, udf and swap.

### It is already encrypted, but with weak parameters — can I fix that?

Yes, without re-encrypting anything. `sudo ./bin/luks-tune.sh` re-costs existing
keyslots to a stronger argon2id profile, backs the header up first, and never
touches data, passphrases or keyslot existence. A LUKS1 volume is offered an
in-place conversion to LUKS2 first. If GRUB itself unlocks the volume, both
tools say so and stay within GRUB's ceiling (above).

### My root= is `PARTUUID=…`, or my bootloader is rEFInd / Limine / systemd-boot with the ESP at `/efi`

Handled. Every file that carries a kernel command line is found and rewritten:
a `root=` or `resume=` that names the raw partition — `PARTUUID=`,
`PARTLABEL=`, `/dev/nvme0n1p3`, `/dev/disk/by-id/…` — becomes
`/dev/mapper/root_crypt`, while `root=UUID=<filesystem uuid>` is left alone
because the filesystem keeps its UUID inside the container. Ubuntu's
`/etc/default/grub.d/*.cfg` drop-ins, which override `/etc/default/grub` when
`grub-mkconfig` runs, get the same edit, and `GRUB_FORCE_PARTUUID` (cloud
images) is disabled because it boots `root=PARTUUID=` straight past the mapper.
A UKI target with no `/etc/kernel/cmdline` gets one seeded from the UKI's own
`.cmdline`, so the rebuild cannot bake in the live USB's `/proc/cmdline`. Check
V14 then reads every carrier back. Nothing in this stage aborts the run: a file
that cannot be rewritten is reported and the gate refuses the reboot.

### How do I check what I actually ended up with?

`sudo cryptsetup luksDump /dev/<your-root-partition>` prints the cipher, the
KDF and its parameters. It shows no key material and is safe to paste into a
bug report — unlike `--dump-master-key`, which is not. `extras/luks-fetch-cache`
turns the same information into a one-line-per-volume fastfetch readout.

---

## Documentation

| Doc | Covers |
|-----|--------|
| [ABOUT.md](docs/ABOUT.md) | What the project is, who it is for, what it deliberately does not do |
| [INSTALL.md](docs/INSTALL.md) | Step-by-step install, start to finish, with what each prompt means |
| [FILESYSTEMS.md](docs/FILESYSTEMS.md) | Every filesystem classified: shrinkable in place, slack-only, or not at all — with workarounds |
| [RECOVERY.md](docs/RECOVERY.md) | Interrupted encryption, unbootable system, corrupt header, undoing a shrink |
| [BOOTLOADERS.md](docs/BOOTLOADERS.md) | Which boot machinery is actually written, and where systemd-boot, UKIs and Secure Boot stand |
| [SECURITY.md](SECURITY.md) | Scope, reporting, and **what never to attach to a bug report** |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Expected conduct in issues and pull requests |
| [CONTRIBUTING.md](CONTRIBUTING.md) | What this project accepts, the diagnostic bundle, and what a filesystem handler must do |

---

## Contributing

This project takes **serious bugs** and **new filesystem support**, and nothing
else. Refactors, new options and general feature requests will be declined
regardless of quality — every added code path here is a path that can lose
someone's disk, and there is one maintainer to be sure it does not.
**[CONTRIBUTING.md](CONTRIBUTING.md)** has the full scope, the read-only
diagnostic bundle, and what a filesystem handler has to do to merge.

**Test reports are wanted as much as bug reports.** Every UKI, systemd-boot and
Secure Boot path is verified by fixtures in CI but has not been through a full
encrypt-and-reboot cycle on real hardware, and neither have xfs, f2fs, ntfs, the
Raspberry Pi and U-Boot boot stacks, or aarch64 hardware.
[CONTRIBUTING.md](CONTRIBUTING.md) has the table of what is still unconfirmed;
a report that a configuration *worked* is the only way a row gets ticked.

Because this tooling rewrites a live root filesystem and its bootloader, a
description of what went wrong is rarely enough to act on. Say which distro you
ran it **from** and which distro you ran it **against** — those are different
code paths through the same script — and attach the diagnostic bundle:

```bash
sudo ./bin/linuxlocker-diag.sh -o linuxlocker-report.md
```

It is read-only, it redacts UUIDs by default, and it deliberately excludes
everything that would be key material. Read it before posting anyway.

Before opening a pull request, run what CI runs:

```bash
shellcheck -S warning $(git ls-files '*.sh') extras/bin/luks-fetch-cache
sudo bash tests/loopback-core-test.sh
bash tests/uki-fixture-test.sh
bash tests/cmdline-fixture-test.sh
```

Expect `31 passed, 0 failed` from the loopback suite and `0 failed` from the
fixture suites (`bash tests/cmdline-fixture-test.sh` is the third). The loopback suite exercises the whole encryption core — shrink
guards, in-place re-encryption, `--resume-only`, a hard kill mid-re-encrypt
followed by `cryptsetup repair`, recovery keys, the ext4 path and LUKS1 → LUKS2
conversion — against file-backed loop devices. The fixture suite exercises the
UKI, systemd-boot and Secure Boot decision logic against synthetic target trees.
Neither touches a real disk, and both run on every push against x86_64 and
aarch64 runners. A `SKIP` in loopback stage 5b is normal and lowers the count
without any failure; `0 failed` is the invariant.

Every shell script in the repository is `shellcheck -S warning` clean and must
stay that way — this is a pure **shell-script** project with no runtime
dependencies beyond the tools a **sysadmin** already has on a rescue USB, and
that is deliberate: a recovery tool that needs a language runtime installed is a
recovery tool you cannot use from a minimal live environment.

**Security issues do not belong in the issue tracker.** Read
[SECURITY.md](SECURITY.md) first: the recovery key, the header backups and the
recovery bundle are key material, not diagnostics.

## License and contact

MIT — see [LICENSE](LICENSE).

- **Version:** 1.4.2
- **Author:** William MacKinnon ([doug445](https://github.com/doug445))
- **Email:** spilled-bowline0j@icloud.com
- **Repository:** https://github.com/doug445/LinuxLocker

Copyright (c) 2026 William MacKinnon &lt;spilled-bowline0j@icloud.com&gt;
