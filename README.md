# LinuxLocker — universal in-place LUKS2 disk encryption for Linux

[![CI](https://github.com/doug445/LinuxLocker/actions/workflows/lint.yml/badge.svg)](https://github.com/doug445/LinuxLocker/actions/workflows/lint.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform: x86_64 | aarch64](https://img.shields.io/badge/platform-x86__64%20%7C%20aarch64-lightgrey.svg)](#requirements)
[![KDF: argon2id](https://img.shields.io/badge/KDF-argon2id-blue.svg)](#kdf-profiles--argon2id-only)

Add **full-disk encryption (FDE) to a Linux install you already have.**
LinuxLocker encrypts the root filesystem of an already-installed system in
place — without reinstalling, and without a second copy of your data. One
tool, any distro family it can chroot into, x86_64 and ARM alike: Fedora,
RHEL, Rocky, AlmaLinux, Debian, Ubuntu, Linux Mint, Pop!_OS, Raspberry Pi OS,
Arch, Manjaro, EndeavourOS and openSUSE.

> **On Apple Silicon?** Use
> [AsahiLocker](https://github.com/doug445/AsahiLocker) instead — same job,
> with the Fedora Asahi Remix boot guards this tool deliberately drops.

`luks-deploy.sh` converts your existing root (or data) partition into a LUKS2
container holding that same filesystem. Your files and the filesystem UUID
survive; the partition simply gains an encryption layer. It then rewrites every
piece of boot configuration that has to change — `crypttab`, `fstab`, GRUB
defaults, BLS entries, `cmdline.txt`, `extlinux.conf`, initramfs generator
config, **all** initramfs images — and refuses to let you reboot until a full
verification gate passes.

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
7. **Gates the reboot** behind a verification pass over every applicable
   component — a check that doesn't apply to this target is reported as SKIP,
   never silently passed.

### Idempotent modes — re-run it any time

| The script finds | What happens |
|---|---|
| plain filesystem | normal encryption run |
| LUKS2 header with `online-reencrypt` flag | a previous run was interrupted → finishes it (`--resume-only`, with automatic `cryptsetup repair` after a hard kill), then redoes config |
| complete LUKS2 header | shows a truncated `luksDump`, then offers: **tune** (launches `luks-tune.sh` to raise the KDF), **config** (redo boot config + verification), or **quit** |
| LUKS1 header | offers in-place **conversion to LUKS2** (`cryptsetup convert`), then re-costs each keyslot to argon2id using the same three profiles — with an explicit warning gate for GRUB-unlocked (`cryptomount`) volumes, which cannot open argon2id slots |
| no `/etc/fstab` inside | offers **data-partition mode**: encrypt + recovery key + header backup, no boot config |

---

## KDF profiles — argon2id only

Three presets. All argon2id; there is deliberately no pbkdf2 profile, and the
`fast` profile is a **hard floor** — the tool refuses to write anything
cheaper, with no override flag.

| Profile | Memory | Iterations | Unlock time* |
|---|---|---|---|
| aggressive | 4 GiB | 10 | `~<FILL-IN>` s |
| moderate *(default)* | 2 GiB | 8 | `~<FILL-IN>` s |
| fast | 1 GiB | 9 | `~<FILL-IN>` s |

\* **Benchmark machine: `<FILL-IN: CPU / RAM / machine model>`** — replace
these placeholders with measured numbers from `cryptsetup benchmark` /
a real deployment on your reference hardware. The installer always
benchmarks **the machine it is running on** and shows live estimates in the
menu, so these table numbers are documentation, not configuration.

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

---

## What's in here

| Path | What it is |
|------|------------|
| `bin/linuxlocker.sh` | **Start here.** Detects the live OS + package manager, installs core dependencies, dispatches to the other scripts (`deploy` / `tune` / `post` / `bundle`). |
| `bin/luks-deploy.sh` | **The main event.** In-place LUKS2 encryption, run from a live USB. Auto-detects everything, resolves boot partitions from the target's fstab, self-repairs failed initramfs steps, fixes SELinux labels, and gates the reboot behind verification. Fully resumable. |
| `bin/lib-deps.sh` | Shared OS / package-manager detection and dependency installer (sourced, not run). |
| `bin/luks-tune.sh` | ncurses KDF re-costing for existing LUKS2 volumes. `--dry-run` prints the command and changes nothing. |
| `bin/post-encryption-setup.sh` | Run once on the newly-encrypted system: recovery bundle, snapper subvolumes (btrfs roots), splash-argument restore, verification. Idempotent. |
| `bin/save-luks-recovery-bundle.sh` | Labeled recovery bundle: fresh header backup + crypttab/fstab/boot state + a README with distro-specific repair commands. |
| `extras/` | Optional: `luks-fetch-cache`, a disk-encryption status readout for fastfetch (LUKS **and** BitLocker volumes — KDF, cipher, protectors; public header metadata only). Its `install.sh` also installs fastfetch itself if missing. |
| `tests/loopback-core-test.sh` | CI-safe loopback test of the whole core: shrink guards, reencrypt, resume, hard-kill repair, recovery keys, the ext4 path, and LUKS1→LUKS2 conversion. Touches no real disk, and runs on every push against x86_64 **and** aarch64 runners. |
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
```

## Requirements

- A live/rescue Linux environment for the target machine (the target distro's
  own live ISO is the safest bet). The script hard-refuses to run from the
  installed system without a typed override.
- `cryptsetup` ≥ 2.4 in the live environment (in-place reencryption).
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
- Forgetting the passphrase (or a Caps-Locked passphrase — the script checks
  the LED state and warns) with no recovery key enrolled means the data is
  gone. That is the feature working as designed.
- On LUKS1 systems where **GRUB itself** unlocks the disk (encrypted `/boot`,
  `cryptomount`), converting keyslots to argon2id would make the system
  unbootable — the conversion flow warns and gates on this explicitly.

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
(zypper, dracut), and Raspberry Pi OS. Alpine, Void and Gentoo are recognised by
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

The root volume is unlocked by the initramfs, which can afford a real argon2id
cost. An encrypted `/boot` has to be unlocked by GRUB, which is far more
constrained — and weakening the KDF to fit the bootloader trades a strong
defence for a partial one. If your system already has GRUB unlocking an
encrypted `/boot` (`cryptomount`), the LUKS1 conversion flow explicitly gates
on that, because argon2id keyslots are ones GRUB cannot open at all.

### What happens if the encryption is interrupted — power loss, a crash, a closed lid?

LUKS2 re-encryption is journaled with checksum resilience. Re-run the script:
it detects the `online-reencrypt` flag, runs `cryptsetup repair` first if the
journal is dirty, finishes the re-encryption, and then redoes the configuration
work. The one way to lose the disk here is to panic-format it before re-running.

### Can it unlock with a TPM, Secure Boot, or no passphrase at all?

No. LinuxLocker enrolls a passphrase and, optionally, a recovery keyslot. TPM
enrollment and network-bound unlock are features it does not implement — you
type the passphrase at boot.

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
in-place conversion to LUKS2 first.

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
| [SECURITY.md](SECURITY.md) | Scope, reporting, and **what never to attach to a bug report** |
| [CONTRIBUTING.md](CONTRIBUTING.md) | What this project accepts, the diagnostic bundle, and what a filesystem handler must do |

---

## Contributing

This project takes **serious bugs** and **new filesystem support**, and nothing
else. Refactors, new options and general feature requests will be declined
regardless of quality — every added code path here is a path that can lose
someone's disk, and there is one maintainer to be sure it does not.
**[CONTRIBUTING.md](CONTRIBUTING.md)** has the full scope, the read-only
diagnostic bundle, and what a filesystem handler has to do to merge.

Because this tooling rewrites a live root filesystem and its bootloader, a
description of what went wrong is rarely enough to act on. Say which distro you
ran it **from** and which distro you ran it **against** — those are different
code paths through the same script — and include `--dry-run` output where you
can.

Before opening a pull request, run what CI runs:

```bash
shellcheck -S warning $(git ls-files '*.sh') extras/bin/luks-fetch-cache
sudo bash tests/loopback-core-test.sh
```

Expect `29 passed, 0 failed`. The suite exercises the whole core — shrink
guards, in-place re-encryption, `--resume-only`, a hard kill mid-re-encrypt
followed by `cryptsetup repair`, recovery keys, the ext4 path and LUKS1 → LUKS2
conversion — against file-backed loop devices. It touches no real disk, and
runs on every push against both x86_64 and aarch64 runners. A `SKIP` in stage 5b
is normal and lowers the count without any failure; `0 failed` is the invariant.

**Security issues do not belong in the issue tracker.** Read
[SECURITY.md](SECURITY.md) first: the recovery key, the header backups and the
recovery bundle are key material, not diagnostics.

## License and contact

MIT — see [LICENSE](LICENSE).

- **Author:** William MacKinnon ([doug445](https://github.com/doug445))
- **Email:** spilled-bowline0j@icloud.com
- **Repository:** https://github.com/doug445/LinuxLocker

Copyright (c) 2026 William MacKinnon &lt;spilled-bowline0j@icloud.com&gt;
