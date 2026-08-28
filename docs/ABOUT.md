# About LinuxLocker

**LinuxLocker is a universal, in-place LUKS2 full-disk-encryption tool for
Linux systems that are already installed.** It converts an existing root (or
data) partition into an encrypted LUKS2 container — `dm-crypt` under
`aes-xts-plain64`, argon2id keyslots — without reinstalling the operating
system, without a second copy of your data, and without changing the filesystem
UUID. Your **ext4** or **btrfs** root, its subvolumes and its snapshots come
through the in-place encryption unchanged; the partition simply gains an
encryption layer.

You run it from a **live USB**, it detects everything about the target itself,
and it refuses to let you reboot until the result verifies.

This page is the long-form description of what the project is, who it is for,
and where its boundaries are. For how to run it, start with the
[README](../README.md) and [`docs/INSTALL.md`](INSTALL.md).

---

## The problem it solves

Almost every Linux installer offers full-disk encryption **at install time** and
nothing afterwards. Realise a month later that your laptop's root filesystem is
plaintext and the standard answer is: back up, wipe, reinstall, restore, and
rebuild every bit of local state you had accumulated. For a workstation with
containers, VMs, snapshots and half-remembered `/etc` edits, that is a day of
work and a real chance of losing something.

`cryptsetup reencrypt --encrypt` has been able to encrypt a filesystem in place
since 2.4. The encryption itself is one command. **The work is everything
around it** — and that is what LinuxLocker automates:

- shrinking the filesystem by 32 MiB so the LUKS2 header has somewhere to live,
  using whichever resize tool that filesystem needs;
- discovering which distro, which init system, which initramfs generator and
  which bootloader the *target* actually uses, from the target's own artefacts;
- rewriting `crypttab`, `fstab`, GRUB defaults, BLS entries, `cmdline.txt`,
  `extlinux.conf` and the initramfs generator's config to match;
- rebuilding **every** initramfs image inside a chroot — `dracut`, `mkinitcpio`
  or `initramfs-tools` — and self-repairing any that come out without
  `cryptsetup` or `dm-crypt` in them;
- rebuilding and re-signing the Unified Kernel Image, on the targets that boot
  one, because a UKI carries the kernel command line inside the signed `.efi`
  where no amount of editing `/etc/kernel/cmdline` can reach it;
- refusing to let you reboot until a verification pass over every applicable
  component succeeds.

Any one of those steps done wrong produces a machine that boots to an emergency
shell with an encrypted root it cannot open. That failure mode is the reason
this project exists as a tool rather than a wiki page.

## Who it is for

- **Anyone who skipped FDE at install time** and does not want to reinstall to
  get it. This is the main case.
- **People inheriting a machine** — a second-hand laptop, a handed-down
  workstation — who want the disk encrypted before it holds anything.
- **Small-fleet admins** who need reproducible KDF parameters across machines
  rather than whatever `cryptsetup` benchmarks on each one. Every prompt has an
  `LUKS_*` environment variable behind it, so an unattended run is a matter of
  presetting them.
- **Single-board and ARM users** — Raspberry Pi OS `cmdline.txt` and U-Boot
  `extlinux.conf` are handled as first-class boot stacks, not afterthoughts.
- **Anyone with an existing LUKS1 volume** who wants LUKS2 and argon2id
  keyslots, which `luks-tune.sh` and the conversion flow provide without
  touching data.
- **Anyone running systemd-boot with Unified Kernel Images and Secure Boot** —
  the modern Arch, Manjaro and Fedora layout, and the one most in-place
  encryption guides quietly break, because they stop at `crypttab` and the
  initramfs and never touch the `.efi` that actually boots.

## What makes it different

**It is keyed off the target, not off a distro name.** Behaviour is decided by
what is actually installed on the machine being encrypted — is `dracut` there,
or `mkinitcpio`, or `initramfs-tools`; does `/boot/loader/entries` exist; does a
preset carry a `_uki=` line; what does the target's own fstab say `/boot` and the
ESP are. Derivatives therefore
inherit support from their family without needing to be named anywhere. Fedora,
RHEL, Rocky, AlmaLinux, Debian, Ubuntu, Linux Mint, Pop!\_OS, Raspberry Pi OS,
Arch, Manjaro, EndeavourOS and openSUSE are all covered by that rule, on x86_64
and aarch64 alike.

**argon2id only, with a hard floor.** There is deliberately no pbkdf2 profile.
The three presets are 4 GiB × 10, 2 GiB × 8 and 1 GiB × 9 iterations, and the
cheapest of them is a floor the tool will not write below — there is no override
flag. A second guard measures what `cryptsetup` would have chosen unaided on
that machine and raises the iteration count past it if the hardware is fast
enough to have outrun the preset. The point is to beat a bare `luksFormat`,
never to undercut it.

**The reboot is gated.** The deploy script will not tell you to reboot until it
has re-read the LUKS header, opened the container, confirmed the inner
filesystem type and UUID are unchanged, and checked every boot-configuration
component that applies to this target. A check that does not apply is reported
as SKIP, never quietly counted as a pass.

**It is resumable, on purpose.** LUKS2 re-encryption is journaled with checksum
resilience. A power cut mid-run leaves a header carrying the `online-reencrypt`
flag; re-running the script detects that, runs `cryptsetup repair` if the
journal is dirty, finishes the re-encryption, and then redoes the configuration
work. The same entry point handles a plain filesystem, an interrupted run, a
finished LUKS2 volume and a LUKS1 volume — you never have to know which state
you are in.

**`--dry-run` is real.** It runs the entire read-only half — detection, the
fstab cross-check, the KDF benchmark, and the exact `cryptsetup` invocation it
would issue — and exits before the point of no return.

## What it deliberately does not do

- **It does not encrypt `/boot`.** The root volume is unlocked by the initramfs;
  an encrypted `/boot` would have to be unlocked by GRUB, which is far more
  constrained in what KDF cost it can afford. Weakening argon2id to fit the
  bootloader would trade a real defence for a partial one.
- **It does not enroll a TPM2, seal to PCRs, or set up network-bound unlock.**
  You type the passphrase at boot. Secure Boot is a different matter and *is*
  handled: when a target boots a Unified Kernel Image, the rebuilt `.efi` is
  re-signed with `sbctl` or `sbsign` and the signature verified before the
  reboot is allowed — because on Arch and Manjaro the usual signing hook is a
  libalpm hook that never fires when a tool rebuilds the UKI directly.
- **It does not run from the system it is encrypting.** It hard-refuses without
  a typed override, because rewriting the filesystem you are booted from is not
  a supported operation.
- **It has no backdoor.** A forgotten passphrase with no recovery key enrolled
  means the data is gone. That is the product working as designed.

## Relationship to AsahiLocker

LinuxLocker is the universal fork of
[AsahiLocker](https://github.com/doug445/AsahiLocker), which does the same job
for Fedora Asahi Remix on Apple Silicon. AsahiLocker stays the right tool on
that platform — it carries Apple-Silicon-specific boot guards (ESP stub
protection, U-Boot EFI entry cleanup) that have no meaning elsewhere.
LinuxLocker drops those and generalises everything else: the package-manager
layer, the filesystem handlers, and the boot-configuration rewriter.

**On Apple Silicon, use AsahiLocker. Everywhere else, use LinuxLocker.** You do
not have to keep that straight yourself — LinuxLocker detects Fedora Asahi Remix
and Apple Silicon hardware and exits with a link to AsahiLocker before touching
any device.

## Safety posture

This is destructive-by-nature tooling: it rewrites a live root filesystem in
place. The project's answer to that is not reassurance but machinery — the
typed `ENCRYPT` gate, the fstab cross-check on your partition selection, the
live-medium deprioritisation in the disk menu, the AC-power check, the Caps
Lock check on the passphrase prompt, the recovery keyslot, the header backups,
the resumable journal, and the verification gate before reboot. Every one of
those exists because the failure it prevents is unrecoverable.

The whole core is exercised by `tests/loopback-core-test.sh` against loop
devices — including a hard kill mid-re-encryption and a LUKS1 → LUKS2
conversion — so the recovery paths are tested, not assumed. The UKI,
systemd-boot and Secure Boot decision logic is exercised separately by
`tests/uki-fixture-test.sh` against synthetic target trees, covering every ESP
layout, every rebuild backend, every signer, and the refusal matrix. Neither
touches a real disk; both run in CI on x86_64 and aarch64.

Read [`SECURITY.md`](../SECURITY.md) before filing anything, and especially
before attaching diagnostics: the artefacts this tool produces can be the keys
themselves.

## Project facts

| | |
|---|---|
| **License** | MIT |
| **Language** | Bash — a pure shell-script project, `shellcheck -S warning` clean, no runtime dependencies a sysadmin would not already have on a rescue USB |
| **Architectures** | x86_64, aarch64 |
| **Boot stacks** | GRUB + BLS, systemd-boot, Unified Kernel Images, Secure Boot, Raspberry Pi `cmdline.txt`, U-Boot `extlinux.conf` |
| **Filesystems** | ext4/ext3/ext2, btrfs, xfs (slack only), f2fs, ntfs, vfat |
| **Cipher** | `aes-xts-plain64`, 512-bit key (AES-256-XTS) |
| **KDF** | argon2id, pinned per profile — no pbkdf2 path |
| **Requires** | `cryptsetup` ≥ 2.4 in the live environment |
| **Author** | William MacKinnon &lt;spilled-bowline0j@icloud.com&gt; |
| **Source** | https://github.com/doug445/LinuxLocker |
