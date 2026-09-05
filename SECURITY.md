# Security Policy

**LinuxLocker 1.2.0**

## Supported Versions

LinuxLocker is maintained by one person and carries no backport branches. Fixes
land on `main` and go out in the next tagged release. Only the newest release is
supported; there is no long-term-support line and older tags do not receive
patches.

| Version | Supported |
| ------- | --------- |
| `main` | :white_check_mark: fixes land here first |
| Newest tagged release | :white_check_mark: |
| Any earlier tag | :x: upgrade to the newest release |

The [releases page](https://github.com/doug445/LinuxLocker/releases) lists every
tag, newest first, and each release's notes record what changed in it. This
project keeps that history in the release notes rather than in a
`CHANGELOG.md`.

If you are running a checkout you pulled weeks ago, `git pull` and retry before
reporting — the issue may already be fixed. Include what you are running:

```bash
git -C /path/to/LinuxLocker describe --tags --always --dirty
```

A `-dirty` suffix means the working tree has local modifications, and a hash
with no tag means the checkout is somewhere between releases. Say so in the
report either way — it changes what I can reproduce.

Say which distro you ran it **from** and which distro you ran it **against**.
LinuxLocker keys its behaviour off what is installed on the target, not off a
distro name, so "Arch live USB against Debian 13" and "Fedora live USB against
Fedora 44" are different code paths through the same script.

## Reporting a Vulnerability

I take the security of LinuxLocker seriously. If you discover a security
vulnerability, please do not open a public issue.

Instead, please report it privately by emailing the report to: spilled-bowline0j@icloud.com

**What to expect:**
* **Acknowledgment:** You will receive an initial response to your report within 72 hours.
* **Updates:** I will keep you informed of my progress as I investigate the issue and develop a fix.
* **Resolution:** If the vulnerability is accepted, I will address it promptly in a new release and notify you. If declined, I will provide a clear explanation of my reasoning.

Please include as much detail as possible in your email, including steps to
reproduce. Read [Before you send diagnostics](#before-you-send-diagnostics)
first — this project's output can contain key material.

## What is in scope

This tooling runs as root from a live environment, rewrites every sector of a
root partition in place, enrolls keyslots, and edits `crypttab`, `fstab`, GRUB
defaults, BLS entries, `cmdline.txt`, `extlinux.conf`, the initramfs generator's
config and every initramfs image on the target. A mistake here does not degrade
a feature — it loses a disk, bricks a boot, or hands a volume over. That is the
interesting surface:

* **Key material going somewhere it should not.** The recovery key file, the
  LUKS header backups, and anything read from `LUKS_PASSPHRASE_FILE`. A secret
  written world-readable, left on a filesystem the user did not choose, echoed
  into the deployment log or the journal, or passed on a command line where `ps`
  can see it is a real finding.
* **`harden_path` not warning when it cannot harden.** `chmod` succeeds and
  does nothing on vfat/exfat/ntfs — the mode comes from the mount's `fmask`, not
  the inode — and the recovery key and header backup land on the deployment
  drive, which is very often exactly such a stick. The script sets the mode,
  reads it back, and warns loudly when it did not take. That read-back silently
  passing, or the warning not firing, is in scope: it is the difference between
  a key at `0400` and a key anyone who picks the drive up can read.
* **Weakening the crypto without saying so.** Falling back to pbkdf2, enrolling
  a keyslot below the documented argon2id floor, or reporting parameters that
  are not the ones actually written to the header. The `fast` profile's floor is
  a hard floor by design and is not meant to be reachable from outside;
  `LUKS_PBKDF_ACK_WEAK` widening past what it documents is a finding, as is the
  stock-strength check failing to raise a profile that a fast machine has
  outrun.
* **A verification gate that passes when it should not.** `luks-deploy.sh` gates
  the reboot behind its verification pass; `post-encryption-setup.sh` verifies
  the result. Either reporting success on a system that is not actually
  encrypted, or that will not boot, is a vulnerability and not a cosmetic bug.
  **A SKIP counted as a PASS is the same bug**: a check that does not apply to
  this target must be reported as SKIP, and a check that applies and did not run
  must never be reported as either.
* **Writing to the wrong device.** Anything that touches a disk other than the
  detected target — in particular the live medium the script is running from,
  another install's ESP, or a Windows/macOS partition, none of which this
  tooling has any business modifying. The live-USB deprioritisation in the
  partition menu and the cross-check of your selection against the target's own
  fstab are both security controls, not conveniences.
* **Boot partitions resolved to the wrong volume.** `/boot` and the ESP are
  resolved from the *target's* fstab by UUID, PARTUUID or LABEL. Resolving those
  to another system's volumes means rewriting another system's bootloader.
* **A resume that resumes the wrong thing.** `--resume-only`, the
  `online-reencrypt` flag detection, and the automatic `cryptsetup repair` after
  a hard kill acting on a device or header that does not match the state the
  interrupted run recorded.
* **The encrypted-`/boot` recogniser being wrong in the unsafe direction.**
  `lib-boot.sh` decides from the GRUB images on the disk and the volume's own
  layout whether GRUB itself unlocks a volume, whether that GRUB reads LUKS2,
  and whether it embeds the argon2 module. A false "GRUB does not unlock this"
  lets the LUKS1 conversion or `luks-tune.sh` write a header or keyslot GRUB
  cannot open; a false "argon2 supported" does the same; and a target whose
  `/boot` lives inside the volume being encrypted must be refused before the
  shrink. Any of those firing late, not firing, or being bypassable is in scope.
* **A command-line carrier missed or corrupted.** Every file that carries a
  kernel command line — GRUB defaults and `grub.d` drop-ins, BLS/systemd-boot
  entries in any ESP layout, `/etc/kernel/cmdline`, `cmdline.d`, `cmdline.txt`,
  `extlinux.conf`, `refind_linux.conf`, `limine.conf` — must end up pointing
  `root=` at the mapper and carrying the unlock arguments, and a file the
  rewriter does not understand must be left byte-identical. Check V14 reads them
  back; a carrier that passes V14 and still boots the raw partition is a bug.
* **A filesystem handler shrinking what it must not.** The 32 MiB header gap is
  taken by `resize2fs`, `btrfs filesystem resize`, `resize.f2fs`, `ntfsresize`
  or `fatresize` depending on the target. xfs cannot shrink and is accepted only
  with pre-existing slack; anything that shrinks an xfs volume, shrinks past the
  used extent, or proceeds when the probe could not confirm the new size is a
  data-loss bug, not a resize bug.
* **The dependency installer trusting the wrong thing.** `lib-deps.sh` runs
  dnf, apt, pacman, zypper, apk, xbps or emerge as root — in the live
  environment, and inside the chroot when it installs `cryptsetup-initramfs`. A
  repository added without signature checking, a package pulled from an
  unverified source, or an install that lands in the wrong root is in scope.
* **A Unified Kernel Image that is not what it claims to be.** The `.efi` is
  the object the firmware actually loads; `crypttab`, `/etc/kernel/cmdline` and
  the standalone initramfs are not. A run that rebuilds every one of those
  correctly and leaves a stale `.efi` in place produces an unbootable machine
  from a green report — the exact silent-pass class this project treats as a
  vulnerability. Check V11 reads the `.cmdline` section back out of each rebuilt
  UKI; V11 passing on a UKI that does **not** carry the LUKS arguments, or being
  skipped when it could have run, is in scope.
* **An unsigned UKI on a Secure Boot machine.** Rebuilding a UKI invalidates its
  signature, and distro signing automation does not fire from a chroot — Arch's
  `zz-sbctl.hook` is a libalpm hook, so a bare `mkinitcpio -P` rebuilds the image
  and leaves it unsigned. Step 7g signs it and check V12 verifies that. V12
  reporting a signed image that is not signed, or the deployment proceeding past
  a failed signing with Secure Boot enabled, is a finding: the result is a
  machine the firmware refuses to boot at all.
* **A UKI refusal that fails to fire.** The two remaining refusals — no rebuild
  backend, and Secure Boot enabled with no signer — run before the shrink and
  before encryption, while aborting is still free. Either of them not firing on
  a target that meets its condition is in scope, as is `sbctl` being claimed as
  a signer when it has no key directory (it exits 0 having signed nothing).
* **The Apple Silicon guard not guarding.** Fedora Asahi Remix and Apple Silicon
  hardware are detected and refused before any device is touched, because this
  tool drops the boot guards AsahiLocker carries. That refusal failing to fire
  on an Asahi system is a serious bug, not a missing feature.
* **The diagnostic bundle leaking key material.** `linuxlocker-diag.sh` is
  read-only and is meant to be pasted into a public issue. Anything resembling
  key material appearing in its output — a master key, header-backup contents,
  a key file's contents, a passphrase — is a finding, and so is the UUID
  redaction failing to apply when it was not disabled with `--no-redact`.
* **A read-only tool that writes.** `luks-tune.sh` must never create or destroy
  a keyslot, change a passphrase, or touch data; `--dry-run` anywhere must reach
  no point of no return; `extras/luks-fetch-cache` must read public header
  metadata and nothing else, and its cache at `/var/cache/luks-fetch.txt` is
  world-readable by design, so anything resembling key material appearing in it
  is a finding; `bin/linuxlocker-diag.sh` must mount nothing read-write and
  modify nothing; `tests/loopback-core-test.sh` must touch no real disk, and
  `tests/uki-fixture-test.sh` must touch no disk at all.

## What is out of scope

* **Bugs in the software LinuxLocker drives** — `cryptsetup`, LUKS2, the argon2
  implementation, GRUB, U-Boot, systemd, dracut, mkinitcpio, initramfs-tools,
  `grubby`, SELinux, and every resize tool named above. Report those upstream.
* **`/boot` being unencrypted**, and the evil-maid class of attack that permits.
  LinuxLocker encrypts the root volume and leaves the boot chain readable. That
  is the documented boundary of what this tool does, not an oversight — an
  encrypted `/boot` has to be unlocked by GRUB, which is far more KDF-constrained
  than the initramfs, and the answer to that is not to weaken the KDF.
* **Having to type the passphrase at every boot.** There is no TPM enrollment,
  no Secure Boot binding and no network-bound unlock here. Those are features
  this tool does not implement, not vulnerabilities in what it does.
* **A forgotten passphrase, or a lost recovery key.** There is no backdoor. That
  is the product working.
* **A weak passphrase you chose.** The README covers what the KDF can and cannot
  buy you here.
* **A boot stack this tool does not handle.** A distro or bootloader outside the
  supported matrix is a feature request. It becomes a finding only if the
  verification gate calls that target verified.
* **exfat, udf and swap being refused in place.** Documented in
  [`docs/FILESYSTEMS.md`](docs/FILESYSTEMS.md), with the workarounds.

## Before you send diagnostics

**Read this one.** Unlike a networking tool, the artifacts this project produces
can be the keys themselves.

**Use the diagnostic bundle rather than assembling one by hand.** It is built to
be safe to paste in public: it never runs `--dump-master-key`, never reads a key
file's contents, and truncates UUIDs to eight characters unless you pass
`--no-redact`.

```bash
sudo ./bin/linuxlocker-diag.sh -o linuxlocker-report.md
```

Read the file before you post it. The script is careful, but you are the last
check on what leaves your machine — and for a **security** report, send it to
the email address above rather than attaching it to an issue.

* **Never send a LUKS header backup.** Not `/boot/luks-header-backup.img`, not
  the copy on the deployment drive, not one from a recovery bundle. It carries
  your keyslots. They are argon2id-protected rather than plaintext, but sending
  one hands an attacker everything they need to start guessing offline, with no
  access to your machine required. There is no bug report that needs it.
* **Never send a recovery key or a passphrase**, and never send the
  `LUKS_PASSPHRASE_FILE` you pointed the script at.
* **`cryptsetup luksDump` output is safe to share** — it prints parameters, not
  key material. **Never add `--dump-master-key`**, which prints exactly that.
* **Recovery bundles are not diagnostics.** They are built to unlock the volume.
  Send the piece you are asking about, never the bundle.
* **Read the deployment log before attaching it.** `luks-deploy-*.log` sits next
  to the script on the deployment drive and carries device paths, UUIDs and your
  partition layout. Usually fine to send, occasionally more than you meant to.
* **`luks-fetch-cache` output is metadata only** — KDF, cipher, protectors — and
  is safe to paste.

Send the smallest thing that demonstrates the problem.
