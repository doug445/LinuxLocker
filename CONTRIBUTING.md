# Contributing to LinuxLocker

**LinuxLocker 1.2.0**

This project rewrites a live root filesystem and its bootloader. Every added
code path is a path that can lose someone's disk, and there is one maintainer to
be sure it does not. Scope is therefore narrow on purpose.

| | |
|---|---|
| **Wanted** | Test reports from boot stacks I cannot reach — see below |
| **Wanted** | Serious bugs, with a diagnostic bundle |
| **Wanted** | New filesystem support |
| **Declined** | Refactors, new options, general feature requests — regardless of quality |

---

## Most wanted: test reports from other setups

The encryption core is exercised against loop devices in CI on every push, and
the UKI / systemd-boot / Secure Boot decision logic is exercised against fixture
trees. What neither can prove is that a **real machine boots afterwards**.

Every row marked below is a configuration the code claims to handle and that has
not been confirmed on metal by me. **A report that it worked is as valuable as a
bug report** — it is the only way these rows ever get ticked.

### Boot stacks

| Setup | Status | What to confirm |
|---|---|---|
| GRUB + BLS (Fedora / RHEL / Rocky / Alma) | long-standing path | still worth a report |
| GRUB + `update-grub` (Debian / Ubuntu / Mint) | long-standing path | still worth a report |
| GRUB + `grub-mkconfig` (Arch / Manjaro) | long-standing path | still worth a report |
| **systemd-boot, Type #1, ESP at `/boot`** | **untested on metal** | entries gained `rd.luks.*`; machine boots |
| **systemd-boot, Type #1, ESP at `/efi` + XBOOTLDR `/boot`** | **untested on metal** | V13 passes; the old "no recognised bootloader" warning does *not* fire |
| **UKI via mkinitcpio preset (`_uki=`)** | **untested on metal** | `.cmdline` of the rebuilt `.efi` carries `rd.luks.*` |
| **UKI via `kernel-install` (`layout=uki`)** | **untested on metal** | same, plus that each kernel got its own `.efi` |
| **UKI via `dracut --uki-file`** | **untested on metal** | same |
| **UKI via `ukify`** | **untested on metal** | same; this path needs a standalone initramfs to exist |
| **Secure Boot + UKI, signed with `sbctl`** | **untested on metal** | `sbctl verify` lists the rebuilt `.efi`; firmware accepts it |
| **Secure Boot + UKI, signed with `sbsign`** | **untested on metal** | `sbverify --list` shows a signature; firmware accepts it |
| **Secure Boot + shim + GRUB, no UKI** | **untested on metal** | genuinely no interaction; `mokutil --sb-state` unchanged |
| **pesign / NSS targets (Fedora Secure Boot)** | refused by design | that the refusal fires and names pesign |
| Raspberry Pi OS `cmdline.txt` | untested on metal | `root=` points at the mapper; `auto_initramfs=1` present |
| U-Boot `extlinux.conf` (ARM SBCs) | untested on metal | `APPEND` rewritten; board boots |

### Filesystems

| Filesystem | Status |
|---|---|
| ext4 / ext3 / ext2 | exercised in CI against loop devices |
| btrfs (incl. subvolume layouts) | exercised in CI against loop devices |
| xfs (slack-only path) | untested on metal |
| f2fs | untested on metal |
| ntfs / vfat (data partitions) | untested on metal |

### Architectures

x86_64 and aarch64 both run the full CI suite. aarch64 **hardware** deployment
(Raspberry Pi, other SBCs, ARM laptops) is untested on metal.

### How to file a test report

Open an issue titled `Test report: <boot stack> on <distro>` with:

1. the diagnostic bundle (below), collected **after** the deployment;
2. whether the machine booted, and how many attempts it took;
3. anything you had to fix by hand — that is the actual finding.

A `--dry-run` report is useful too, and costs nothing: it exercises all of
detection without touching the disk. Say so in the title if that is what it is.

---

## The diagnostic bundle

Almost every bug here is a boot-configuration bug, and a description of what
went wrong is rarely enough to act on. There is a script that collects
everything needed, formatted as Markdown to paste straight into an issue:

```bash
sudo ./bin/linuxlocker-diag.sh -o linuxlocker-report.md
# or, equivalently:
sudo ./bin/linuxlocker.sh diag -o linuxlocker-report.md
```

It collects: the live environment's OS and tool inventory, `lsblk -f`, firmware
and Secure Boot state, the target's `fstab` / `crypttab` / `kernel/cmdline` /
GRUB defaults, the initramfs generator's configuration and presets, every
bootloader entry, the **baked-in `.cmdline` of every UKI**, each UKI's signature
status, what LinuxLocker's own detection *thinks* it found, public LUKS header
metadata, and the relevant journal lines.

**It only reads.** It mounts nothing read-write and runs no `cryptsetup`
subcommand that touches key material.

Useful flags:

| Flag | Effect |
|---|---|
| *(default)* | UUIDs truncated to 8 characters — enough to correlate lines in one report, not enough to fingerprint your disks |
| `--no-redact` | keep UUIDs whole; only for a private report |
| `-o FILE` | write to a file instead of stdout |
| `/dev/sdXN` | also `luksDump` that specific partition |

If the diagnostic section headed *"What LinuxLocker's own detection reports"*
disagrees with the raw output above it in the same file, **that disagreement is
the bug**, and it is the single most useful thing you can send.

### What never to attach

The bundle already excludes these, and you should not add them by hand:

- `cryptsetup luksDump --dump-master-key` output — that is the volume key
- LUKS header backups (`*.img`) — every keyslot, offline-attackable
- `recovery-key.txt`, or any key file — a working credential
- the recovery bundle from `save-luks-recovery-bundle.sh` — the same, packaged

`luksDump` **without** `--dump-master-key` is public header metadata and is safe.
[SECURITY.md](SECURITY.md) has the full list and the reasoning.

---

## What counts as a serious bug

- Data loss, or a plausible path to it.
- A machine that does not boot after a run the tool reported as verified.
- A verification check that passes when it should fail — the silent-pass class,
  which is what the UKI work in 1.2.0 existed to close.
- A refusal that fires on a configuration that is actually fine, blocking a
  legitimate deployment.
- Detection reporting one thing while the system is demonstrably another.

Not serious: cosmetic output, a wish for a flag, a preference about defaults.

## Reporting one

Say which distro you ran the tool **from** and which distro you ran it
**against** — those are different code paths through the same script, and half
of all reports omit one of them.

Include:

1. the diagnostic bundle;
2. `--dry-run` output if you still can (it is read-only, so it is usually
   possible even after a failure);
3. the exact command line and any `LUKS_*` variables you set;
4. what you expected, and what happened.

## Adding filesystem support

A filesystem handler has to answer four questions, and a pull request that
cannot answer all four will not merge:

1. **Can it shrink in place?** If not, can it report existing free space at the
   *end* of the partition, so the slack-only path can accept it?
2. **How much slack does it need**, and how is that measured without mounting
   read-write?
3. **What tool does the shrink**, what package provides it on each family, and
   what is the minimum version?
4. **How is the grow-back verified?** A handler that shrinks but cannot prove it
   grew back is worse than no handler.

Add it to `tests/loopback-core-test.sh` in the same pull request. A handler
without a loopback test is a handler nobody can regression-test, and it will be
declined however correct it looks.

## Before opening a pull request

Run what CI runs:

```bash
shellcheck -S warning $(git ls-files '*.sh') extras/bin/luks-fetch-cache
sudo bash tests/loopback-core-test.sh      # expect 29 passed, 0 failed
bash tests/uki-fixture-test.sh             # expect 0 failed
```

On a machine that boots a UKI, run the fixture suite **as root** as well:
section 10 self-checks detection against that real system and will tell you if
your change broke it.

Requirements for any patch:

- `bash -n` clean and `shellcheck -S warning` clean. Both are enforced in CI.
- No new runtime dependency. This is a pure shell-script project so it runs from
  a minimal rescue environment; a recovery tool that needs a language runtime
  installed first is a recovery tool you cannot use when you need it.
- Comments explain **why**, not what. The existing code is dense with reasons
  for non-obvious choices; match that.
- Anything that can fail must fail loudly. A check that does not apply reports
  SKIP; it is never silently counted as a pass. That invariant is the whole
  safety model — do not weaken it for a tidier output.

## Testing

`tests/loopback-core-test.sh` exercises the encryption core against file-backed
loop devices: shrink guards, in-place re-encryption, `--resume-only`, a hard kill
mid-re-encryption followed by `cryptsetup repair`, recovery keys, the ext4 path,
and LUKS1 → LUKS2 conversion. It needs root and touches no real disk.

`tests/uki-fixture-test.sh` exercises the UKI, systemd-boot and Secure Boot
logic against synthetic target trees: every ESP layout, every rebuild backend,
every signer, the refusal matrix, `.cmdline` round-trips through a real PE
binary, and the Fedora Asahi Remix guard. It needs neither root nor a disk.

Both run in CI on x86_64 and aarch64 for every push.

## Security issues

**Do not open an issue.** Read [SECURITY.md](SECURITY.md) first — the recovery
key, the header backups and the recovery bundle are key material, not
diagnostics.

## Apple Silicon

Bugs about Fedora Asahi Remix belong in
[AsahiLocker](https://github.com/doug445/AsahiLocker), not here. LinuxLocker
detects Asahi and Apple Silicon hardware and refuses before touching any device;
if that refusal *fails to fire* on an Asahi system, that is a LinuxLocker bug and
a serious one — please report it here with a diagnostic bundle.

## Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
