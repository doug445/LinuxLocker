# Tested systems

The machines behind the ✅ claims: a row here has had a real in-place
encryption and boots from it, or an end-to-end run of the script on a disk
image that was then booted. Nothing is listed on the strength of a dry run or
a unit test alone — those are the loopback and fixture suites below. Same
format as [linux-backup-system's](https://github.com/doug445/linux-backup-system/blob/main/docs/TESTED-SYSTEMS.md).

| Distro (arch) | Machine | Layout | Verified |
|---|---|---|---|
| Manjaro (x86_64) | 2019 ASUS ZenBook UX534FTC (i7-10510U, 4 cores / 8 threads, 16 GiB RAM, 2 TB NVMe) | btrfs root (`@` / `@home` / `@cache`, snapper, swapfile) on LUKS2 argon2id **`aggressive`** (4 GiB × 10) unlocked by sd-encrypt (`rd.luks.name=`), vfat XBOOTLDR `/boot` + ESP at `/efi`, systemd-boot + UKIs from mkinitcpio, Secure Boot with sbctl keys, Linux 6.18 LTS, cryptsetup 2.8.7 | **runs `aggressive` in production ✅** — the reference machine: **35.7 CPU-seconds per unlock, mean over 56 real boots** from the journal's per-unit accounting, ~16 s wall; every unlock figure in the README's KDF table is from this machine. The UKI path — `LUKS_ALLOW_UKI`, the mkinitcpio/kernel-install/dracut/ukify rebuild backends, sbctl/sbsign signing, the V11 embedded-command-line gate — was written for it |
| Fedora Asahi Remix 44 (aarch64) | 2023 MacBook Pro 14" (M2 Max) | the same code path in [AsahiLocker 1.12.1](https://github.com/doug445/AsahiLocker/blob/main/docs/TESTED-SYSTEMS.md): a plain copy of the system on a 60 GiB loop image, encrypted in place with the partition-end alignment and 4096-byte sectors, `ALL CHECKS PASSED`, booted in QEMU with the passphrase to a login prompt in 40 s | **end-to-end on a test image ✅ — 2026-09-19** (AsahiLocker's run; LinuxLocker's own end-to-end run on a system image is the next thing to do) |

The loopback suite (`tests/loopback-core-test.sh`, 44 checks) runs on every
push on x86_64 and aarch64 runners: btrfs and ext4 shrink, in-place reencrypt
with the script's exact flags, header and content survival, recovery-key
enrolment with the AF hash pinned, resume after `--init-only` and after a
hard kill, LUKS1 → LUKS2 conversion and argon2id re-costing, 4096-byte
sectors on a 4Kn and a 512-byte device, and the GPT-tail alignment run by the
script's own function against an ext4 partition ending on the reserved tail.
`tests/uki-fixture-test.sh` and `tests/cmdline-fixture-test.sh` cover the
UKI and command-line rewrites against synthetic trees. None of these is a
boot.
