# Installation & walkthrough

## What you need

- The target machine, with its Linux install intact and **backed up**.
- A **separate, unencrypted `/boot` partition** if the machine boots with GRUB
  or extlinux. Fedora-family installs always have one; Debian, Ubuntu and
  openSUSE defaults often keep `/boot` on the root filesystem, and LinuxLocker
  refuses those before touching anything — encrypting them would make GRUB
  itself responsible for the unlock, which this tool never sets up (see
  [BOOTLOADERS.md](BOOTLOADERS.md#encrypted-boot)). UKI, systemd-boot and
  Raspberry Pi targets keep their kernel on the ESP or firmware partition and
  are fine without one.
- A live USB for that machine. The safest choice is the target distro's own
  live ISO (it guarantees kernel + filesystem tool compatibility); any live
  Linux with `cryptsetup ≥ 2.4` available works.
- A second USB drive (or the live USB's writable area) holding this
  repository — logs, pre-encryption state and the recovery key are written
  next to the scripts, so put the kit on media that survives a reboot, not in
  the live session's tmpfs.
- AC power on laptops.

## 1. Get the kit

On any machine:

```bash
git clone https://github.com/doug445/LinuxLocker.git
# put it on the USB drive you'll have plugged in during the run
```

## 2. Boot the live environment

Boot the live USB with the kit drive plugged in. Open a terminal, become
root-capable, and mount the kit drive if the desktop hasn't already.

## 3. Run it

```bash
sudo /path/to/LinuxLocker/bin/linuxlocker.sh
```

`linuxlocker.sh` will:

1. Print what it detected — live OS, family, package manager, architecture.
2. Install any missing core tools (cryptsetup, util-linux) with the detected
   package manager.
3. Launch `luks-deploy.sh`.

The deploy script then walks you through:

- **Partition selection** — a scored menu (internal disks preferred, the live
  USB's own disk deprioritised). Pick the root partition of the installed
  system. Boot/EFI/firmware partitions are then resolved automatically from
  the target's own fstab.
- **Filesystem identification** — the filesystem's tools are auto-installed
  the moment the type is known (e.g. `e2fsprogs` for ext4, `ntfsprogs` for
  NTFS).
- **Integrity check** — optional read-only fsck before anything changes.
- **KDF profile** — aggressive / moderate / fast, with unlock-time estimates
  benchmarked on the machine in front of you.
- **The `ENCRYPT` gate** — a typed confirmation. Immediately before
  `cryptsetup` asks for the passphrase, the script asks you to type `yes` in
  lower case: that cannot be entered with Caps Lock on, so accepting it is the
  proof the passphrase you are about to set is the one you think it is.

Everything after that is automated: shrink, in-place encryption, verification
of the inner filesystem, boot configuration, initramfs rebuilds, and the
final verification gate. **Do not reboot if the gate reports errors** — it
prints exactly what failed.

Want a rehearsal first? `sudo ./bin/linuxlocker.sh deploy --dry-run` runs all
of the detection and prints the exact plan, changing nothing.

## 4. First boot

Reboot into the installed system. The passphrase prompt appears early — the
script strips the boot splash (`rhgb quiet splash`) so the prompt is visible;
if the screen looks hung, just type the passphrase and press Enter.

## 5. Finish on the encrypted system

```bash
sudo /path/to/LinuxLocker/bin/post-encryption-setup.sh
```

This saves a labeled recovery bundle, restores the splash arguments, sets up
snapper snapshot subvolumes (btrfs roots with snapper installed), and
verifies the system end-to-end. Then:

- **Move the recovery key and header backup to secure offline storage.** They
  were written to the kit drive (`pre-luks-state-*/`) — anyone holding them
  can unlock the disk.
- Take a fresh backup: the old one predates crypttab/fstab changes.

## Non-interactive / fleet use

Every prompt has an environment override — see the header of
`bin/luks-deploy.sh` or the README's knob table. A fully pinned run looks
like:

```bash
sudo LUKS_TARGET_ROOT=/dev/nvme0n1p3 \
     LUKS_TARGET_BOOT=/dev/nvme0n1p2 \
     LUKS_TARGET_EFI=/dev/nvme0n1p1 \
     LUKS_PROFILE=moderate \
     LUKS_PASSPHRASE_FILE=/run/secret/pass \
     LUKS_RECOVERY_KEY=yes \
     ./bin/luks-deploy.sh
```

(The typed `ENCRYPT` gate remains; it is the consent step.)

## If anything goes wrong

Re-run the script — every state is re-entrant (interrupted encryption
resumes; a broken config phase re-runs idempotently). Details and manual
procedures: [RECOVERY.md](RECOVERY.md).
