# Recovery

Every failure mode below assumes you can boot a live USB for the machine.
**Never wipe, reformat or "repair-install" anything before working through
this page** — nearly every state is recoverable.

## First rule: re-run the script

`luks-deploy.sh` is re-entrant. Boot the live USB, run it again, select the
same partition, and it will land in the right mode by inspecting the header:

| On-disk state | What the re-run does |
|---|---|
| shrunk but never encrypted | detects the 32 MiB gap, skips the shrink, encrypts |
| interrupted mid-encryption (`online-reencrypt` flag) | finishes with `cryptsetup reencrypt --resume-only`; after a hard power cut it runs `cryptsetup repair` first, automatically |
| encrypted, config phase incomplete | configuration-only mode: unlocks, redoes crypttab/fstab/initramfs/bootloader, re-verifies |
| fully deployed | offers KDF tuning, config repair, or a clean exit |

## Manual resume (if you prefer to see it happen)

```bash
cryptsetup reencrypt --resume-only /dev/<rootpart>
# "Device requires reencryption recovery. Run repair first."?
cryptsetup repair /dev/<rootpart>
cryptsetup reencrypt --resume-only /dev/<rootpart>
```

## System won't boot after deployment

From the live USB:

```bash
cryptsetup open /dev/<rootpart> root_crypt
mount /dev/mapper/root_crypt /mnt                    # btrfs: -o subvol=<name>
# mount /boot, EFI and/or firmware partitions as the target's fstab lists them
for i in dev dev/pts proc sys run; do mount --bind /$i /mnt/$i; done
chroot /mnt /bin/bash
```

Inside the chroot, check in this order:

1. `/etc/crypttab` — one line: `root_crypt UUID=<luks-uuid> none luks,discard`
   (Debian-family: `...,initramfs`).
2. `/etc/fstab` — root on `/dev/mapper/root_crypt`.
3. The kernel arguments for your initramfs style:
   - dracut: `rd.luks.uuid=<uuid> rd.luks.name=<uuid>=root_crypt`
   - mkinitcpio (busybox): `cryptdevice=UUID=<uuid>:root_crypt`
   - mkinitcpio (systemd): `rd.luks.name=<uuid>=root_crypt`
   - initramfs-tools: none needed — crypttab drives it
   - Raspberry Pi: `cmdline.txt` must say `root=/dev/mapper/root_crypt`
4. Rebuild the initramfs:
   - `dracut --regenerate-all --force`
   - `update-initramfs -u -k all`
   - `mkinitcpio -P`
5. Regenerate the bootloader config (`update-grub`, `grub2-mkconfig -o
   /boot/grub2/grub.cfg`, or `grubby --update-kernel=ALL --args="..."`).

Every file the deployment changed has a `.pre-luks` sibling with the
original contents.

## Corrupt LUKS header

Backups exist in up to three places:

- `/boot/luks-header-backup.img` on the target (unencrypted /boot)
- `pre-luks-state-<timestamp>/luks-header-backup.img` on the kit drive
- `LUKS-RECOVERY-<host>-<timestamp>/` bundles made by
  `save-luks-recovery-bundle.sh`

```bash
cryptsetup luksHeaderRestore /dev/<rootpart> --header-backup-file <backup.img>
```

A header backup contains key **slots**, not your key — it cannot decrypt
anything without the passphrase, but treat it as private anyway.

## Forgotten passphrase

If a recovery key was enrolled (`recovery-key.txt`, 64 hex characters):
type/paste it at the boot prompt, or from a live USB:

```bash
cryptsetup open /dev/<rootpart> root_crypt --key-file recovery-key.txt
```

Then set a new passphrase: `cryptsetup luksAddKey /dev/<rootpart>
--key-file recovery-key.txt`, and remove the old slot with `luksKillSlot`.

No recovery key and no passphrase = no data. There is no bypass; that is the
security property you installed.

## LUKS1 conversion went sideways

`convert_luks1` backs up the LUKS1 header to the kit drive before touching
anything (`pre-luks-state-*/luks1-header-backup.img`). Restoring it returns
the volume to exactly its pre-conversion state:

```bash
cryptsetup luksHeaderRestore /dev/<part> --header-backup-file luks1-header-backup.img
```

A keyslot that failed to re-cost to argon2id is still a working pbkdf2 slot —
convert it later with `luks-tune.sh` or
`cryptsetup luksConvertKey -S <slot> --hash sha512 --pbkdf argon2id /dev/<part>`.
Keep the `--hash sha512`: without it cryptsetup falls back to `sha256` and the
slot's AF hash comes out lower than the one `linuxlocker.sh` formats with.

## Splash never came back

`post-encryption-setup.sh` restores the stripped `rhgb`/`quiet`/`splash`
tokens and keeps the marker (`/var/lib/linuxlocker/restore-splash`) if the
restore fails, so re-running it retries. To do it by hand, add the tokens back
to your bootloader's kernel arguments and regenerate its config.
