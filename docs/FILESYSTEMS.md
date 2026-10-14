# Filesystem support matrix

LinuxLocker's in-place encryption needs 32 MiB at the end of the partition for
the LUKS2 header (`cryptsetup reencrypt --reduce-device-size 32M`). Whether a
filesystem is supported in place therefore comes down to one question: **can
it be shrunk by 32 MiB, or does it already have that much slack?**

Everything gnome-disks can format is classified below.

| Filesystem | In place? | Shrink tool | Size probe (idempotency guard) | Notes |
|---|---|---|---|---|
| ext4 / ext3 / ext2 | ✅ | `resize2fs` (offline, after a repairing `e2fsck -f -p`, then `-y`) | `dumpe2fs` block count × block size | grow-back via `resize2fs` with no size argument |
| btrfs | ✅ | `btrfs filesystem resize -32M` (mounted) | `dump-super total_bytes` | subvolume layouts (`root`, `@`, `@rootfs`, flat) auto-detected; grow via `resize max` |
| xfs | ⚠️ slack only | **none — XFS cannot shrink** | `xfs_db` dblocks × blocksize | accepted only when ≥ 32 MiB of slack already exists between filesystem end and partition end; grow via `xfs_growfs` |
| f2fs | ✅ | `resize.f2fs -t` (needs f2fs-tools ≥ 1.16), after a repairing `fsck.f2fs -f` | none — the script asks on re-runs whether a previous shrink completed | common on SBC/flash installs |
| ntfs | ✅ | `ntfsresize --size` | `ntfsresize --info` | data partitions; the resize marks the volume for a consistency check on the next Windows boot (normal) |
| vfat | ✅ | `fatresize` | none — asks on re-runs | data partitions / firmware copies |
| exfat | ❌ | no shrink tool exists | — | back up → `mkfs.exfat` on a LUKS container → restore |
| udf | ❌ | no shrink tool exists | — | same workaround as exfat |
| swap | ❌ (by design) | — | — | swap holds no data worth an in-place conversion; see below |

## The integrity check

Before anything is changed, a real run offers to check the target
filesystem (`LUKS_FSCK=yes|no`; a dry run skips it). The check is read-only
for every filesystem: no checker runs in a mode that can repair, and none is
handed your keyboard — stdin is closed, so no fix question can be answered.

| Filesystem | Check |
|---|---|
| ext4 / ext3 / ext2 | `e2fsck -f -n` |
| btrfs | `btrfs check --readonly` |
| xfs | `xfs_repair -n` |
| f2fs | `fsck.f2fs --dry-run` |
| ntfs | `ntfsfix --no-action` |
| vfat | `fsck.fat -n` |

- **Errors** are reported and nothing is repaired; the run stops unless you
  type `FORCE` (`LUKS_FSCK_FORCE=FORCE`). If you go on, know that the shrink
  that follows runs a repairing check of its own, because its tools need a
  consistent filesystem — ext2/3/4 `e2fsck -f -p` and then `e2fsck -f -y`,
  f2fs `fsck.f2fs -f` — unless an earlier run already shrank it. Both repair
  what they find; the `FORCE` prompt says so.
- **No read-only checker on this machine** — a `fsck.f2fs` without
  `--dry-run`, an `ntfsfix` without `--no-action`, a missing tool — and the
  check is skipped with a warning that says why. It never falls back to a
  repairing mode, as f2fs's did until 1.6.7 (`fsck.f2fs -a`).

## System vs data partitions

- A partition containing `/etc/fstab` is treated as an **installed system**:
  the full boot-configuration phase runs (crypttab, fstab, initramfs,
  bootloader) and the verification gate covers every applicable component.
- A partition without one is offered as a **data partition**: same encryption,
  recovery key and header backup, but no boot configuration. Afterwards, add
  it to whatever system mounts it:

  ```
  # /etc/crypttab on the host
  mydata UUID=<luks-uuid> none luks,discard,nofail

  # /etc/fstab on the host
  /dev/mapper/mydata  /srv/data  ext4  defaults,nofail  0 2
  ```

## Encrypted swap

Don't convert a swap partition in place — there is nothing in it to preserve.
Give it a random key each boot instead:

```
# /etc/crypttab
swap  /dev/disk/by-partuuid/<partuuid>  /dev/urandom  swap,cipher=aes-xts-plain64,size=512

# /etc/fstab
/dev/mapper/swap  none  swap  defaults  0 0
```

(Use the by-partuuid path, not by-uuid — the swap UUID changes every boot.)
Note this is incompatible with hibernation; hibernating systems need a
passphrase- or keyfile-unlocked swap enrolled like any other LUKS volume.

## XFS in practice

XFS genuinely cannot shrink — this is a filesystem limitation, not a tooling
gap. Your options, in order of preference:

1. **Grow the partition** by 32 MiB if unallocated space follows it
   (`parted resizepart`), then run LinuxLocker — the slack check will pass.
2. **Recreate slightly smaller from a backup**: `xfsdump`, `mkfs.xfs` on a
   partition 32 MiB under-sized (`mkfs.xfs -d size=...`), `xfsrestore`, then
   run LinuxLocker.
3. Reinstall onto LUKS directly if the distro installer supports it.
