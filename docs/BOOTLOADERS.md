# Bootloaders: GRUB, systemd-boot, UKIs and Secure Boot

LinuxLocker keys every decision off what is **installed on the target**, never
off the distro's name. This document covers what each boot stack gets, and
where the remaining sharp edges are.

> **Status.** The GRUB / BLS / U-Boot paths are the long-standing ones. UKI,
> systemd-boot and Secure Boot support landed in 1.2.0 and is verified by
> `tests/uki-fixture-test.sh` — 45 assertions across every ESP layout, rebuild
> backend and signer combination, plus a live self-check against a real
> UKI + Secure Boot machine. It has **not** yet been through a full
> encrypt-and-reboot cycle on hardware. The checklist at the end is what turns
> that into "tested on metal".

## What a deployment touches

| Detected | Set from | Written by |
|---|---|---|
| GRUB config generator | `update-grub` / `grub2-mkconfig` / `grub-mkconfig` on the target | stage 6c (`/etc/default/grub`), step 7d (regenerate `grub.cfg`) |
| `grubby` | `command -v grubby` in the chroot | step 7c (BLS entry arguments) |
| BLS entries | `[ -d /mnt/boot/loader/entries ]` | step 7c, verified by V5 |
| Raspberry Pi `cmdline.txt` | `/boot/firmware/cmdline.txt`, `/boot/cmdline.txt` | stage 6f, verified by V6 |
| `extlinux.conf` | `/boot/extlinux/`, `/extlinux/` | stage 6g, verified by V6 |
| **Unified Kernel Images** | `EFI/Linux/*.efi` on the ESP, XBOOTLDR or root | **step 7f**, verified by **V11** |
| **Secure Boot signatures** | `sbctl` / `sbsign` + a findable key pair | **step 7g**, verified by **V12** |
| **systemd-boot** | the loader binary on the ESP | verified by **V13** |

Initramfs generators: `dracut`, `mkinitcpio`, `initramfs-tools`. Step 7a rebuilds
images with `dracut --regenerate-all --force` (or a per-kernel loop),
`mkinitcpio -P`, or `update-initramfs -u -k all`.

## Unified Kernel Images

A UKI is a single PE binary with the kernel, the initramfs and the kernel
command line baked in as `.linux`, `.initrd` and `.cmdline`. Changing
`/etc/kernel/cmdline` or rebuilding `/boot/initramfs-$kver.img` does not change
what the firmware loads. The `.efi` has to be rebuilt.

Before 1.2.0 this was refused outright, because a run would:

1. write `crypttab`, `fstab` and `/etc/kernel/cmdline` **correctly**;
2. rebuild `/boot/initramfs-$kver.img` **correctly**, with the crypt modules;
3. leave `EFI/Linux/*.efi` **untouched**, still carrying the pre-encryption
   command line and an initramfs with no `dm-crypt`;
4. boot the stale UKI, fail to find the root device, and drop to an emergency
   shell — on a disk that is already encrypted;
5. and **report success**, because every file the verification stage read really
   was correct. Nothing inspected the UKI.

### What happens now

`bin/lib-uki.sh` detects which tool owns the `.efi`, and step 7f runs it:

| Backend | Detected from | Command |
|---|---|---|
| `mkinitcpio-preset` | any `/etc/mkinitcpio.d/*.preset` with a `_uki=` line | `mkinitcpio -P` |
| `kernel-install` | `layout=uki` in `/etc/kernel/install.conf`, or a `*uki*.install` dropin | `kernel-install add $kver …` |
| `dracut-uki` | the `dracut` script mentions `--uki-file` | `dracut --force --uki-file … --kernel-cmdline …` |
| `ukify` | `ukify` on the target | `ukify build --cmdline=@/etc/kernel/cmdline …` |

First match wins; a box can have several installed at once. `LUKS_UKI_REGEN`
overrides the choice.

**Detection is deliberately narrow on mkinitcpio.** Every Arch box has
mkinitcpio and presets; only a preset carrying `_uki=` actually builds a UKI.
Claiming the backend on the strength of `mkinitcpio` alone would run
`mkinitcpio -P` and then wait for an `.efi` that never appears.

### Step 7f runs after the splash strip, not after step 7a

This ordering is load-bearing. Step 7c½ strips `rhgb quiet splash` from
`/etc/kernel/cmdline` so the passphrase prompt is visible, and the UKI bakes
that file in. Rebuilding before the strip bakes in the pre-strip command line
and hides the prompt behind boot graphics — on a machine where the user also
cannot see that it is asking for anything.

On mkinitcpio targets this is why step 7f re-runs `mkinitcpio -P`: step 7a
already ran one, and on a `default_uki=` preset that run *did* write an `.efi` —
with the wrong command line in it.

### UKI-only targets have no standalone initramfs

A preset with `default_uki=` and no `default_image=` writes only the `.efi`.
Steps 7b and check V7 iterate `/boot/initramfs-*.img`, find nothing, and would
fail a perfectly good deployment. Both now fall back to extracting the
`.initrd` section from the UKI and running the same `cryptsetup` / `dm-crypt`
presence checks against it.

An image that cannot be inspected — no `objcopy`, or no
`lsinitrd`/`lsinitcpio`/`lsinitramfs` — reports **SKIP**, never a silent pass.

## Secure Boot

Secure Boot verifies the chain `shim → bootloader → kernel`. On a conventional
shim + GRUB or shim + systemd-boot system the initramfs is not part of the
verified chain, so rebuilding it in step 7a is invisible to Secure Boot. **No
interaction expected**, and none of shim, the bootloader EFI binary or `vmlinuz`
is touched.

A UKI changes that completely: **the UKI is the signed object.** Rebuilding it
invalidates the signature, and an unsigned `.efi` on a Secure Boot machine is a
firmware-level refusal to boot — a different failure from the stale-cmdline one,
and a harder one to diagnose, because nothing gets far enough to print anything.

### Distro signing automation does not fire from a chroot

This is the trap worth knowing about even if you never use this tool.

Arch and Manjaro sign EFI binaries through `zz-sbctl.hook`, which is a **libalpm
hook**: `Exec = /usr/bin/sbctl sign-all -g`, triggered by pacman transactions.
Running `mkinitcpio -P` by hand — which is exactly what step 7a does — rebuilds
the UKI and **does not fire the hook**. sbctl's other entry point,
`91-sbctl.install`, only runs under `kernel-install` with
`KERNEL_INSTALL_LAYOUT=uki`.

So a UKI rebuilt by any tool that is not a package manager is unsigned until
something signs it explicitly. Step 7g is that something:

| Backend | Detected from | Command |
|---|---|---|
| `sbctl` | `sbctl` **and** `/var/lib/sbctl/keys/db/db.key` | `sbctl sign -s <uki>` |
| `sbsign` | `sbsign` + a findable key pair | `sbsign --key … --cert … --output …` |

sbsign key/cert discovery order: `LUKS_SB_KEY`/`LUKS_SB_CERT`, then
`/var/lib/sbctl/keys/db/db.{key,pem}`, `/etc/secureboot/keys/db/*`,
`/var/lib/shim-signed/mok/MOK.{priv,der}`.

`sbctl` **without** a key directory is deliberately not claimed as a signer:
`sbctl sign` there exits 0 having signed nothing, which would look like success.

`sbctl sign -s` also adds the file to sbctl's own database, so later kernel
upgrades keep signing it without anyone having to rediscover this.

**pesign / NSS is not implemented.** The certificate nickname and NSS database
cannot be discovered reliably from a chroot, and a silently unsigned `.efi` is
precisely the failure this work exists to prevent. pesign is detected, named in
the refusal message, and refused.

## The remaining refusals

A UKI target is refused, before the shrink and before encryption, in exactly two
cases:

| Condition | Why |
|---|---|
| No rebuild backend found | Nothing can regenerate the `.efi`; the original failure mode, unchanged |
| Secure Boot **enabled** and no signing backend | The rebuild would succeed and the firmware would reject the result |

`LUKS_ALLOW_UKI=1` overrides both and makes regenerating and re-signing your
problem. `LUKS_SKIP_UKI_SIGN=1` rebuilds without signing and downgrades V12 to a
warning — useful when you sign out-of-band, dangerous otherwise.

The old unconditional refusal is still in `bin/luks-deploy.sh`, commented out
directly above the block that replaced it, so the change is legible in place.

## systemd-boot

Previously supported "by coincidence": `HAS_BLS` keys off
`/boot/loader/entries`, which systemd-boot also uses, so a Type #1 install with
its ESP at `/boot` fell into the BLS path and worked. With the ESP at `/efi` or
`/boot/efi` there was no `/mnt/boot/loader/entries`, no GRUB tool either, and the
run printed *"No recognised bootloader config"* and left the kernel arguments to
the operator.

systemd-boot is now detected properly, from the loader binary on the ESP
(`EFI/systemd/systemd-boot*.efi`, or a `BOOT*.EFI` whose `LoaderInfo` string says
systemd-boot), falling back to `loader/loader.conf` + `loader/entries`. Check V13
then confirms that at least one thing systemd-boot can actually boot — a UKI or a
Type #1 entry — carries the LUKS arguments. Check V6 accepts a UKI as a valid
bootloader configuration in its own right, which is what lets an ESP-at-`/efi`
box pass at all.

Still true: **nothing runs `bootctl`.** No `bootctl install`, no `bootctl
update`, no check that the loader on the ESP matches the installed systemd
version. LinuxLocker does not install bootloaders.

`GRUB_ENABLE_CRYPTODISK=y` is still written to `/etc/default/grub` when that file
exists. It is inert without GRUB — harmless, but misleading in the log.

## What the verification gate checks

| Check | Asserts |
|---|---|
| V11 | every `EFI/Linux/*.efi` has the LUKS arguments in its `.cmdline`, and no stale `root=UUID=` |
| V12 | with Secure Boot on, every UKI carries a signature |
| V13 | systemd-boot has at least one bootable object pointing at the encrypted root |

V11 is the check whose absence made the original failure silent. A check that
does not apply reports SKIP, as everywhere else in the gate.

## Environment knobs

```
LUKS_ALLOW_UKI=1              proceed past the two refusals above
LUKS_UKI_REGEN=<backend>      mkinitcpio | kernel-install | dracut | ukify | none
LUKS_UKI_SIGN=<backend>       sbctl | sbsign | none
LUKS_SB_KEY=<path>            explicit sbsign key ...
LUKS_SB_CERT=<path>           ... and certificate (both, or neither)
LUKS_SKIP_UKI_SIGN=1          rebuild but do not sign; V12 becomes a warning
LUKS_SB_STATE=enabled|disabled  override Secure Boot autodetection (testing)
```

## Testing checklist

`tests/uki-fixture-test.sh` covers the logic. What it cannot cover is a real
encrypt-and-reboot cycle, so for a systemd-boot / UKI / Secure Boot box, in
rough order of risk:

- [ ] **Snapshot or image the disk first.** These are the untested-on-metal paths.
- [ ] Record the starting state: `bootctl status`, `bootctl list`,
      `mokutil --sb-state`, `sbctl status`, `findmnt /boot /efi /boot/efi`,
      `ls /boot/loader/entries /boot/EFI/Linux 2>/dev/null`.
- [ ] Run `sudo bash tests/uki-fixture-test.sh` **as root** on that machine.
      Section 10 self-checks detection against the real system; it must report
      the rebuild backend, signer and Secure Boot state you actually have.
- [ ] Run `luks-deploy.sh --dry-run` and confirm steps 7f/7g name the backend
      and signer you expect.
- [ ] **UKI target, Secure Boot on, sbctl present.** Expected: a normal run, then
      `objcopy --dump-section .cmdline=/dev/stdout /boot/EFI/Linux/*.efi` shows
      `rd.luks.uuid=`, and `sbctl verify` lists the `.efi` as signed. Then reboot.
- [ ] **UKI target, no rebuild backend** (rename the preset's `_uki=` line).
      Expected: refusal before the shrink; `lsblk -f` shows the original
      filesystem, no `crypto_LUKS`.
- [ ] **UKI target, Secure Boot on, signer removed** (move `/var/lib/sbctl/keys`
      aside). Expected: refusal naming the missing signer.
- [ ] **Type #1 systemd-boot, ESP at `/boot`, no UKI.** Expected: the BLS path,
      unchanged. Confirm the `options` line of every entry gained
      `rd.luks.uuid=` / `rd.luks.name=` before rebooting.
- [ ] **Type #1 systemd-boot, ESP at `/efi`.** Expected: V13 passes via the
      Type #1 entries, and the "No recognised bootloader config" warning does
      **not** fire any more.
- [ ] **Secure Boot enabled, GRUB or systemd-boot, no UKI.** Expected: no
      interaction. Confirm `mokutil --sb-state` is unchanged.
- [ ] Each ESP layout you have: ESP at `/boot/efi`, at `/efi`, a separate
      XBOOTLDR `/boot`, and `/boot` on the root filesystem.

## Recovery

If a UKI target does end up unbootable, the data is encrypted and intact and the
machine is fixable from the live USB — see [RECOVERY.md](RECOVERY.md). The
UKI-specific repair is to chroot in and re-run the backend by hand:

```bash
# in the chroot, after mounting the ESP and /boot
mkinitcpio -P                                   # preset-based targets
kernel-install add "$kver" "/usr/lib/modules/$kver/vmlinuz"   # kernel-install
sbctl sign -s /boot/EFI/Linux/*.efi             # then re-sign, if Secure Boot is on
```

## Apple Silicon

Fedora Asahi Remix is **refused outright**, at the front door and again when the
selected partition turns out to hold one. Its boot chain is
iBoot → m1n1 → U-Boot → GRUB, and its stub partitions are read by the Apple
firmware itself. Use [AsahiLocker](https://github.com/doug445/AsahiLocker),
which carries the guards this tool deliberately drops.
