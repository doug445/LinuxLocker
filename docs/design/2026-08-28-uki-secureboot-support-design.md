# UKI / systemd-boot / Secure Boot support for LinuxLocker

**Date:** 2026-08-28
**Status:** approved, implementing
**Affects:** `bin/luks-deploy.sh`, new `bin/lib-uki.sh`, new `tests/uki-fixture-test.sh`,
`docs/BOOTLOADERS.md`, `README.md`, `docs/ABOUT.md`, `.github/workflows/lint.yml`

## Problem

LinuxLocker refuses to deploy onto a target that boots a Unified Kernel Image.
The refusal is correct today: a UKI is a single PE binary carrying `.linux`,
`.initrd` and `.cmdline` sections, and nothing in the tree regenerates it.
A run would write `/etc/kernel/cmdline` correctly, rebuild the standalone
initramfs correctly, leave `EFI/Linux/*.efi` stale, report success, and drop the
machine to an emergency shell on an already-encrypted disk.

Two failure modes are in scope. The first is the documented one above. The
second is not documented anywhere and is specific to Arch-family targets:

> `zz-sbctl.hook` is a **libalpm** hook (`Exec = sbctl sign-all -g`), fired by
> pacman transactions. Step 7a runs `mkinitcpio -P` directly in a chroot, which
> on a preset with `default_uki=` *does* rebuild the UKI — and the hook never
> fires, so the rebuilt `.efi` is **unsigned**. On a Secure Boot machine the
> firmware then rejects it. Distro signing automation cannot be relied on from
> inside a chroot; signing must be explicit and backend-aware.

A third problem is latent in the existing checks rather than new: a mkinitcpio
preset with `default_uki=` and no `default_image=` produces **no standalone
initramfs at all**. Step 7b and check V7 both iterate `/boot/initramfs-*.img`,
find nothing, and fail the run — so even a correct UKI deployment would be
reported as broken.

## Reference hardware

The design is validated against one real UKI + Secure Boot target:

| | |
|---|---|
| Machine | ASUS ZenBook UX534FTC, i7-10510U (4C/8T), 16 GiB |
| Bootloader | systemd-boot 259.5, ESP at `/efi`, XBOOTLDR at `/boot` |
| UKI | `/boot/EFI/Linux/manjaro-6.18-x86_64.efi` |
| Built by | mkinitcpio presets (`default_uki=`, `default_options="--cmdline /etc/kernel/cmdline"`) |
| Signed by | sbctl; Secure Boot enabled (user mode) |
| Also present | `kernel-install` with `50-mkinitcpio.install`, `90-uki-copy.install`, `91-sbctl.install` |

This layout is the hardest current case: `HAS_BLS` keys off
`/mnt/boot/loader/entries`, which exists here, so the script believes it has BLS
entries to patch while the object that actually boots is a `.efi` elsewhere.

## Non-goals

- TPM2 enrollment or PCR sealing. Out of scope for the project.
- `bootctl install` / `bootctl update` — LinuxLocker does not install bootloaders.
- pesign / NSS signing. Detected, then refused with instructions; the certificate
  nickname and NSS database cannot be discovered reliably from a chroot, and a
  silently-unsigned result is the exact failure this work exists to prevent.
- Encrypting `/boot` or the ESP.

## Architecture

### `bin/lib-uki.sh` (new, sourced)

Detection, regeneration and signing live in a sourced library rather than inline,
so the fixture harness can call them directly. Every function takes a root-prefix
argument, so the same code runs against `/mnt_temp/$SUBPATH` during discovery,
`/mnt` during configuration, and `/` inside the chroot.

```
uki_detect        <rootdir> <espdir> <bootdir>  -> UKI_FOUND[] UKI_PATHS[] UKI_LAYOUT
uki_detect_regen  <rootdir>                     -> UKI_REGEN
uki_detect_signer <rootdir>                     -> UKI_SIGN, UKI_SB_KEY, UKI_SB_CERT
uki_detect_sb     <rootdir>                     -> UKI_SB_STATE
uki_regenerate                                  -> runs backend; UKI_DRY=1 echoes
uki_sign                                        -> runs signer;  UKI_DRY=1 echoes
uki_cmdline_of    <efi>                         -> prints .cmdline section
uki_initrd_has    <efi> <pattern>               -> greps embedded .initrd
```

`UKI_REGEN` detection order, first match wins (a box may have several installed):

1. `mkinitcpio-preset` — any `/etc/mkinitcpio.d/*.preset` sets `_uki=`
2. `kernel-install` — `/usr/lib/kernel/install.d/*uki*` exists, or
   `/etc/kernel/install.conf` sets `layout=uki`
3. `dracut-uki` — dracut present and its `--help` lists `--uki-file`
4. `ukify` — `ukify` on PATH
5. `none`

`UKI_SIGN` detection order: `sbctl` -> `sbsign` (only when a key/cert pair is
findable) -> `none`. Key/cert discovery order: `LUKS_SB_KEY`/`LUKS_SB_CERT` env,
`/var/lib/sbctl/keys/db/db.{key,pem}`, `/etc/secureboot/keys/db/*`,
`/var/lib/shim-signed/mok/MOK.{priv,der}`.

`UKI_SB_STATE` comes from the target's `SecureBoot-8be4df61-*` efivar when
readable, else `mokutil --sb-state` in the live environment, else `unknown`.

### The guard becomes conditional (discovery, before the shrink)

Detection runs against `/mnt_temp/$SUBPATH`, already mounted read-only at that
point, so presets and signers are visible *before* anything is written.

| Found | Behaviour |
|---|---|
| UKI + regen path | Proceed; log the backend and signer to be used |
| UKI + regen path + SB on + no signer | **Refuse** — regenerating yields an unsigned `.efi` the firmware rejects |
| UKI + no regen path | **Refuse**, for the original reason, with the original message |

`LUKS_ALLOW_UKI=1` overrides either refusal, unchanged in role.

The original unconditional block is retained directly above, commented out, with
a note recording what replaced it and why.

### Step 7f — regeneration (in chroot)

Runs **after 7c-and-a-half**, not after 7a. 7c-and-a-half strips
`rhgb quiet splash` from `/etc/kernel/cmdline`, and the UKI bakes that file in.
Regenerating earlier bakes in the pre-strip line, hiding the passphrase prompt
behind the splash — on a machine where the user also cannot see that it is
asking.

| `UKI_REGEN` | Command |
|---|---|
| `mkinitcpio-preset` | `mkinitcpio -P` (a second run, now that the cmdline is final) |
| `kernel-install` | `kernel-install add "$kver" "/lib/modules/$kver/vmlinuz"` per kernel |
| `dracut-uki` | `dracut --force --uki-file <path> --kernel-cmdline "$(cat /etc/kernel/cmdline)"` per kernel |
| `ukify` | `ukify build --linux=... --initrd=... --cmdline=@/etc/kernel/cmdline --output=...` |

Every `EFI/Linux/*.efi` mtime is recorded before and after. An unchanged mtime is
an error, not a pass.

### Step 7g — signing (in chroot)

| `UKI_SIGN` | Behaviour |
|---|---|
| `sbctl` | `sbctl sign -s <uki>` per file, then `sbctl verify` |
| `sbsign` | `sbsign --key K --cert C --output <uki> <uki>`, then `sbverify --cert C` |
| `none`, SB enabled | Hard error; blocks the reboot with instructions |
| `none`, SB disabled | SKIP, logged |

`LUKS_SKIP_UKI_SIGN=1` downgrades the hard error to a warning.

### Existing checks taught about UKIs

- **7b** — when no standalone initramfs exists but UKIs do, extract each
  `.initrd` section and run the same `cryptsetup` / `dm-crypt` presence checks
  against it. `INITRD_FOUND=0` stops being a failure when UKIs accounted for it.
- **V7** — same fix.
- **V6** — a UKI whose `.cmdline` carries the LUKS arguments now counts as a
  valid bootloader configuration, so an ESP-at-`/efi` systemd-boot box can pass.

### New verification checks

- **V11** — every `EFI/Linux/*.efi` has `$LUKS_BOOT_ARGS` in its `.cmdline`
  section and no stale `root=UUID=$ORIG_FS_UUID`. The absence of this check is
  what made the original failure silent.
- **V12** — when Secure Boot is enabled on the target, every regenerated UKI
  carries a valid signature. FAIL otherwise.
- **V13** — when systemd-boot is detected, at least one bootable object (UKI or
  Type #1 entry) carries the LUKS arguments, and the ESP still holds the loader.

Checks that do not apply report SKIP, consistent with the existing gate.

### Environment knobs

```
LUKS_UKI_REGEN=mkinitcpio|kernel-install|dracut|ukify|none   force the backend
LUKS_UKI_SIGN=sbctl|sbsign|none                              force the signer
LUKS_SB_KEY=<path>   LUKS_SB_CERT=<path>                     explicit sbsign pair
LUKS_SKIP_UKI_SIGN=1                                         regenerate, do not sign
LUKS_ALLOW_UKI=1                                             override the refusal
```

## Testing

`tests/uki-fixture-test.sh` builds fixture target trees in a tmpdir and asserts
detection plus dry-run dispatch. No real disk, no root required for the fixture
half; runs in CI beside the loopback test.

| Layout | ESP | UKI | Backend | Signer | Expected |
|---|---|---|---|---|---|
| reference box | `/efi` + XBOOTLDR `/boot` | yes | mkinitcpio-preset | sbctl | proceed, sign |
| Fedora UKI | `/boot/efi` | yes | kernel-install | none, SB off | proceed, skip signing |
| Fedora UKI + SB | `/boot/efi` | yes | kernel-install | none, SB on | refuse |
| boot-on-root | `/boot/efi` | yes | dracut-uki | sbsign | proceed, sign |
| UKI, no backend | `/boot/efi` | yes | none | — | refuse |
| sd-boot Type #1 | `/boot` | no | — | — | unchanged BLS path |
| GRUB + BLS | `/boot/efi` | no | — | — | unchanged |

Also covered: `.cmdline` / `.initrd` round-trips against a real PE built with
`objcopy`, and a read-only probe against the reference box asserting detection
reports `mkinitcpio-preset` + `sbctl` + SB enabled + XBOOTLDR.

Hardware end-to-end remains untested; `docs/BOOTLOADERS.md` keeps its checklist
for that, with the status line updated to say what is now covered by fixtures.

## Documentation

`docs/BOOTLOADERS.md` moves from "not supported, fails silently" to what is
handled, retaining the hardware checklist as the outstanding caveat. `README.md`
gains a supported-systems row, revised UKI FAQ answers, the new env knobs, and
measured KDF numbers for the reference box. `docs/ABOUT.md` and `README.md` are
both revised for search coverage across the repository's twenty GitHub topics.
