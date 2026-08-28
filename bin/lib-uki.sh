#!/bin/bash
#
# LinuxLocker — universal in-place LUKS2 encryption for Linux (x86_64 / aarch64)
# https://github.com/doug445/LinuxLocker
#
# Copyright (c) 2026 William MacKinnon <spilled-bowline0j@icloud.com>
# SPDX-License-Identifier: MIT
#
# ============================================================================
# lib-uki.sh — Unified Kernel Image / systemd-boot / Secure Boot support
# ============================================================================
# Sourced (not executed) by luks-deploy.sh — from the live environment AND
# again from inside the chroot — and by tests/uki-fixture-test.sh.
#
# A UKI is one PE binary carrying the kernel (.linux), the initramfs (.initrd)
# and the kernel command line (.cmdline). Editing /etc/kernel/cmdline or
# rebuilding /boot/initramfs-$kver.img changes NOTHING about what the firmware
# loads: the .efi has to be rebuilt. On a Secure Boot machine it then has to be
# re-signed, because the .efi IS the object the firmware verifies.
#
# Every function takes a ROOT PREFIX so the same code runs in three places:
#   discovery      uki_detect_regen /mnt_temp/$SUBPATH   (target mounted r/o)
#   configuration  uki_detect_regen /mnt                 (target mounted r/w)
#   chroot         uki_detect_regen ""                   (target IS /)
#
#   uki_reset                        clear all UKI_* state
#   uki_find_ukis     <root>         fill UKI_PATHS[] from the three ESP layouts
#   uki_scan_dir      <dir> <label>  append finds under a mounted directory
#   uki_probe_dev     <dev> <label>  mount a block device r/o and scan it
#   uki_detect_regen  <root>         -> UKI_REGEN, UKI_REGEN_DETAIL
#   uki_detect_signer <root>         -> UKI_SIGN, UKI_SB_KEY/CERT, UKI_SIGN_DETAIL
#   uki_detect_sb                    -> UKI_SB_STATE (firmware, not the target)
#   uki_detect_sdboot <root> <esp>   -> UKI_SDBOOT, UKI_SDBOOT_DETAIL
#   uki_regenerate    <root>         rebuild every UKI with the current cmdline
#   uki_sign          <root>         sign every UKI with the detected backend
#   uki_cmdline_of    <efi>          print the .cmdline section
#   uki_initrd_has    <efi> <pat>    0 found / 1 absent / 2 cannot inspect
#
# Set UKI_DRY=1 to have uki_regenerate / uki_sign print what they WOULD run
# and change nothing. That is what the fixture tests exercise.
# ============================================================================

# Every UKI_* global below is read by luks-deploy.sh (and the fixture tests)
# after sourcing this file, not within it.
# shellcheck disable=SC2034

# ─── State ───────────────────────────────────────────────────────────────────
UKI_FOUND=()          # "label:basename" pairs, for human-readable messages
UKI_PATHS=()          # absolute paths to EFI/Linux/*.efi (last scan)
UKI_REGEN="none"      # mkinitcpio-preset | kernel-install | dracut-uki | ukify | none
UKI_REGEN_DETAIL=""   # what the detection actually keyed off
UKI_SIGN="none"       # sbctl | sbsign | none
UKI_SIGN_DETAIL=""
UKI_SB_KEY=""
UKI_SB_CERT=""
UKI_SB_STATE="unknown"   # enabled | disabled | unknown
UKI_SDBOOT=0
UKI_SDBOOT_DETAIL=""

# The three places a distro puts the ESP, relative to the target root. Order
# matters only for reporting; all three are always scanned, because a machine
# can legitimately have XBOOTLDR at /boot AND the ESP at /efi (systemd's
# recommended layout) and the UKIs may live on either.
UKI_DIRS='/boot/EFI/Linux /efi/EFI/Linux /boot/efi/EFI/Linux'

uki_reset() {
    UKI_FOUND=(); UKI_PATHS=()
    UKI_REGEN="none"; UKI_REGEN_DETAIL=""
    UKI_SIGN="none";  UKI_SIGN_DETAIL=""; UKI_SB_KEY=""; UKI_SB_CERT=""
    UKI_SB_STATE="unknown"
    UKI_SDBOOT=0; UKI_SDBOOT_DETAIL=""
}

# Logging that works both standalone and inside luks-deploy.sh, which defines
# log/warn/err. Never assume the caller's helpers exist.
_uki_log()  { if declare -F log  >/dev/null 2>&1; then log  "$@"; else echo "[uki] $*"; fi; }
_uki_warn() { if declare -F warn >/dev/null 2>&1; then warn "$@"; else echo "[uki] WARN: $*" >&2; fi; }
_uki_err()  { if declare -F err  >/dev/null 2>&1; then err  "$@"; else echo "[uki] ERROR: $*" >&2; fi; }

# Execute, or print under UKI_DRY=1. Everything that touches the target goes
# through here so the fixture tests can assert on the command stream.
uki_run() {
    if [ "${UKI_DRY:-0}" = "1" ]; then
        printf 'DRY: %s\n' "$*"
        return 0
    fi
    "$@"
}

# ─── Discovery ───────────────────────────────────────────────────────────────

# uki_scan_dir <dir> <label> — append any EFI/Linux/*.efi below a MOUNTED dir.
# Handles both an ESP mounted directly (<dir>/EFI/Linux) and a root filesystem
# with the ESP nested inside it (<dir>/efi/EFI/Linux, <dir>/boot/EFI/Linux).
uki_scan_dir() {
    local dir="${1%/}" label="$2" sub f
    [ -d "$dir" ] || return 0
    for sub in "" /efi /boot /boot/efi; do
        [ -d "$dir$sub/EFI/Linux" ] || continue
        for f in "$dir$sub"/EFI/Linux/*.efi; do
            [ -f "$f" ] || continue
            UKI_FOUND+=("$label:$(basename "$f")")
            UKI_PATHS+=("$f")
        done
    done
    return 0
}

# uki_probe_dev <device> <label> — mount a block device read-only and scan it.
# Used during discovery, when /boot and the ESP are still just partitions.
uki_probe_dev() {
    local dev="$1" label="$2" probe
    [ -n "$dev" ] && [ -b "$dev" ] || return 0
    probe=$(mktemp -d /tmp/luks-uki-probe.XXXXXX) || return 0
    if mount -o ro "$dev" "$probe" 2>/dev/null; then
        uki_scan_dir "$probe" "$label"
        umount "$probe" 2>/dev/null || true
    fi
    rmdir "$probe" 2>/dev/null || true
    return 0
}

# uki_find_ukis <root> — fill UKI_PATHS from the three canonical ESP layouts,
# for a target whose filesystems are all already mounted under <root>.
uki_find_ukis() {
    local root="${1%/}" d f
    UKI_PATHS=()
    for d in $UKI_DIRS; do
        for f in "$root$d"/*.efi; do
            [ -f "$f" ] || continue
            UKI_PATHS+=("$f")
        done
    done
    return 0
}

# ─── Which tool rebuilds the UKI on this target? ─────────────────────────────
# First match wins. A box can have several of these installed at once — this
# machine has mkinitcpio presets AND kernel-install with a uki layout — so the
# order encodes which one actually owns the .efi that boots.
uki_detect_regen() {
    local root="${1%/}" p
    UKI_REGEN="none"; UKI_REGEN_DETAIL=""

    if [ -n "${LUKS_UKI_REGEN:-}" ]; then
        case "$LUKS_UKI_REGEN" in
            mkinitcpio|mkinitcpio-preset) UKI_REGEN="mkinitcpio-preset" ;;
            kernel-install)               UKI_REGEN="kernel-install" ;;
            dracut|dracut-uki)            UKI_REGEN="dracut-uki" ;;
            ukify)                        UKI_REGEN="ukify" ;;
            none)                         UKI_REGEN="none" ;;
            *) _uki_err "Unknown LUKS_UKI_REGEN '$LUKS_UKI_REGEN' (mkinitcpio|kernel-install|dracut|ukify|none)"; return 2 ;;
        esac
        UKI_REGEN_DETAIL="forced by LUKS_UKI_REGEN"
        return 0
    fi

    # 1. mkinitcpio preset with a *_uki= line. This is Arch/Manjaro's native
    #    UKI path: `mkinitcpio -P` reads the preset and writes the .efi named
    #    there. The preset is authoritative — the presence of mkinitcpio alone
    #    proves nothing, because a non-UKI Arch box has mkinitcpio too.
    for p in "$root"/etc/mkinitcpio.d/*.preset; do
        [ -f "$p" ] || continue
        grep -Eq '^[[:space:]]*[A-Za-z0-9_]+_uki=' "$p" || continue
        UKI_REGEN="mkinitcpio-preset"; UKI_REGEN_DETAIL="${p#"$root"}"
        return 0
    done

    # 2. kernel-install with layout=uki, or a uki-aware dropin. systemd's
    #    orchestrator: `kernel-install add` runs every install.d/ dropin, which
    #    is what builds AND (via 91-sbctl.install) signs on Arch.
    if [ -x "$root/usr/bin/kernel-install" ] || [ -x "$root/usr/sbin/kernel-install" ]; then
        if grep -Eqs '^[[:space:]]*layout[[:space:]]*=[[:space:]]*uki' "$root/etc/kernel/install.conf"; then
            UKI_REGEN="kernel-install"; UKI_REGEN_DETAIL="/etc/kernel/install.conf layout=uki"
            return 0
        fi
        for p in "$root"/usr/lib/kernel/install.d/*uki*.install \
                 "$root"/etc/kernel/install.d/*uki*.install; do
            [ -f "$p" ] || continue
            UKI_REGEN="kernel-install"; UKI_REGEN_DETAIL="${p#"$root"}"
            return 0
        done
    fi

    # 3. dracut --uki-file (dracut >= 057). dracut is a shell script, so
    #    grepping it for the option is a reliable capability probe that works
    #    against an unmounted-but-visible target without executing anything.
    for p in "$root/usr/bin/dracut" "$root/usr/sbin/dracut"; do
        [ -f "$p" ] || continue
        grep -q -- '--uki-file' "$p" 2>/dev/null || continue
        UKI_REGEN="dracut-uki"; UKI_REGEN_DETAIL="${p#"$root"} supports --uki-file"
        return 0
    done

    # 4. ukify, last resort: it builds a UKI from parts we have to supply
    #    ourselves, so it only works when a standalone initramfs also exists.
    for p in "$root/usr/bin/ukify" "$root/usr/lib/systemd/ukify"; do
        [ -x "$p" ] || continue
        UKI_REGEN="ukify"; UKI_REGEN_DETAIL="${p#"$root"}"
        return 0
    done

    return 0
}

# ─── Which tool signs it? ────────────────────────────────────────────────────
# Signing must be EXPLICIT. Distro automation cannot be relied on from a
# chroot: Arch's zz-sbctl.hook is a libalpm hook, so it fires on pacman
# transactions and NOT on a bare `mkinitcpio -P`. A UKI rebuilt by this tool is
# therefore unsigned until this function's backend signs it.
uki_detect_signer() {
    local root="${1%/}" pair k c
    UKI_SIGN="none"; UKI_SIGN_DETAIL=""; UKI_SB_KEY=""; UKI_SB_CERT=""

    if [ -n "${LUKS_UKI_SIGN:-}" ]; then
        case "$LUKS_UKI_SIGN" in
            sbctl|sbsign|none) UKI_SIGN="$LUKS_UKI_SIGN" ;;
            *) _uki_err "Unknown LUKS_UKI_SIGN '$LUKS_UKI_SIGN' (sbctl|sbsign|none)"; return 2 ;;
        esac
        UKI_SIGN_DETAIL="forced by LUKS_UKI_SIGN"
    fi

    # An explicitly pinned key/cert pair always wins over discovery.
    if [ -n "${LUKS_SB_KEY:-}" ] && [ -n "${LUKS_SB_CERT:-}" ]; then
        UKI_SIGN="sbsign"; UKI_SB_KEY="$LUKS_SB_KEY"; UKI_SB_CERT="$LUKS_SB_CERT"
        UKI_SIGN_DETAIL="key/cert pinned by LUKS_SB_KEY / LUKS_SB_CERT"
        return 0
    fi
    [ -n "$UKI_SIGN_DETAIL" ] && return 0

    # sbctl, but only with keys actually generated — sbctl with no key
    # directory signs nothing and exits 0, which would look like success.
    if { [ -x "$root/usr/bin/sbctl" ] || [ -x "$root/usr/local/bin/sbctl" ]; } \
       && [ -f "$root/var/lib/sbctl/keys/db/db.key" ]; then
        UKI_SIGN="sbctl"; UKI_SIGN_DETAIL="sbctl, keys at /var/lib/sbctl/keys"
        return 0
    fi

    # Raw sbsign against whichever key pair this distro keeps.
    if [ -x "$root/usr/bin/sbsign" ] || [ -x "$root/usr/sbin/sbsign" ]; then
        for pair in "/var/lib/sbctl/keys/db/db.key:/var/lib/sbctl/keys/db/db.pem" \
                    "/etc/secureboot/keys/db/db.key:/etc/secureboot/keys/db/db.crt" \
                    "/etc/secureboot/keys/db/db.key:/etc/secureboot/keys/db/db.pem" \
                    "/var/lib/shim-signed/mok/MOK.priv:/var/lib/shim-signed/mok/MOK.der"; do
            k="${pair%%:*}"; c="${pair##*:}"
            [ -f "$root$k" ] && [ -f "$root$c" ] || continue
            UKI_SIGN="sbsign"; UKI_SB_KEY="$k"; UKI_SB_CERT="$c"
            UKI_SIGN_DETAIL="sbsign with $k"
            return 0
        done
    fi

    # pesign/NSS is deliberately not implemented: the certificate nickname and
    # NSS database cannot be discovered reliably from a chroot, and a silently
    # unsigned .efi is the exact failure this whole file exists to prevent.
    # Report it so the refusal message can name it.
    if [ -x "$root/usr/bin/pesign" ]; then
        UKI_SIGN_DETAIL="pesign present, unsupported (NSS db + cert nickname are not discoverable from a chroot)"
    fi
    return 0
}

# ─── Is Secure Boot on? ──────────────────────────────────────────────────────
# This is FIRMWARE state, not target state, so it is read from the live
# environment — the same machine will boot the target. The efivar's last byte
# is the flag; mokutil is the fallback.
uki_detect_sb() {
    local var out
    UKI_SB_STATE="unknown"

    if [ -n "${LUKS_SB_STATE:-}" ]; then
        UKI_SB_STATE="$LUKS_SB_STATE"
        return 0
    fi

    var=/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
    if [ -r "$var" ]; then
        # 4 bytes of attributes then one byte of value; od the last byte.
        case "$(od -An -t u1 "$var" 2>/dev/null | tr -s ' ' | awk '{print $NF}')" in
            1) UKI_SB_STATE="enabled";  return 0 ;;
            0) UKI_SB_STATE="disabled"; return 0 ;;
        esac
    fi

    if command -v mokutil >/dev/null 2>&1; then
        out=$(mokutil --sb-state 2>/dev/null || true)
        case "$out" in
            *"SecureBoot enabled"*)  UKI_SB_STATE="enabled";  return 0 ;;
            *"SecureBoot disabled"*) UKI_SB_STATE="disabled"; return 0 ;;
        esac
    fi

    # No EFI variables at all means this is not even an EFI boot.
    [ -d /sys/firmware/efi ] || UKI_SB_STATE="disabled"
    return 0
}

# ─── systemd-boot ────────────────────────────────────────────────────────────
# Detected properly rather than inferred from /boot/loader/entries, which GRUB's
# BLS support also uses. The loader binary on the ESP is the real evidence.
uki_detect_sdboot() {
    local root="${1%/}" d f
    UKI_SDBOOT=0; UKI_SDBOOT_DETAIL=""
    for d in /efi /boot /boot/efi; do
        for f in "$root$d"/EFI/systemd/systemd-boot*.efi \
                 "$root$d"/EFI/BOOT/BOOT*.EFI; do
            [ -f "$f" ] || continue
            # BOOTX64.EFI is also shim's and GRUB's name; only claim
            # systemd-boot when the binary says so.
            case "$f" in
                */EFI/systemd/*) UKI_SDBOOT=1; UKI_SDBOOT_DETAIL="${f#"$root"}"; return 0 ;;
            esac
            if grep -qa '#### LoaderInfo: systemd-boot' "$f" 2>/dev/null; then
                UKI_SDBOOT=1; UKI_SDBOOT_DETAIL="${f#"$root"} (systemd-boot)"
                return 0
            fi
        done
        if [ -f "$root$d/loader/loader.conf" ] && [ -d "$root$d/loader/entries" ]; then
            UKI_SDBOOT=1; UKI_SDBOOT_DETAIL="${d}/loader/loader.conf"
            return 0
        fi
    done
    return 0
}

# ─── Reading a built UKI ─────────────────────────────────────────────────────

# uki_cmdline_of <efi> — print the baked-in kernel command line.
uki_cmdline_of() {
    local f="$1" out
    [ -f "$f" ] || return 2
    if command -v objcopy >/dev/null 2>&1; then
        out=$(objcopy --dump-section .cmdline=/dev/stdout "$f" /dev/null 2>/dev/null || true)
        if [ -n "$out" ]; then
            printf '%s' "$out" | tr -d '\0'
            return 0
        fi
    fi
    # Without binutils we cannot address the section, so fall back to scanning
    # the binary for a line that looks like a kernel command line. Weaker, but
    # it still catches a stale root= — and it never reports a false OK, because
    # a miss returns 2 (cannot inspect), not 1 (absent).
    if command -v strings >/dev/null 2>&1; then
        out=$(strings -a "$f" 2>/dev/null | grep -m1 -E '(^|[[:space:]])(root=|rd\.luks|cryptdevice=)' || true)
        if [ -n "$out" ]; then
            printf '%s' "$out"
            return 0
        fi
    fi
    return 2
}

# uki_initrd_has <efi> <pattern> — is <pattern> inside the embedded initramfs?
#   0 = present, 1 = absent, 2 = could not inspect.
# The 2 matters: a UKI-only target has no standalone initramfs for step 7b to
# check, so this is the ONLY way to prove the crypt stack made it in — and an
# uninspectable image must report SKIP, never a silent pass.
uki_initrd_has() {
    local f="$1" pat="$2" tmp rc=2
    [ -f "$f" ] || return 2
    command -v objcopy >/dev/null 2>&1 || return 2
    tmp=$(mktemp /tmp/luks-uki-initrd.XXXXXX) || return 2
    if objcopy --dump-section .initrd="$tmp" "$f" /dev/null 2>/dev/null && [ -s "$tmp" ]; then
        if command -v lsinitrd >/dev/null 2>&1 && lsinitrd "$tmp" >/dev/null 2>&1; then
            lsinitrd "$tmp" 2>/dev/null | grep -q -- "$pat" && rc=0 || rc=1
        elif command -v lsinitcpio >/dev/null 2>&1 && lsinitcpio "$tmp" >/dev/null 2>&1; then
            lsinitcpio "$tmp" 2>/dev/null | grep -q -- "$pat" && rc=0 || rc=1
        elif command -v lsinitramfs >/dev/null 2>&1 && lsinitramfs "$tmp" >/dev/null 2>&1; then
            lsinitramfs "$tmp" 2>/dev/null | grep -q -- "$pat" && rc=0 || rc=1
        fi
    fi
    rm -f "$tmp"
    return $rc
}

# ─── Where should a rebuilt UKI go? ──────────────────────────────────────────
# Prefer the path of an existing UKI for this kernel version — whatever named
# it is what the boot entry or the firmware's BootOrder points at, and inventing
# a second .efi beside it would leave the stale one still bootable.
uki_output_for() {
    local root="${1%/}" kver="$2" d f token
    for f in "${UKI_PATHS[@]+"${UKI_PATHS[@]}"}"; do
        case "$(basename "$f")" in
            *"$kver"*) printf '%s' "$f"; return 0 ;;
        esac
    done
    token=""
    [ -r "$root/etc/kernel/entry-token" ] && token=$(head -1 "$root/etc/kernel/entry-token" 2>/dev/null)
    [ -z "$token" ] && [ -r "$root/etc/machine-id" ] && token=$(head -1 "$root/etc/machine-id" 2>/dev/null)
    [ -z "$token" ] && token="linux"
    for d in $UKI_DIRS; do
        [ -d "$root$d" ] || continue
        printf '%s' "$root$d/$token-$kver.efi"
        return 0
    done
    return 1
}

# All kernel versions with a vmlinuz we can actually build from.
uki_kernel_versions() {
    local root="${1%/}" d kver
    for d in "$root"/usr/lib/modules/*/ "$root"/lib/modules/*/; do
        [ -d "$d" ] || continue
        kver=$(basename "$d")
        [ -f "$d/vmlinuz" ] || [ -f "$root/boot/vmlinuz-$kver" ] || continue
        printf '%s\n' "$kver"
    done | sort -u
}

# ─── Regeneration ────────────────────────────────────────────────────────────
# MUST run after the splash tokens are stripped from /etc/kernel/cmdline. The
# UKI bakes that file in; rebuilding before the strip bakes in the pre-strip
# line and hides the passphrase prompt behind the splash — on a machine where
# the user also cannot see that it is asking for one.
uki_regenerate() {
    local root="${1%/}" kver out initrd rc=0 built=0

    case "$UKI_REGEN" in
    mkinitcpio-preset)
        # A second `mkinitcpio -P`. Step 7a already ran one, but that was
        # before the cmdline was final, so its .efi carries the wrong line.
        _uki_log "  Regenerating UKI(s) with mkinitcpio -P (cmdline is now final)..."
        uki_run mkinitcpio -P || rc=1
        built=1
        ;;
    kernel-install)
        while read -r kver; do
            [ -n "$kver" ] || continue
            if [ -f "$root/usr/lib/modules/$kver/vmlinuz" ]; then
                out="/usr/lib/modules/$kver/vmlinuz"
            else
                out="/boot/vmlinuz-$kver"
            fi
            _uki_log "  kernel-install add $kver"
            uki_run kernel-install add "$kver" "$out" || rc=1
            built=1
        done <<< "$(uki_kernel_versions "$root")"
        ;;
    dracut-uki)
        while read -r kver; do
            [ -n "$kver" ] || continue
            out=$(uki_output_for "$root" "$kver") || { _uki_err "  No place to write a UKI for $kver"; rc=1; continue; }
            _uki_log "  dracut --uki-file $out  ($kver)"
            uki_run dracut --force --uki-file "$out" \
                --kernel-cmdline "$(tr '\n' ' ' < "$root/etc/kernel/cmdline" 2>/dev/null)" \
                --kver "$kver" || rc=1
            built=1
        done <<< "$(uki_kernel_versions "$root")"
        ;;
    ukify)
        while read -r kver; do
            [ -n "$kver" ] || continue
            out=$(uki_output_for "$root" "$kver") || { rc=1; continue; }
            initrd=""
            for f in "$root/boot/initramfs-$kver.img" "$root/boot/initrd.img-$kver"; do
                [ -f "$f" ] && initrd="${f#"$root"}" && break
            done
            if [ -z "$initrd" ]; then
                _uki_err "  ukify needs a standalone initramfs for $kver and none exists"
                rc=1; continue
            fi
            _uki_log "  ukify build -> $out  ($kver)"
            uki_run ukify build \
                --linux="/usr/lib/modules/$kver/vmlinuz" \
                --initrd="$initrd" \
                --cmdline="@/etc/kernel/cmdline" \
                --output="${out#"$root"}" || rc=1
            built=1
        done <<< "$(uki_kernel_versions "$root")"
        ;;
    none)
        _uki_warn "  No UKI regeneration backend — nothing rebuilt."
        return 0
        ;;
    esac

    [ "$built" -eq 1 ] || { _uki_err "  No kernels found to rebuild a UKI for."; rc=1; }
    return $rc
}

# ─── Signing ─────────────────────────────────────────────────────────────────
uki_sign() {
    local root="${1%/}" f rc=0 signed=0

    case "$UKI_SIGN" in
    sbctl)
        for f in "${UKI_PATHS[@]+"${UKI_PATHS[@]}"}"; do
            _uki_log "  sbctl sign ${f#"$root"}"
            # -s adds the file to sbctl's signing database, so future kernel
            # upgrades keep signing it without the user rediscovering this.
            uki_run sbctl sign -s "${f#"$root"}" || rc=1
            signed=1
        done
        ;;
    sbsign)
        [ -n "$UKI_SB_KEY" ] && [ -n "$UKI_SB_CERT" ] || {
            _uki_err "  sbsign selected but no key/cert pair is set"; return 1; }
        for f in "${UKI_PATHS[@]+"${UKI_PATHS[@]}"}"; do
            _uki_log "  sbsign ${f#"$root"}"
            # sbsign cannot sign in place; write beside it and move over.
            uki_run sbsign --key "$UKI_SB_KEY" --cert "$UKI_SB_CERT" \
                --output "${f#"$root"}.signed" "${f#"$root"}" || { rc=1; continue; }
            uki_run mv -f "${f#"$root"}.signed" "${f#"$root"}" || rc=1
            signed=1
        done
        ;;
    none)
        return 0
        ;;
    esac

    [ "$signed" -eq 1 ] || _uki_warn "  No UKI files were signed (none found)."
    return $rc
}

# uki_verify_signed <efi> — 0 signed, 1 unsigned, 2 cannot tell.
uki_verify_signed() {
    local f="$1"
    [ -f "$f" ] || return 2
    if command -v sbverify >/dev/null 2>&1; then
        sbverify --list "$f" 2>/dev/null | grep -q 'signature certificates' && return 0
        # sbverify --list prints nothing useful on an unsigned binary
        sbverify --list "$f" >/dev/null 2>&1 && return 0
        return 1
    fi
    if command -v sbctl >/dev/null 2>&1; then
        sbctl verify 2>/dev/null | grep -qF "$(basename "$f")" && return 0
        return 1
    fi
    # An Authenticode signature lives in the PE security directory; objdump
    # does not surface it, so without a verifier we genuinely cannot tell.
    return 2
}
