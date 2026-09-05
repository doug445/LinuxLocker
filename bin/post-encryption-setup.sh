#!/usr/bin/env bash
#
# LinuxLocker — universal in-place LUKS2 encryption for Linux (x86_64 / aarch64)
# https://github.com/doug445/LinuxLocker
#
# Copyright (c) 2026 William MacKinnon <spilled-bowline0j@icloud.com>
# SPDX-License-Identifier: MIT
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# ============================================================================
# post-encryption-setup.sh — finish the job after the box first boots encrypted
# ============================================================================
# Run ON THE ENCRYPTED TARGET, after it has booted encrypted at least once
# (NOT from the live USB):
#
#     sudo ./post-encryption-setup.sh
#     sudo ./post-encryption-setup.sh --config /path/to/post-encryption.conf
#
# What it does (all idempotent — safe to re-run):
#   0. Saves a labeled LUKS recovery bundle (header + boot state) to disk.
#   1. On btrfs roots with snapper installed: creates the snapshot subvolumes,
#      which must be made AFTER encryption so they live on the encrypted
#      volume. Skipped automatically everywhere else.
#   2. Enables any extra units you list in the config file.
#   3. Restores the splash boot arguments luks-deploy.sh stripped (rhgb /
#      quiet / splash — whichever this distro actually had) to every
#      command-line carrier lib-boot.sh knows — GRUB defaults and their
#      drop-ins, /etc/kernel/cmdline, cmdline.d, BLS and systemd-boot entries
#      wherever the ESP is, cmdline.txt, extlinux, rEFInd, Limine —
#      regenerating the GRUB config when the distro needs that.
#   4. Verifies the result and prints a summary.
#
# Written as a script on purpose: scripts do NOT source ~/.bashrc, so shell
# aliases (cp='cp -i', rm='rm -i', cat=bat, find=fd ...) cannot corrupt it,
# and PATH is pinned below so the system tools are the ones that run.
# ============================================================================
set -uo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

G='\033[0;32m'; Y='\033[1;33m'; RED='\033[0;31m'; C='\033[0;36m'; B='\033[1m'; N='\033[0m'
ok(){   echo -e "  ${G}[ok]${N} $*"; }
warn(){ echo -e "  ${Y}[warn]${N} $*"; }
err(){  echo -e "  ${RED}[fail]${N} $*"; }
hdr(){  echo -e "\n${B}${C}## $* ${N}"; }

[ "$(id -u)" -eq 0 ] || { err "run as root (sudo)"; exit 1; }

SELFDIR=$(dirname "$(readlink -f "$0")")
FAILS=0

# ─── Config ─────────────────────────────────────────────────────────────────
# Optional. Lets you enable your own units without editing this script.
# Arguments are strict (mirrors luks-tune.sh): a mistyped option silently
# ignored would run with defaults while the caller believed their config was
# in effect.
CONFIG=""
case "${1:-}" in
    "") ;;
    --config)
        CONFIG="${2:-}"
        if [ -z "$CONFIG" ] || [ ! -f "$CONFIG" ]; then
            err "--config requires an existing file (got: '${2:-}')"; exit 2
        fi
        [ "$#" -le 2 ] || { err "unexpected argument: $3"; exit 2; }
        ;;
    *)
        err "unknown option: $1 (only '--config <file>' is accepted)"; exit 2
        ;;
esac
[ -z "$CONFIG" ] && [ -f "$SELFDIR/post-encryption.conf" ] && CONFIG="$SELFDIR/post-encryption.conf"
[ -z "$CONFIG" ] && [ -f /etc/post-encryption.conf ] && CONFIG=/etc/post-encryption.conf

# Defaults; a config file may override.
SNAPPER_SUBVOLS=("/.snapshots" "/home/.snapshots")
SNAPPER_CONFIGS="root home"
ENABLE_SNAPPER=1
EXTRA_UNITS=()

if [ -n "$CONFIG" ] && [ -f "$CONFIG" ]; then
    # shellcheck disable=SC1090
    . "$CONFIG" && ok "loaded config: $CONFIG"
else
    warn "no config file — using built-in defaults (see post-encryption.conf.example)"
fi

ROOT_FSTYPE=$(findmnt -no FSTYPE / 2>/dev/null || echo unknown)

# ============================================================================
hdr "0. LUKS recovery bundle"
# ============================================================================
if [ -x "$SELFDIR/save-luks-recovery-bundle.sh" ]; then
    "$SELFDIR/save-luks-recovery-bundle.sh" || warn "recovery-bundle step reported an issue (see above)"
else
    warn "save-luks-recovery-bundle.sh not found next to this script — skipping bundle"
fi

# ============================================================================
hdr "1. Snapper subvolumes on the encrypted volume (btrfs only)"
# ============================================================================
if [ "$ROOT_FSTYPE" != "btrfs" ]; then
    ok "root is $ROOT_FSTYPE, not btrfs — snapper step does not apply"
elif [ "$ENABLE_SNAPPER" != 1 ]; then
    warn "ENABLE_SNAPPER=0 — skipping snapper setup"
elif ! command -v snapper >/dev/null 2>&1; then
    warn "snapper not installed — skipping (install it with your package manager if you want snapshots)"
else
    # Register the configs with snapper itself FIRST. `snapper create-config`
    # writes /etc/snapper/configs/<name>, adds it to SNAPPER_CONFIGS, and
    # creates the .snapshots subvolume itself (and refuses if one already
    # exists) — so configs come before any manual subvolume creation.
    for cfg in $SNAPPER_CONFIGS; do
        subject="/"; [ "$cfg" != "root" ] && subject="/$cfg"
        if [ -f "/etc/snapper/configs/$cfg" ]; then
            ok "snapper config exists: $cfg"
        elif cc_out=$(snapper -c "$cfg" create-config "$subject" 2>&1); then
            ok "created snapper config: $cfg → $subject"
        else
            err "snapper create-config failed for $cfg ($subject): $cc_out"
            FAILS=$((FAILS+1))
        fi
    done
    # Ensure the snapshot subvolumes exist (covers pre-existing configs whose
    # .snapshots subvolume was lost, e.g. not carried over by a restore).
    for sv in "${SNAPPER_SUBVOLS[@]}"; do
        if btrfs subvolume show "$sv" >/dev/null 2>&1; then
            ok "subvolume exists: $sv"
        elif btrfs subvolume create "$sv" >/dev/null 2>&1; then
            ok "created subvolume: $sv"
        else
            err "could not create subvolume: $sv"; FAILS=$((FAILS+1)); continue
        fi
        chmod 0750 "$sv" 2>/dev/null; chown root:root "$sv" 2>/dev/null
        command -v restorecon >/dev/null 2>&1 && restorecon -RF "$sv" 2>/dev/null || true
    done
    if [ -f /etc/sysconfig/snapper ]; then
        grep -q "SNAPPER_CONFIGS=\"$SNAPPER_CONFIGS\"" /etc/sysconfig/snapper \
            || sed -i "s/^SNAPPER_CONFIGS=.*/SNAPPER_CONFIGS=\"$SNAPPER_CONFIGS\"/" /etc/sysconfig/snapper
    fi
    systemctl restart snapperd 2>/dev/null || systemctl start snapperd 2>/dev/null || true
    sleep 1
    missing=0
    for cfg in $SNAPPER_CONFIGS; do
        snapper list-configs 2>/dev/null | grep -q "\b$cfg\b" || missing=1
    done
    if [ "$missing" -eq 0 ]; then
        ok "snapper configs registered ($SNAPPER_CONFIGS)"
        systemctl enable --now snapper-timeline.timer snapper-cleanup.timer >/dev/null 2>&1 \
            && ok "snapper timers enabled" || warn "could not enable snapper timers"
    else
        err "snapper configs NOT registered ($SNAPPER_CONFIGS)"; FAILS=$((FAILS+1))
    fi
fi

# ============================================================================
hdr "2. Extra units from config"
# ============================================================================
if [ "${#EXTRA_UNITS[@]}" -eq 0 ]; then
    warn "extra units: none configured"
else
    for u in "${EXTRA_UNITS[@]}"; do
        if [ ! -e "/etc/systemd/system/$u" ] && [ ! -e "/usr/lib/systemd/system/$u" ] \
           && [ ! -e "/lib/systemd/system/$u" ]; then
            warn "absent: $u"; continue
        fi
        if systemctl is-enabled "$u" >/dev/null 2>&1; then ok "already enabled: $u"; continue; fi
        systemctl enable --now "$u" >/dev/null 2>&1 \
            && ok "enabled: $u" || warn "enable failed (check: systemctl status $u): $u"
    done
fi

# ============================================================================
hdr "3. Restore splash boot arguments if luks-deploy stripped them"
# ============================================================================
# luks-deploy.sh strips the splash tokens (rhgb/quiet on Fedora-family,
# quiet/splash on Debian-family) so the first LUKS passphrase prompt is
# visible instead of hiding behind the splash, and leaves this marker with
# the exact tokens it removed. Idempotent.
SPLASH_MARKER=/var/lib/linuxlocker/restore-splash
GRUBBY=""
command -v grubby >/dev/null 2>&1 && GRUBBY=grubby
HAVE_BOOT_LIB=0
if [ -f "$SELFDIR/lib-boot.sh" ]; then
    # shellcheck source=lib-boot.sh
    . "$SELFDIR/lib-boot.sh"
    HAVE_BOOT_LIB=1
fi
if [ -f "$SPLASH_MARKER" ]; then
    TOKENS=$(cat "$SPLASH_MARKER" 2>/dev/null)
    TOKENS=${TOKENS:-quiet}
    FIRST_TOKEN=${TOKENS%% *}
    SPLASH_OK=1
    GRUB_DEFAULT_TOUCHED=0
    if [ "$HAVE_BOOT_LIB" -eq 1 ]; then
        # Restore mode: add the tokens, touch nothing else (read by lib-boot.sh).
        # shellcheck disable=SC2034
        CL_LUKS_ARGS=""
        # shellcheck disable=SC2034
        CL_ADD_ARGS=0
        # shellcheck disable=SC2034
        CL_FIX_ROOT=0
        # shellcheck disable=SC2034
        CL_ADD_TOKENS="$TOKENS"
    fi
    # BLS entries via grubby (Fedora-family); absent elsewhere and that is fine.
    if [ -d /boot/loader/entries ] && [ -n "$GRUBBY" ]; then
        if "$GRUBBY" --update-kernel=ALL --args="$TOKENS" >/dev/null 2>&1; then
            ok "BLS entries: restored '$TOKENS' (grubby)"
        else
            err "could not restore '$TOKENS' to the BLS entries"; FAILS=$((FAILS+1)); SPLASH_OK=0
        fi
    fi
    # GRUB defaults: the tokens go back into ONE variable per file — the
    # _DEFAULT one where it exists (Debian/Arch put the splash there), else
    # GRUB_CMDLINE_LINUX — so grub-mkconfig does not end up with 'quiet quiet'.
    # Drop-ins in /etc/default/grub.d override the main file, so they get the
    # same treatment.
    for gf in /etc/default/grub /etc/default/grub.d/*.cfg; do
        [ -f "$gf" ] || continue
        grep -qw "$FIRST_TOKEN" "$gf" && continue
        GVAR=""
        if grep -qE '^[[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT=' "$gf"; then GVAR=GRUB_CMDLINE_LINUX_DEFAULT
        elif grep -qE '^[[:space:]]*GRUB_CMDLINE_LINUX=' "$gf"; then GVAR=GRUB_CMDLINE_LINUX
        fi
        [ -n "$GVAR" ] || { [ "$gf" = /etc/default/grub ] && warn "/etc/default/grub: no GRUB_CMDLINE_LINUX[_DEFAULT] line to append '$TOKENS' to"; continue; }
        if [ "$HAVE_BOOT_LIB" -eq 1 ]; then
            cl_patch_file grubvar "$gf" "$GVAR"
        else
            sed -i -E "s/^([[:space:]]*${GVAR}=\".*)\"[[:space:]]*\$/\1 $TOKENS\"/" "$gf"
        fi
        # sed exits 0 even when it matched nothing — confirm the tokens landed.
        if grep -qw "$FIRST_TOKEN" "$gf"; then
            ok "$gf: appended '$TOKENS' to $GVAR"; GRUB_DEFAULT_TOUCHED=1
        else
            warn "$gf: could not append '$TOKENS' to $GVAR (unquoted value?)"; SPLASH_OK=0
        fi
    done
    if [ "$HAVE_BOOT_LIB" -eq 1 ]; then
        # Every other carrier: /etc/kernel/cmdline, cmdline.txt, cmdline.d,
        # Type #1 entries under /efi or /boot/efi (and /boot without grubby),
        # extlinux, rEFInd, Limine. Restoring is adding tokens where absent.
        CMDLINE_D_SEEN=0; CMDLINE_D_HAS=0
        while IFS=$'\t' read -r ckind cpath; do
            [ -n "$cpath" ] || continue
            case "$ckind" in
                grubd) continue ;;                          # done above
                bls)   [ -n "$GRUBBY" ] && case "$cpath" in /boot/loader/entries/*) continue ;; esac ;;
                dropin)
                    CMDLINE_D_SEEN=1
                    grep -qw "$FIRST_TOKEN" "$cpath" && CMDLINE_D_HAS=1
                    continue ;;
            esac
            grep -qw "$FIRST_TOKEN" "$cpath" 2>/dev/null && continue
            case "$ckind" in
                cmdline)        cl_patch_file cmdline  "$cpath" ;;
                bls)            cl_patch_file bls      "$cpath" ;;
                extlinux)       cl_patch_file extlinux "$cpath" ;;
                refind)         cl_patch_file refind   "$cpath" ;;
                limine)         cl_patch_file limine   "$cpath" ;;
                limine-default) cl_patch_file grubvar  "$cpath" 'KERNEL_CMDLINE(\[[^]]*\])?' ;;
                *) continue ;;
            esac
            if grep -qw "$FIRST_TOKEN" "$cpath"; then
                ok "$cpath: appended '$TOKENS'"
            else
                warn "$cpath: could not append '$TOKENS'"; SPLASH_OK=0
            fi
        done < <(cl_find_carriers "")
        # cmdline.d fragments are concatenated: one file carrying the tokens is
        # enough, and the one LinuxLocker owns is the right place.
        if [ "$CMDLINE_D_SEEN" -eq 1 ] && [ "$CMDLINE_D_HAS" -eq 0 ] && [ ! -f /etc/kernel/cmdline ]; then
            printf '%s\n' "$TOKENS" >> /etc/cmdline.d/90-linuxlocker.conf \
                && ok "/etc/cmdline.d/90-linuxlocker.conf: appended '$TOKENS'"
        fi
        # A UKI bakes the command line in; the restored tokens reach the
        # firmware only when the .efi is next rebuilt. That is deliberately
        # NOT done here: rebuilding outside the package manager skips the
        # distro's signing hook, and an unsigned UKI on a Secure Boot machine
        # does not boot. The next kernel update rebuilds and signs it.
        for ud in /boot/EFI/Linux /efi/EFI/Linux /boot/efi/EFI/Linux; do
            [ -d "$ud" ] || continue
            if ls "$ud"/*.efi >/dev/null 2>&1; then
                warn "this machine boots a Unified Kernel Image: the splash returns at the next UKI rebuild (kernel update), which also re-signs it"
                break
            fi
        done
    else
        # Without lib-boot.sh: the original three carriers only.
        if [ -f /etc/kernel/cmdline ] && ! grep -qw "$FIRST_TOKEN" /etc/kernel/cmdline; then
            sed -i "1s/[[:space:]]*\$/ $TOKENS/" /etc/kernel/cmdline \
                && ok "/etc/kernel/cmdline: appended '$TOKENS'"
        fi
        for CMDTXT in /boot/firmware/cmdline.txt /boot/cmdline.txt; do
            [ -f "$CMDTXT" ] || continue
            if ! grep -qw "$FIRST_TOKEN" "$CMDTXT"; then
                sed -i "1s/[[:space:]]*\$/ $TOKENS/" "$CMDTXT" \
                    && ok "$CMDTXT: appended '$TOKENS'"
            fi
            break
        done
        warn "lib-boot.sh not found next to this script — systemd-boot entries outside /boot, cmdline.d, extlinux, rEFInd and Limine were not restored"
    fi
    # Debian-family reads the splash from the generated grub.cfg — regenerate.
    if [ "$GRUB_DEFAULT_TOUCHED" -eq 1 ]; then
        if command -v update-grub >/dev/null 2>&1; then
            update-grub >/dev/null 2>&1 && ok "update-grub: regenerated grub.cfg" \
                || { warn "update-grub failed — run it manually"; SPLASH_OK=0; }
        elif command -v grub2-mkconfig >/dev/null 2>&1 && [ -f /boot/grub2/grub.cfg ]; then
            grub2-mkconfig -o /boot/grub2/grub.cfg >/dev/null 2>&1 \
                && ok "grub2-mkconfig: regenerated grub.cfg" \
                || { warn "grub2-mkconfig failed — run it manually"; SPLASH_OK=0; }
        fi
    fi
    # Remove the marker only when the restore actually landed — otherwise
    # a re-run would see no marker and never retry.
    if [ "$SPLASH_OK" -eq 1 ]; then
        rm -f "$SPLASH_MARKER" && ok "splash restored; marker removed"
    else
        warn "keeping $SPLASH_MARKER so a re-run can retry the restore"
    fi
else
    ok "no splash-restore marker — nothing to do"
fi

# ============================================================================
hdr "4. Verification"
# ============================================================================
echo "  --- is root actually LUKS-encrypted? ---"
# btrfs sources look like /dev/mapper/root_crypt[/root] — strip the subvol
# suffix before handing the name to cryptsetup. Check ROOT itself, not merely
# that *some* crypt device exists somewhere on the box.
ROOT_SRC=$(findmnt -no SOURCE / 2>/dev/null | sed 's/\[.*//')
ROOT_MAPPER=${ROOT_SRC#/dev/mapper/}
if [ "$ROOT_MAPPER" != "$ROOT_SRC" ] \
   && cryptsetup status "$ROOT_MAPPER" 2>/dev/null | grep -q 'LUKS'; then
    ok "root is on a LUKS mapper: $ROOT_SRC"
    cryptsetup status "$ROOT_MAPPER" 2>/dev/null \
        | grep -E 'cipher|keysize|device' | sed 's/^/    /' || true
else
    err "root ($ROOT_SRC) is not on an active LUKS mapper — is this box actually encrypted?"; FAILS=$((FAILS+1))
fi

echo "  --- initramfs carries the crypt tooling? ---"
KVER=$(uname -r)
INITRD=""
for f in "/boot/initramfs-${KVER}.img" "/boot/initrd.img-${KVER}" /boot/initramfs-linux.img; do
    [ -f "$f" ] && INITRD="$f" && break
done
list_initrd() {
    if command -v lsinitrd >/dev/null 2>&1; then lsinitrd "$1" 2>/dev/null
    elif command -v lsinitramfs >/dev/null 2>&1; then lsinitramfs "$1" 2>/dev/null
    elif command -v lsinitcpio >/dev/null 2>&1; then lsinitcpio "$1" 2>/dev/null
    fi
}
# Match the actual artifacts (cryptsetup binaries / dm-crypt module); a bare
# 'crypt' would also hit libcrypto etc. and pass on any initramfs.
if [ -n "$INITRD" ] && list_initrd "$INITRD" | grep -qE 'cryptsetup|dm-crypt|cryptroot'; then
    ok "$(basename "$INITRD") contains crypt support"
else
    warn "could not confirm crypt support in the running kernel's initramfs (listing tool unavailable, or crypt genuinely missing — check manually)"
fi

echo "  --- failed units ---"
FAILED=$(systemctl --failed --no-legend 2>/dev/null | wc -l)
if [ "$FAILED" -eq 0 ]; then ok "0 failed units"
else systemctl --failed --no-legend | sed 's/^/    /'; FAILS=$((FAILS+1)); fi

echo
if [ "$FAILS" -eq 0 ]; then
    echo -e "${G}${B}Post-encryption setup complete.${N}"
    echo -e "${C}Now copy the LUKS recovery bundle off this machine, and take a fresh backup${N}"
    echo -e "${C}so the encrypted box has its own first snapshot with the new crypttab/fstab.${N}"
else
    echo -e "${Y}${B}Completed with $FAILS issue(s) — review the [warn]/[fail] lines above.${N}"
fi
# Nonzero on failure so fleet automation can detect problems.
[ "$FAILS" -eq 0 ]
exit $?
