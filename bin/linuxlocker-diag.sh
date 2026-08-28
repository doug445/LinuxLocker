#!/bin/bash
#
# LinuxLocker — universal in-place LUKS2 encryption for Linux (x86_64 / aarch64)
# https://github.com/doug445/LinuxLocker
#
# Copyright (c) 2026 William MacKinnon <spilled-bowline0j@icloud.com>
# SPDX-License-Identifier: MIT
#
# ============================================================================
# linuxlocker-diag.sh — read-only diagnostic bundle for bug reports
# ============================================================================
# Collects everything a maintainer needs to reproduce a boot-configuration bug,
# formatted as Markdown you can paste straight into a GitHub issue.
#
#   sudo ./bin/linuxlocker-diag.sh                    # this machine
#   sudo ./bin/linuxlocker-diag.sh /dev/nvme0n1p3     # + inspect a target
#   sudo ./bin/linuxlocker-diag.sh --no-redact        # keep full UUIDs
#   sudo ./bin/linuxlocker-diag.sh -o report.md       # write to a file
#
# THIS SCRIPT ONLY READS. It mounts nothing read-write, changes nothing, and
# runs no cryptsetup subcommand that touches key material.
#
# What it deliberately never collects, because these ARE the keys:
#   * `cryptsetup luksDump --dump-master-key` output    (the volume key)
#   * LUKS header backups (*.img)                       (every keyslot)
#   * recovery-key.txt / any key file                   (a working passphrase)
#   * /etc/crypttab key-file *contents*                 (ditto)
# `luksDump` WITHOUT --dump-master-key is public header metadata — cipher, KDF,
# costs, salts — and is safe. That is the only form used here.
#
# By default UUIDs are truncated to their first 8 characters: enough to
# correlate lines within one report, not enough to fingerprint your disks in a
# public issue. --no-redact keeps them whole.
# ============================================================================
set -uo pipefail

LL_VERSION="1.2.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REDACT=1
OUTFILE=""
TARGET=""

while [ $# -gt 0 ]; do
    case "$1" in
        --no-redact) REDACT=0; shift ;;
        -o|--output) OUTFILE="${2:-}"; shift 2 ;;
        -h|--help)
            sed -n '10,34p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
            exit 0 ;;
        /dev/*) TARGET="$1"; shift ;;
        *) echo "Unknown argument: $1 (try --help)" >&2; exit 1 ;;
    esac
done

# Keep the original stdout on fd 3 so the closing note can reach the terminal
# even when the report itself is redirected to a file.
exec 3>&1
[ -n "$OUTFILE" ] && exec > "$OUTFILE"

# Truncate anything shaped like a UUID to 8 chars + an ellipsis marker.
redact() {
    if [ "$REDACT" -eq 1 ]; then
        sed -E 's/([0-9a-fA-F]{8})-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/\1-…/g'
    else
        cat
    fi
}

# Run a command into a fenced block, or say plainly that it is unavailable.
# Never let a missing tool abort the report — an incomplete bundle still helps.
sec() {   # $1 = heading, rest = command
    local heading="$1"; shift
    echo ""
    echo "### $heading"
    echo ""
    if ! command -v "${1}" >/dev/null 2>&1 && [ "${1}" != "cat" ] && [ "${1}" != "ls" ]; then
        echo "_(\`$1\` not installed in this environment)_"
        return 0
    fi
    echo '```'
    "$@" 2>&1 | redact || echo "(command failed: $*)"
    echo '```'
}

file_sec() {   # $1 = heading, $2 = path
    echo ""
    echo "### $1"
    echo ""
    if [ -r "$2" ]; then
        echo '```'
        redact < "$2"
        echo '```'
    else
        echo "_(not present or not readable: \`$2\`)_"
    fi
}

echo "<!-- LinuxLocker diagnostic bundle — paste this whole block into the issue -->"
echo ""
echo "## LinuxLocker diagnostic bundle"
echo ""
echo "| | |"
echo "|---|---|"
echo "| LinuxLocker version | \`$LL_VERSION\` |"
if command -v git >/dev/null 2>&1 && git -C "$SCRIPT_DIR" rev-parse --short HEAD >/dev/null 2>&1; then
    echo "| git revision | \`$(git -C "$SCRIPT_DIR" rev-parse --short HEAD)\` |"
fi
echo "| collected | \`$(date -u '+%Y-%m-%d %H:%M:%S UTC')\` |"
echo "| UUIDs | $( [ "$REDACT" -eq 1 ] && echo 'truncated to 8 chars' || echo '**not redacted**' ) |"
echo "| running as | \`$(id -un)\` (uid $(id -u)) |"
echo "| target argument | \`${TARGET:-none given}\` |"

echo ""
echo "---"
echo ""
echo "## 1. Live environment"
echo ""
echo "_The environment the script RUNS FROM. On a correct deployment this is a"
echo "live USB, not the system being encrypted — they are different code paths._"

file_sec "/etc/os-release (live)" /etc/os-release
sec "Kernel and architecture" uname -a
sec "Root filesystem of the live environment" findmnt -n -o SOURCE,FSTYPE,TARGET /
sec "cryptsetup version" cryptsetup --version
sec "Memory" free -h

echo ""
echo "### Tool availability (live environment)"
echo ""
echo '```'
for t in cryptsetup blkid lsblk findmnt resize2fs dumpe2fs e2fsck btrfs xfs_info \
         resize.f2fs ntfsresize fatresize dracut mkinitcpio update-initramfs \
         grub-mkconfig grub2-mkconfig update-grub grubby bootctl kernel-install \
         ukify sbctl sbsign sbverify mokutil objcopy lsinitrd lsinitcpio lsinitramfs; do
    printf '%-18s %s\n' "$t" "$(command -v "$t" 2>/dev/null || echo '-')"
done
echo '```'

echo ""
echo "---"
echo ""
echo "## 2. Block devices"
echo ""
echo "_\`crypto_LUKS\` in the FSTYPE column means that partition is already"
echo "encrypted. This is the fastest way to see whether a run got as far as"
echo "writing a header._"

sec "lsblk -f" lsblk -o NAME,FSTYPE,FSVER,LABEL,UUID,SIZE,MOUNTPOINTS
sec "Partition table layout" lsblk -o NAME,SIZE,TYPE,PARTTYPENAME
sec "Active device-mapper targets" dmsetup ls --target crypt

echo ""
echo "---"
echo ""
echo "## 3. Firmware and Secure Boot"

if [ -d /sys/firmware/efi ]; then
    echo ""
    echo "_Booted in UEFI mode._"
else
    echo ""
    echo "_No \`/sys/firmware/efi\` — this is a **BIOS/legacy** boot. UKI and"
    echo "Secure Boot sections below do not apply._"
fi

sec "Secure Boot state" mokutil --sb-state
sec "sbctl status" sbctl status
sec "bootctl status" bootctl status

echo ""
echo "---"
echo ""
echo "## 4. Boot stack of the target"
echo ""
echo "_Everything below is read from the TARGET system. If the target is not"
echo "mounted, mount it first — the maintainer cannot infer this from anything"
echo "else in the report._"

# Prefer an explicitly mounted target at /mnt (what luks-deploy.sh uses), else
# fall back to the running system, which is right when the report is filed
# after a successful deployment rather than during a failed one.
ROOT=""
if [ -d /mnt/etc ] && [ -f /mnt/etc/fstab ]; then
    ROOT=/mnt
    echo ""
    echo "**Target detected at \`/mnt\`** (a deployment is in progress or was interrupted)."
else
    ROOT=""
    echo ""
    echo "**No target mounted at \`/mnt\`** — reporting on the running system instead."
fi

file_sec "os-release (target)"   "$ROOT/etc/os-release"
file_sec "/etc/fstab"            "$ROOT/etc/fstab"

echo ""
echo "### /etc/crypttab"
echo ""
echo "_Field 3 is the key file. Its **path** is shown; its contents are never read._"
echo ""
if [ -r "$ROOT/etc/crypttab" ]; then
    echo '```'
    redact < "$ROOT/etc/crypttab"
    echo '```'
else
    echo "_(not present or not readable)_"
fi

file_sec "/etc/kernel/cmdline"   "$ROOT/etc/kernel/cmdline"
file_sec "/etc/default/grub"     "$ROOT/etc/default/grub"
file_sec "/proc/cmdline (currently running kernel)" /proc/cmdline

echo ""
echo "### Mount points of the boot partitions"
echo ""
echo '```'
findmnt -n -o SOURCE,TARGET,FSTYPE /boot /efi /boot/efi /boot/firmware 2>/dev/null | redact \
    || echo "(none of /boot /efi /boot/efi /boot/firmware are mounted)"
echo '```'

echo ""
echo "### Initramfs generator configuration"
echo ""
echo '```'
if [ -r "$ROOT/etc/mkinitcpio.conf" ]; then
    echo "--- $ROOT/etc/mkinitcpio.conf (HOOKS/MODULES only) ---"
    grep -E '^(HOOKS|MODULES|BINARIES)=' "$ROOT/etc/mkinitcpio.conf"
fi
[ -d "$ROOT/etc/mkinitcpio.d" ] && { echo "--- $ROOT/etc/mkinitcpio.d ---"; ls -1 "$ROOT/etc/mkinitcpio.d"; }
for f in "$ROOT"/etc/mkinitcpio.d/*.preset; do
    [ -r "$f" ] || continue
    echo "--- $f ---"; grep -Ev '^\s*(#|$)' "$f"
done
[ -d "$ROOT/etc/dracut.conf.d" ] && { echo "--- $ROOT/etc/dracut.conf.d ---"; ls -1 "$ROOT/etc/dracut.conf.d"; }
for f in "$ROOT"/etc/dracut.conf.d/*luks*.conf; do
    [ -r "$f" ] || continue
    echo "--- $f ---"; cat "$f"
done
[ -e "$ROOT/usr/share/initramfs-tools/hooks/cryptroot" ] && echo "initramfs-tools cryptroot hook: PRESENT"
echo '```'

echo ""
echo "### Initramfs images and kernels"
echo ""
echo '```'
ls -la "$ROOT"/boot/initramfs-*.img "$ROOT"/boot/initrd.img-* "$ROOT"/boot/vmlinuz-* 2>/dev/null \
    || echo "(no standalone initramfs or vmlinuz in /boot — normal on a UKI-only target)"
echo '```'

echo ""
echo "### Bootloader entries"
echo ""
echo '```'
for d in "$ROOT"/boot/loader/entries "$ROOT"/efi/loader/entries "$ROOT"/boot/efi/loader/entries; do
    [ -d "$d" ] || continue
    echo "--- $d ---"
    for e in "$d"/*.conf; do
        [ -f "$e" ] || continue
        echo "== $(basename "$e")"
        redact < "$e"
    done
done
for g in "$ROOT"/boot/grub2/grub.cfg "$ROOT"/boot/grub/grub.cfg; do
    [ -f "$g" ] || continue
    echo "--- $g (linux/cryptomount lines only) ---"
    grep -nE '^\s*(linux|cryptomount|search)' "$g" | head -20 | redact
done
for c in "$ROOT"/boot/cmdline.txt "$ROOT"/boot/firmware/cmdline.txt "$ROOT"/boot/extlinux/extlinux.conf; do
    [ -f "$c" ] || continue
    echo "--- $c ---"; redact < "$c"
done
echo '```'

echo ""
echo "---"
echo ""
echo "## 5. Unified Kernel Images"

echo ""
echo '```'
UKI_ANY=0
for d in "$ROOT"/boot/EFI/Linux "$ROOT"/efi/EFI/Linux "$ROOT"/boot/efi/EFI/Linux; do
    [ -d "$d" ] || continue
    UKI_ANY=1
    echo "--- $d ---"
    ls -la "$d"
done
[ "$UKI_ANY" -eq 0 ] && echo "(no EFI/Linux directory — this target does not boot a UKI)"
echo '```'

if [ "$UKI_ANY" -eq 1 ]; then
    echo ""
    echo "### Baked-in kernel command line of each UKI"
    echo ""
    echo "_This is the check that matters. A UKI carries its command line inside"
    echo "the \`.cmdline\` section; if the LUKS arguments are missing here, the"
    echo "machine will not unlock no matter what \`/etc/kernel/cmdline\` says._"
    echo ""
    echo '```'
    if command -v objcopy >/dev/null 2>&1; then
        for d in "$ROOT"/boot/EFI/Linux "$ROOT"/efi/EFI/Linux "$ROOT"/boot/efi/EFI/Linux; do
            for u in "$d"/*.efi; do
                [ -f "$u" ] || continue
                echo "== $(basename "$u")"
                CL=$(objcopy --dump-section .cmdline=/dev/stdout "$u" /dev/null 2>/dev/null | tr -d '\0')
                if [ -n "$CL" ]; then printf '%s\n' "$CL" | redact
                else echo "(no .cmdline section)"; fi
                echo ""
            done
        done
    else
        echo "(objcopy not installed — install binutils and re-run to include this)"
    fi
    echo '```'

    echo ""
    echo "### Signature status"
    echo ""
    echo '```'
    if command -v sbverify >/dev/null 2>&1; then
        for d in "$ROOT"/boot/EFI/Linux "$ROOT"/efi/EFI/Linux "$ROOT"/boot/efi/EFI/Linux; do
            for u in "$d"/*.efi; do
                [ -f "$u" ] || continue
                printf '%-45s ' "$(basename "$u")"
                sbverify --list "$u" >/dev/null 2>&1 && echo "SIGNED" || echo "UNSIGNED"
            done
        done
    else
        echo "(sbverify not installed — install sbsigntools and re-run)"
    fi
    echo '```'
fi

echo ""
echo "### What LinuxLocker's own detection reports"
echo ""
echo "_If this disagrees with the sections above, that disagreement IS the bug._"
echo ""
echo '```'
if [ -f "$SCRIPT_DIR/lib-uki.sh" ]; then
    # shellcheck source=lib-uki.sh
    . "$SCRIPT_DIR/lib-uki.sh"
    uki_reset
    uki_find_ukis     "$ROOT"
    uki_detect_regen  "$ROOT" >/dev/null 2>&1
    uki_detect_signer "$ROOT" >/dev/null 2>&1
    uki_detect_sdboot "$ROOT" >/dev/null 2>&1
    uki_detect_sb
    echo "UKIs found          : ${#UKI_PATHS[@]}"
    echo "rebuild backend     : $UKI_REGEN   ($UKI_REGEN_DETAIL)"
    echo "signing backend     : $UKI_SIGN   ($UKI_SIGN_DETAIL)"
    echo "Secure Boot state   : $UKI_SB_STATE"
    echo "systemd-boot        : $UKI_SDBOOT   ($UKI_SDBOOT_DETAIL)"
else
    echo "(bin/lib-uki.sh not found next to this script)"
fi
if [ -f "$SCRIPT_DIR/lib-deps.sh" ]; then
    # shellcheck source=lib-deps.sh
    . "$SCRIPT_DIR/lib-deps.sh"
    ll_detect_os
    ll_detect_pkg_mgr >/dev/null 2>&1 || true
    echo "live OS family      : $LL_FAMILY   (id=$LL_OS_ID)"
    echo "live package mgr    : ${LL_PKG_MGR:-none}"
    if ll_detect_asahi "$ROOT"; then
        echo "Apple Silicon/Asahi : YES — $LL_ASAHI_REASON  (use AsahiLocker)"
    else
        echo "Apple Silicon/Asahi : no"
    fi
fi
echo '```'

echo ""
echo "---"
echo ""
echo "## 6. LUKS header metadata"
echo ""
echo "_Public header metadata only — cipher, KDF and its costs. No key material."
echo "\`--dump-master-key\` is never run by this script and must never be pasted."
echo "into an issue._"

if [ -n "$TARGET" ]; then
    sec "luksDump $TARGET" cryptsetup luksDump "$TARGET"
else
    echo ""
    echo "### luksDump"
    echo ""
    echo '```'
    FOUND_LUKS=0
    while read -r dev; do
        [ -n "$dev" ] || continue
        FOUND_LUKS=1
        echo "===== $dev ====="
        cryptsetup luksDump "$dev" 2>&1 | redact
        echo ""
    done < <(lsblk -rno NAME,FSTYPE | awk '$2=="crypto_LUKS"{print "/dev/"$1}')
    [ "$FOUND_LUKS" -eq 0 ] && echo "(no crypto_LUKS partitions found; pass one explicitly: linuxlocker-diag.sh /dev/sdXN)"
    echo '```'
fi

echo ""
echo "---"
echo ""
echo "## 7. Logs"

echo ""
echo "### Most recent LinuxLocker deploy log (last 80 lines)"
echo ""
echo '```'
LATEST=$(ls -t "$SCRIPT_DIR"/luks-deploy-*.log "$ROOT"/boot/luks-deploy.log 2>/dev/null | head -1)
if [ -n "$LATEST" ]; then
    echo "--- $LATEST ---"
    tail -80 "$LATEST" | redact
else
    echo "(no luks-deploy log found next to the script or at /boot/luks-deploy.log)"
fi
echo '```'

echo ""
echo "### Unlock-related journal entries"
echo ""
echo '```'
if command -v journalctl >/dev/null 2>&1; then
    journalctl -b -o short-precise --no-pager 2>/dev/null \
        | grep -iE 'cryptsetup|Cryptography Setup|dm-crypt|luks|Failed to (start|open)' \
        | tail -40 | redact \
        || echo "(no matching journal entries this boot)"
else
    echo "(journalctl not available)"
fi
echo '```'

echo ""
echo "---"
echo ""
echo "<!-- end of LinuxLocker diagnostic bundle -->"

if [ -n "$OUTFILE" ]; then
    {
        echo "Diagnostic bundle written to: $OUTFILE"
        echo "Read it before posting — you are the last check on what it contains."
    } >&3
fi
exec 3>&-
