#!/bin/bash
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
# LinuxLocker LUKS2 Deployment Script (hardened, multi-distro)
# ============================================================================
# In-place LUKS2 encryption of an existing root (or data) partition.
#
# Targets: any Linux the live environment can chroot into — Fedora/RHEL-family
# (dracut + grubby + BLS), Debian/Ubuntu/Raspberry Pi OS (initramfs-tools +
# update-grub / cmdline.txt), Arch-family (mkinitcpio), openSUSE (dracut +
# grub2-mkconfig). x86_64 and aarch64 alike; nothing here is CPU-specific.
#
# Filesystems (in-place): ext4/ext3/ext2, btrfs, xfs*, f2fs, ntfs, vfat.
#   * xfs cannot be shrunk — it is accepted only when >= 32 MiB of slack
#     already exists between the end of the filesystem and the partition end.
#   exfat/udf cannot be shrunk or probed reliably: not supported in place.
#   See docs/FILESYSTEMS.md for the full support matrix.
#
# MUST be run from a live USB / rescue environment, NOT the installed system.
#
# What this script does:
#   1. Auto-detects partitions, target OS, filesystems, boot configuration
#   2. Resolves missing filesystem tools via the live distro's package manager
#   3. Shrinks the filesystem by 32MB for LUKS2 header space
#   4. In-place encrypts the partition with LUKS2 + checksum resilience
#   5. Verifies LUKS header, opens container, grows the filesystem back
#   6. Updates fstab, crypttab, GRUB / BLS entries / cmdline.txt / extlinux
#   7. Rebuilds ALL initramfs images (dracut / mkinitcpio / initramfs-tools)
#   8. Self-verifies every component; auto-repairs failed initramfs
#   9. Full verification gate: blocks reboot until ALL applicable checks pass
#
# Idempotent / re-entrant / resumable:
#   - Interrupted mid-encryption? Re-run: it detects the LUKS2
#     'online-reencrypt' requirement flag and finishes the encryption with
#     `cryptsetup reencrypt --resume-only`, then redoes the config phase.
#   - Died during the config phase? Re-run: configuration-only mode unlocks
#     the container and redoes every config + verification step (all
#     idempotent) without touching the data.
#   - LUKS1 header found? Offers automatic conversion to LUKS2, then re-costs
#     the keyslots to argon2id using the same three KDF profiles.
#   - Complete LUKS2 header found? Shows a truncated luksDump and offers the
#     KDF tuning UI (luks-tune.sh), config repair, or a clean exit.
# ============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Mapper name for the unlocked root. Overridable for fleets that need a
# different device-mapper name; the companion scripts (recovery bundle,
# post-encryption setup) auto-detect it from the booted system's root source.
LUKS_NAME="${LUKS_MAPPER_NAME:-root_crypt}"
case "$LUKS_NAME" in
    *[!A-Za-z0-9_-]*|'') echo "LUKS_MAPPER_NAME must match [A-Za-z0-9_-]+" >&2; exit 1;;
esac

# ─── CLI flags ───────────────────────────────────────────────────────────────
# --dry-run (or LUKS_DRY_RUN=1): run every read-only phase — detection, menus,
# fstab cross-checks, KDF benchmark, state backup to the deployment drive —
# print the full plan, and exit BEFORE the point of no return. Nothing on the
# TARGET is modified (config-only dry-run still asks for the passphrase to
# unlock the container for discovery; all discovery mounts are read-only).
DRY_RUN="${LUKS_DRY_RUN:-0}"
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        *) echo "Unknown argument: $arg (only --dry-run is accepted; everything else is via LUKS_* env vars — see the header of this script)" >&2; exit 1 ;;
    esac
done

# ─── Non-interactive passphrase (fleet / automated testing) ──────────────────
# LUKS_PASSPHRASE_FILE=<path>: read the passphrase from a file instead of the
# terminal (used for reencrypt/resume/open and as the existing key when
# enrolling the recovery key). The file's exact bytes are the passphrase — no
# trailing newline. The file is NOT deleted; the caller owns its lifecycle.
CRYPT_PASS_ARGS=()      # for interactive prompts these stay empty
CRYPT_BATCH_ARGS=()
if [ -n "${LUKS_PASSPHRASE_FILE:-}" ]; then
    [ -r "$LUKS_PASSPHRASE_FILE" ] && [ -s "$LUKS_PASSPHRASE_FILE" ] \
        || { echo "LUKS_PASSPHRASE_FILE=$LUKS_PASSPHRASE_FILE is missing, unreadable, or empty" >&2; exit 1; }
    CRYPT_PASS_ARGS=(--key-file "$LUKS_PASSPHRASE_FILE")
    # --batch-mode also skips cryptsetup's own are-you-sure prompt; this
    # script's typed ENCRYPT gate remains the consent step.
    CRYPT_BATCH_ARGS=(--batch-mode)
fi

# Log to the directory this script lives in (the USB/deployment drive),
# not /tmp (which is tmpfs on live USB and gets wiped on reboot)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_LOG="$SCRIPT_DIR/luks-deploy-$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "$DEPLOY_LOG") 2>&1
echo "Full log: $DEPLOY_LOG"

log()  { echo -e "[$(date '+%H:%M:%S')] ${GREEN}[LUKS]${NC} $*"; }
warn() { echo -e "[$(date '+%H:%M:%S')] ${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "[$(date '+%H:%M:%S')] ${RED}[ERROR]${NC} $*" >&2; }
fatal() { err "$@"; exit 1; }

# ─── Shared dependency helpers (OS / package manager / installer) ────────────
# Optional: if lib-deps.sh sits next to this script, missing filesystem tools
# are auto-installed with the live distro's package manager; without it they
# are simply reported as fatal with the package named.
LL_HAVE_DEPS_LIB=0
if [ -f "$SCRIPT_DIR/lib-deps.sh" ]; then
    # shellcheck source=lib-deps.sh
    . "$SCRIPT_DIR/lib-deps.sh"
    LL_HAVE_DEPS_LIB=1
    ll_detect_os
    ll_detect_pkg_mgr || true
fi

# ─── UKI / systemd-boot / Secure Boot support ────────────────────────────────
# Optional in the same way: without lib-uki.sh a UKI target is refused outright
# (the pre-1.2.0 behaviour), because nothing else here can regenerate the .efi.
LL_HAVE_UKI_LIB=0
if [ -f "$SCRIPT_DIR/lib-uki.sh" ]; then
    # shellcheck source=lib-uki.sh
    . "$SCRIPT_DIR/lib-uki.sh"
    LL_HAVE_UKI_LIB=1
fi

# ─── Kernel command-line carriers + encrypted-/boot recognition ──────────────
# Not optional: stages 6d-6h, the splash strip, checks V3/V11/V14 and the
# refusal of /boot-inside-the-volume targets all go through it.
[ -f "$SCRIPT_DIR/lib-boot.sh" ] \
    || fatal "lib-boot.sh not found next to this script — the bin/ directory is incomplete."
# shellcheck source=lib-boot.sh
. "$SCRIPT_DIR/lib-boot.sh"

# ─── Apple Silicon / Fedora Asahi Remix — wrong tool, stop here ──────────────
# Checked before ANY device is touched. AsahiLocker carries the boot guards
# this script deliberately drops; running here risks an unbootable Mac.
if [ "$LL_HAVE_DEPS_LIB" -eq 1 ] && ll_detect_asahi ""; then
    ll_asahi_refuse "This live environment is running on Apple Silicon / Fedora Asahi Remix."
    exit 3
fi

# ─── Permissions on the deployment drive ─────────────────────────────────────
# chmod(2) SUCCEEDS and does nothing on vfat/exfat/ntfs: the mode comes from the
# mount's fmask/dmask, not from the inode. So `chmod 0400 secret` on a FAT stick
# reports success and leaves the file world-readable. The recovery key and the
# LUKS header backup both land on the deployment drive, which is very often
# exactly such a stick, so a silent no-op here is the dangerous case -- not a
# hard failure.
#
# Set the mode, read it back, and say so ONCE if it did not take. Never returns
# non-zero: a drive that cannot hold permissions is a reason to warn loudly, not
# to abort a deployment that is already under way.
MODE_WARNED=0
harden_path() {                        # harden_path <octal-mode> <path>
    local mode="$1" path="$2" got
    chmod "$mode" "$path" 2>/dev/null || true
    got="$(stat -c '%a' "$path" 2>/dev/null || true)"
    if [ "$got" = "${mode#0}" ]; then
        return 0
    fi
    if [ "$MODE_WARNED" -eq 0 ]; then
        MODE_WARNED=1
        warn "This drive cannot store Unix permissions (vfat/exfat?)."
        warn "  Wanted mode $mode on $(basename "$path"); it is ${got:-unknown}."
        warn "  The recovery key and LUKS header backup written here are readable"
        warn "  by ANYONE who picks this drive up. Move them to secure offline"
        warn "  storage as soon as deployment finishes."
    fi
    return 0
}

# ─── LUKS2 KDF profiles ──────────────────────────────────────────────────────
# Three presets, chosen interactively before encryption starts. The KDF is
# re-run in the INITRAMFS at every boot, so its memory cost must be allocatable
# there — and you pay its full cost as unlock latency on EVERY boot.
#
# argon2id cost is ~proportional to (memory x iterations). The script benchmarks
# THIS machine and shows a real estimated unlock time for each profile, rather
# than quoting numbers from someone else's hardware.
#
#   aggressive  4 GiB  t=10   paranoid; 4 GiB is argon2id's maximum memory
#                              cost - cryptsetup refuses anything above
#                              4194304 KiB - so cost above it buys iterations.
#                              Needs >= ~6 GiB RAM at every unlock — do not
#                              pick it on small boards (Raspberry Pi etc.).
#   moderate    2 GiB  t=8    balanced; the default
#   fast        1 GiB  t=9    the FLOOR, not a discount. cryptsetup's own
#                              default is argon2id at 1 GiB with iterations
#                              auto-tuned to ~2000 ms. t=9 stays above stock
#                              on typical desktop hardware; the stock-floor
#                              guard below re-checks that on THIS machine.
#
# ALWAYS argon2id. It is memory-hard, which is what makes GPU/ASIC cracking
# expensive; never substitute pbkdf2 to save memory or time — argon2id at 1 GiB
# beats pbkdf2 at any iteration count. There is no profile that selects pbkdf2.
#
# Non-interactive use:
#   LUKS_PROFILE=fast ./luks-deploy.sh                       # pick a preset
#   LUKS_PBKDF_MEMORY=3145728 LUKS_PBKDF_ITER=8 ./luks-deploy.sh   # fully custom
# Setting any LUKS_PBKDF_* variable pins the parameters and skips the menu.
#
# Partition pinning (skips the selection menus — for fleet/scripted use):
#   LUKS_TARGET_ROOT=/dev/nvme0n1p3 LUKS_TARGET_BOOT=/dev/nvme0n1p2 \
#   LUKS_TARGET_EFI=/dev/nvme0n1p1 ./luks-deploy.sh
# Each pinned device is still fstype-checked, cross-checked against the
# target's fstab, and subject to the same typed ENCRYPT confirmation.
#
# Recovery key (2nd keyslot): prompted interactively; pin with
#   LUKS_RECOVERY_KEY=yes|no ./luks-deploy.sh
#
# More environment knobs:
#   LUKS_PASSPHRASE_FILE=<path>  read the passphrase from a file (fleet/testing);
#                                the file's exact bytes are the passphrase
#   LUKS_MAPPER_NAME=<name>      device-mapper name (default: root_crypt)
#   LUKS_KEEP_SPLASH=1           do NOT strip 'rhgb quiet splash' from the boot
#                                args (default: strip whichever are present, so
#                                the passphrase prompt is visible;
#                                post-encryption-setup.sh restores them)
#   LUKS_SKIP_VERSION_CHECK=1    bypass the cryptsetup >= 2.4 floor
#   LUKS_ALLOW_UKI=1             deploy onto a UKI target even when this script
#                                cannot rebuild or sign the .efi itself. UKI
#                                targets with a working rebuild path are
#                                supported WITHOUT this flag; it exists only to
#                                override the two remaining refusals (no rebuild
#                                backend, or Secure Boot on with no signer).
#                                Regenerating and re-signing EFI/Linux/*.efi
#                                then becomes your job, before the first reboot.
#   LUKS_UKI_REGEN=<backend>     force the UKI rebuild backend instead of
#                                detecting it: mkinitcpio | kernel-install |
#                                dracut | ukify | none
#   LUKS_UKI_SIGN=<backend>      force the signing backend: sbctl | sbsign | none
#   LUKS_SB_KEY=<path>           explicit sbsign key ... and
#   LUKS_SB_CERT=<path>          ... its certificate. Both, or neither.
#   LUKS_SKIP_UKI_SIGN=1         rebuild the UKI but do not sign it. On a Secure
#                                Boot machine this WILL fail to boot until you
#                                sign it yourself — V12 downgrades to a warning.
#   LUKS_SB_STATE=enabled|disabled
#                                override Secure Boot autodetection (testing).
#                                See docs/BOOTLOADERS.md for all of the above.
#   LUKS_DRY_RUN=1 (or --dry-run flag)  preview: full detection + plan, no
#                                       changes to the target, exit before
#                                       the point of no return
#   LUKS_GRUB_KDF_FACTOR=<x>     unlock-time multiplier shown for a volume that
#                                GRUB itself unlocks (encrypted /boot). Default
#                                8.5, measured on one machine; see lib-boot.sh
#   LUKS_GRUB_ARGON2_MAX_KIB=<n> argon2id memory ceiling for such a volume.
#                                Default 1 GiB — the x86 UEFI contiguous heap
#
# Encrypted /boot is RECOGNISED, never set up. A target whose /boot lives on
# the root filesystem under GRUB or extlinux is refused before the shrink: the
# bootloader would have to unlock the volume itself, and LinuxLocker does not
# re-embed GRUB images, does not offer pbkdf2, and will not put a keyslot
# where a single-threaded bootloader with a 1 GiB heap has to open it. On a
# volume GRUB already unlocks, the only thing offered is KDF tuning within
# that ceiling, with the unlock estimate multiplied by GRUB's slowdown.

KDF_PROFILE_AGGRESSIVE_MEM=4194304;  KDF_PROFILE_AGGRESSIVE_ITER=10
KDF_PROFILE_MODERATE_MEM=2097152;    KDF_PROFILE_MODERATE_ITER=8
KDF_PROFILE_FAST_MEM=1048576;        KDF_PROFILE_FAST_ITER=9
KDF_DEFAULT_PARALLEL=4

# This machine's RAM, needed wherever a memory cost is chosen — the profile
# menu, the LUKS1 conversion re-cost, and the pinned-parameter check.
MEM_TOTAL_KIB=$(awk '/^MemTotal:/{print $2; exit}' /proc/meminfo 2>/dev/null || echo 0)
case "$MEM_TOTAL_KIB" in ''|*[!0-9]*) MEM_TOTAL_KIB=0;; esac

# Did the caller pin anything explicitly? (checked before defaults are applied)
KDF_PINNED_BY_ENV=0
if [ -n "${LUKS_PBKDF_MEMORY:-}" ] || [ -n "${LUKS_PBKDF_ITER:-}" ] || [ -n "${LUKS_PBKDF_PARALLEL:-}" ]; then
    KDF_PINNED_BY_ENV=1
fi

# Defaults = the moderate profile; the menu (or LUKS_PROFILE) may replace them.
LUKS_PBKDF_MEMORY="${LUKS_PBKDF_MEMORY:-$KDF_PROFILE_MODERATE_MEM}"
LUKS_PBKDF_ITER="${LUKS_PBKDF_ITER:-$KDF_PROFILE_MODERATE_ITER}"
LUKS_PBKDF_PARALLEL="${LUKS_PBKDF_PARALLEL:-$KDF_DEFAULT_PARALLEL}"
KDF_PROFILE_NAME="moderate"

case "$LUKS_PBKDF_MEMORY" in ''|*[!0-9]*) echo "LUKS_PBKDF_MEMORY must be an integer (KiB)" >&2; exit 1;; esac
case "$LUKS_PBKDF_ITER" in ''|*[!0-9]*) echo "LUKS_PBKDF_ITER must be an integer" >&2; exit 1;; esac
case "$LUKS_PBKDF_PARALLEL" in ''|*[!0-9]*) echo "LUKS_PBKDF_PARALLEL must be an integer" >&2; exit 1;; esac

# ─── The 'fast' profile IS the floor ────────────────────────────────────────
# Nothing below it is accepted, and there is deliberately NO acknowledgement
# flag. cryptsetup's own default is argon2id at 1 GiB with iterations tuned to
# ~2000 ms, so anything cheaper than 'fast' would ship a volume weaker than a
# plain `luksFormat` with no arguments — which this tool exists to beat, not to
# offer as a setting. It also catches the classic typo (LUKS_PBKDF_MEMORY=1048
# for 1048576). If you genuinely want a cheaper KDF, run cryptsetup's
# luksConvertKey yourself; this script will not do it for you.
#
# Two conditions, because they fail differently: memory below 1 GiB loses the
# memory-hardness that is the entire point, and total work below 'fast' is
# cheaper per guess however the two factors are traded off.
KDF_FLOOR_MEM=$KDF_PROFILE_FAST_MEM
KDF_FLOOR_WORK=$((KDF_PROFILE_FAST_MEM * KDF_PROFILE_FAST_ITER))

if [ "$KDF_PINNED_BY_ENV" -eq 1 ]; then
    if [ -n "${LUKS_PBKDF_ACK_WEAK:-}" ]; then
        warn "LUKS_PBKDF_ACK_WEAK is not honoured — the 'fast' profile is a hard floor."
    fi
    if [ "$LUKS_PBKDF_MEMORY" -lt "$KDF_FLOOR_MEM" ] \
       || [ $((LUKS_PBKDF_MEMORY * LUKS_PBKDF_ITER)) -lt "$KDF_FLOOR_WORK" ]; then
        fatal "Pinned KDF parameters are below the 'fast' floor.
       requested : $((LUKS_PBKDF_MEMORY / 1024)) MiB x ${LUKS_PBKDF_ITER} iterations
       floor     : $((KDF_FLOOR_MEM / 1024)) MiB x ${KDF_PROFILE_FAST_ITER} iterations (the 'fast' profile)
     There is no override. cryptsetup's own default is ~1 GiB with iterations
     tuned to 2000 ms, so this would be weaker than luksFormat with no flags.
     LinuxLocker hardens; it never writes a weaker KDF. If you truly want one,
     that is a manual cryptsetup luksFormat/luksConvertKey outside this tool."
    fi
fi

# Apply a named profile requested via the environment.
apply_kdf_profile() {
    case "$1" in
        aggressive) LUKS_PBKDF_MEMORY=$KDF_PROFILE_AGGRESSIVE_MEM; LUKS_PBKDF_ITER=$KDF_PROFILE_AGGRESSIVE_ITER ;;
        moderate)   LUKS_PBKDF_MEMORY=$KDF_PROFILE_MODERATE_MEM;   LUKS_PBKDF_ITER=$KDF_PROFILE_MODERATE_ITER ;;
        fast)       LUKS_PBKDF_MEMORY=$KDF_PROFILE_FAST_MEM;       LUKS_PBKDF_ITER=$KDF_PROFILE_FAST_ITER ;;
        *) return 1 ;;
    esac
    LUKS_PBKDF_PARALLEL=$KDF_DEFAULT_PARALLEL
    KDF_PROFILE_NAME="$1"
}

# Estimate unlock time for (mem_kib, iters, parallel) by calibrating against
# cryptsetup's own benchmark on THIS machine. benchmark reports how many
# iterations fit in ~2000 ms and CLAMPS requested memory to what it can
# actually allocate right now, so scale from the memory it actually used
# rather than the memory we asked for.
kdf_estimate_ms() {
    local mem_kib="$1" iters="$2" par="$3" out b_iters b_mem
    out=$(cryptsetup benchmark --pbkdf argon2id --pbkdf-memory "$mem_kib" \
              --pbkdf-parallel "$par" 2>/dev/null | grep -m1 'argon2id') || return 1
    b_iters=$(echo "$out" | awk '{print $2}')
    b_mem=$(echo "$out"   | awk '{print $4}')
    case "$b_iters" in ''|*[!0-9]*) return 1;; esac
    case "$b_mem"   in ''|*[!0-9]*) return 1;; esac
    [ "$b_iters" -gt 0 ] && [ "$b_mem" -gt 0 ] || return 1
    awk -v ti="$iters" -v tm="$mem_kib" -v bi="$b_iters" -v bm="$b_mem" \
        'BEGIN{ printf "%.0f", 2000.0 * (ti*tm) / (bi*bm) }'
}

# Read cryptsetup's OWN default parameters for this machine: argon2id at its
# default memory with the iteration count auto-tuned to --iter-time (2000 ms).
# Sets STOCK_ITER / STOCK_MEM. Returns non-zero if the benchmark is unusable.
#
# Sampled, and the LOWEST reading wins. This benchmark is load-sensitive —
# measured readings on the same machine can halve under load for the same
# 1 GiB. Bias matters here because the two errors are not symmetric: reading
# stock too LOW only makes the guard a no-op, while reading it too HIGH
# inflates the iteration count permanently and you pay that as unlock latency
# at EVERY boot. The static 'fast' floor is what guarantees the baseline; this
# guard only has to catch hardware faster than the profiles assume.
KDF_STOCK_SAMPLES=3
kdf_stock_params() {
    local out i it mem best_it="" best_mem=""
    for i in $(seq 1 "$KDF_STOCK_SAMPLES"); do
        out=$(cryptsetup benchmark --pbkdf argon2id 2>/dev/null | grep -m1 'argon2id') || continue
        it=$(echo "$out"  | awk '{print $2}')
        mem=$(echo "$out" | awk '{print $4}')
        case "$it"  in ''|*[!0-9]*) continue;; esac
        case "$mem" in ''|*[!0-9]*) continue;; esac
        [ "$it" -gt 0 ] && [ "$mem" -gt 0 ] || continue
        if [ -z "$best_it" ] || [ $((it * mem)) -lt $((best_it * best_mem)) ]; then
            best_it=$it; best_mem=$mem
        fi
    done
    [ -n "$best_it" ] || return 1
    STOCK_ITER=$best_it
    STOCK_MEM=$best_mem
}

# Never ship a KDF weaker than what a bare `luksFormat` would have produced on
# THIS machine. The profiles are fixed numbers; stock is a fixed *time*, so on
# faster hardware stock climbs and a fixed profile can fall behind it.
#
#   named profile  -> raise the iteration count past stock, and say so
#   pinned numbers -> fatal; the operator chose exact values, so silently
#                     changing them would break the fleet reproducibility that
#                     pinning exists to provide
#
# The boost overshoots by KDF_STOCK_MARGIN_PCT rather than landing exactly on
# stock: matching it would only tie with a plain luksFormat, and the benchmark
# jitters run to run, so an exact match can read as 'weaker' on the next boot.
KDF_STOCK_MARGIN_PCT=25
kdf_enforce_stock_floor() {
    local stock_work sel_work target_work need
    if ! kdf_stock_params; then
        warn "Could not read cryptsetup's default KDF parameters — skipping the stock-strength check."
        return 0
    fi
    stock_work=$((STOCK_MEM * STOCK_ITER))
    sel_work=$((LUKS_PBKDF_MEMORY * LUKS_PBKDF_ITER))
    [ "$sel_work" -ge "$stock_work" ] && return 0

    if [ "$KDF_PINNED_BY_ENV" -eq 1 ]; then
        fatal "Pinned KDF parameters are weaker than cryptsetup's own default on this machine.
       requested : $((LUKS_PBKDF_MEMORY / 1024)) MiB x ${LUKS_PBKDF_ITER} iterations
       stock     : $((STOCK_MEM / 1024)) MiB x ${STOCK_ITER} iterations (argon2id tuned to 2000 ms)
     Raise the iteration count and re-run. There is no override: LinuxLocker
     hardens, never weakens. A weaker KDF is a manual cryptsetup operation."
    fi

    target_work=$(( stock_work * (100 + KDF_STOCK_MARGIN_PCT) / 100 ))
    need=$(( (target_work + LUKS_PBKDF_MEMORY - 1) / LUKS_PBKDF_MEMORY ))
    # ceil() can still tie when the division is exact; never come back equal.
    [ $((need * LUKS_PBKDF_MEMORY)) -gt "$stock_work" ] || need=$((need + 1))
    warn "Profile '$KDF_PROFILE_NAME' ($((LUKS_PBKDF_MEMORY / 1024)) MiB x ${LUKS_PBKDF_ITER}) is weaker than cryptsetup's"
    warn "  own default on this machine ($((STOCK_MEM / 1024)) MiB x ${STOCK_ITER}). Raising iterations ${LUKS_PBKDF_ITER} -> ${need}"
    warn "  — ${KDF_STOCK_MARGIN_PCT}% past stock, so the volume is never cheaper to attack than a"
    warn "  plain luksFormat with no arguments."
    LUKS_PBKDF_ITER=$need
    KDF_PROFILE_NAME="$KDF_PROFILE_NAME (boosted past stock)"
}

kdf_fmt_ms() {
    local ms="$1"
    case "$ms" in ''|*[!0-9]*) echo "?"; return;; esac
    if [ "$ms" -lt 1000 ]; then echo "${ms} ms"
    else awk -v m="$ms" 'BEGIN{ printf "%.1f s", m/1000 }'; fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Filesystem handler layer
# ═══════════════════════════════════════════════════════════════════════════════
# Everything filesystem-specific funnels through these functions. To add a
# filesystem: extend each case below and the tool map, nothing else.
#
#   shrinkable   : ext2/3/4 (resize2fs), btrfs (online resize), ntfs
#                  (ntfsresize), f2fs (resize.f2fs), vfat (fatresize)
#   slack-only   : xfs — cannot shrink; accepted when >= 32 MiB of slack
#                  already exists between filesystem end and partition end
#   unsupported  : exfat, udf — no shrink tool and no reliable offline size
#                  probe exist; see docs/FILESYSTEMS.md for alternatives

SHRINK_MB=32
SHRINK_BYTES=$((SHRINK_MB * 1024 * 1024))

# Filesystems accepted as an encryption TARGET (plus crypto_LUKS for resume).
SUPPORTED_FSTYPES='ext4|ext3|ext2|btrfs|xfs|f2fs|ntfs|vfat'

fs_is_supported() {
    [[ "$1" =~ ^(ext4|ext3|ext2|btrfs|xfs|f2fs|ntfs|vfat)$ ]]
}

fs_can_shrink() {
    case "$1" in
        ext2|ext3|ext4|btrfs|ntfs|f2fs|vfat) return 0 ;;
        *) return 1 ;;
    esac
}

# Commands (with their logical package) each filesystem needs, as
# "cmd:logical-pkg" pairs consumable by ll_ensure_tools.
fs_tool_pairs() {
    case "$1" in
        ext2|ext3|ext4) echo "resize2fs:e2fsprogs e2fsck:e2fsprogs dumpe2fs:e2fsprogs" ;;
        btrfs)          echo "btrfs:btrfs-progs" ;;
        xfs)            echo "xfs_db:xfsprogs xfs_growfs:xfsprogs xfs_repair:xfsprogs" ;;
        ntfs)           echo "ntfsresize:ntfsprogs" ;;
        f2fs)           echo "resize.f2fs:f2fs-tools fsck.f2fs:f2fs-tools" ;;
        vfat)           echo "fatresize:fatresize fsck.fat:dosfstools" ;;
    esac
}

# Resolve the tools for a filesystem: install them via lib-deps if available,
# otherwise fail with the exact list. Called the moment the target fs is known.
ensure_fs_tools() {
    local fstype="$1" pairs missing=() pair cmd
    pairs=$(fs_tool_pairs "$fstype")
    [ -n "$pairs" ] || return 0
    for pair in $pairs; do
        cmd="${pair%%:*}"
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$pair")
    done
    [ "${#missing[@]}" -eq 0 ] && return 0
    log "Filesystem '$fstype' needs tools that are not installed: ${missing[*]%%:*}"
    if [ "$LL_HAVE_DEPS_LIB" -eq 1 ] && [ -n "${LL_PKG_MGR:-}" ]; then
        # shellcheck disable=SC2086
        ll_ensure_tools $pairs || fatal "Could not install the $fstype tools — install them manually and re-run."
    else
        local names=()
        for pair in "${missing[@]}"; do names+=("${pair#*:}"); done
        fatal "Missing tools for $fstype: ${missing[*]%%:*} (packages: ${names[*]}). Install them and re-run."
    fi
}

# fs_bytes <dev> <fstype> — the filesystem's OWN size in bytes, probed offline.
# Prints nothing when the filesystem cannot be probed (f2fs, vfat).
fs_bytes() {
    local dev="$1" fstype="$2" a b
    case "$fstype" in
        ext2|ext3|ext4)
            a=$(dumpe2fs -h "$dev" 2>/dev/null | awk -F': *' '/^Block count:/{print $2; exit}')
            b=$(dumpe2fs -h "$dev" 2>/dev/null | awk -F': *' '/^Block size:/{print $2; exit}')
            case "$a$b" in *[!0-9]*|'') return 0;; esac
            echo $((a * b)) ;;
        btrfs)
            btrfs inspect-internal dump-super "$dev" 2>/dev/null \
                | awk '/^total_bytes/{print $2; exit}' ;;
        xfs)
            a=$(xfs_db -r -c 'sb 0' -c 'p dblocks' "$dev" 2>/dev/null | awk '{print $3; exit}')
            b=$(xfs_db -r -c 'sb 0' -c 'p blocksize' "$dev" 2>/dev/null | awk '{print $3; exit}')
            case "$a$b" in *[!0-9]*|'') return 0;; esac
            echo $((a * b)) ;;
        ntfs)
            ntfsresize --info --force "$dev" 2>/dev/null \
                | sed -n 's/.*urrent volume size[^0-9]*\([0-9]\{1,\}\) bytes.*/\1/p' | head -1 ;;
        *) : ;;   # f2fs, vfat: no reliable offline probe
    esac
}

# fs_check_ro <dev> <fstype> — read-only integrity check. Returns the checker's
# exit status; returns 2 (distinct "cannot check") when no checker exists.
fs_check_ro() {
    local dev="$1" fstype="$2"
    case "$fstype" in
        ext2|ext3|ext4) e2fsck -f -n "$dev" ;;
        btrfs)          btrfs check --readonly "$dev" 2>&1 | tail -3 ;;
        xfs)            xfs_repair -n "$dev" ;;
        ntfs)           ntfsfix --no-action "$dev" 2>&1 || ntfsresize --info --force "$dev" >/dev/null ;;
        f2fs)           fsck.f2fs --dry-run "$dev" 2>&1 || fsck.f2fs -a "$dev" ;;
        vfat)           fsck.fat -n "$dev" ;;
        *)              return 2 ;;
    esac
}

# fs_shrink <dev> <fstype> — shrink the filesystem by SHRINK_MB so the LUKS2
# header fits. Fatal on failure (nothing has been encrypted yet; aborting is
# free). Caller has already verified the device is unmounted.
fs_shrink() {
    local dev="$1" fstype="$2" cur new
    case "$fstype" in
        btrfs)
            mkdir -p /mnt_temp
            mount "$dev" /mnt_temp
            if ! btrfs filesystem df /mnt_temp >/dev/null 2>&1; then
                umount /mnt_temp; rmdir /mnt_temp
                fatal "Cannot read btrfs filesystem. Partition may be damaged."
            fi
            btrfs filesystem resize -${SHRINK_MB}M /mnt_temp
            sync
            umount /mnt_temp
            rmdir /mnt_temp
            ;;
        ext2|ext3|ext4)
            # resize2fs refuses to run without a clean recent fsck.
            e2fsck -f -p "$dev" || e2fsck -f -y "$dev" \
                || fatal "e2fsck failed on $dev — fix the filesystem before encrypting."
            cur=$(fs_bytes "$dev" "$fstype")
            [ -n "$cur" ] || fatal "Cannot read the $fstype size from $dev."
            new=$(( (cur - SHRINK_BYTES) / 1024 ))
            resize2fs "$dev" "${new}K" \
                || fatal "resize2fs could not shrink $dev (not enough free space?)."
            ;;
        ntfs)
            cur=$(fs_bytes "$dev" "$fstype")
            [ -n "$cur" ] || fatal "Cannot read the NTFS volume size from $dev."
            new=$(( cur - SHRINK_BYTES ))
            # ntfsresize marks the volume for a consistency check on the next
            # Windows boot; harmless, and unavoidable when resizing NTFS.
            printf 'y\n' | ntfsresize --force --size "$new" "$dev" \
                || fatal "ntfsresize could not shrink $dev (run 'ntfsresize --info $dev' to see the minimum)."
            ;;
        f2fs)
            # resize.f2fs takes the new size in 512-byte sectors. Shrinking
            # needs recent f2fs-tools; older ones refuse and we stop cleanly.
            fsck.f2fs -f "$dev" || fatal "fsck.f2fs failed on $dev — fix the filesystem before encrypting."
            new=$(( ($(blockdev --getsize64 "$dev") - SHRINK_BYTES) / 512 ))
            resize.f2fs -t "$new" "$dev" \
                || fatal "resize.f2fs could not shrink $dev — your f2fs-tools may be too old to shrink (needs >= 1.16)."
            ;;
        vfat)
            new=$(( ($(blockdev --getsize64 "$dev") / 1024 / 1024) - SHRINK_MB ))
            fatresize --size "${new}Mi" "$dev" \
                || fatal "fatresize could not shrink $dev."
            ;;
        xfs)
            fatal "XFS cannot be shrunk — this should have been caught earlier (slack check)."
            ;;
        *)
            fatal "No shrink handler for filesystem '$fstype'."
            ;;
    esac
}

# fs_grow_max <dev> <fstype> — grow the filesystem back out to fill the opened
# LUKS container. Best-effort (a failure here loses 32MB of space, not data).
fs_grow_max() {
    local dev="$1" fstype="$2"
    case "$fstype" in
        btrfs)
            mkdir -p /mnt_temp
            mount "$dev" /mnt_temp
            btrfs filesystem resize max /mnt_temp 2>/dev/null || true
            umount /mnt_temp
            rmdir /mnt_temp
            ;;
        ext2|ext3|ext4)
            e2fsck -f -p "$dev" >/dev/null 2>&1 || true
            resize2fs "$dev" 2>/dev/null || warn "  resize2fs grow failed (space unreclaimed, data unaffected)."
            ;;
        xfs)
            mkdir -p /mnt_temp
            if mount "$dev" /mnt_temp 2>/dev/null; then
                xfs_growfs /mnt_temp >/dev/null 2>&1 || true
                umount /mnt_temp
            fi
            rmdir /mnt_temp 2>/dev/null || true
            ;;
        ntfs)
            printf 'y\n' | ntfsresize --force "$dev" >/dev/null 2>&1 \
                || warn "  ntfsresize grow failed (space unreclaimed, data unaffected)."
            ;;
        f2fs)
            resize.f2fs "$dev" >/dev/null 2>&1 \
                || warn "  resize.f2fs grow failed (space unreclaimed, data unaffected)."
            ;;
        vfat)
            local mib=$(( $(blockdev --getsize64 "$dev") / 1024 / 1024 ))
            fatresize --size "${mib}Mi" "$dev" >/dev/null 2>&1 \
                || warn "  fatresize grow failed (space unreclaimed, data unaffected)."
            ;;
    esac
}

# ─── Cleanup Trap ────────────────────────────────────────────────────────────
cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        echo ""
        err "════════════════════════════════════════════════════════════"
        err "  Script exited with error (code $exit_code). Cleaning up..."
        err "════════════════════════════════════════════════════════════"
    fi
    # Clean up any temp mounts first (-R: the BLS check nests a boot mount
    # inside /mnt_temp, and a plain umount would fail on the child mount)
    umount -R /mnt_temp 2>/dev/null || umount /mnt_temp 2>/dev/null || true
    rmdir /mnt_temp 2>/dev/null || true
    for uki_probe_dir in /tmp/luks-uki-probe.* /tmp/luks-grub-probe.*; do
        [ -d "$uki_probe_dir" ] || continue
        umount "$uki_probe_dir" 2>/dev/null || true
        rmdir "$uki_probe_dir" 2>/dev/null || true
    done
    # Clean up chroot bind mounts (specific order matters)
    umount /mnt/sys/firmware/efi/efivars 2>/dev/null || true
    for mp in /mnt/run /mnt/sys /mnt/proc /mnt/dev/pts /mnt/dev; do
        umount "$mp" 2>/dev/null || true
    done
    umount /mnt/boot/efi 2>/dev/null || true
    umount /mnt/efi 2>/dev/null || true
    umount /mnt/boot/firmware 2>/dev/null || true
    umount /mnt/boot 2>/dev/null || true
    umount /mnt/home 2>/dev/null || true
    umount /mnt 2>/dev/null || true
    cryptsetup close ${LUKS_NAME} 2>/dev/null || true
    cryptsetup close "luks-probe-$$" 2>/dev/null || true
    rm -f /mnt/tmp/.luks-deploy-env /mnt/tmp/.luks-lib-uki.sh /mnt/tmp/.luks-lib-boot.sh 2>/dev/null || true
    if [ $exit_code -ne 0 ]; then
        echo ""
        echo "Recovery options:"
        echo "  If the filesystem was shrunk but encryption didn't start:"
        echo "    the shrink is harmless — re-running this script skips it and continues."
        echo "  If encryption was interrupted:"
        echo "    RE-RUN THIS SCRIPT — it detects the interrupted state and"
        echo "    resumes automatically (cryptsetup reencrypt --resume-only)."
        echo "  If encryption completed but config is wrong:"
        echo "    RE-RUN THIS SCRIPT — it offers a configuration-only mode that"
        echo "    redoes crypttab/fstab/initramfs/bootloader and re-runs verification."
        echo "  LUKS header restore (if backed up):"
        echo "    cryptsetup luksHeaderRestore <ROOT_DEV> --header-backup-file /boot/luks-header-backup.img"
        echo ""
        echo "  Pre-encryption backups saved to: $SCRIPT_DIR/"
        echo "  Full log: $DEPLOY_LOG"
    fi
    # Give the background tee logger a moment to drain the pipe, so the final
    # lines (including the recovery instructions above) reach the log file.
    sync
    sleep 1
}
trap cleanup EXIT

# ─── Root Check ──────────────────────────────────────────────────────────────
[ "$EUID" -eq 0 ] || fatal "Must run as root: sudo $0"

# ─── Partial Previous Run Detection ─────────────────────────────────────────
# If a previous run was interrupted, detect and warn
if [ -b /dev/mapper/${LUKS_NAME} ]; then
    warn "Found /dev/mapper/${LUKS_NAME} already open from a previous run!"
    echo "  keep  = leave it open and reuse it (saves a passphrase prompt in config-only mode)"
    echo "  close = close it and start fresh"
    read -p "Keep or close? (keep/close): " STALE_CHOICE
    umount -R /mnt 2>/dev/null || true
    case "$STALE_CHOICE" in
        keep)
            log "  Keeping ${LUKS_NAME} open — it will be reused."
            ;;
        close)
            cryptsetup close ${LUKS_NAME} 2>/dev/null \
                || fatal "Could not close ${LUKS_NAME} (still in use?). Close it manually and re-run."
            log "  Closed stale ${LUKS_NAME}."
            ;;
        *)
            fatal "Answer 'keep' or 'close'. Nothing was changed."
            ;;
    esac
fi

# ─── Dependency Check (live environment core) ────────────────────────────────
# Only the tools the LIVE environment itself needs. The target's initramfs and
# bootloader tools (dracut/mkinitcpio/update-initramfs, grub) live INSIDE the
# target and are detected + used through the chroot, so their absence here is
# irrelevant. Filesystem-specific tools are resolved by ensure_fs_tools once
# the target filesystem is known.
log "Checking required tools..."
CORE_TOOL_PAIRS=(cryptsetup:cryptsetup blkid:util-linux lsblk:util-linux
                 findmnt:util-linux blockdev:util-linux mktemp:coreutils)
MISSING=()
for pair in "${CORE_TOOL_PAIRS[@]}"; do
    command -v "${pair%%:*}" &>/dev/null || MISSING+=("$pair")
done
if [ ${#MISSING[@]} -gt 0 ]; then
    if [ "$LL_HAVE_DEPS_LIB" -eq 1 ] && [ -n "${LL_PKG_MGR:-}" ]; then
        log "  Installing missing core tools: ${MISSING[*]%%:*}"
        ll_ensure_tools "${MISSING[@]}" || fatal "Could not install: ${MISSING[*]%%:*}"
    else
        fatal "Missing required tools: ${MISSING[*]%%:*}"
    fi
fi

CRYPTSETUP_VER=$(cryptsetup --version | awk '{print $2}')
# LUKS2 online/in-place reencryption needs cryptsetup >= 2.4.
if [ "${LUKS_SKIP_VERSION_CHECK:-0}" != "1" ]; then
    if [ "$(printf '%s\n2.4.0\n' "$CRYPTSETUP_VER" | sort -V | head -1)" != "2.4.0" ]; then
        fatal "cryptsetup $CRYPTSETUP_VER is too old — LUKS2 in-place reencryption needs >= 2.4 (LUKS_SKIP_VERSION_CHECK=1 to override)."
    fi
fi
if [ "$LL_HAVE_DEPS_LIB" -eq 1 ]; then
    log "Tools OK. cryptsetup=$CRYPTSETUP_VER arch=$(uname -m) live-os=${LL_OS_ID:-unknown} pkg-mgr=${LL_PKG_MGR:-none}"
else
    log "Tools OK. cryptsetup=$CRYPTSETUP_VER arch=$(uname -m) (lib-deps.sh not found — no auto-install)"
fi

# ─── Kernel Module Preload ───────────────────────────────────────────────────
log "Loading required kernel modules..."
modprobe dm-crypt 2>/dev/null || true
modprobe dm_mod 2>/dev/null || true
if ! lsmod | grep -q dm_crypt; then
    warn "Cannot load dm-crypt module. cryptsetup may still work via kernel built-in."
fi

# ─── Live Environment Check ──────────────────────────────────────────────────
CURRENT_ROOT_FSTYPE=$(findmnt -n -o FSTYPE / 2>/dev/null || echo "unknown")
CURRENT_ROOT_SRC=$(findmnt -n -o SOURCE / 2>/dev/null || echo "unknown")
log "Current root filesystem: $CURRENT_ROOT_FSTYPE ($CURRENT_ROOT_SRC)"

case "$CURRENT_ROOT_FSTYPE" in
    overlay|squashfs|tmpfs|ramfs|aufs|iso9660)
        log "  Root is $CURRENT_ROOT_FSTYPE — looks like a live/rescue environment. Good."
        ;;
    *)
        echo ""
        err "Your current root filesystem is $CURRENT_ROOT_FSTYPE on $CURRENT_ROOT_SRC —"
        err "this does NOT look like a live/rescue environment."
        err "This script MUST be run from a LIVE USB / rescue environment."
        err "Running on the installed system WILL destroy your data."
        echo ""
        read -p "Are you certain you are in a live/rescue environment? (Type 'LIVE' to override): " LIVE_OVERRIDE
        [ "$LIVE_OVERRIDE" = "LIVE" ] || fatal "Aborted for safety."
        ;;
esac

# ─── Power / Battery Check ──────────────────────────────────────────────────
for ps_dir in /sys/class/power_supply/*/; do
    [ -d "$ps_dir" ] || continue
    ps_type=$(cat "$ps_dir/type" 2>/dev/null || echo "")
    if [ "$ps_type" = "Battery" ]; then
        bat_capacity=$(cat "$ps_dir/capacity" 2>/dev/null || echo "100")
        # Guard the arithmetic below: a garbled sysfs read must not kill the
        # script under set -e with an inscrutable '[ -lt ]' error.
        case "$bat_capacity" in ''|*[!0-9]*) bat_capacity=100;; esac
        bat_status=$(cat "$ps_dir/status" 2>/dev/null || echo "Unknown")
        log "Battery: ${bat_capacity}%, Status: ${bat_status}"
        if [ "$bat_capacity" -lt 50 ] && [ "$bat_status" != "Charging" ] && [ "$bat_status" != "Full" ]; then
            echo ""
            err "╔══════════════════════════════════════════════════════╗"
            err "║  DANGER: Battery at ${bat_capacity}% and NOT charging!       ║"
            err "║  If power dies mid-encryption, ALL DATA IS LOST.    ║"
            err "║  Connect AC power before proceeding.                ║"
            err "╚══════════════════════════════════════════════════════╝"
            echo ""
            read -p "Continue on battery? (Type 'BATTERY' to override): " BAT_OVERRIDE
            [ "$BAT_OVERRIDE" = "BATTERY" ] || fatal "Connect AC power and try again."
        fi
        break
    fi
done

# ─── Block Device Display ────────────────────────────────────────────────────
echo ""
log "=== Block Devices ==="
lsblk -o NAME,FSTYPE,LABEL,PARTLABEL,SIZE,MOUNTPOINT | grep -v "loop"
echo ""

# ─── Smart Partition Detection & Selection ──────────────────────────────────
# Prefers internal disks (nvme/mmcblk) over USB, uses LABEL/PARTLABEL for
# scoring, excludes the live USB disk from defaults, and presents a numbered
# menu for each partition type.

# Identify the live USB's disk so we can deprioritize its partitions
LIVE_ROOT_DEV=$(findmnt -n -o SOURCE / 2>/dev/null | sed 's/\[.*//')
LIVE_ROOT_DISK=$(lsblk -no PKNAME "$LIVE_ROOT_DEV" 2>/dev/null | head -1)
log "Live environment disk: ${LIVE_ROOT_DISK:-(unknown)}"

pick_partition() {
    # Usage: pick_partition <ROLE> <FSTYPE> <LABEL_HINT_REGEX>
    # Displays scored numbered list, returns selected device path on stdout.
    # All display/prompts go to stderr so stdout is clean for capture.
    local role="$1" fstype="$2" label_hint="$3"
    local -a devs=() disp_labels=() sizes=() disks=() scores=()
    local idx=0 best_idx=0 best_score=-999

    # Collect all partitions matching fstype (skip loop devices).
    # lsblk -P (KEY="value" pairs) instead of positional columns: columnar
    # output collapses empty fields (e.g. missing FSTYPE) and shifts columns.
    local NAME FSTYPE SIZE PKNAME lsblk_line
    while IFS= read -r lsblk_line; do
        NAME=""; FSTYPE=""; SIZE=""; PKNAME=""
        eval "$lsblk_line"    # safe: lsblk -P hex-escapes unsafe characters
        local name="$NAME" fs="$FSTYPE" size="$SIZE" disk="$PKNAME"
        [ -n "$name" ] || continue
        [[ "$fs" =~ ^($fstype)$ ]] || continue
        echo "$name" | grep -q "^loop" && continue

        local dev="/dev/$name"
        local label partlabel
        label=$(blkid -s LABEL -o value "$dev" 2>/dev/null || echo "")
        partlabel=$(blkid -s PARTLABEL -o value "$dev" 2>/dev/null || echo "")
        local disp="${label:-${partlabel:-(none)}}"

        # Score this candidate
        local score=0
        # Strongly prefer internal disks (NVMe / eMMC / SD) over USB/SATA
        [[ "$dev" == *nvme* || "$dev" == *mmcblk* ]] && score=$((score + 100))
        # Bonus for label matching the expected role
        if [ -n "$label_hint" ]; then
            echo "$label $partlabel" | grep -Eqi "$label_hint" 2>/dev/null && score=$((score + 50))
        fi
        # Heavily penalize anything on the live USB disk
        [ -n "$LIVE_ROOT_DISK" ] && [ "$disk" = "$LIVE_ROOT_DISK" ] && score=$((score - 200))

        devs+=("$dev")
        disp_labels+=("$disp")
        sizes+=("$size")
        disks+=("$disk")
        scores+=("$score")

        if [ "$score" -gt "$best_score" ]; then
            best_score=$score
            best_idx=$idx
        fi
        idx=$((idx + 1))
    done < <(lsblk -P -o NAME,FSTYPE,SIZE,PKNAME 2>/dev/null)

    echo "" >&2
    echo -e "  ${CYAN}Select ${role} partition (${fstype}):${NC}" >&2

    # No candidates at all — ask for manual entry
    if [ ${#devs[@]} -eq 0 ]; then
        echo "  No $fstype partitions found!" >&2
        while true; do
            read -p "  Enter device path manually: " manual_dev
            [ -b "$manual_dev" ] && { echo "  Selected: $manual_dev" >&2; echo "$manual_dev"; return; }
            echo "  ERROR: $manual_dev is not a block device." >&2
        done
    fi

    # Display numbered candidates with recommended marker
    for ((i=0; i<${#devs[@]}; i++)); do
        local marker=""
        [ "$i" -eq "$best_idx" ] && marker=" ${GREEN}← recommended${NC}"
        printf "    %d) %-18s  %-22s  %8s  (%s)" \
            "$((i+1))" "${devs[$i]}" "${disp_labels[$i]}" "${sizes[$i]}" "${disks[$i]}" >&2
        echo -e "$marker" >&2
    done

    # Selection loop
    while true; do
        read -p "  Select [1-${#devs[@]}] or device path [default: $((best_idx+1))]: " choice
        choice="${choice:-$((best_idx+1))}"

        # Numeric selection
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#devs[@]}" ]; then
            local sel="${devs[$((choice-1))]}"
            echo -e "  Selected: ${GREEN}${sel}${NC}" >&2
            echo "$sel"
            return
        fi

        # Direct device path
        if [ -b "$choice" ]; then
            local actual_fs
            actual_fs=$(blkid -s TYPE -o value "$choice" 2>/dev/null || echo "unknown")
            if ! [[ "$actual_fs" =~ ^($fstype)$ ]]; then
                echo "  WARNING: $choice has '$actual_fs', expected '$fstype'." >&2
                read -p "  Accept anyway? (yes/no): " accept
                [ "$accept" != "yes" ] && continue
            fi
            echo -e "  Selected: ${GREEN}${choice}${NC}" >&2
            echo "$choice"
            return
        fi

        echo "  Invalid selection. Enter a number or device path." >&2
    done
}

# Non-interactive pinning: LUKS_TARGET_ROOT / LUKS_TARGET_BOOT / LUKS_TARGET_EFI
# skip the menu but still enforce the fstype (all display goes to stderr —
# stdout is captured by the caller).
pinned_partition() {
    # $1 = role, $2 = env var name, $3 = pinned device, $4 = fstype regex
    local role="$1" var="$2" dev="$3" fstype="$4" actual
    [ -b "$dev" ] || fatal "\$$var=$dev is not a block device."
    actual=$(blkid -s TYPE -o value "$dev" 2>/dev/null || echo "unknown")
    [[ "$actual" =~ ^($fstype)$ ]] \
        || fatal "\$$var=$dev has fstype '$actual', expected '$fstype'."
    log "  $role pinned via \$$var: $dev ($actual)" >&2
    echo "$dev"
}

# ─── ROOT target selection ──────────────────────────────────────────────────
# ROOT also accepts crypto_LUKS so an interrupted/half-configured previous
# run can be re-selected and resumed, a LUKS1 volume can be converted, and a
# finished LUKS2 volume can be tuned (see mode detection below).
if [ -n "${LUKS_TARGET_ROOT:-}" ]; then
    TARGET_ROOT=$(pinned_partition "ROOT" "LUKS_TARGET_ROOT" "$LUKS_TARGET_ROOT" "${SUPPORTED_FSTYPES}|crypto_LUKS")
else
    TARGET_ROOT=$(pick_partition "ROOT" "${SUPPORTED_FSTYPES}|crypto_LUKS" "root|fedora|debian|ubuntu|arch|suse|linux|rootfs")
fi

# Refuse to operate on the device backing the live environment itself.
TARGET_ROOT_REAL=$(readlink -f "$TARGET_ROOT")
LIVE_ROOT_REAL=$(readlink -f "$LIVE_ROOT_DEV" 2>/dev/null || echo "")
if [ -n "$LIVE_ROOT_REAL" ] && [ "$TARGET_ROOT_REAL" = "$LIVE_ROOT_REAL" ]; then
    fatal "$TARGET_ROOT is the live environment's own root device. Pick the installed system's partition."
fi

# ─── Stale Mapper Cross-Check ────────────────────────────────────────────────
# If ${LUKS_NAME} is open (e.g. kept from a previous run), it MUST be backed by
# the ROOT partition just selected. Otherwise every later step that reuses the
# mapper (discovery, config, verification) would run against a DIFFERENT device
# than the one LUKS_UUID/crypttab point at — cross-wiring two systems.
if [ -b /dev/mapper/${LUKS_NAME} ]; then
    MAPPER_BACKING=$(cryptsetup status ${LUKS_NAME} 2>/dev/null \
        | awk '$1 == "device:" {print $2; exit}')
    MAPPER_BACKING=$(readlink -f "$MAPPER_BACKING" 2>/dev/null || echo "${MAPPER_BACKING:-unknown}")
    if [ "$MAPPER_BACKING" = "$TARGET_ROOT_REAL" ]; then
        log "Open ${LUKS_NAME} is backed by $TARGET_ROOT_REAL — OK to reuse."
    else
        err "/dev/mapper/${LUKS_NAME} is open but backed by: $MAPPER_BACKING"
        err "You selected ROOT: $TARGET_ROOT_REAL"
        err "Reusing this mapper would configure the WRONG system — closing it."
        if cryptsetup close ${LUKS_NAME} 2>/dev/null; then
            log "  Closed mismatched ${LUKS_NAME}; the selected device will be opened when needed."
        else
            fatal "Could not close ${LUKS_NAME} (still in use?). Close it manually and re-run."
        fi
    fi
fi

# ─── Mounted-Target Guard ────────────────────────────────────────────────────
# Live desktops (udisks) automount internal partitions, and cryptsetup
# reencrypt refuses busy devices — catch that NOW, not an hour after the
# user typed ENCRYPT and walked away.
ensure_unmounted() {
    # $1 = device; offer to unmount every mountpoint it currently has
    local dev="$1" mps mp
    # findmnt -S lists every mountpoint of a source on any util-linux; lsblk's
    # MOUNTPOINTS column only arrived in 2.37, and on older live media the
    # old lsblk call errored out and this guard silently passed.
    # sort -r: unmount nested child mounts (/mnt/home) before parents (/mnt)
    mps=$(findmnt -rno TARGET -S "$dev" 2>/dev/null | grep -v '^$' | sort -r || true)
    [ -n "$mps" ] || return 0
    warn "$dev is currently mounted at:"
    echo "$mps" | sed 's/^/    /'
    if [ "$DRY_RUN" = "1" ]; then
        warn "  [dry-run] a real run would require unmounting these first."
        return 0
    fi
    read -p "  Unmount it now? (yes/no): " UNMOUNT_OK
    [ "$UNMOUNT_OK" = "yes" ] || fatal "Cannot operate on a mounted device."
    while IFS= read -r mp; do
        [ -n "$mp" ] || continue
        umount "$mp" || fatal "Could not unmount $mp — close whatever is using it and re-run."
    done <<< "$mps"
    log "  Unmounted $dev."
}
ensure_unmounted "$TARGET_ROOT"
if [ -b /dev/mapper/${LUKS_NAME} ]; then
    ensure_unmounted /dev/mapper/${LUKS_NAME}
fi

# ─── Pretty (truncated) luksDump ─────────────────────────────────────────────
pretty_luks_dump() {
    # $1 = device. Header identity + a one-line-per-keyslot table; the pages of
    # digest/segment/token detail a full luksDump prints are left out.
    local dev="$1"
    echo "  ── LUKS header on $dev ──────────────────────────────"
    cryptsetup luksDump "$dev" 2>/dev/null \
        | awk -F': *' '/^Version:|^UUID:|^Label:|^Cipher:.*/{printf "  %-10s %s\n", $1":", $2}' | head -4
    echo "  Keyslots:"
    cryptsetup luksDump "$dev" 2>/dev/null | awk '
        /^[[:space:]]+[0-9]+: luks2/  { slot=$1; sub(":","",slot); k=""; m=""; i=""; t=""; next }
        /^[[:space:]]+[0-9]+: luks1/  { slot=$1; sub(":","",slot); printf "    slot %-2s  luks1 pbkdf2\n", slot; slot=""; next }
        slot!="" && /PBKDF:/      { k=$2 }
        slot!="" && /Time cost:/  { i=$3 }
        slot!="" && /Memory:/     { m=$2 }
        slot!="" && /Threads:/    { t=$2
            mem = (m ~ /^[0-9]+$/) ? sprintf("%.0f MiB", m/1024) : "-"
            printf "    slot %-2s  %-9s %-9s t=%-3s threads=%s\n", slot, k, mem, i, t; slot="" }
        slot!="" && k=="pbkdf2" && /Iterations:/ {
            printf "    slot %-2s  %-9s iterations=%s\n", slot, k, $2; slot="" }
    '
    # LUKS1 headers use a different keyslot syntax entirely
    cryptsetup luksDump "$dev" 2>/dev/null | awk '
        /^Key Slot [0-9]+: ENABLED/ { printf "    %s (pbkdf2)\n", $0 }
    ' | sed 's/: ENABLED//'
    echo "  ─────────────────────────────────────────────────────"
}

# ─── LUKS1 → LUKS2 conversion ────────────────────────────────────────────────
# A LUKS1 header is converted in place with `cryptsetup convert --type luks2`,
# then each keyslot is re-costed to argon2id with one of the same three KDF
# profiles the encrypter itself offers. Idempotent: the next run sees LUKS2
# and lands in the tune/config menu instead.
convert_luks1() {
    local dev="$1" stamp state_dir hdr_backup slot slots profile
    echo ""
    warn "$dev carries a LUKS1 header."
    pretty_luks_dump "$dev"
    echo ""
    echo "  LinuxLocker can convert it to LUKS2 in place, then re-cost the"
    echo "  keyslots from pbkdf2 to argon2id using the standard profiles"
    echo "  (aggressive 4 GiB x 10 / moderate 2 GiB x 8 / fast 1 GiB x 9)."
    echo ""
    echo "  The data is NOT re-encrypted and is not touched; only the header"
    echo "  and keyslot areas change. A full header backup is taken first."
    echo ""

    # ── Does GRUB itself unlock this volume? (encrypted /boot) ─────────────
    # Two things brick such a system: a LUKS2 header its GRUB cannot read
    # (LUKS2 support arrived in GRUB 2.06), and an argon2id keyslot its GRUB
    # has no code for (stock 2.12 prints "Argon2 not supported"). The GRUB
    # images on this disk are inspected first; if they do not settle it, the
    # volume is opened read-only and its own layout is checked.
    bt_grub_probe "$dev"
    if [ "$BT_GRUB_UNLOCKS" -eq 0 ] && [ "$DRY_RUN" != "1" ]; then
        log "  Checking whether GRUB itself unlocks this volume — it is opened read-only"
        log "  for a look at its fstab (enter the passphrase)..."
        if cryptsetup open --readonly "${CRYPT_PASS_ARGS[@]}" "$dev" "luks-probe-$$"; then
            local pfs psub="" ptry
            pfs=$(blkid -s TYPE -o value "/dev/mapper/luks-probe-$$" 2>/dev/null || echo "")
            mkdir -p /mnt_temp
            if [ "$pfs" = "btrfs" ] && mount -o ro,subvolid=5 "/dev/mapper/luks-probe-$$" /mnt_temp 2>/dev/null; then
                for ptry in root @rootfs @ ""; do
                    [ -f "/mnt_temp/${ptry}${ptry:+/}etc/fstab" ] && { psub="${ptry}${ptry:+/}"; break; }
                done
                bt_grub_probe "$dev" "/mnt_temp/${psub%/}"
                umount /mnt_temp
            elif [ -n "$pfs" ] && mount -o ro "/dev/mapper/luks-probe-$$" /mnt_temp 2>/dev/null; then
                bt_grub_probe "$dev" /mnt_temp
                umount /mnt_temp
            else
                warn "  Could not mount the volume read-only ($pfs) — GRUB check inconclusive."
            fi
            rmdir /mnt_temp 2>/dev/null || true
            cryptsetup close "luks-probe-$$"
        else
            fatal "Could not open $dev — wrong passphrase? Header unchanged."
        fi
    fi

    GRUB_RECOST="any"          # any | fast-only | none
    if [ "$BT_GRUB_UNLOCKS" -eq 1 ]; then
        echo ""
        err "  ┌──────────────────────────────────────────────────────────────┐"
        err "  │ GRUB ITSELF unlocks this volume at boot (encrypted /boot).   │"
        err "  └──────────────────────────────────────────────────────────────┘"
        bt_grub_summary | sed 's/^/    /'
        echo ""
        if [ "$BT_GRUB_LUKS2" != "yes" ]; then
            err "  The GRUB image on this disk could not be shown to read LUKS2"
            err "  headers (support arrived in GRUB 2.06; result: $BT_GRUB_LUKS2)."
            err "  Converting this header would leave GRUB unable to open /boot —"
            err "  the machine would not boot."
            echo ""
            echo "  LinuxLocker never sets up or re-embeds an encrypted /boot. If you"
            echo "  know your GRUB reads LUKS2, convert by hand and re-run grub-install"
            echo "  so the image embeds the luks2 module:"
            echo "      cryptsetup convert --type luks2 $dev"
            echo "  See docs/BOOTLOADERS.md, 'Encrypted /boot'."
            fatal "Refusing to convert a LUKS1 header that GRUB unlocks. Header unchanged."
        fi
        if [ "$BT_GRUB_ARGON2" = "yes" ]; then
            GRUB_RECOST="fast-only"
            warn "  The keyslots CAN be re-costed to argon2id — memory-hard, GPU-resistant:"
            warn "  this GRUB embeds the argon2 module. It takes the memory as one"
            warn "  contiguous block from the firmware heap, so the 1 GiB profile is"
            warn "  what is offered; the unlock estimate shown is for GRUB, which runs"
            warn "  the KDF single-threaded (kernel-side x ${BT_GRUB_KDF_FACTOR}, measured on one machine)."
        else
            GRUB_RECOST="none"
            warn "  The keyslots will stay pbkdf2: this GRUB has no argon2 code"
            warn "  (result: $BT_GRUB_ARGON2). An argon2id keyslot would be one GRUB"
            warn "  cannot open. LinuxLocker hardens; it never writes pbkdf2 or any"
            warn "  weaker KDF, so the header is converted and the KDF is left exactly"
            warn "  as it is. Changing it is a manual cryptsetup operation, outside"
            warn "  this tool."
        fi
        echo ""
    else
        # Not GRUB-unlocked as far as the images and the volume show. Keep
        # the old operator gate: the operator may know something the disk
        # does not say (a GRUB image on another disk, a USB /boot).
        err "  ┌──────────────────────────────────────────────────────────────┐"
        err "  │ IMPORTANT: if GRUB itself unlocks this volume at boot        │"
        err "  │ (encrypted /boot, GRUB_ENABLE_CRYPTODISK + cryptomount —     │"
        err "  │ common on older Debian/Ubuntu full-disk installs), GRUB      │"
        err "  │ cannot open argon2id keyslots. Converting the keyslots       │"
        err "  │ would make that system UNBOOTABLE. No evidence of that was   │"
        err "  │ found on this disk — only proceed if the passphrase prompt   │"
        err "  │ at boot comes from the initramfs, not from GRUB itself.      │"
        err "  └──────────────────────────────────────────────────────────────┘"
        echo ""
    fi
    if [ "$DRY_RUN" = "1" ]; then
        log "[dry-run] Would back up the header, run 'cryptsetup convert --type luks2 $dev',"
        case "$GRUB_RECOST" in
            any)       log "[dry-run] then offer per-keyslot argon2id re-costing (all three profiles)." ;;
            fast-only) log "[dry-run] then offer per-keyslot argon2id re-costing (1 GiB only — GRUB unlocks it)." ;;
            none)      log "[dry-run] and leave the keyslots on pbkdf2 (GRUB unlocks it and has no argon2)." ;;
        esac
        log "[dry-run] Nothing was changed."
        exit 0
    fi
    read -p "  Type 'CONVERT' to convert this LUKS1 header to LUKS2: " CONFIRM_CONV
    [ "$CONFIRM_CONV" = "CONVERT" ] || fatal "Aborted — header unchanged."

    # Close any mapper currently backed by this device; convert needs it inactive.
    local holder
    for holder in $(lsblk -rno NAME,TYPE "$dev" 2>/dev/null | awk '$2=="crypt"{print $1}'); do
        warn "  $dev is open as /dev/mapper/$holder — closing it for the conversion."
        cryptsetup close "$holder" \
            || fatal "Could not close $holder (still in use?). Close it manually and re-run."
    done

    stamp=$(date +%Y%m%d_%H%M%S)
    state_dir="$SCRIPT_DIR/pre-luks-state-$stamp"
    mkdir -p "$state_dir"
    harden_path 0700 "$state_dir"
    hdr_backup="$state_dir/luks1-header-backup.img"
    # umask 077: luksHeaderBackup creates the file itself and refuses to
    # overwrite, so the mode has to be right at creation, not chmod'd after.
    ( umask 077; cryptsetup luksHeaderBackup "$dev" --header-backup-file "$hdr_backup" ) \
        || fatal "Header backup failed — refusing to convert without one."
    harden_path 0400 "$hdr_backup"
    log "  LUKS1 header backed up to: $hdr_backup"
    log "  (keep it until the converted volume has unlocked at boot at least once)"

    cryptsetup convert --type luks2 --batch-mode "$dev" \
        || fatal "cryptsetup convert failed — header is unchanged (restore available at $hdr_backup)."
    log "  Header converted to LUKS2."

    # ── Re-cost the keyslots to argon2id ────────────────────────────────────
    profile=skip
    if [ "$GRUB_RECOST" = "none" ]; then
        echo ""
        log "  Keyslots left on pbkdf2 — GRUB unlocks this volume and cannot open argon2id."
    else
        echo ""
        echo "  The keyslots still use pbkdf2 (carried over from LUKS1)."
        echo "  Re-costing them to argon2id gives the volume the same GPU-resistant"
        echo "  KDF a fresh LinuxLocker deployment gets. Pick a profile:"
        echo ""
        EST_AGG=$(kdf_estimate_ms "$KDF_PROFILE_AGGRESSIVE_MEM" "$KDF_PROFILE_AGGRESSIVE_ITER" "$KDF_DEFAULT_PARALLEL" || echo "")
        EST_MOD=$(kdf_estimate_ms "$KDF_PROFILE_MODERATE_MEM"   "$KDF_PROFILE_MODERATE_ITER"   "$KDF_DEFAULT_PARALLEL" || echo "")
        EST_FAST=$(kdf_estimate_ms "$KDF_PROFILE_FAST_MEM"      "$KDF_PROFILE_FAST_ITER"       "$KDF_DEFAULT_PARALLEL" || echo "")
        if [ "$GRUB_RECOST" = "fast-only" ]; then
            # GRUB does this unlock: single-threaded, no SIMD, firmware heap.
            EST_FAST_GRUB=$(bt_grub_ms "${EST_FAST:-}" || echo "")
            printf "   3) fast          1 GiB,  9 iterations    unlock ~%s in GRUB (~%s kernel-side)\n" \
                "$(kdf_fmt_ms "${EST_FAST_GRUB:-}")" "$(kdf_fmt_ms "${EST_FAST:-}")"
            echo   "   4) skip — keep pbkdf2 (re-run later, or use luks-tune.sh)"
            echo ""
            echo "   aggressive (4 GiB) and moderate (2 GiB) are not offered: GRUB takes"
            echo "   argon2id's memory as ONE contiguous block from the firmware heap,"
            echo "   and x86 UEFI has never reliably given out more than 1 GiB."
            if [ -n "${EST_FAST_GRUB:-}" ] && [ "$EST_FAST_GRUB" -ge $((BT_GRUB_RESET_WALL_S * 1000)) ]; then
                warn "   ~$(kdf_fmt_ms "$EST_FAST_GRUB") of uninterrupted compute inside GRUB: firmware"
                warn "   watchdogs have been seen to reset a machine past ~${BT_GRUB_RESET_WALL_S} s. Consider"
                warn "   keeping pbkdf2, or a custom cost via luks-tune.sh."
            fi
            echo ""
            while true; do
                read -p "  Select [3-4, default 4=skip]: " KDF_CHOICE
                case "${KDF_CHOICE:-4}" in
                    3) profile=fast; apply_kdf_profile fast; break ;;
                    4) profile=skip; break ;;
                    *) echo "  Invalid selection '$KDF_CHOICE' — enter 3 or 4." ;;
                esac
            done
        else
            printf "   1) aggressive    4 GiB, 10 iterations    unlock ~%s\n" "$(kdf_fmt_ms "${EST_AGG:-}")"
            printf "   2) moderate      2 GiB,  8 iterations    unlock ~%s   [default]\n" "$(kdf_fmt_ms "${EST_MOD:-}")"
            printf "   3) fast          1 GiB,  9 iterations    unlock ~%s\n" "$(kdf_fmt_ms "${EST_FAST:-}")"
            echo   "   4) skip — keep pbkdf2 for now (re-run later, or use luks-tune.sh)"
            if [ "$MEM_TOTAL_KIB" -gt 0 ] && [ "$MEM_TOTAL_KIB" -lt $((6 * 1024 * 1024)) ]; then
                echo ""
                echo -e "   ${YELLOW}This machine has $((MEM_TOTAL_KIB / 1024 / 1024)) GiB RAM — 'aggressive' (4 GiB) is NOT safe"
                echo -e "   here; the unlock could OOM at boot. Pick moderate or fast.${NC}"
            fi
            echo ""
            while true; do
                read -p "  Select [1-4, default 2=moderate]: " KDF_CHOICE
                case "${KDF_CHOICE:-2}" in
                    1) profile=aggressive; apply_kdf_profile aggressive ;;
                    2) profile=moderate;   apply_kdf_profile moderate ;;
                    3) profile=fast;       apply_kdf_profile fast ;;
                    4) profile=skip; break ;;
                    *) echo "  Invalid selection '$KDF_CHOICE' — enter 1, 2, 3 or 4."; continue ;;
                esac
                # The KDF re-runs at every boot on THIS machine; it must fit.
                if [ "$MEM_TOTAL_KIB" -gt 0 ] && [ "$LUKS_PBKDF_MEMORY" -ge "$MEM_TOTAL_KIB" ]; then
                    warn "  $profile needs $((LUKS_PBKDF_MEMORY / 1024)) MiB; this machine has $((MEM_TOTAL_KIB / 1024)) MiB. Pick a smaller profile."
                    continue
                fi
                break
            done
        fi
    fi

    if [ "$profile" != "skip" ]; then
        kdf_enforce_stock_floor
        if [ "$GRUB_RECOST" = "fast-only" ] && ! bt_grub_mem_ok "$LUKS_PBKDF_MEMORY"; then
            fatal "Internal: chosen memory cost exceeds the GRUB ceiling. Keyslots unchanged."
        fi
        # Every active keyslot, one luksConvertKey each. cryptsetup prompts for
        # that slot's passphrase on the terminal; a slot whose passphrase (or
        # keyfile) isn't at hand can be skipped and converted later.
        # --hash sha512: luksConvertKey rewrites the keyslot area and re-stamps
        # its AF hash; without an explicit hash cryptsetup substitutes sha256.
        slots=$(cryptsetup luksDump "$dev" 2>/dev/null \
            | awk '/^[[:space:]]+[0-9]+: luks2/{s=$1; sub(":","",s); print s}')
        for slot in $slots; do
            echo ""
            log "  Re-costing keyslot $slot to argon2id $((LUKS_PBKDF_MEMORY / 1024)) MiB x ${LUKS_PBKDF_ITER} (enter that slot's passphrase)..."
            if cryptsetup luksConvertKey -S "$slot" --pbkdf argon2id \
                    --hash sha512 \
                    --pbkdf-memory "$LUKS_PBKDF_MEMORY" \
                    --pbkdf-force-iterations "$LUKS_PBKDF_ITER" \
                    --pbkdf-parallel "$LUKS_PBKDF_PARALLEL" \
                    "${CRYPT_PASS_ARGS[@]}" "$dev"; then
                log "  Keyslot $slot → argon2id."
            else
                warn "  Keyslot $slot NOT converted (wrong passphrase / keyfile slot?)."
                warn "  Convert it later with luks-tune.sh or:"
                warn "    cryptsetup luksConvertKey -S $slot --hash sha512 --pbkdf argon2id $dev"
            fi
        done
    fi

    echo ""
    log "Conversion complete. Final header state:"
    pretty_luks_dump "$dev"
    echo ""
    log "Header backup (LUKS1, pre-conversion): $hdr_backup"
    log "Keep it until this system has booted and unlocked successfully, then"
    log "delete it — it wraps your key under the OLD pbkdf2 parameters."
    log "No boot configuration changes are needed: the system referenced this"
    log "volume by UUID already, and the UUID is unchanged."
    exit 0
}

# ─── Already Encrypted / Resume / Convert / Tune Detection ───────────────────
# A selected partition that already carries a LUKS header lands in one of four
# places, checked in this order:
#   1. LUKS2 with the 'online-reencrypt' requirement flag → a previous in-place
#      encryption was INTERRUPTED; finish it (reencrypt --resume-only), then
#      run the config phase as in a fresh deployment.
#   2. LUKS1 → offer in-place conversion to LUKS2 + argon2id re-costing.
#   3. Complete LUKS2 → show a truncated luksDump, then offer the KDF tuning
#      UI (luks-tune.sh), configuration repair (config-only mode), or exit.
#   4. Unreadable header → repair guidance, abort.
DEPLOY_MODE="encrypt"          # encrypt | resume | config-only
if blkid "$TARGET_ROOT" | grep -q 'TYPE="crypto_LUKS"'; then
    echo ""
    warn "$TARGET_ROOT already contains a LUKS header."
    if ! cryptsetup luksDump "$TARGET_ROOT" >/dev/null 2>&1; then
        err "blkid reports crypto_LUKS but 'cryptsetup luksDump' cannot read the header."
        echo "  Try repairing it first, then re-run this script:"
        echo "    cryptsetup repair $TARGET_ROOT"
        fatal "LUKS header unreadable — see docs/RECOVERY.md."
    fi
    LUKS_HDR_VER=$(cryptsetup luksDump "$TARGET_ROOT" 2>/dev/null | awk '/^Version:/{print $2; exit}')
    if cryptsetup luksDump "$TARGET_ROOT" 2>/dev/null | grep -q 'online-reencrypt'; then
        warn "The header carries the 'online-reencrypt' requirement flag:"
        warn "a previous in-place encryption was INTERRUPTED partway through."
        echo ""
        echo "  The safe fix is to let cryptsetup finish the encryption"
        echo "  (reencrypt --resume-only) and then redo the configuration"
        echo "  phase. This script can do both now."
        echo ""
        read -p "  Resume the interrupted encryption now? (yes/no): " RESUME_OK
        [ "$RESUME_OK" = "yes" ] \
            || fatal "Aborted. Resume manually with: cryptsetup reencrypt --resume-only $TARGET_ROOT"
        DEPLOY_MODE="resume"
    elif [ "$LUKS_HDR_VER" = "1" ]; then
        convert_luks1 "$TARGET_ROOT"     # does not return
    else
        warn "The header is complete LUKS2 — the encryption itself FINISHED."
        echo ""
        pretty_luks_dump "$TARGET_ROOT"
        # Recognise, never set up: if GRUB opens this volume, say so here so
        # the tune option is taken with GRUB's ceiling in mind (luks-tune.sh
        # re-checks and enforces it).
        bt_grub_probe "$TARGET_ROOT"
        if [ "$BT_GRUB_UNLOCKS" -eq 1 ]; then
            echo ""
            warn "GRUB itself unlocks this volume at boot (encrypted /boot):"
            bt_grub_summary | sed 's/^/    /'
            warn "  LinuxLocker never sets up or re-embeds an encrypted /boot. 'tune'"
            warn "  applies GRUB's ceiling: 1 GiB argon2id, and unlock estimates"
            warn "  multiplied by ${BT_GRUB_KDF_FACTOR} for GRUB's single-threaded KDF."
        fi
        echo ""
        echo "  What next?"
        echo ""
        echo "   1) tune    — raise/inspect the KDF cost of the keyslots"
        echo "                (runs luks-tune.sh; header-backed-up, data untouched)"
        echo "   2) config  — redo the boot configuration + verification phase"
        echo "                (crypttab, fstab, initramfs, bootloader — for a"
        echo "                 deployment that died after encryption finished)"
        echo "   3) quit    — leave everything exactly as it is"
        echo ""
        while true; do
            read -p "  Select [1-3, default 3=quit]: " LUKS2_CHOICE
            case "${LUKS2_CHOICE:-3}" in
                1)
                    log "Launching the KDF tuning UI..."
                    [ -x "$SCRIPT_DIR/luks-tune.sh" ] \
                        || fatal "luks-tune.sh not found next to this script."
                    if [ "$LL_HAVE_DEPS_LIB" -eq 1 ]; then
                        ll_ensure_tools dialog:dialog || true
                    fi
                    exec "$SCRIPT_DIR/luks-tune.sh"
                    ;;
                2)
                    DEPLOY_MODE="config-only"
                    break
                    ;;
                3)
                    log "Nothing changed. Bye."
                    exit 0
                    ;;
                *) echo "  Invalid selection '$LUKS2_CHOICE' — enter 1, 2 or 3." ;;
            esac
        done
    fi
fi

# Resume the interrupted encryption immediately — a half-encrypted disk is the
# most fragile state there is, so finish it before anything else. Afterwards
# the remaining work is identical to the config-only path.
if [ "$DEPLOY_MODE" = "resume" ]; then
    echo ""
    log "Resuming interrupted LUKS encryption (you will be asked for the passphrase)..."
    if ! cryptsetup reencrypt --resume-only --verbose "${CRYPT_PASS_ARGS[@]}" "${CRYPT_BATCH_ARGS[@]}" "$TARGET_ROOT"; then
        # A HARD interruption (power loss, kill -9) leaves the reencryption
        # journal dirty and --resume-only refuses with "Device requires
        # reencryption recovery. Run repair first." — verified in
        # tests/loopback-core-test.sh. cryptsetup repair fixes the journal,
        # then resume proceeds normally.
        warn "  Resume refused — running 'cryptsetup repair' (dirty reencryption journal after a hard interrupt), then retrying..."
        cryptsetup repair "${CRYPT_PASS_ARGS[@]}" "${CRYPT_BATCH_ARGS[@]}" "$TARGET_ROOT" \
            || fatal "cryptsetup repair failed. Do NOT wipe or reformat anything — see docs/RECOVERY.md."
        cryptsetup reencrypt --resume-only --verbose "${CRYPT_PASS_ARGS[@]}" "${CRYPT_BATCH_ARGS[@]}" "$TARGET_ROOT" \
            || fatal "Resume still failing after repair. Do NOT wipe or reformat anything — see docs/RECOVERY.md."
    fi
    log "  Reencryption finished."
    DEPLOY_MODE="config-only"
fi

# In config-only mode the raw partition is a LUKS container, so discovery
# (filesystem, fstab, UUIDs) must read through the opened mapper device.
DISCOVERY_DEV="$TARGET_ROOT"
if [ "$DEPLOY_MODE" = "config-only" ]; then
    if [ ! -b /dev/mapper/${LUKS_NAME} ]; then
        log "Unlocking $TARGET_ROOT (passphrase required)..."
        cryptsetup open "${CRYPT_PASS_ARGS[@]}" "$TARGET_ROOT" ${LUKS_NAME}
    fi
    DISCOVERY_DEV="/dev/mapper/${LUKS_NAME}"
fi

# ─── Filesystem identification ──────────────────────────────────────────────
echo ""
log "Identifying the target filesystem..."
ORIG_FSTYPE=$(blkid -s TYPE -o value "$DISCOVERY_DEV" 2>/dev/null || echo "unknown")
if ! fs_is_supported "$ORIG_FSTYPE"; then
    err "Filesystem on $DISCOVERY_DEV is '$ORIG_FSTYPE'."
    err "Supported for in-place encryption: ext4/ext3/ext2, btrfs, xfs (with"
    err "pre-existing slack), f2fs, ntfs, vfat. exfat/udf cannot be shrunk in"
    err "place — see docs/FILESYSTEMS.md for what to do instead."
    fatal "Unsupported filesystem: $ORIG_FSTYPE"
fi
log "  Filesystem: $ORIG_FSTYPE"
IS_BTRFS=0
[ "$ORIG_FSTYPE" = "btrfs" ] && IS_BTRFS=1

# Resolve (and if needed auto-install) the tools this filesystem requires.
ensure_fs_tools "$ORIG_FSTYPE"

# XFS cannot shrink: in encrypt mode it is accepted only when the filesystem
# is ALREADY >= 32 MiB smaller than the partition (slack from a previous
# shrink attempt elsewhere, or a deliberately undersized mkfs).
if [ "$DEPLOY_MODE" = "encrypt" ] && ! fs_can_shrink "$ORIG_FSTYPE"; then
    DEV_BYTES=$(blockdev --getsize64 "$TARGET_ROOT" 2>/dev/null || echo 0)
    FSB=$(fs_bytes "$TARGET_ROOT" "$ORIG_FSTYPE")
    if [ -z "$FSB" ] || [ "$DEV_BYTES" -le 0 ]; then
        fatal "Cannot measure the $ORIG_FSTYPE filesystem size to check for header slack."
    fi
    if [ $((DEV_BYTES - FSB)) -lt "$SHRINK_BYTES" ]; then
        err "$ORIG_FSTYPE cannot be shrunk, and only $(( (DEV_BYTES - FSB) / 1024 / 1024 )) MiB of slack exists"
        err "after the filesystem — the LUKS2 header needs ${SHRINK_MB} MiB."
        err "Options: (a) recreate the filesystem slightly smaller from a backup,"
        err "or (b) grow the partition by ${SHRINK_MB} MiB if free space follows it."
        fatal "Not enough slack to encrypt an unshrinkable filesystem in place."
    fi
    log "  $ORIG_FSTYPE has $(( (DEV_BYTES - FSB) / 1024 / 1024 )) MiB of slack — enough for the LUKS2 header."
fi

# ─── System / fstab Auto-Discovery ──────────────────────────────────────────
echo ""
log "Auto-discovering the target system's configuration..."

mkdir -p /mnt_temp

ROOT_SUBVOL=""
HOME_SUBVOL=""
SUBPATH=""            # path prefix of the root subvolume inside /mnt_temp
if [ "$IS_BTRFS" -eq 1 ]; then
    # Mount top-level subvolume (ID 5) to see all subvolume directories
    # (through the opened mapper in config-only mode, raw partition otherwise)
    mount -o subvolid=5,ro "$DISCOVERY_DEV" /mnt_temp
    for try_sub in root @rootfs @ ""; do
        if [ -f "/mnt_temp/${try_sub}${try_sub:+/}etc/fstab" ]; then
            ROOT_SUBVOL="$try_sub"
            SUBPATH="${try_sub}${try_sub:+/}"
            break
        fi
    done
else
    mount -o ro "$DISCOVERY_DEV" /mnt_temp
    [ -f /mnt_temp/etc/fstab ] && SUBPATH=""
fi

SYSTEM_MODE=1
if [ ! -f "/mnt_temp/${SUBPATH}etc/fstab" ]; then
    echo ""
    warn "No /etc/fstab found on $DISCOVERY_DEV — this does not look like the"
    warn "root filesystem of an installed Linux."
    if [ "$IS_BTRFS" -eq 1 ]; then
        echo "  Btrfs subvolumes present:"
        btrfs subvolume list /mnt_temp 2>/dev/null | sed 's/^/    /' || true
    fi
    echo ""
    echo "  LinuxLocker can still encrypt it as a DATA partition: same in-place"
    echo "  encryption, recovery key and header backup, but no boot configuration"
    echo "  is touched (there is none to touch). You will unlock it manually or"
    echo "  via a crypttab entry on whatever system mounts it."
    echo ""
    if [ "$DEPLOY_MODE" = "config-only" ]; then
        umount /mnt_temp; rmdir /mnt_temp
        log "Config-only mode has nothing to do on a data partition — the"
        log "encryption itself is complete. Add it to the host's crypttab/fstab"
        log "by hand if you want it auto-unlocked; see docs/FILESYSTEMS.md."
        exit 0
    fi
    read -p "  Encrypt $TARGET_ROOT as a data partition? (yes/no): " DATA_OK
    [ "$DATA_OK" = "yes" ] || fatal "Aborted — no system found and data mode declined."
    SYSTEM_MODE=0
fi

# btrfs: parse home subvolume name from fstab
if [ "$SYSTEM_MODE" -eq 1 ] && [ "$IS_BTRFS" -eq 1 ]; then
    HOME_SUBVOL=$(sed -n 's|^[^#]*[[:space:]]/home[[:space:]]\+btrfs[[:space:]]\+.*subvol=\([^,[:space:]]*\).*|\1|p' \
        "/mnt_temp/${SUBPATH}etc/fstab" | head -1)
    [ -n "$HOME_SUBVOL" ] || HOME_SUBVOL="$ROOT_SUBVOL"
    log "  Btrfs subvolumes: root='${ROOT_SUBVOL:-(top-level)}', home='${HOME_SUBVOL:-(top-level)}'"
fi

# ─── Target OS identification ───────────────────────────────────────────────
TARGET_OS_PRETTY="unknown"
TARGET_OS_ID=""
TARGET_OS_LIKE=""
TARGET_FAMILY="unknown"
if [ "$SYSTEM_MODE" -eq 1 ]; then
    TREL="/mnt_temp/${SUBPATH}etc/os-release"
    [ -r "$TREL" ] || TREL="/mnt_temp/${SUBPATH}usr/lib/os-release"
    if [ -r "$TREL" ]; then
        TARGET_OS_ID=$(awk -F= '$1=="ID"{gsub(/"/,"",$2); print $2; exit}' "$TREL")
        TARGET_OS_LIKE=$(awk -F= '$1=="ID_LIKE"{gsub(/"/,"",$2); print $2; exit}' "$TREL")
        TARGET_OS_PRETTY=$(awk -F= '$1=="PRETTY_NAME"{gsub(/"/,"",$2); print $2; exit}' "$TREL")
    fi
    if [ "$LL_HAVE_DEPS_LIB" -eq 1 ]; then
        ll_family_for "$TARGET_OS_ID $TARGET_OS_LIKE"
        TARGET_FAMILY="$LL_FAMILY_RESULT"
    else
        case " $TARGET_OS_ID $TARGET_OS_LIKE " in
            *fedora*|*rhel*|*centos*)          TARGET_FAMILY=redhat ;;
            *debian*|*ubuntu*|*raspbian*)      TARGET_FAMILY=debian ;;
            *arch*|*manjaro*)                  TARGET_FAMILY=arch ;;
            *suse*)                            TARGET_FAMILY=suse ;;
        esac
    fi
    log "  Target OS: $TARGET_OS_PRETTY (id=${TARGET_OS_ID:-?} family=$TARGET_FAMILY)"

    # The TARGET may be Fedora Asahi Remix even when the live environment is
    # not (an Asahi disk read from another machine, a rescue image that does
    # not identify itself). ID=fedora, so only the variant fields catch it.
    if [ "$LL_HAVE_DEPS_LIB" -eq 1 ] && ll_detect_asahi "/mnt_temp/${SUBPATH%/}"; then
        ll_asahi_refuse "The partition you selected holds a Fedora Asahi Remix install."
        exit 3
    fi
fi

# Capture the filesystem UUID before encryption. In config-only mode the raw
# partition holds the LUKS header, so the fs UUID must be read from the mapper.
ORIG_FS_UUID=$(blkid -s UUID -o value "$DISCOVERY_DEV")

# ─── Boot / EFI / firmware partition resolution (from the target's fstab) ────
# Instead of asking the operator to pick boot partitions and then checking the
# choice against fstab, resolve them FROM the target's own fstab: the fstab is
# the authority on which partitions belong to this install. A spec that cannot
# be resolved falls back to an interactive menu, and LUKS_TARGET_BOOT /
# LUKS_TARGET_EFI env pins always win (cross-checked, override by typed
# 'MISMATCH').
TARGET_FSTAB="/mnt_temp/${SUBPATH}etc/fstab"

fstab_spec_for() {
    # $1 = mountpoint; prints the fs_spec of its non-comment fstab line, if any
    awk -v mp="$1" '$1 !~ /^#/ && $2 == mp { print $1; exit }' "$TARGET_FSTAB" 2>/dev/null
}

resolve_spec() {
    # $1 = fstab fs_spec (UUID=/PARTUUID=/LABEL=/PARTLABEL=//dev/...) → device path
    local spec="$1" dev=""
    case "$spec" in
        UUID=*)      dev=$(blkid --uuid "${spec#UUID=}" 2>/dev/null || true) ;;
        PARTUUID=*)  dev=$(blkid -t "PARTUUID=${spec#PARTUUID=}" -o device 2>/dev/null | head -1 || true) ;;
        LABEL=*)     dev=$(blkid --label "${spec#LABEL=}" 2>/dev/null || true) ;;
        PARTLABEL=*) dev=$(blkid -t "PARTLABEL=${spec#PARTLABEL=}" -o device 2>/dev/null | head -1 || true) ;;
        /dev/*)      dev="$spec" ;;
    esac
    [ -n "$dev" ] && [ -b "$dev" ] && readlink -f "$dev"
}

# Parallel arrays: extra mountpoints (relative to the target root) + devices.
MNT_MPS=()
MNT_DEVS=()
TARGET_BOOT=""       # device holding /boot, if it is a separate partition
# shellcheck disable=SC2034  # kept for symmetry with TARGET_BOOT / future use
TARGET_EFI=""        # device holding /boot/efi or /efi, if present
BOOT_IS_SEPARATE=0

resolve_boot_partition() {
    # $1 = mountpoint, $2 = role, $3 = env pin value (may be empty),
    # $4 = env var name, $5 = fallback fstype regex for the menu
    local mp="$1" role="$2" pin="$3" var="$4" fsre="$5" spec dev fstab_dev
    spec=$(fstab_spec_for "$mp")
    [ -n "$spec" ] || return 1           # target has no such mountpoint
    fstab_dev=$(resolve_spec "$spec" || true)
    if [ -n "$pin" ]; then
        dev=$(pinned_partition "$role" "$var" "$pin" "$fsre")
        if [ -n "$fstab_dev" ] && [ "$fstab_dev" != "$(readlink -f "$dev")" ]; then
            echo ""
            err "  fstab cross-check MISMATCH for $role:"
            err "    You pinned          : $dev"
            err "    Target fstab wants  : $spec → ${fstab_dev}"
            err "  The pinned $role partition likely belongs to a DIFFERENT install."
            err "  Writing boot config there would break BOTH systems."
            read -p "  Use $dev anyway? (Type 'MISMATCH' to override): " XCHK
            [ "$XCHK" = "MISMATCH" ] || fatal "Fix the partition selection and re-run."
        fi
    elif [ -n "$fstab_dev" ]; then
        dev="$fstab_dev"
        log "  $role: $mp → $dev (resolved from target fstab: $spec)"
    else
        warn "  Target fstab mounts $mp from '$spec' but no such device exists on"
        warn "  this machine right now. Pick it manually (or ctrl-C and check)."
        dev=$(pick_partition "$role" "$fsre" "boot|efi|esp|firmware")
    fi
    MNT_MPS+=("$mp")
    MNT_DEVS+=("$dev")
    # shellcheck disable=SC2034  # TARGET_EFI kept for symmetry / env-pin documentation
    case "$mp" in
        /boot)               TARGET_BOOT="$dev"; BOOT_IS_SEPARATE=1 ;;
        /boot/efi|/efi)      TARGET_EFI="$dev" ;;
    esac
    return 0
}

if [ "$SYSTEM_MODE" -eq 1 ]; then
    log "Resolving boot partitions from the target's fstab..."
    resolve_boot_partition /boot          "BOOT" "${LUKS_TARGET_BOOT:-}" LUKS_TARGET_BOOT 'ext4|ext3|ext2|xfs|btrfs|vfat' \
        || log "  No separate /boot partition — /boot lives on the root filesystem."
    resolve_boot_partition /boot/efi      "EFI"  "${LUKS_TARGET_EFI:-}"  LUKS_TARGET_EFI  'vfat' \
        || resolve_boot_partition /efi    "EFI"  "${LUKS_TARGET_EFI:-}"  LUKS_TARGET_EFI  'vfat' \
        || log "  No EFI system partition in fstab (BIOS boot, or firmware-managed)."
    resolve_boot_partition /boot/firmware "FIRMWARE" "" _ 'vfat' \
        && log "  /boot/firmware present — Raspberry Pi-style firmware partition."
fi

# ─── /boot inside the volume: recognised, never encrypted ───────────────────
# With no separate /boot, the kernel, the initramfs and grub.cfg all live on
# the root filesystem. Encrypting it means GRUB (or U-Boot's extlinux, which
# cannot at all) has to open the LUKS volume before it can load anything.
# That is an encrypted-/boot setup: GRUB runs the KDF itself, single-threaded
# from the firmware's contiguous heap (1 GiB on x86 UEFI), its image has to be
# re-embedded with the crypto modules by grub-install, and whether it can open
# argon2id at all depends on the build. LinuxLocker does not offer any of
# that. The fix is a separate, unencrypted /boot partition; then re-run.
#
# A volume that is ALREADY encrypted and unlocked by GRUB (config-only mode)
# is recognised and its configuration is repaired; its KDF is left to
# luks-tune.sh, which applies GRUB's ceiling.
BOOT_IN_VOLUME=""
if [ "$SYSTEM_MODE" -eq 1 ] && [ "$BOOT_IS_SEPARATE" -eq 0 ]; then
    for bdir in "/mnt_temp/${SUBPATH}boot/grub2" "/mnt_temp/${SUBPATH}boot/grub" "/mnt_temp/${SUBPATH}boot/extlinux"; do
        [ -d "$bdir" ] || continue
        BOOT_IN_VOLUME="${bdir#/mnt_temp/"${SUBPATH}"}"
        break
    done
fi
if [ -n "$BOOT_IN_VOLUME" ] && [ "$DEPLOY_MODE" = "encrypt" ]; then
    echo ""
    err "╔══════════════════════════════════════════════════════════════╗"
    err "║  /boot lives INSIDE the partition you selected               ║"
    err "╚══════════════════════════════════════════════════════════════╝"
    err "  Target fstab has no separate /boot, and /$BOOT_IN_VOLUME is on this"
    err "  filesystem. Encrypting it would put the kernel, the initramfs and the"
    err "  bootloader config inside the LUKS container, so the bootloader itself"
    err "  would have to unlock the volume before it could load anything."
    echo ""
    echo "  That is an encrypted /boot, and LinuxLocker does not set one up,"
    echo "  because the keyslot GRUB opens would be the weakest way in:"
    echo "    - argon2id's strength is its memory cost, taken as ONE contiguous"
    echo "      allocation. GRUB gets it from the firmware heap: 1 GiB at most on"
    echo "      x86 UEFI, against the 4 GiB the initramfs gives your root;"
    echo "    - stock GRUB 2.12 cannot open argon2id at all, and any GRUB image"
    echo "      would have to be re-embedded with the crypto modules by grub-install;"
    echo "    - GRUB runs the KDF single-threaded, about ${BT_GRUB_KDF_FACTOR}x the initramfs time;"
    echo "    - extlinux / U-Boot cannot read LUKS in any form."
    echo "  Leaving /boot clear keeps the strong keyslot where the initramfs can use it."
    echo ""
    echo "  Give the system a separate, unencrypted /boot partition (1 GiB is"
    echo "  plenty), move the contents of /boot there, add it to fstab, re-run"
    echo "  grub-install / update-grub, and run LinuxLocker again."
    echo "  Details: docs/BOOTLOADERS.md, 'Encrypted /boot'."
    umount -R /mnt_temp 2>/dev/null || true
    rmdir /mnt_temp 2>/dev/null || true
    fatal "Refusing to encrypt a volume that holds /boot. Nothing was changed."
elif [ -n "$BOOT_IN_VOLUME" ]; then
    log "  /boot is inside this (already encrypted) volume — GRUB unlocks it at boot."
    log "  Recognised: configuration is repaired; the KDF is not touched here."
fi

# ─── Same-Disk Sanity Check ──────────────────────────────────────────────────
DISK_ROOT=$(lsblk -no PKNAME "$TARGET_ROOT" 2>/dev/null | head -n1)

# An ESP or XBOOTLDR partition the target never lists in fstab is mounted at
# boot by systemd-gpt-auto-generator, not by fstab. Nothing here can tell that
# it belongs to this install, so it is not mounted into the chroot — and any
# boot entries or UKIs on it are not updated. Say so now, while stopping is free.
if [ "$SYSTEM_MODE" -eq 1 ] && [ -n "$DISK_ROOT" ] && [ -d /sys/firmware/efi ]; then
    GPT_AUTO_MISSED=$(lsblk -rno NAME,PARTTYPE "/dev/$DISK_ROOT" 2>/dev/null | awk '
        tolower($2)=="c12a7328-f81f-11d2-ba4b-00a0c93ec93b" { print "/dev/"$1" (EFI System Partition)" }
        tolower($2)=="bc13c2ff-59e6-4262-a352-b275fd6f7172" { print "/dev/"$1" (XBOOTLDR)" }')
    if [ -n "$GPT_AUTO_MISSED" ]; then
        while IFS= read -r gp; do
            [ -n "$gp" ] || continue
            gp_dev=${gp%% *}
            gp_real=$(readlink -f "$gp_dev" 2>/dev/null || echo "$gp_dev")
            gp_listed=0
            for gd in "${MNT_DEVS[@]+"${MNT_DEVS[@]}"}"; do
                [ "$(readlink -f "$gd" 2>/dev/null)" = "$gp_real" ] && gp_listed=1
            done
            [ "$gp_listed" -eq 1 ] && continue
            warn "  $gp is on this disk but the target's fstab never mounts it"
            warn "  (systemd-gpt-auto-generator layout?). It will NOT be mounted into the"
            warn "  chroot, so boot entries or UKIs on it are not updated. Add it to the"
            warn "  target's fstab first if that is where this system boots from."
        done <<< "$GPT_AUTO_MISSED"
    fi
fi
for i in "${!MNT_MPS[@]}"; do
    d=$(lsblk -no PKNAME "${MNT_DEVS[$i]}" 2>/dev/null | head -n1)
    if [ -n "$d" ] && [ "$d" != "$DISK_ROOT" ]; then
        warn "${MNT_MPS[$i]} (${MNT_DEVS[$i]}) is on disk '$d' but ROOT is on '$DISK_ROOT'!"
        read -p "Proceed with partitions on different disks? (yes/no): " cross_disk
        [ "$cross_disk" = "yes" ] || fatal "Aborted."
        break
    fi
done

# ─── Pre-Encryption State Backup (to the deployment drive) ──────────────────
log "  Saving pre-encryption state to the deployment drive..."
STATE_DIR="$SCRIPT_DIR/pre-luks-state-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$STATE_DIR"
# Lock the directory before the recovery key or the header backup land in it.
# This is also the first harden_path call, so an unsuitable deployment drive
# is reported here — before encryption starts and while aborting is free.
harden_path 0700 "$STATE_DIR"
if [ "$SYSTEM_MODE" -eq 1 ]; then
    cp "/mnt_temp/${SUBPATH}etc/fstab" "$STATE_DIR/fstab" 2>/dev/null || true
    cp "/mnt_temp/${SUBPATH}etc/default/grub" "$STATE_DIR/grub-defaults" 2>/dev/null || true
    cp "/mnt_temp/${SUBPATH}etc/kernel/cmdline" "$STATE_DIR/kernel-cmdline" 2>/dev/null || true
    cp "/mnt_temp/${SUBPATH}etc/mkinitcpio.conf" "$STATE_DIR/mkinitcpio.conf" 2>/dev/null || true
    cp "/mnt_temp/${SUBPATH}etc/os-release" "$STATE_DIR/os-release" 2>/dev/null || true
    [ -f "/mnt_temp/${SUBPATH}etc/crypttab" ] && \
        cp "/mnt_temp/${SUBPATH}etc/crypttab" "$STATE_DIR/crypttab"
fi
lsblk -o NAME,FSTYPE,LABEL,PARTLABEL,SIZE,UUID > "$STATE_DIR/lsblk.txt" 2>/dev/null || true
blkid > "$STATE_DIR/blkid.txt" 2>/dev/null || true
[ "$IS_BTRFS" -eq 1 ] && btrfs subvolume list /mnt_temp > "$STATE_DIR/btrfs-subvols.txt" 2>/dev/null || true
log "  Pre-encryption state saved to: $STATE_DIR/"

# ─── Check BLS entries for consistency (btrfs subvol installs only) ──────────
# Fedora-style installs boot via BLS entries whose 'options' line pins the
# root subvolume; if it disagrees with fstab, config changes could land in a
# subvolume the system never boots from.
BLS_ROOT_SUBVOL=""
if [ "$SYSTEM_MODE" -eq 1 ]; then
    BLS_SRC=""
    if [ "$BOOT_IS_SEPARATE" -eq 1 ]; then
        if mount -o ro "$TARGET_BOOT" "/mnt_temp/${SUBPATH}boot" 2>/dev/null; then
            BLS_SRC="/mnt_temp/${SUBPATH}boot"
        fi
    else
        BLS_SRC="/mnt_temp/${SUBPATH}boot"
    fi
    if [ -n "$BLS_SRC" ] && [ -d "$BLS_SRC/loader/entries" ]; then
        for bls_entry in "$BLS_SRC"/loader/entries/*.conf; do
            [ -f "$bls_entry" ] || continue
            echo "$bls_entry" | grep -q 'rescue' && continue
            bls_subvol=$(sed -n 's/.*rootflags=subvol=\([^[:space:]]*\).*/\1/p' "$bls_entry")
            if [ -n "$bls_subvol" ]; then
                BLS_ROOT_SUBVOL="$bls_subvol"
                break
            fi
        done
        cp "$BLS_SRC"/loader/entries/*.conf "$STATE_DIR/" 2>/dev/null || true
    fi
    if [ "$BOOT_IS_SEPARATE" -eq 1 ] && [ "$BLS_SRC" = "/mnt_temp/${SUBPATH}boot" ]; then
        umount "/mnt_temp/${SUBPATH}boot" 2>/dev/null || true
    fi
fi

# ─── Unified Kernel Image detection + conditional guard ──────────────────────
# A UKI carries the kernel, the initramfs AND the kernel command line inside one
# PE binary (EFI/Linux/*.efi). Writing /etc/kernel/cmdline and rebuilding
# /boot/initramfs-*.img changes nothing about what the firmware loads: the .efi
# has to be REBUILT, and on a Secure Boot machine re-signed, because the .efi is
# the object the firmware verifies.
#
# Up to 1.1.0 this block refused every UKI target unconditionally. It is now
# conditional: step 7f rebuilds the .efi and step 7g signs it, so a UKI target
# with a working regeneration path is supported. The refusal survives for the
# two cases where proceeding would still hand back a green report and a dead
# machine — no way to rebuild the .efi, or no way to sign it with Secure Boot on.
#
# --- The pre-1.2.0 unconditional refusal, kept for reference ----------------
# if [ "${#UKI_FOUND[@]}" -gt 0 ]; then
#     warn "  Unified Kernel Images found on this target:"
#     for uki in "${UKI_FOUND[@]}"; do warn "    $uki"; done
#     warn "  ... nothing here regenerates the .efi ..."
#     if [ "${LUKS_ALLOW_UKI:-0}" = "1" ]; then
#         warn "  LUKS_ALLOW_UKI=1 is set — continuing anyway."
#     else
#         fatal "Refusing to deploy onto a UKI target (set LUKS_ALLOW_UKI=1 to override)."
#     fi
# fi
# ---------------------------------------------------------------------------
#
# Everything below runs BEFORE the shrink and BEFORE encryption, while aborting
# still costs nothing. See docs/BOOTLOADERS.md.
UKI_FOUND=()
UKI_ACTIVE=0            # 1 = this run must regenerate (and maybe sign) a UKI
if [ "$LL_HAVE_UKI_LIB" -eq 1 ] && [ "$SYSTEM_MODE" -eq 1 ]; then
    uki_probe_dev "$TARGET_EFI"  "ESP"      # the usual home of EFI/Linux
    uki_probe_dev "$TARGET_BOOT" "/boot"    # XBOOTLDR layouts keep them here
    # /boot on the root filesystem: /mnt_temp is already mounted read-only.
    if [ "$BOOT_IS_SEPARATE" -eq 0 ]; then
        uki_scan_dir "/mnt_temp/${SUBPATH%/}" "/boot"
    fi
    uki_detect_regen  "/mnt_temp/${SUBPATH%/}" || true
    uki_detect_signer "/mnt_temp/${SUBPATH%/}" || true
    uki_detect_sdboot "/mnt_temp/${SUBPATH%/}" || true
    uki_detect_sb
elif [ "$SYSTEM_MODE" -eq 1 ]; then
    # No lib-uki.sh next to this script: fall back to bare detection so the
    # refusal below still fires. Never proceed onto a UKI we cannot rebuild.
    for uki in "/mnt_temp/${SUBPATH:-}boot"/EFI/Linux/*.efi \
               "/mnt_temp/${SUBPATH:-}boot/efi"/EFI/Linux/*.efi \
               "/mnt_temp/${SUBPATH:-}efi"/EFI/Linux/*.efi; do
        [ -f "$uki" ] || continue
        UKI_FOUND+=("/boot:$(basename "$uki")")
    done
fi

if [ "${#UKI_FOUND[@]}" -gt 0 ]; then
    echo ""
    log "════════════════════════════════════════════════════════════"
    log "  Unified Kernel Images found on this target:"
    for uki in "${UKI_FOUND[@]}"; do log "    $uki"; done
    log "    rebuild backend : ${UKI_REGEN:-none}${UKI_REGEN_DETAIL:+  ($UKI_REGEN_DETAIL)}"
    log "    signing backend : ${UKI_SIGN:-none}${UKI_SIGN_DETAIL:+  ($UKI_SIGN_DETAIL)}"
    log "    Secure Boot     : ${UKI_SB_STATE:-unknown}"
    [ "${UKI_SDBOOT:-0}" -eq 1 ] && log "    systemd-boot    : $UKI_SDBOOT_DETAIL"
    log "════════════════════════════════════════════════════════════"

    UKI_REFUSE=""
    if [ "$LL_HAVE_UKI_LIB" -eq 0 ]; then
        UKI_REFUSE="lib-uki.sh is not next to this script, so nothing here can regenerate the .efi"
    elif [ "${UKI_REGEN:-none}" = "none" ]; then
        UKI_REFUSE="no UKI regeneration backend found (mkinitcpio preset with _uki=, kernel-install with layout=uki, dracut --uki-file, or ukify)"
    elif [ "${UKI_SB_STATE:-unknown}" = "enabled" ] && [ "${UKI_SIGN:-none}" = "none" ] \
         && [ "${LUKS_SKIP_UKI_SIGN:-0}" != "1" ]; then
        UKI_REFUSE="Secure Boot is enabled but no signing backend was found${UKI_SIGN_DETAIL:+ — $UKI_SIGN_DETAIL}"
    fi

    if [ -n "$UKI_REFUSE" ]; then
        echo ""
        warn "  Cannot safely deploy onto this UKI target:"
        warn "    $UKI_REFUSE"
        warn ""
        warn "  Proceeding would encrypt the disk, rebuild the standalone"
        warn "  initramfs correctly, write /etc/kernel/cmdline correctly — and"
        warn "  leave the firmware booting an .efi that still carries the"
        warn "  pre-encryption command line, or one it refuses to load at all."
        warn "  Every check in step 8 would report OK, because the files those"
        warn "  checks read really are correct. See docs/BOOTLOADERS.md."
        if [ "${LUKS_ALLOW_UKI:-0}" = "1" ]; then
            warn ""
            warn "  LUKS_ALLOW_UKI=1 is set — continuing anyway. Regenerating and"
            warn "  re-signing EFI/Linux/*.efi before the first reboot is YOUR"
            warn "  responsibility now."
            UKI_ACTIVE=1
        else
            fatal "Refusing to deploy onto this UKI target (set LUKS_ALLOW_UKI=1 to override)."
        fi
    else
        UKI_ACTIVE=1
        log "  UKI support active: step 7f rebuilds the .efi, step 7g signs it,"
        log "  and checks V11/V12 verify both before the reboot is allowed."
    fi
fi

if [ "$IS_BTRFS" -eq 1 ] && [ -n "$BLS_ROOT_SUBVOL" ] && [ "$BLS_ROOT_SUBVOL" != "$ROOT_SUBVOL" ]; then
    warn "BLS boot entry uses subvol='$BLS_ROOT_SUBVOL'"
    warn "  but fstab uses subvol='${ROOT_SUBVOL:-(top-level)}'"
    warn "  The script will mount and modify the fstab subvolume."
    warn "  If the system boots from a DIFFERENT subvolume, config changes"
    warn "  may not take effect. Consider fixing this inconsistency first."
    read -p "  Continue anyway? (yes/no): " subvol_override
    [ "$subvol_override" = "yes" ] || fatal "Fix subvolume inconsistency first."
fi

# ─── Free Space Check ───────────────────────────────────────────────────────
FS_AVAIL_MB=$(df --block-size=1M /mnt_temp | tail -1 | awk '{print $4}')
log "  Free space: ${FS_AVAIL_MB} MiB"
# Only the 32M shrink needs headroom; config-only mode never resizes, and an
# unshrinkable fs (xfs) already proved its slack.
if [ "$DEPLOY_MODE" = "encrypt" ] && fs_can_shrink "$ORIG_FSTYPE" && [ "$FS_AVAIL_MB" -lt 64 ]; then
    umount -R /mnt_temp
    rmdir /mnt_temp
    fatal "Less than 64 MiB free. Need at least 64 MiB. Free up space first."
fi

umount -R /mnt_temp
rmdir /mnt_temp

# ─── Optional Filesystem Integrity Check ────────────────────────────────────
echo ""
CHECK_DEV="$TARGET_ROOT"
[ "$DEPLOY_MODE" = "config-only" ] && CHECK_DEV="/dev/mapper/${LUKS_NAME}"
if [ "$DRY_RUN" = "1" ]; then
    DO_CHECK="n"
    log "[dry-run] Skipping the $ORIG_FSTYPE integrity check (a real run offers it here)."
else
    read -p "Run a read-only $ORIG_FSTYPE integrity check first? (Recommended, takes 5-30 min) [Y/n]: " DO_CHECK
fi
if [ "$DO_CHECK" != "n" ] && [ "$DO_CHECK" != "N" ]; then
    log "  Running read-only $ORIG_FSTYPE check (this may take a while)..."
    if fs_check_ro "$CHECK_DEV" "$ORIG_FSTYPE"; then
        log "  Filesystem check: PASSED"
    else
        err "  Filesystem check found errors!"
        read -p "  Continue despite filesystem errors? (Type 'FORCE' to override): " fsck_override
        [ "$fsck_override" = "FORCE" ] || fatal "Fix filesystem errors before encrypting."
    fi
else
    warn "  Skipping filesystem check."
fi

# ─── KDF Profile Selection ──────────────────────────────────────────────────
# Done here, just before the point of no return, so the estimates reflect the
# machine as it will actually be. Skipped when parameters are pinned by env.
if [ "$DEPLOY_MODE" = "config-only" ]; then
    KDF_PROFILE_NAME="(existing header — unchanged)"
    log "Config-only mode: the KDF is already fixed in the LUKS header; skipping profile menu."
elif [ "$KDF_PINNED_BY_ENV" -eq 1 ]; then
    KDF_PROFILE_NAME="custom (pinned by environment)"
    log "KDF pinned via environment: mem=$((LUKS_PBKDF_MEMORY / 1024)) MiB iters=$LUKS_PBKDF_ITER parallel=$LUKS_PBKDF_PARALLEL"
elif [ -n "${LUKS_PROFILE:-}" ]; then
    apply_kdf_profile "$LUKS_PROFILE" \
        || fatal "Unknown LUKS_PROFILE '$LUKS_PROFILE' (expected: aggressive, moderate, or fast)"
    log "KDF profile from environment: $KDF_PROFILE_NAME"
else
    echo ""
    log "Benchmarking argon2id on this machine to estimate unlock times..."
    EST_AGG=$(kdf_estimate_ms "$KDF_PROFILE_AGGRESSIVE_MEM" "$KDF_PROFILE_AGGRESSIVE_ITER" "$KDF_DEFAULT_PARALLEL" || echo "")
    EST_MOD=$(kdf_estimate_ms "$KDF_PROFILE_MODERATE_MEM"   "$KDF_PROFILE_MODERATE_ITER"   "$KDF_DEFAULT_PARALLEL" || echo "")
    EST_FAST=$(kdf_estimate_ms "$KDF_PROFILE_FAST_MEM"      "$KDF_PROFILE_FAST_ITER"       "$KDF_DEFAULT_PARALLEL" || echo "")
    [ -n "$EST_AGG$EST_MOD$EST_FAST" ] || warn "  Benchmark unavailable — showing profiles without time estimates."

    echo ""
    echo "  ════════════════════════════════════════════════════════════"
    echo "   LUKS2 KDF PROFILE"
    echo "   All three are argon2id. None uses pbkdf2."
    echo "  ════════════════════════════════════════════════════════════"
    echo ""
    printf "   1) aggressive    4 GiB, 10 iterations    unlock ~%s\n" "$(kdf_fmt_ms "${EST_AGG:-}")"
    echo   "      Strongest. A 24 GB GPU fits only ~6 guesses at once"
    echo   "      against this. 4 GiB is argon2id's maximum memory cost,"
    echo   "      so anything beyond it has to buy iterations instead."
    echo ""
    printf "   2) moderate      2 GiB,  8 iterations    unlock ~%s   [default]\n" "$(kdf_fmt_ms "${EST_MOD:-}")"
    echo   "      Strong. ~12 concurrent guesses on that same GPU."
    echo ""
    printf "   3) fast          1 GiB,  9 iterations    unlock ~%s\n" "$(kdf_fmt_ms "${EST_FAST:-}")"
    echo   "      Still memory-hard: ~24 at once. The right pick for"
    echo   "      low-memory machines (small boards, old laptops)."
    echo ""
    echo "  ════════════════════════════════════════════════════════════"
    echo "   argon2id needs its full memory for EVERY guess. That is"
    echo "   what caps an attacker's guess rate: they cannot trade"
    echo "   memory for speed. With a real passphrase (8+ diceware"
    echo "   words) an offline attack runs past 10^20 years. A short"
    echo "   or reused passphrase collapses that, whichever profile"
    echo "   you pick."
    echo ""
    echo "   Estimates come from cryptsetup benchmark on THIS machine;"
    echo "   approximate, and they shift with system load. cryptsetup"
    echo "   clamps the benchmark to what it can allocate right now, so"
    echo "   a profile above that clamp is extrapolated, not measured."
    echo "   The KDF runs once per boot, in the initramfs, with the machine"
    echo "   to itself — so the memory cost you pick must fit in THIS"
    echo "   machine's RAM. That memory is exactly what the attacker has to"
    echo "   pay for every guess."
    if [ "$MEM_TOTAL_KIB" -gt 0 ] && [ "$MEM_TOTAL_KIB" -lt $((6 * 1024 * 1024)) ]; then
        echo ""
        echo -e "   ${YELLOW}This machine has $((MEM_TOTAL_KIB / 1024 / 1024)) GiB RAM — 'aggressive' (4 GiB) is NOT safe"
        echo -e "   here; the unlock could OOM at boot. Pick moderate or fast.${NC}"
    fi
    echo ""
    # Re-prompt on a typo: by this point the user may have sat through a
    # 5-30 minute filesystem check, so a mistyped digit must not abort the run.
    while true; do
        read -p "  Select KDF profile [1-3, default 2=moderate]: " KDF_CHOICE
        case "${KDF_CHOICE:-2}" in
            1) apply_kdf_profile aggressive; break ;;
            2) apply_kdf_profile moderate;   break ;;
            3) apply_kdf_profile fast;       break ;;
            *) echo "  Invalid selection '$KDF_CHOICE' — enter 1, 2 or 3." ;;
        esac
    done
    log "  Selected: $KDF_PROFILE_NAME ($((LUKS_PBKDF_MEMORY / 1024)) MiB, ${LUKS_PBKDF_ITER} iterations)"
fi

# Refuse a profile whose memory cost cannot fit in this machine's RAM at all —
# that is not a trade-off, it is an unlock that OOMs at every boot.
if [ "$DEPLOY_MODE" != "config-only" ] && [ "$MEM_TOTAL_KIB" -gt 0 ] \
   && [ "$LUKS_PBKDF_MEMORY" -ge "$MEM_TOTAL_KIB" ]; then
    fatal "KDF memory cost ($((LUKS_PBKDF_MEMORY / 1024)) MiB) exceeds this machine's RAM ($((MEM_TOTAL_KIB / 1024)) MiB).
     The KDF re-runs at every boot in the initramfs; it must fit in RAM.
     Pick a smaller profile."
fi

# Applies to EVERY path that formats a new header — the menu, LUKS_PROFILE, and
# pinned LUKS_PBKDF_* alike. config-only is exempt: that header already exists
# and its KDF cannot be changed from here (use luks-tune.sh).
if [ "$DEPLOY_MODE" != "config-only" ]; then
    kdf_enforce_stock_floor
fi

# ─── Pre-Flight Summary ─────────────────────────────────────────────────────
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                    PRE-FLIGHT SUMMARY                     ║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "  ROOT    : $TARGET_ROOT  (UUID=$ORIG_FS_UUID, $ORIG_FSTYPE)"
if [ "$SYSTEM_MODE" -eq 1 ]; then
    echo "  OS      : $TARGET_OS_PRETTY (family=$TARGET_FAMILY)"
    for i in "${!MNT_MPS[@]}"; do
        printf "  %-8s: %s  (UUID=%s)\n" "${MNT_MPS[$i]}" "${MNT_DEVS[$i]}" \
            "$(blkid -s UUID -o value "${MNT_DEVS[$i]}" 2>/dev/null || echo '?')"
    done
    [ "$BOOT_IS_SEPARATE" -eq 0 ] && echo "  /boot   : (directory on the root filesystem)"
    [ "$IS_BTRFS" -eq 1 ] && echo "  Subvols : root=${ROOT_SUBVOL:-(top-level)}, home=${HOME_SUBVOL:-(top-level)}"
else
    echo "  Mode    : DATA PARTITION (no boot configuration will be touched)"
fi
echo "  Free    : ${FS_AVAIL_MB} MiB"
echo "  Arch    : $(uname -m)"
echo "  Crypto  : cryptsetup $CRYPTSETUP_VER"
echo "  Mode    : $DEPLOY_MODE"
if [ "$DEPLOY_MODE" = "config-only" ]; then
    echo "  KDF     : (existing LUKS header — unchanged)"
else
    echo "  KDF     : argon2id $KDF_PROFILE_NAME — $((LUKS_PBKDF_MEMORY / 1024)) MiB, ${LUKS_PBKDF_ITER} iterations, ${LUKS_PBKDF_PARALLEL} threads"
    # State the strength claim as a number measured on THIS machine, at the
    # moment of decision — not as a promise from the README.
    if [ -n "${STOCK_ITER:-}" ] && [ -n "${STOCK_MEM:-}" ]; then
        printf "            = %s the work of cryptsetup's own default here (%s MiB x %s)\n" \
            "$(awk -v a="$((LUKS_PBKDF_MEMORY * LUKS_PBKDF_ITER))" \
                   -v b="$((STOCK_MEM * STOCK_ITER))" 'BEGIN{printf "%.4gx", a/b}')" \
            "$((STOCK_MEM / 1024))" "$STOCK_ITER"
    fi
fi
[ -n "$BLS_ROOT_SUBVOL" ] && echo "  BLS boot: subvol=$BLS_ROOT_SUBVOL"
echo ""
if [ "$DEPLOY_MODE" = "config-only" ]; then
    echo -e "  ${YELLOW}${BOLD}Configuration-only mode: no data will be (re-)encrypted.${NC}"
    echo -e "  ${YELLOW}Boot configuration will be rewritten and re-verified.${NC}"
else
    echo -e "  ${RED}${BOLD}WARNING: This will perform IRREVERSIBLE in-place encryption.${NC}"
    echo -e "  ${RED}Ensure AC power is connected. Ensure you have a backup.${NC}"
fi
echo "  Pre-encryption state saved to: $STATE_DIR/"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
# ─── Dry-run: print the plan and stop here ──────────────────────────────────
if [ "$DRY_RUN" = "1" ]; then
    echo ""
    log "[dry-run] Detection, cross-checks and state backup are done. A real run would now:"
    if [ "$DEPLOY_MODE" = "encrypt" ]; then
        if fs_can_shrink "$ORIG_FSTYPE"; then
            echo "  1. shrink the $ORIG_FSTYPE filesystem on $TARGET_ROOT by ${SHRINK_MB}M  (skipped if already shrunk)"
        else
            echo "  1. (no shrink: $ORIG_FSTYPE already has ${SHRINK_MB}M+ of slack)"
        fi
        echo "  2. cryptsetup reencrypt --encrypt --type luks2 \\"
        echo "         --cipher aes-xts-plain64 --key-size 512 \\"
        echo "         --pbkdf argon2id --pbkdf-memory $LUKS_PBKDF_MEMORY \\"
        echo "         --pbkdf-parallel $LUKS_PBKDF_PARALLEL --pbkdf-force-iterations $LUKS_PBKDF_ITER \\"
        echo "         --hash sha512 --reduce-device-size ${SHRINK_MB}M --resilience checksum $TARGET_ROOT"
    else
        echo "  1-2. (config-only: no shrink, no encryption)"
    fi
    echo "  3. open the container as /dev/mapper/${LUKS_NAME}; verify inner $ORIG_FSTYPE UUID"
    if [ "$SYSTEM_MODE" -eq 1 ]; then
        echo "  4. grow the filesystem to fill the container; mount the target (+boot/EFI) and bind-mount for chroot"
        echo "  5. offer a recovery keyslot; back up the LUKS header to /boot + $STATE_DIR/"
        echo "  6. edit on the target: /etc/crypttab, /etc/fstab, and whichever of"
        echo "     /etc/default/grub (+ grub.d drop-ins), /etc/kernel/cmdline, cmdline.d,"
        echo "     /etc/mkinitcpio.conf, cmdline.txt, extlinux.conf, systemd-boot entries,"
        echo "     refind_linux.conf, limine.conf the target actually uses (originals"
        echo "     saved as *.pre-luks); root=PARTUUID=/root=/dev/... become the mapper"
        if [ "${LUKS_KEEP_SPLASH:-0}" != "1" ]; then
            echo "     and strip 'rhgb quiet splash' so the passphrase prompt is visible"
            echo "     (post-encryption-setup.sh restores them; LUKS_KEEP_SPLASH=1 to skip)"
        fi
        echo "  7. in chroot: rebuild ALL initramfs images (dracut/mkinitcpio/initramfs-tools),"
        echo "     update BLS entries / GRUB config (never the ESP stub), restorecon if SELinux"
        if [ "$UKI_ACTIVE" -eq 1 ]; then
            echo "  7f. rebuild ${#UKI_FOUND[@]} Unified Kernel Image(s) with ${UKI_REGEN}"
            echo "      (AFTER the splash strip, so the final cmdline is what gets baked in)"
            if [ "${UKI_SIGN:-none}" != "none" ]; then
                echo "  7g. sign the rebuilt .efi with ${UKI_SIGN}${UKI_SB_KEY:+ ($UKI_SB_KEY)}"
            else
                echo "  7g. (no signing backend; Secure Boot is ${UKI_SB_STATE})"
            fi
        fi
        echo "  8. run the verification gate; refuse the reboot message on any error"
        [ "$UKI_ACTIVE" -eq 1 ] && echo "      including V11 (.cmdline of every UKI) and V12 (its signature)"
    else
        echo "  4. grow the filesystem to fill the container"
        echo "  5. offer a recovery keyslot; back up the LUKS header to $STATE_DIR/"
        echo "  6-8. (data partition: no boot configuration, reduced verification)"
    fi
    echo ""
    log "[dry-run] No changes were made to the target. Backups/plan artifacts: $STATE_DIR/"
    exit 0
fi

if [ "$DEPLOY_MODE" = "config-only" ]; then
    read -p "Type 'CONFIGURE' to redo the configuration phase: " CONFIRM
    [ "$CONFIRM" = "CONFIGURE" ] || fatal "Aborted."
else
    read -p "Type 'ENCRYPT' to begin — there is no going back: " CONFIRM
    [ "$CONFIRM" = "ENCRYPT" ] || fatal "Aborted."
fi

log "Starting LUKS deployment. Pre-encryption $ORIG_FSTYPE UUID: $ORIG_FS_UUID"

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 1: Shrink the filesystem
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
if [ "$DEPLOY_MODE" = "config-only" ]; then
    log "[1/8] Skipped (config-only mode) — filesystem shrink not needed."
elif ! fs_can_shrink "$ORIG_FSTYPE"; then
    log "[1/8] Skipped ($ORIG_FSTYPE cannot shrink — pre-existing slack verified earlier)."
else
    log "[1/8] Shrinking $ORIG_FSTYPE filesystem by ${SHRINK_MB}M for the LUKS2 header..."

    # Idempotency: if a previous interrupted run already shrank the fs, don't
    # shrink again (each retry would silently eat another 32M until the final
    # grow). The gap is measured offline via the filesystem's own size probe.
    DEV_BYTES=$(blockdev --getsize64 "$TARGET_ROOT" 2>/dev/null || echo 0)
    FS_BYTES=$(fs_bytes "$TARGET_ROOT" "$ORIG_FSTYPE")
    SKIP_SHRINK=0
    if [ -n "$FS_BYTES" ] && [ "$DEV_BYTES" -gt 0 ] \
       && [ $(( DEV_BYTES - FS_BYTES )) -ge "$SHRINK_BYTES" ]; then
        log "  Filesystem is already >= ${SHRINK_MB}M smaller than the partition (fs=$FS_BYTES, dev=$DEV_BYTES) — skipping shrink."
        SKIP_SHRINK=1
    elif [ -z "$FS_BYTES" ]; then
        # f2fs/vfat cannot be probed offline; the only witness to a previous
        # shrink is the operator. Shrinking twice wastes 32M but loses nothing.
        warn "  Cannot probe the $ORIG_FSTYPE size to verify whether a previous run"
        warn "  already shrank it. If this is a RE-RUN after an interruption and the"
        warn "  shrink step had completed, answer yes."
        read -p "  Was this filesystem already shrunk by a previous run? (yes/NO): " PREV_SHRUNK
        [ "$PREV_SHRUNK" = "yes" ] && SKIP_SHRINK=1
    fi

    if [ "$SKIP_SHRINK" != "1" ]; then
        fs_shrink "$TARGET_ROOT" "$ORIG_FSTYPE"
        sync
        log "  $ORIG_FSTYPE shrink complete."
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 2: In-Place LUKS2 Encryption
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
if [ "$DEPLOY_MODE" = "config-only" ]; then
    log "[2/8] Skipped (config-only mode) — partition is already encrypted."
else
    log "[2/8] Encrypting partition with LUKS2..."
    log "  KDF pinned: argon2id  mem=$(( LUKS_PBKDF_MEMORY / 1024 )) MiB (${LUKS_PBKDF_MEMORY} KiB)  time-cost(iters)=${LUKS_PBKDF_ITER}  parallel=${LUKS_PBKDF_PARALLEL}"
    log "  Hash: sha512  (AF splitter + LUKS2 volume-key digest; --hash sets both)"
    log "  Cipher: aes-xts-plain64  key-size=512 (AES-256-XTS)"
    log "  You will be prompted to set a passphrase (type it twice)."
    log "  If interrupted, just re-run this script — it resumes automatically."
    echo ""

    # ── Caps Lock gate ──────────────────────────────────────────────────────
    # cryptsetup's next two prompts are, in this order:
    #     Are you sure? (Type 'yes' in capital letters):
    #     Enter passphrase for /dev/...:
    # Reaching for Caps Lock to type that YES is the natural thing to do, and it
    # stays on for the passphrase one prompt later. cryptsetup asks for the
    # passphrase twice, but both entries are inverted the same way, so its
    # type-it-twice check passes and the mistake only surfaces at the boot
    # prompt — Caps Lock off, nothing works, and the volume holds the only copy
    # of the data.
    #
    # So the last thing typed before cryptsetup runs is a LOWER CASE word. It
    # cannot be entered with Caps Lock on, which makes accepting it the proof:
    # no keyboard LED reading (unreliable over Bluetooth, absent on many
    # laptops), and no warning issued minutes before the keystroke it is about.
    if [ -z "${LUKS_PASSPHRASE_FILE:-}" ]; then
        warn "  cryptsetup will now ask you to type YES in capital letters, and"
        warn "  then for the passphrase this machine will boot with."
        warn "  Hold SHIFT for that YES — do NOT use Caps Lock. Left on, it"
        warn "  inverts the passphrase both times, so the type-it-twice check"
        warn "  still passes and the boot prompt is where you would find out."
        CAPS_TRIES=0
        while :; do
            if ! read -p "  Type 'yes' in lower case to confirm Caps Lock is off: " CAPS_OK; then
                echo ""
                fatal "Aborted (no input)."
            fi
            [ "$CAPS_OK" = "yes" ] && break
            CAPS_TRIES=$((CAPS_TRIES + 1))
            if [ "$CAPS_TRIES" -ge 5 ]; then
                fatal "Aborted."
            fi
            if [ "$CAPS_OK" = "YES" ]; then
                warn "  That arrived as 'YES' — Caps Lock is ON. Turn it off and"
                warn "  type yes again in lower case."
            else
                warn "  Type yes (lower case) to continue, or Ctrl-C to abort."
            fi
        done
        echo ""
    fi

    # LUKS2 KDF pinned for fleet consistency — do NOT fall back to cryptsetup's
    # auto-benchmark defaults (they pick sha256 + variable, time-benchmarked memory).
    # --pbkdf-force-iterations REPLACES time benchmarking, so no --iter-time here.
    # Unlock at boot re-runs this KDF inside the initramfs, so LUKS_PBKDF_MEMORY KiB
    # must be allocatable there — the RAM-fit check before the summary enforced it.
    cryptsetup reencrypt \
        --encrypt \
        --type luks2 \
        --cipher aes-xts-plain64 \
        --key-size 512 \
        --pbkdf argon2id \
        --pbkdf-memory "$LUKS_PBKDF_MEMORY" \
        --pbkdf-parallel "$LUKS_PBKDF_PARALLEL" \
        --pbkdf-force-iterations "$LUKS_PBKDF_ITER" \
        --hash sha512 \
        --reduce-device-size ${SHRINK_MB}M \
        --resilience checksum \
        --verbose \
        "${CRYPT_PASS_ARGS[@]}" "${CRYPT_BATCH_ARGS[@]}" \
        "$TARGET_ROOT"

    log "  Encryption complete."
fi

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 3: Open & Verify LUKS Container
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
log "[3/8] Verifying LUKS header and opening container..."

log "  LUKS header (truncated):"
pretty_luks_dump "$TARGET_ROOT"
echo ""

LUKS_UUID=$(blkid -s UUID -o value "$TARGET_ROOT")
[ -n "$LUKS_UUID" ] || fatal "Cannot read LUKS UUID — header may be corrupt! Check: cryptsetup luksDump $TARGET_ROOT"
log "  LUKS UUID: $LUKS_UUID"

# Open the LUKS container (already open if we came in via config-only mode)
if [ -b /dev/mapper/${LUKS_NAME} ]; then
    log "  Container already open: /dev/mapper/${LUKS_NAME}"
else
    cryptsetup open "${CRYPT_PASS_ARGS[@]}" "$TARGET_ROOT" ${LUKS_NAME}
fi

# Verify mapper device exists
[ -b /dev/mapper/${LUKS_NAME} ] || fatal "/dev/mapper/${LUKS_NAME} does not exist after open!"
log "  Mapper device: /dev/mapper/${LUKS_NAME} OK"

# Verify the filesystem is intact inside LUKS
INNER_FSTYPE=$(blkid -s TYPE -o value /dev/mapper/${LUKS_NAME} 2>/dev/null || echo "")
INNER_UUID=$(blkid -s UUID -o value /dev/mapper/${LUKS_NAME} 2>/dev/null || echo "")
log "  Inner filesystem: type=$INNER_FSTYPE UUID=$INNER_UUID"

if [ "$INNER_FSTYPE" != "$ORIG_FSTYPE" ]; then
    fatal "Inner filesystem is '$INNER_FSTYPE', expected '$ORIG_FSTYPE'! Encryption may have corrupted data."
fi
if [ "$INNER_UUID" != "$ORIG_FS_UUID" ]; then
    err "Inner filesystem UUID changed! Was: $ORIG_FS_UUID, Now: $INNER_UUID"
    err "  This should NEVER happen — in-place encryption preserves the inner"
    err "  filesystem. It usually means the open mapper is backed by a DIFFERENT"
    err "  device than expected, or the filesystem was damaged. Continuing"
    err "  would write boot configuration for the wrong system."
    read -p "  Continue with UUID $INNER_UUID anyway? (Type 'UUID-CHANGED' to override): " UUID_OVERRIDE
    [ "$UUID_OVERRIDE" = "UUID-CHANGED" ] || fatal "Aborted — investigate before configuring anything."
    warn "  Override accepted — updating ORIG_FS_UUID to $INNER_UUID."
    ORIG_FS_UUID="$INNER_UUID"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 4: Grow the filesystem + Mount for Chroot
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
log "[4/8] Growing the filesystem to fill the LUKS container..."
fs_grow_max "/dev/mapper/${LUKS_NAME}" "$ORIG_FSTYPE"
log "  Filesystem grow complete."

if [ "$SYSTEM_MODE" -eq 0 ]; then
    log "  Data partition mode — no chroot mounts needed."
else
    # Mount with the correct subvolume (btrfs) or plainly (everything else)
    log "  Mounting filesystems for chroot..."
    if [ "$IS_BTRFS" -eq 1 ]; then
        if [ -n "$ROOT_SUBVOL" ]; then
            mount -o "subvol=$ROOT_SUBVOL" /dev/mapper/${LUKS_NAME} /mnt
        else
            mount -o subvolid=5 /dev/mapper/${LUKS_NAME} /mnt
        fi
    else
        mount /dev/mapper/${LUKS_NAME} /mnt
    fi

    # Verify we got the right filesystem root
    if [ ! -f /mnt/etc/fstab ]; then
        if [ "$IS_BTRFS" -eq 1 ]; then
            err "  /mnt/etc/fstab not found after mounting subvol=${ROOT_SUBVOL:-(top-level)}!"
            err "  Trying subvolid=5 (top-level) as fallback..."
            umount /mnt
            mount -o subvolid=5 /dev/mapper/${LUKS_NAME} /mnt
            if [ -n "$ROOT_SUBVOL" ] && [ -f "/mnt/${ROOT_SUBVOL}/etc/fstab" ]; then
                log "  Found fstab at /mnt/${ROOT_SUBVOL}/etc/fstab — remounting correctly..."
                umount /mnt
                mount -o "subvol=${ROOT_SUBVOL}" /dev/mapper/${LUKS_NAME} /mnt
            elif [ ! -f /mnt/etc/fstab ]; then
                fatal "Cannot find /etc/fstab in any mount configuration."
            fi
        else
            fatal "/mnt/etc/fstab not found — the filesystem no longer looks like a system root."
        fi
    fi

    # Mount home subvolume (btrfs, if separate from root)
    if [ "$IS_BTRFS" -eq 1 ] && [ -n "$HOME_SUBVOL" ] && [ "$HOME_SUBVOL" != "$ROOT_SUBVOL" ]; then
        mkdir -p /mnt/home
        mount -o "subvol=$HOME_SUBVOL" /dev/mapper/${LUKS_NAME} /mnt/home
    fi

    # Mount the boot/EFI/firmware partitions resolved from fstab, parents
    # before children (sorted by path depth).
    if [ "${#MNT_MPS[@]}" -gt 0 ]; then
        while IFS=$'\t' read -r mp dev; do
            [ -n "$mp" ] || continue
            mkdir -p "/mnt$mp"
            mount "$dev" "/mnt$mp"
            log "    mounted $dev → /mnt$mp"
        done < <(for i in "${!MNT_MPS[@]}"; do printf '%s\t%s\n' "${MNT_MPS[$i]}" "${MNT_DEVS[$i]}"; done | sort)
    fi

    # Bind-mount virtual filesystems for chroot
    for i in /dev /dev/pts /proc /sys /run; do
        mount --bind "$i" "/mnt$i"
    done
    if [ -d /sys/firmware/efi/efivars ] && [ -d /mnt/sys/firmware/efi/efivars ]; then
        mount --bind /sys/firmware/efi/efivars /mnt/sys/firmware/efi/efivars 2>/dev/null || true
    fi
    log "  All mounts complete."

    # An already-encrypted volume that GRUB itself opens (encrypted /boot) is
    # recognised here, with everything mounted. Its configuration is repaired
    # like any other; its GRUB image and KDF are never touched by this script.
    if [ "$DEPLOY_MODE" = "config-only" ]; then
        bt_grub_probe "$TARGET_ROOT" /mnt
        if [ "$BT_GRUB_UNLOCKS" -eq 1 ]; then
            echo ""
            warn "GRUB itself unlocks this volume at boot (encrypted /boot):"
            bt_grub_summary | sed 's/^/    /'
            warn "  Configuration is repaired as usual. Nothing here re-embeds the GRUB"
            warn "  image or changes the KDF — use luks-tune.sh for that, which applies"
            warn "  GRUB's 1 GiB argon2id ceiling and its ${BT_GRUB_KDF_FACTOR}x unlock-time factor."
        fi
    fi
fi

# ─── Target boot machinery detection (initramfs generator + bootloader) ──────
# Detected from what is INSTALLED ON THE TARGET, never from the live
# environment or the distro's name.
#
# systemd-boot is now detected properly (uki_detect_sdboot looks for the loader
# binary on the ESP) rather than inferred from /boot/loader/entries, which GRUB's
# own BLS support uses too. HAS_BLS still keys off that directory, because
# patching Type #1 entries is correct for both.
#
# UKIs are re-detected here against /mnt, where every target filesystem is
# mounted — the discovery pass ran against read-only probe mounts and could
# only see partitions it was handed. This pass is the authoritative one, and it
# is what steps 7f/7g and checks V11-V13 act on. See docs/BOOTLOADERS.md.
INITRAMFS_STYLE="none"
MKINITCPIO_SD=0
GRUB_UPDATE_TOOL=""
HAS_GRUBBY=0
HAS_BLS=0
RPI_CMDLINE=""
EXTLINUX_CONF=""
if [ "$SYSTEM_MODE" -eq 1 ]; then
    log "  Detecting the target's boot machinery..."
    if [ -x /mnt/usr/bin/dracut ] || [ -x /mnt/usr/sbin/dracut ]; then
        INITRAMFS_STYLE="dracut"
    elif [ -f /mnt/etc/mkinitcpio.conf ]; then
        INITRAMFS_STYLE="mkinitcpio"
        grep -Eq '^HOOKS=.*[( ]systemd[ )]' /mnt/etc/mkinitcpio.conf && MKINITCPIO_SD=1
    elif [ -x /mnt/usr/sbin/update-initramfs ] || [ -d /mnt/etc/initramfs-tools ]; then
        INITRAMFS_STYLE="initramfs-tools"
    fi
    [ "$INITRAMFS_STYLE" != "none" ] \
        || fatal "No initramfs generator (dracut/mkinitcpio/initramfs-tools) found on the target — cannot build an unlockable boot."

    if [ -x /mnt/usr/sbin/update-grub ] || [ -x /mnt/usr/bin/update-grub ]; then
        GRUB_UPDATE_TOOL="update-grub"
    elif chroot /mnt /bin/sh -c 'command -v grub2-mkconfig' >/dev/null 2>&1; then
        GRUB_UPDATE_TOOL="grub2-mkconfig"
    elif chroot /mnt /bin/sh -c 'command -v grub-mkconfig' >/dev/null 2>&1; then
        GRUB_UPDATE_TOOL="grub-mkconfig"
    fi
    chroot /mnt /bin/sh -c 'command -v grubby' >/dev/null 2>&1 && HAS_GRUBBY=1
    [ -d /mnt/boot/loader/entries ] && HAS_BLS=1
    for f in /mnt/boot/firmware/cmdline.txt /mnt/boot/cmdline.txt; do
        [ -f "$f" ] && RPI_CMDLINE="$f" && break
    done
    for f in /mnt/boot/extlinux/extlinux.conf /mnt/extlinux/extlinux.conf; do
        [ -f "$f" ] && EXTLINUX_CONF="$f" && break
    done

    # Authoritative UKI / systemd-boot pass, with everything mounted under /mnt.
    if [ "$LL_HAVE_UKI_LIB" -eq 1 ]; then
        uki_find_ukis     /mnt
        uki_detect_regen  /mnt || true
        uki_detect_signer /mnt || true
        uki_detect_sdboot /mnt || true
        [ "${#UKI_PATHS[@]}" -gt 0 ] && UKI_ACTIVE=1
    fi

    log "    initramfs : $INITRAMFS_STYLE$( [ "$MKINITCPIO_SD" -eq 1 ] && echo ' (systemd hooks)' )"
    log "    grub tool : ${GRUB_UPDATE_TOOL:-none}   grubby: $HAS_GRUBBY   BLS entries: $HAS_BLS"
    [ -n "$RPI_CMDLINE" ]  && log "    cmdline.txt : ${RPI_CMDLINE#/mnt} (Raspberry Pi-style boot)"
    [ -n "$EXTLINUX_CONF" ] && log "    extlinux    : ${EXTLINUX_CONF#/mnt}"
    [ "${UKI_SDBOOT:-0}" -eq 1 ] && log "    sd-boot   : ${UKI_SDBOOT_DETAIL}"
    if [ "$LL_HAVE_UKI_LIB" -eq 1 ] && [ "${#UKI_PATHS[@]}" -gt 0 ]; then
        log "    UKI       : ${#UKI_PATHS[@]} image(s), rebuild=${UKI_REGEN} sign=${UKI_SIGN} secureboot=${UKI_SB_STATE}"
    fi

    if [ "$GRUB_UPDATE_TOOL" = "" ] && [ "$HAS_BLS" -eq 0 ] && [ -z "$RPI_CMDLINE" ] \
       && [ -z "$EXTLINUX_CONF" ] && [ "$UKI_ACTIVE" -eq 0 ]; then
        # No GRUB, no BLS entries, no cmdline.txt, no extlinux — and no UKI to
        # rebuild either. Nothing here knows how this machine gets its kernel
        # arguments, so say so rather than reporting a silent success.
        warn "  No recognised bootloader config (GRUB / BLS / UKI / cmdline.txt / extlinux)."
        warn "  crypttab, fstab and the initramfs will still be configured, but you"
        warn "  must add the kernel arguments to your bootloader yourself."
        warn "  systemd-boot / UKI targets: see docs/BOOTLOADERS.md."
    fi
fi

# The kernel arguments that make the initramfs unlock the volume — they differ
# by initramfs generator:
#   dracut               rd.luks.uuid + rd.luks.name (systemd-cryptsetup)
#   mkinitcpio (systemd) rd.luks.name (sd-encrypt hook)
#   mkinitcpio (busybox) cryptdevice=UUID=..:name (encrypt hook)
#   initramfs-tools      none — it reads /etc/crypttab (entries marked
#                        'initramfs') and finds the root device on its own
LUKS_BOOT_ARGS=""
case "$INITRAMFS_STYLE" in
    dracut)
        LUKS_BOOT_ARGS="rd.luks.uuid=$LUKS_UUID rd.luks.name=${LUKS_UUID}=$LUKS_NAME" ;;
    mkinitcpio)
        if [ "$MKINITCPIO_SD" -eq 1 ]; then
            LUKS_BOOT_ARGS="rd.luks.name=${LUKS_UUID}=$LUKS_NAME"
        else
            LUKS_BOOT_ARGS="cryptdevice=UUID=${LUKS_UUID}:$LUKS_NAME"
        fi ;;
    initramfs-tools)
        LUKS_BOOT_ARGS="" ;;
esac
[ "$SYSTEM_MODE" -eq 1 ] && log "  Kernel LUKS arguments: ${LUKS_BOOT_ARGS:-'(none needed — crypttab-driven)'}"

# Configure the command-line carrier layer (lib-boot.sh) for this target.
# root=/resume= values that name the RAW partition — PARTUUID=, a device path
# — must become the mapper; UUID=<inner fs uuid> is still correct and stays.
CL_TARGET_PARTUUID=$(blkid -s PARTUUID -o value "$TARGET_ROOT" 2>/dev/null || echo "")
# (each is read by the lib-boot.sh functions, not here)
# shellcheck disable=SC2034
CL_MAPPER="$LUKS_NAME"
# shellcheck disable=SC2034
CL_LUKS_ARGS="$LUKS_BOOT_ARGS"
# shellcheck disable=SC2034
CL_TARGET_REAL="$TARGET_ROOT_REAL"
# shellcheck disable=SC2034
CL_LUKS_UUID="$LUKS_UUID"
# shellcheck disable=SC2034
CL_FS_UUID="$ORIG_FS_UUID"

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 5: Recovery Key + LUKS Header Backup
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
log "[5/8] Recovery key + LUKS header backup..."

# ─── 5a: Optional recovery key (second keyslot) ─────────────────────────────
# A random 256-bit key in its own keyslot: if the passphrase is ever forgotten,
# this key still unlocks the volume. Enrolled BEFORE the header backup below so
# the backup contains the new slot. Saved to the deployment drive — the user
# must move it to secure OFFLINE storage afterwards.
# Non-interactive: LUKS_RECOVERY_KEY=yes|no
SLOTS_IN_USE=$(cryptsetup luksDump "$TARGET_ROOT" 2>/dev/null | grep -cE '^[[:space:]]+[0-9]+: luks2' || true)
RK_CHOICE="${LUKS_RECOVERY_KEY:-}"

# Default the prompt to NO on a configuration-only re-run. Each acceptance
# enrols another keyslot, so someone who re-runs the config phase a few times
# and keeps hitting Enter ends up with a header full of recovery keys they
# cannot tell apart. A fresh encrypt still defaults to yes: that is the run
# where there is no recovery key yet, and no way back if the passphrase is lost.
RK_DEFAULT="yes"
[ "$DEPLOY_MODE" = "config-only" ] && RK_DEFAULT="no"

if [ -z "$RK_CHOICE" ]; then
    echo ""
    echo "  A recovery key is a random 64-hex-character key in a second LUKS"
    echo "  keyslot. It unlocks the volume if the passphrase is ever forgotten."
    echo "  It will be written to $STATE_DIR/ — move it to secure offline"
    echo "  storage (NOT this machine) once deployment is done."
    if [ "${SLOTS_IN_USE:-0}" -gt 1 ]; then
        warn "  Note: $SLOTS_IN_USE keyslots are already in use — a recovery key may already be enrolled."
    fi
    if [ "$RK_DEFAULT" = "no" ]; then
        warn "  This is a configuration-only re-run: saying yes adds ANOTHER"
        warn "  keyslot on top of what is already there. Defaulting to no."
        read -p "  Generate and enroll a recovery key now? [y/N]: " RK_CHOICE
    else
        read -p "  Generate and enroll a recovery key now? [Y/n]: " RK_CHOICE
    fi
    # A bare Enter takes the default rather than falling through to "enrol".
    RK_CHOICE="${RK_CHOICE:-$RK_DEFAULT}"
fi
case "$RK_CHOICE" in
    [Nn]|[Nn][Oo])
        warn "  Skipping recovery key (passphrase will be the only way in)."
        ;;
    *)
        RK_FILE="$STATE_DIR/recovery-key.txt"
        # 32 random bytes as 64 hex chars: unambiguous to read back and type.
        RECOVERY_KEY=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')
        if [ "${#RECOVERY_KEY}" -ne 64 ]; then
            warn "  Could not generate a recovery key (urandom read failed?) — skipping."
        else
            # No trailing newline: the file must byte-match what a human would
            # later TYPE at a passphrase prompt.
            install -m 600 /dev/null "$RK_FILE"
            printf '%s' "$RECOVERY_KEY" > "$RK_FILE"
            harden_path 0600 "$RK_FILE"
            # The slot gets the CURRENT LUKS_PBKDF_* parameters. In config-only
            # mode these are the moderate defaults (or env), not necessarily
            # what the header's other slots use — cryptographically irrelevant
            # for a random 256-bit key, but say so rather than surprise a
            # later luksDump audit.
            log "  Enrolling recovery key (enter the volume passphrase when asked)..."
            log "  Recovery keyslot KDF: argon2id $((LUKS_PBKDF_MEMORY / 1024)) MiB x ${LUKS_PBKDF_ITER} (current profile — other slots may differ)"
            # --hash sha512: a new keyslot gets its own AF hash, and without an
            # explicit value cryptsetup stamps its compiled-in sha256 — the
            # same silent downgrade luks-tune.sh had, verified on cryptsetup 2.8.
            if cryptsetup luksAddKey "${CRYPT_PASS_ARGS[@]}" "$TARGET_ROOT" "$RK_FILE" \
                   --hash sha512 \
                   --pbkdf argon2id \
                   --pbkdf-memory "$LUKS_PBKDF_MEMORY" \
                   --pbkdf-parallel "$LUKS_PBKDF_PARALLEL" \
                   --pbkdf-force-iterations "$LUKS_PBKDF_ITER"; then
                # Keep the keyfile PURE (usable as-is with --key-file); the
                # instructions live in a sibling README instead.
                cat > "$STATE_DIR/recovery-key-README.txt" <<RK_EOF
LUKS recovery key for $TARGET_ROOT (UUID=$LUKS_UUID), enrolled $(date '+%Y-%m-%d %H:%M').

The key is the 64 hex characters in recovery-key.txt (exactly, no trailing
newline). Two ways to use it if the passphrase is ever lost:
  - Type/paste it at the boot passphrase prompt, or
  - From a live USB:
      cryptsetup open $TARGET_ROOT ${LUKS_NAME} --key-file recovery-key.txt

MOVE BOTH FILES TO SECURE OFFLINE STORAGE — anyone holding the key can
unlock the disk.
RK_EOF
                harden_path 0600 "$STATE_DIR/recovery-key-README.txt"
                log "  Recovery key enrolled. Saved to: $RK_FILE"
            else
                rm -f "$RK_FILE"
                warn "  Recovery key enrollment FAILED (wrong passphrase?) — continuing without it."
                warn "  You can enroll one later: cryptsetup luksAddKey $TARGET_ROOT"
            fi
        fi
        ;;
esac

# ─── 5b: LUKS header backup ─────────────────────────────────────────────────
# To the deployment drive always; to the target's /boot too when there is a
# system to hold it. luksHeaderBackup refuses to overwrite; drop any stale
# copy from a previous run first (the current header is authoritative).
HDR_TMP="$STATE_DIR/luks-header-backup.img"
rm -f "$HDR_TMP"
# umask 077 in a subshell: luksHeaderBackup creates the file itself and refuses
# to overwrite, so the mode must be right at creation rather than fixed after.
( umask 077; cryptsetup luksHeaderBackup "$TARGET_ROOT" --header-backup-file "$HDR_TMP" )
harden_path 0400 "$HDR_TMP"
log "  Header backup: $HDR_TMP (deployment drive)"
if [ "$SYSTEM_MODE" -eq 1 ]; then
    # install(1) rather than cp(1): cp creates the destination at 0666 & ~umask
    # -- 0644 by default -- so the header would sit world-readable for the
    # length of the copy and stay that way if the chmod that follows is a
    # no-op. install sets the mode as it creates the file.
    rm -f /mnt/boot/luks-header-backup.img
    install -m 0400 "$HDR_TMP" /mnt/boot/luks-header-backup.img
    harden_path 0400 /mnt/boot/luks-header-backup.img
    log "  Header backup: /boot/luks-header-backup.img (on target)"
fi

# ─── Data partition mode: no boot configuration — verify and finish here ─────
if [ "$SYSTEM_MODE" -eq 0 ]; then
    echo ""
    log "[6-7/8] Skipped — data partition mode has no boot configuration."
    echo ""
    log "[8/8] Verification (data partition)..."
    ERRORS=0
    if [ -b /dev/mapper/${LUKS_NAME} ]; then
        log "  V1 OK: /dev/mapper/${LUKS_NAME} is active"
    else
        err "  V1 FAIL: /dev/mapper/${LUKS_NAME} not found!"; ERRORS=$((ERRORS + 1))
    fi
    if [ "$(blkid -s TYPE -o value /dev/mapper/${LUKS_NAME} 2>/dev/null)" = "$ORIG_FSTYPE" ]; then
        log "  V2 OK: inner filesystem is $ORIG_FSTYPE"
    else
        err "  V2 FAIL: inner filesystem unreadable!"; ERRORS=$((ERRORS + 1))
    fi
    if [ -f "$HDR_TMP" ]; then
        log "  V3 OK: LUKS header backup on deployment drive"
    else
        err "  V3 FAIL: header backup missing!"; ERRORS=$((ERRORS + 1))
    fi
    [ "$ERRORS" -eq 0 ] || fatal "Verification failed with $ERRORS error(s). See log: $DEPLOY_LOG"
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║  Data partition encrypted and verified.                   ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  Unlock manually:   cryptsetup open $TARGET_ROOT ${LUKS_NAME}"
    echo "  Auto-unlock: add to the mounting system's /etc/crypttab:"
    echo "      ${LUKS_NAME} UUID=$LUKS_UUID none luks,discard,nofail"
    echo "  and point its fstab at /dev/mapper/${LUKS_NAME}."
    if [ -f "$STATE_DIR/recovery-key.txt" ]; then
        echo "  Recovery key: $STATE_DIR/recovery-key.txt  ← MOVE TO SECURE OFFLINE STORAGE"
    fi
    echo "  Header backup: $HDR_TMP"
    echo ""
    exit 0
fi

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 6: Update System Configuration
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
log "[6/8] Updating system configuration..."

# Nothing in this stage aborts the run. Once the volume is encrypted, dying
# half-way through the configuration leaves the operator with a machine whose
# state has to be reconstructed from a log; finishing every step and letting
# the verification gate list what is wrong does not. Each problem here is
# recorded, echoed, and counted into the gate's total.
CONFIG_ERRORS=0
cfg_fail() { err "$@"; CONFIG_ERRORS=$((CONFIG_ERRORS + 1)); }

# ─── 6a: crypttab ────────────────────────────────────────────────────────────
# initramfs-tools only includes crypttab entries carrying the 'initramfs'
# option (or ones it can prove are needed for the root — be explicit instead
# of trusting that inference). dracut/systemd ignore unknown options, but the
# flag is only written where it means something.
CRYPTTAB_OPTS="luks,discard"
[ "$INITRAMFS_STYLE" = "initramfs-tools" ] && CRYPTTAB_OPTS="luks,discard,initramfs"
if [ ! -f /mnt/etc/crypttab ]; then
    echo "# /etc/crypttab — LUKS encrypted devices" > /mnt/etc/crypttab
    log "  Created /etc/crypttab"
fi
if grep -q "$LUKS_NAME" /mnt/etc/crypttab 2>/dev/null; then
    warn "  $LUKS_NAME already in crypttab — updating."
    sed -i "/^${LUKS_NAME}[[:space:]]/d" /mnt/etc/crypttab
fi
echo "$LUKS_NAME UUID=$LUKS_UUID none $CRYPTTAB_OPTS" >> /mnt/etc/crypttab
log "  crypttab: added $LUKS_NAME UUID=$LUKS_UUID ($CRYPTTAB_OPTS)"
echo "  --- /etc/crypttab ---"
cat /mnt/etc/crypttab

# ─── 6b: fstab ───────────────────────────────────────────────────────────────
cp /mnt/etc/fstab /mnt/etc/fstab.pre-luks
log "  fstab backed up to fstab.pre-luks"

# The root may be referenced by UUID= (most distros), PARTUUID= (Raspberry Pi
# OS), or a direct device path. All become /dev/mapper/$LUKS_NAME.
ORIG_PARTUUID=$(blkid -s PARTUUID -o value "$TARGET_ROOT" 2>/dev/null || echo "")
if grep -q "UUID=$ORIG_FS_UUID" /mnt/etc/fstab; then
    sed -i "s|UUID=$ORIG_FS_UUID|/dev/mapper/$LUKS_NAME|g" /mnt/etc/fstab
    log "  fstab: UUID=$ORIG_FS_UUID → /dev/mapper/$LUKS_NAME"
elif [ -n "$ORIG_PARTUUID" ] && grep -q "PARTUUID=$ORIG_PARTUUID" /mnt/etc/fstab; then
    sed -i "s|PARTUUID=$ORIG_PARTUUID|/dev/mapper/$LUKS_NAME|g" /mnt/etc/fstab
    log "  fstab: PARTUUID=$ORIG_PARTUUID → /dev/mapper/$LUKS_NAME"
elif grep -Eq "^[^#]*[[:space:]]/[[:space:]].*$(basename "$TARGET_ROOT")" /mnt/etc/fstab; then
    sed -i "s|^[^#]*$(basename "$TARGET_ROOT")\([[:space:]]\+/[[:space:]]\)|/dev/mapper/$LUKS_NAME\1|" /mnt/etc/fstab
    log "  fstab: $TARGET_ROOT → /dev/mapper/$LUKS_NAME (device-path entry)"
elif grep -q "/dev/mapper/$LUKS_NAME" /mnt/etc/fstab; then
    log "  fstab already references /dev/mapper/$LUKS_NAME (previous run) — keeping."
else
    warn "  Neither UUID=$ORIG_FS_UUID nor PARTUUID found in fstab!"
    echo "  Current root-looking entries:"
    grep -E "^[^#].*[[:space:]]/[[:space:]]" /mnt/etc/fstab || echo "  (none)"
    cfg_fail "  fstab update failed — cannot find the original root entry (V2 will report it)."
fi

# Verify fstab was updated correctly
if ! grep -q "$LUKS_NAME" /mnt/etc/fstab; then
    cfg_fail "  fstab does not reference $LUKS_NAME after update!"
fi
if grep -q "UUID=$ORIG_FS_UUID" /mnt/etc/fstab; then
    cfg_fail "  fstab still contains old UUID=$ORIG_FS_UUID after replacement!"
fi
echo "  --- /etc/fstab ---"
cat /mnt/etc/fstab

# ─── 6c: /etc/default/grub ───────────────────────────────────────────────────
# Rewrite every definition of $1 in /mnt/etc/default/grub to the literal value
# $2. The rewrite goes through awk/ENVIRON rather than sed so that an & or a |
# in the existing command line cannot corrupt the replacement text.
grub_cmdline_set() {
    local _gv="$1" _nv="$2" _tmp="/mnt/etc/default/.grub.$$"
    GV="$_gv" NV="$_nv" awk '
        BEGIN { v = ENVIRON["GV"]; nv = ENVIRON["NV"] }
        $0 ~ "^[[:space:]]*" v "=" { print v "=\"" nv "\""; next }
        { print }
    ' /mnt/etc/default/grub > "$_tmp" || { rm -f "$_tmp"; return 1; }
    # cat, not mv: keeps the inode, mode, owner and SELinux label intact.
    cat "$_tmp" > /mnt/etc/default/grub
    rm -f "$_tmp"
}

if [ -f /mnt/etc/default/grub ]; then
    log "  Updating /etc/default/grub..."
    cp /mnt/etc/default/grub /mnt/etc/default/grub.pre-luks

    # GRUB_ENABLE_CRYPTODISK is deliberately NOT written. It only matters when
    # GRUB itself has to open a LUKS volume to reach /boot, and LinuxLocker
    # never produces that layout (a /boot inside the volume is refused above).
    # A target that already has it — an existing encrypted /boot in
    # config-only mode — keeps it untouched.

    # WHICH variable carries the kernel command line is distro-dependent, so
    # never assume GRUB_CMDLINE_LINUX is present:
    #   * Fedora / RHEL        ship GRUB_CMDLINE_LINUX
    #   * Debian / Arch        ship both (GRUB_CMDLINE_LINUX often empty)
    #   * Fedora Asahi Remix   ships GRUB_CMDLINE_LINUX_DEFAULT and NO
    #                          GRUB_CMDLINE_LINUX line at all
    # We write GRUB_CMDLINE_LINUX specifically: grub-mkconfig applies it to
    # every generated entry including the recovery ones, whereas _DEFAULT is
    # deliberately left off those — and an unlock argument the recovery entry
    # lacks is an unbootable rescue path. If the file defines neither, add it.
    #
    # This used to read the value with a bare `grep "^GRUB_CMDLINE_LINUX="`
    # inside a command substitution. Under `set -o pipefail` a file without
    # that line made grep return 1, which aborted stage 6 with no message at
    # all — the run just stopped and hit the EXIT trap.
    if [ -n "$LUKS_BOOT_ARGS" ]; then
        if grep -E "^[[:space:]]*GRUB_CMDLINE_LINUX=" /mnt/etc/default/grub \
             | grep -qF "$LUKS_BOOT_ARGS"; then
            log "    GRUB_CMDLINE_LINUX already carries the LUKS arguments — keeping."
        elif grep -qE "^[[:space:]]*GRUB_CMDLINE_LINUX=" /mnt/etc/default/grub; then
            # Last definition wins when the shell sources this file, so that is
            # the one whose value we preserve.
            CURRENT_CMDLINE=$(sed -n -E "s|^[[:space:]]*GRUB_CMDLINE_LINUX=(.*)\$|\1|p" \
                /mnt/etc/default/grub | tail -n1)
            case "$CURRENT_CMDLINE" in
                \"*\") CURRENT_CMDLINE=${CURRENT_CMDLINE#\"}; CURRENT_CMDLINE=${CURRENT_CMDLINE%\"} ;;
                \'*\') CURRENT_CMDLINE=${CURRENT_CMDLINE#\'}; CURRENT_CMDLINE=${CURRENT_CMDLINE%\'} ;;
            esac
            if grub_cmdline_set GRUB_CMDLINE_LINUX \
                "$LUKS_BOOT_ARGS${CURRENT_CMDLINE:+ $CURRENT_CMDLINE}"; then
                log "    Added $LUKS_BOOT_ARGS to GRUB_CMDLINE_LINUX"
            else
                cfg_fail "  Could not rewrite GRUB_CMDLINE_LINUX in /etc/default/grub (V3 will report it)."
            fi
        else
            warn "  No GRUB_CMDLINE_LINUX line in /etc/default/grub — adding one."
            echo "GRUB_CMDLINE_LINUX=\"$LUKS_BOOT_ARGS\"" >> /mnt/etc/default/grub
            log "    Added $LUKS_BOOT_ARGS to GRUB_CMDLINE_LINUX"
        fi

        # The unlock arguments must actually be on disk now.
        if ! grep -qF "$LUKS_BOOT_ARGS" /mnt/etc/default/grub; then
            cfg_fail "  /etc/default/grub still has no '$LUKS_BOOT_ARGS' after update!"
        fi
    else
        log "    ($INITRAMFS_STYLE needs no kernel LUKS arguments — crypttab drives the unlock)"
    fi

    # A root= or resume= inside GRUB_CMDLINE_LINUX that names the raw partition
    # (PARTUUID=, /dev/...) must become the mapper. Arguments were added above.
    CL_ADD_ARGS=0 cl_patch_file grubvar /mnt/etc/default/grub 'GRUB_CMDLINE_LINUX' || true
    [ "$CL_CHANGED" -eq 1 ] && log "    Rewrote a root=/resume= in GRUB_CMDLINE_LINUX to the mapper"

    # /etc/default/grub.d/*.cfg: grub-mkconfig sources these AFTER the main
    # file, so a drop-in that defines GRUB_CMDLINE_LINUX silently replaces what
    # was just written (Ubuntu ships several). Patch every such drop-in too.
    for gd in /mnt/etc/default/grub.d/*.cfg; do
        [ -f "$gd" ] || continue
        cl_grub_var_defined "$gd" GRUB_CMDLINE_LINUX || continue
        [ -f "$gd.pre-luks" ] || cp "$gd" "$gd.pre-luks"
        if cl_patch_file grubvar "$gd" 'GRUB_CMDLINE_LINUX'; then
            log "    ${gd#/mnt}: GRUB_CMDLINE_LINUX drop-in updated"
        else
            cfg_fail "  Could not rewrite GRUB_CMDLINE_LINUX in ${gd#/mnt} (V3 will report it)."
        fi
    done

    # GRUB_FORCE_PARTUUID (Ubuntu cloud images, /etc/default/grub.d/40-force-partuuid.cfg)
    # makes grub-mkconfig write root=PARTUUID=<raw partition> and try an
    # initrd-less boot first. Both point straight past the mapper. Disable it.
    for gd in /mnt/etc/default/grub /mnt/etc/default/grub.d/*.cfg; do
        [ -f "$gd" ] || continue
        grep -qE '^[[:space:]]*GRUB_FORCE_PARTUUID=' "$gd" || continue
        [ -f "$gd.pre-luks" ] || cp "$gd" "$gd.pre-luks"
        sed -i -E 's|^([[:space:]]*GRUB_FORCE_PARTUUID=)|# LinuxLocker: disabled, root is a LUKS mapper now — \1|' "$gd"
        warn "    ${gd#/mnt}: GRUB_FORCE_PARTUUID disabled (it would boot root=PARTUUID past the mapper)"
    done

    # Do not leave this stage unless the value grub-mkconfig will actually use
    # — after every drop-in — carries the unlock arguments.
    if [ -n "$LUKS_BOOT_ARGS" ]; then
        GRUB_EFFECTIVE=$(cl_grub_effective /mnt GRUB_CMDLINE_LINUX || true)
        if ! cl_has_all_args "$GRUB_EFFECTIVE"; then
            cfg_fail "  Effective GRUB_CMDLINE_LINUX (after /etc/default/grub.d/*.cfg) lacks the LUKS arguments: '$GRUB_EFFECTIVE'"
            err "  A drop-in in /etc/default/grub.d overrides them — the gate will refuse the reboot until it is fixed."
        fi
    fi

    # Hand-written menu entries carry their own root= and are never regenerated.
    for gc in /mnt/etc/grub.d/40_custom /mnt/boot/grub2/custom.cfg /mnt/boot/grub/custom.cfg; do
        [ -f "$gc" ] || continue
        if grep -qE '^[[:space:]]*(linux|linuxefi)[[:space:]]' "$gc"; then
            if grep -E '^[[:space:]]*(linux|linuxefi)[[:space:]]' "$gc" \
                 | grep -qE "PARTUUID=${CL_TARGET_PARTUUID:-__none__}|$(basename "$TARGET_ROOT")|UUID=$ORIG_FS_UUID"; then
                warn "    ${gc#/mnt} has a hand-written 'linux' line naming this partition —"
                warn "    it is not regenerated; edit its root= and add '${LUKS_BOOT_ARGS:-(nothing)}' yourself."
            fi
        fi
    done

    echo "  --- /etc/default/grub ---"
    cat /mnt/etc/default/grub
else
    log "  No /etc/default/grub on target (not a GRUB system) — skipping."
fi

# ─── 6d: /etc/kernel/cmdline and /etc/cmdline.d ─────────────────────────────
# /etc/kernel/cmdline is what kernel-install, dracut --uki-file, ukify and
# mkinitcpio bake into new boot entries and UKIs. mkinitcpio ALSO concatenates
# /etc/cmdline.d/*.conf after it. And every one of those tools falls back to
# /proc/cmdline when neither exists — which, from a chroot on a live USB, is
# the LIVE USB's command line. So on a UKI target the file must exist before
# step 7f rebuilds anything.
CMDLINE_D_HAS_CONFS=0
for cd_conf in /mnt/etc/cmdline.d/*.conf; do
    [ -f "$cd_conf" ] && CMDLINE_D_HAS_CONFS=1 && break
done

# Only the targets whose tooling reads this file get one created: UKI
# targets (every rebuild backend reads it) and dracut + BLS (kernel-install
# copies it into new entries). A systemd-boot Type #1 box that never had it
# keeps not having it — its entries are patched directly in stage 6h.
NEEDS_KERNEL_CMDLINE=0
if [ "$UKI_ACTIVE" -eq 1 ] || { [ "$INITRAMFS_STYLE" = "dracut" ] && [ "$HAS_BLS" -eq 1 ]; }; then
    NEEDS_KERNEL_CMDLINE=1
fi
if [ ! -f /mnt/etc/kernel/cmdline ] && [ "$CMDLINE_D_HAS_CONFS" -eq 0 ] && [ "$NEEDS_KERNEL_CMDLINE" -eq 1 ]; then
    SEED_CMDLINE=""
    if [ "$UKI_ACTIVE" -eq 1 ] && [ "$LL_HAVE_UKI_LIB" -eq 1 ] && [ "${#UKI_PATHS[@]}" -gt 0 ]; then
        # The line the machine actually boots with today, out of its UKI.
        SEED_CMDLINE=$(uki_cmdline_of "${UKI_PATHS[0]}" 2>/dev/null || true)
        [ -n "$SEED_CMDLINE" ] && log "  Seeding /etc/kernel/cmdline from $(basename "${UKI_PATHS[0]}")'s .cmdline"
    fi
    if [ -z "$SEED_CMDLINE" ]; then
        for bls_seed in /mnt/boot/loader/entries/*.conf /mnt/efi/loader/entries/*.conf /mnt/boot/efi/loader/entries/*.conf; do
            [ -f "$bls_seed" ] || continue
            basename "$bls_seed" | grep -q rescue && continue
            SEED_CMDLINE=$(sed -n 's/^options[[:space:]]\+//p' "$bls_seed" | head -1)
            [ -n "$SEED_CMDLINE" ] && { log "  Seeding /etc/kernel/cmdline from $(basename "$bls_seed")"; break; }
        done
    fi
    if [ -z "$SEED_CMDLINE" ]; then
        ROOTFLAGS=""
        [ "$IS_BTRFS" -eq 1 ] && [ -n "$ROOT_SUBVOL" ] && ROOTFLAGS=" rootflags=subvol=$ROOT_SUBVOL"
        SEED_CMDLINE="root=UUID=$ORIG_FS_UUID ro${ROOTFLAGS}"
        log "  Seeding /etc/kernel/cmdline from the inner filesystem UUID"
    fi
    if [ -n "$SEED_CMDLINE" ]; then
        warn "  /etc/kernel/cmdline not found — creating it (without it, a rebuild would bake in the LIVE USB's /proc/cmdline)."
        mkdir -p /mnt/etc/kernel
        printf '%s\n' "$SEED_CMDLINE" > /mnt/etc/kernel/cmdline
    fi
fi

if [ -f /mnt/etc/kernel/cmdline ]; then
    log "  Updating /etc/kernel/cmdline..."
    [ -f /mnt/etc/kernel/cmdline.pre-luks ] || cp /mnt/etc/kernel/cmdline /mnt/etc/kernel/cmdline.pre-luks
    cl_patch_file cmdline /mnt/etc/kernel/cmdline || cfg_fail "  Could not rewrite /etc/kernel/cmdline (V14 will report it)."
    [ "$CL_CHANGED" -eq 1 ] && log "    root=/resume= and LUKS arguments applied"
    echo "  --- /etc/kernel/cmdline ---"
    cat /mnt/etc/kernel/cmdline
fi

if [ "$CMDLINE_D_HAS_CONFS" -eq 1 ]; then
    log "  Updating /etc/cmdline.d/*.conf (mkinitcpio concatenates these)..."
    for cd_conf in /mnt/etc/cmdline.d/*.conf; do
        [ -f "$cd_conf" ] || continue
        [ -f "$cd_conf.pre-luks" ] || cp "$cd_conf" "$cd_conf.pre-luks"
        cl_patch_file dropin "$cd_conf" || cfg_fail "  Could not rewrite ${cd_conf#/mnt} (V14 will report it)."
        [ "$CL_CHANGED" -eq 1 ] && log "    ${cd_conf#/mnt}: root=/resume= rewritten to the mapper"
    done
    # The unlock arguments live in ONE fragment, not in every file, and only
    # when /etc/kernel/cmdline is not already carrying them.
    if [ -n "$LUKS_BOOT_ARGS" ] && [ ! -f /mnt/etc/kernel/cmdline ]; then
        printf '%s\n' "$LUKS_BOOT_ARGS" > /mnt/etc/cmdline.d/90-linuxlocker.conf
        log "    Wrote /etc/cmdline.d/90-linuxlocker.conf: $LUKS_BOOT_ARGS"
    fi
fi

# ─── 6e: initramfs generator configuration ───────────────────────────────────
case "$INITRAMFS_STYLE" in
    dracut)
        log "  Configuring dracut LUKS modules..."
        mkdir -p /mnt/etc/dracut.conf.d
        FS_MODULE=""
        [ "$IS_BTRFS" -eq 1 ] && FS_MODULE="btrfs "
        cat > /mnt/etc/dracut.conf.d/99-luks.conf <<DRACUT_CONF
# Added by LinuxLocker luks-deploy.sh — initramfs must include LUKS unlock support
add_dracutmodules+=" crypt dm ${FS_MODULE}"
# Belt-and-suspenders for the kernel-side crypto stack: the crypt dracut
# module's dependency graph usually pulls these, but a missing dm-crypt.ko in
# the initramfs = an unopenable root at boot, so force it explicitly.
# (add_drivers only warns if a name is builtin/absent — safe everywhere.)
add_drivers+=" dm-crypt "
DRACUT_CONF
        log "    Created /etc/dracut.conf.d/99-luks.conf (crypt+dm${FS_MODULE:+ +btrfs} modules, dm-crypt driver pinned)"
        ;;
    mkinitcpio)
        log "  Configuring mkinitcpio hooks..."
        cp /mnt/etc/mkinitcpio.conf /mnt/etc/mkinitcpio.conf.pre-luks
        WANT_HOOK="encrypt"
        [ "$MKINITCPIO_SD" -eq 1 ] && WANT_HOOK="sd-encrypt"
        if grep -Eq "^HOOKS=.*[( ]${WANT_HOOK}[ )]" /mnt/etc/mkinitcpio.conf; then
            log "    HOOKS already contains '$WANT_HOOK'."
        else
            # Insert the encrypt hook immediately before 'filesystems' — the
            # canonical position (after block/keyboard, before fs mount).
            sed -i -E "s/^(HOOKS=.*[( ])filesystems([ )])/\1${WANT_HOOK} filesystems\2/" /mnt/etc/mkinitcpio.conf
            if grep -Eq "^HOOKS=.*[( ]${WANT_HOOK}[ )]" /mnt/etc/mkinitcpio.conf; then
                log "    Inserted '$WANT_HOOK' before 'filesystems' in HOOKS."
            else
                cfg_fail "Could not insert '$WANT_HOOK' into mkinitcpio HOOKS (no 'filesystems' hook to anchor on?) — edit /etc/mkinitcpio.conf on the target; V9 will report it."
            fi
        fi
        grep '^HOOKS=' /mnt/etc/mkinitcpio.conf | sed 's/^/    /'
        ;;
    initramfs-tools)
        log "  Checking initramfs-tools cryptroot support..."
        if [ -e /mnt/usr/share/initramfs-tools/hooks/cryptroot ] \
           || [ -e /mnt/etc/initramfs-tools/hooks/cryptroot ]; then
            log "    cryptsetup-initramfs hook present."
        else
            warn "    The 'cryptsetup-initramfs' package is missing on the target —"
            warn "    without its cryptroot hook the initramfs cannot unlock the root."
            if chroot /mnt /bin/sh -c 'command -v apt-get' >/dev/null 2>&1; then
                log "    Attempting to install it in the chroot (needs network)..."
                if chroot /mnt /bin/sh -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y cryptsetup-initramfs' \
                   && [ -e /mnt/usr/share/initramfs-tools/hooks/cryptroot ]; then
                    log "    cryptsetup-initramfs installed."
                else
                    cfg_fail "Could not install cryptsetup-initramfs in the chroot. Get the target
     online (or pre-install the package) and re-run this script — it lands in
     configuration-only mode and finishes the job. V9 will report this."
                fi
            else
                cfg_fail "cryptsetup-initramfs missing and no apt-get in the chroot (V9 will report it)."
            fi
        fi
        ;;
esac

# ─── 6f: Raspberry Pi-style cmdline.txt ──────────────────────────────────────
# The firmware reads the kernel command line from cmdline.txt on the firmware
# FAT partition; there is no GRUB to regenerate it. root= must point at the
# mapper, and the unlock arguments (if this initramfs style needs any) ride
# along. Single line, by firmware requirement.
if [ -n "$RPI_CMDLINE" ]; then
    log "  Updating ${RPI_CMDLINE#/mnt}..."
    [ -f "${RPI_CMDLINE}.pre-luks" ] || cp "$RPI_CMDLINE" "${RPI_CMDLINE}.pre-luks"
    cl_patch_file cmdline "$RPI_CMDLINE" || cfg_fail "  Could not rewrite ${RPI_CMDLINE#/mnt} (V6 will report it)."
    # cmdline.txt always names the partition (PARTUUID= on Raspberry Pi OS):
    # if root= still is not the mapper, nothing above recognised it.
    if ! grep -q "root=/dev/mapper/$LUKS_NAME" "$RPI_CMDLINE"; then
        sed -i -E "s|root=[^[:space:]]+|root=/dev/mapper/$LUKS_NAME|" "$RPI_CMDLINE"
        grep -q "root=/dev/mapper/$LUKS_NAME" "$RPI_CMDLINE" \
            || sed -i "1s|^|root=/dev/mapper/$LUKS_NAME |" "$RPI_CMDLINE"
    fi
    log "    root= now points at /dev/mapper/$LUKS_NAME"
    echo "  --- ${RPI_CMDLINE#/mnt} ---"
    cat "$RPI_CMDLINE"
    # The firmware only loads an initramfs when config.txt says so; Raspberry
    # Pi OS Bookworm ships auto_initramfs=1, older images may not.
    RPI_CONFIG="$(dirname "$RPI_CMDLINE")/config.txt"
    if [ -f "$RPI_CONFIG" ] && ! grep -q '^auto_initramfs=1' "$RPI_CONFIG"; then
        cp "$RPI_CONFIG" "${RPI_CONFIG}.pre-luks"
        printf '\n# Added by LinuxLocker — load the initramfs that unlocks the root\nauto_initramfs=1\n' >> "$RPI_CONFIG"
        log "    Added auto_initramfs=1 to config.txt"
    fi
fi

# ─── 6g: extlinux.conf (U-Boot distro-boot on many ARM boards) ───────────────
if [ -n "$EXTLINUX_CONF" ]; then
    log "  Updating ${EXTLINUX_CONF#/mnt}..."
    [ -f "${EXTLINUX_CONF}.pre-luks" ] || cp "$EXTLINUX_CONF" "${EXTLINUX_CONF}.pre-luks"
    cl_patch_file extlinux "$EXTLINUX_CONF" || cfg_fail "  Could not rewrite ${EXTLINUX_CONF#/mnt} (V6 will report it)."
    if ! grep -q "root=/dev/mapper/$LUKS_NAME" "$EXTLINUX_CONF"; then
        # An APPEND whose root= was not recognised as this partition (a
        # by-path link, a label): rewrite root= on every APPEND line outright.
        sed -i -E "s#(^[[:space:]]*[Aa][Pp][Pp][Ee][Nn][Dd][[:space:]].*)root=[^[:space:]]+#\1root=/dev/mapper/$LUKS_NAME#" "$EXTLINUX_CONF"
    fi
    grep -inE '^[[:space:]]*(APPEND|append)' "$EXTLINUX_CONF" | sed 's/^/    /' || true
fi

# ─── 6h: every other command-line carrier ────────────────────────────────────
# Type #1 entries under /efi or /boot/efi (systemd-boot with the ESP there —
# /boot/loader/entries is handled by grubby/direct patch in step 7c, but its
# root= is fixed here too), rEFInd's refind_linux.conf, Limine's limine.conf
# and its /etc/default/limine source. Each gets root=/resume= pointed at the
# mapper and the unlock arguments appended; each original is kept as
# *.pre-luks. A stale carrier for a bootloader no longer in use is patched
# too — harmless, and it cannot be told apart from the live one from here.
while IFS=$'\t' read -r ckind cpath; do
    [ -n "$ckind" ] || continue
    case "$ckind" in
        cmdline|dropin|extlinux|grubd) continue ;;     # handled in 6c/6d/6f/6g
        bls|refind|limine|limine-default) ;;
        *) continue ;;
    esac
    [ -f "$cpath.pre-luks" ] || cp "$cpath" "$cpath.pre-luks" 2>/dev/null || true
    case "$ckind" in
        bls)            cl_patch_file bls     "$cpath" ;;
        refind)         cl_patch_file refind  "$cpath" ;;
        limine)         cl_patch_file limine  "$cpath" ;;
        limine-default) cl_patch_file grubvar "$cpath" 'KERNEL_CMDLINE(\[[^]]*\])?' ;;
    esac || { cfg_fail "  Could not rewrite ${cpath#/mnt} ($ckind) — V14 will report it."; continue; }
    if [ "$CL_CHANGED" -eq 1 ]; then
        log "  ${cpath#/mnt} ($ckind): root=/resume= → mapper${LUKS_BOOT_ARGS:+, LUKS arguments added}"
    fi
done < <(cl_find_carriers /mnt)

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 7: Rebuild Initramfs + Update Boot Entries + Rebuild GRUB (in chroot)
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
log "[7/8] Rebuilding initramfs, boot entries, and bootloader config..."

# Pass required variables into the chroot via a sourced env file
mkdir -p /mnt/tmp
cat > /mnt/tmp/.luks-deploy-env <<EOF
LUKS_UUID="$LUKS_UUID"
LUKS_NAME="$LUKS_NAME"
ORIG_FS_UUID="$ORIG_FS_UUID"
LUKS_BOOT_ARGS="$LUKS_BOOT_ARGS"
LUKS_KEEP_SPLASH="${LUKS_KEEP_SPLASH:-0}"
INITRAMFS_STYLE="$INITRAMFS_STYLE"
GRUB_UPDATE_TOOL="$GRUB_UPDATE_TOOL"
RPI_CMDLINE="${RPI_CMDLINE#/mnt}"
EXTLINUX_CONF="${EXTLINUX_CONF#/mnt}"
UKI_ACTIVE="$UKI_ACTIVE"
LL_HAVE_UKI_LIB="$LL_HAVE_UKI_LIB"
LUKS_UKI_REGEN="${UKI_REGEN:-none}"
LUKS_UKI_SIGN="${UKI_SIGN:-none}"
LUKS_SB_KEY="${UKI_SB_KEY:-}"
LUKS_SB_CERT="${UKI_SB_CERT:-}"
LUKS_SB_STATE="${UKI_SB_STATE:-unknown}"
LUKS_SKIP_UKI_SIGN="${LUKS_SKIP_UKI_SIGN:-0}"
CL_TARGET_REAL="$TARGET_ROOT_REAL"
CL_TARGET_PARTUUID="$CL_TARGET_PARTUUID"
EOF

# lib-uki.sh has to run INSIDE the chroot for 7f/7g: the regeneration tools are
# the target's, not the live environment's, and they must see the target's own
# /etc/kernel/cmdline, presets and keys.
if [ "$LL_HAVE_UKI_LIB" -eq 1 ]; then
    cp "$SCRIPT_DIR/lib-uki.sh" /mnt/tmp/.luks-lib-uki.sh 2>/dev/null || true
fi
# lib-boot.sh does the splash strip inside the chroot, across every carrier.
cp "$SCRIPT_DIR/lib-boot.sh" /mnt/tmp/.luks-lib-boot.sh 2>/dev/null \
    || warn "  Could not copy lib-boot.sh into the chroot — the splash will not be stripped."

CHROOT_RC=0
chroot /mnt /bin/bash <<'CHROOT_SCRIPT' || CHROOT_RC=$?
# ── Inside chroot ──────────────────────────────────────────────────────────
source /tmp/.luks-deploy-env
rm -f /tmp/.luks-deploy-env
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

ERRORS=0
echo ""
echo "[CHROOT] ═══════════════════════════════════════════════"
echo "[CHROOT] Architecture : $(uname -m)"
echo "[CHROOT] LUKS UUID    : $LUKS_UUID"
echo "[CHROOT] Mapper name  : $LUKS_NAME"
echo "[CHROOT] Initramfs    : $INITRAMFS_STYLE"
echo "[CHROOT] ═══════════════════════════════════════════════"
echo ""

# ── 7a: Rebuild initramfs for ALL kernels ──────────────────────────────────
# NOTE: We do NOT delete existing initramfs first. Force-overwrite in place:
# if the generator fails for one kernel, the other kernels still have working
# initramfs images.
echo "[CHROOT] Rebuilding initramfs for all installed kernels..."

case "$INITRAMFS_STYLE" in
dracut)
    DRACUT_VER=$(dracut --version 2>/dev/null || echo "unknown")
    echo "[CHROOT] dracut version: $DRACUT_VER"

    if dracut --help 2>&1 | grep -q -- '--regenerate-all'; then
        echo "[CHROOT] Using dracut --regenerate-all --force..."
        if ! dracut --regenerate-all --force 2>&1; then
            echo "[CHROOT] WARN: --regenerate-all failed, trying per-kernel..."
            for kernel in /boot/vmlinuz-*; do
                [ -f "$kernel" ] || continue
                kver=$(basename "$kernel" | sed 's/vmlinuz-//')
                echo "[CHROOT] Building initramfs for $kver ..."
                if ! dracut --force "/boot/initramfs-${kver}.img" "$kver" 2>&1; then
                    echo "[CHROOT] WARN: dracut failed for $kver, retrying with explicit modules..."
                    if ! dracut --force --add "crypt dm" "/boot/initramfs-${kver}.img" "$kver" 2>&1; then
                        echo "[CHROOT] FAIL: dracut failed for $kver even with explicit modules"
                        ERRORS=$((ERRORS + 1))
                    fi
                fi
            done
        fi
    else
        for kernel in /boot/vmlinuz-*; do
            [ -f "$kernel" ] || continue
            kver=$(basename "$kernel" | sed 's/vmlinuz-//')
            echo "[CHROOT] Building initramfs for $kver ..."
            if ! dracut --force "/boot/initramfs-${kver}.img" "$kver" 2>&1; then
                echo "[CHROOT] FAIL: dracut failed for $kver"
                ERRORS=$((ERRORS + 1))
            fi
        done
    fi
    ;;
mkinitcpio)
    echo "[CHROOT] Using mkinitcpio -P (all presets)..."
    mkinitcpio -P 2>&1 || ERRORS=$((ERRORS + 1))
    ;;
initramfs-tools)
    echo "[CHROOT] Using update-initramfs for all kernels..."
    if ! update-initramfs -u -k all 2>&1; then
        echo "[CHROOT] WARN: update-initramfs -u failed, trying -c per kernel..."
        for kernel in /boot/vmlinuz-*; do
            [ -f "$kernel" ] || continue
            kver=$(basename "$kernel" | sed 's/vmlinuz-//')
            update-initramfs -c -k "$kver" 2>&1 || ERRORS=$((ERRORS + 1))
        done
    fi
    ;;
esac

# ── 7b: Verify initramfs images contain cryptsetup ─────────────────────────
# The listing tool differs per generator: lsinitrd (dracut), lsinitramfs
# (initramfs-tools), lsinitcpio (mkinitcpio). 'cryptsetup' matches both the
# userspace binary (crypt/encrypt hooks) and systemd-cryptsetup (sd-encrypt).
list_initrd() {   # $1 = image
    if command -v lsinitrd &>/dev/null; then lsinitrd "$1" 2>/dev/null
    elif command -v lsinitramfs &>/dev/null; then lsinitramfs "$1" 2>/dev/null
    elif command -v lsinitcpio &>/dev/null; then lsinitcpio "$1" 2>/dev/null
    else return 2; fi
}
repair_initrd() {   # $1 = image, $2 = kver (may be empty for mkinitcpio)
    case "$INITRAMFS_STYLE" in
        dracut)          [ -n "$2" ] && dracut --force --add "crypt dm" "$1" "$2" 2>&1 ;;
        mkinitcpio)      mkinitcpio -P 2>&1 ;;
        initramfs-tools) [ -n "$2" ] && update-initramfs -u -k "$2" 2>&1 ;;
    esac
}

echo ""
echo "[CHROOT] Verifying initramfs images..."
INITRD_FOUND=0
for initrd in /boot/initramfs-*.img /boot/initrd.img-*; do
    [ -f "$initrd" ] || continue
    # Skip rescue/fallback images (they may be legitimately different)
    basename "$initrd" | grep -qE '(fallback|rescue)' && continue

    INITRD_FOUND=$((INITRD_FOUND + 1))
    size=$(stat -c%s "$initrd" 2>/dev/null || echo 0)

    if [ "$size" -lt 3000000 ]; then
        echo "[CHROOT]   FAIL: $initrd too small (${size} bytes) — likely corrupt"
        ERRORS=$((ERRORS + 1))
        continue
    fi

    echo "[CHROOT]   OK: $(basename "$initrd") ($((size / 1024 / 1024))MB)"

    ilist=$(list_initrd "$initrd") ; list_rc=$?
    if [ "$list_rc" -eq 2 ]; then
        echo "[CHROOT]       Cannot verify contents (no lsinitrd/lsinitramfs/lsinitcpio)"
        continue
    fi
    if echo "$ilist" | grep -q 'cryptsetup'; then
        echo "[CHROOT]       Contains cryptsetup: YES"
    else
        echo "[CHROOT]       Contains cryptsetup: NO — attempting auto-repair..."
        kver=$(basename "$initrd" | sed -n -e 's/initramfs-\(.*\)\.img/\1/p' -e 's/initrd\.img-\(.*\)/\1/p')
        if repair_initrd "$initrd" "$kver" && list_initrd "$initrd" | grep -q 'cryptsetup'; then
            echo "[CHROOT]       Auto-repair: SUCCESS — cryptsetup now included"
        elif [ "$INITRAMFS_STYLE" = "dracut" ] && [ -n "$kver" ]; then
            # Last resort: force-install the binary itself
            echo "[CHROOT]       Trying --install /usr/sbin/cryptsetup..."
            dracut --force --add "crypt dm" --install "/usr/sbin/cryptsetup" \
                "$initrd" "$kver" 2>&1 || true
            if list_initrd "$initrd" | grep -q 'cryptsetup'; then
                echo "[CHROOT]       Last-resort repair: SUCCESS"
            else
                echo "[CHROOT]       CRITICAL: Cannot include cryptsetup in initramfs!"
                ERRORS=$((ERRORS + 1))
            fi
        else
            echo "[CHROOT]       CRITICAL: Cannot include cryptsetup in $(basename "$initrd")!"
            ERRORS=$((ERRORS + 1))
        fi
    fi
done

if [ "$INITRD_FOUND" -eq 0 ]; then
    # A UKI-only target legitimately has NO standalone initramfs: an mkinitcpio
    # preset carrying default_uki= but no default_image= writes only the .efi.
    # The initramfs still exists — inside the PE binary's .initrd section — so
    # look there before calling this a failure.
    UKI_INITRD_OK=0
    if [ "${UKI_ACTIVE:-0}" = "1" ] && [ -f /tmp/.luks-lib-uki.sh ]; then
        # shellcheck source=/dev/null
        . /tmp/.luks-lib-uki.sh
        uki_find_ukis ""
        for u in "${UKI_PATHS[@]+"${UKI_PATHS[@]}"}"; do
            uki_initrd_has "$u" 'cryptsetup'; irc=$?
            case "$irc" in
                0) echo "[CHROOT]   OK: $(basename "$u") embeds an initramfs containing cryptsetup"
                   UKI_INITRD_OK=1 ;;
                1) echo "[CHROOT]   FAIL: $(basename "$u") embeds an initramfs with NO cryptsetup!"
                   ERRORS=$((ERRORS + 1)); UKI_INITRD_OK=1 ;;
                *) echo "[CHROOT]   SKIP: cannot inspect $(basename "$u") (.initrd needs objcopy + lsinitcpio/lsinitrd)"
                   UKI_INITRD_OK=1 ;;
            esac
        done
    fi
    if [ "$UKI_INITRD_OK" -eq 0 ]; then
        echo "[CHROOT] FAIL: No non-rescue initramfs images found!"
        ERRORS=$((ERRORS + 1))
    else
        echo "[CHROOT] No standalone initramfs — this target is UKI-only (expected)."
    fi
else
    echo "[CHROOT] Found $INITRD_FOUND non-rescue initramfs image(s)."
fi

# ── 7c: Update BLS boot entries (grubby, or direct patch) ──────────────────
# Only meaningful where BLS entries exist AND this initramfs style takes its
# unlock instructions from the kernel command line.
if [ -n "$LUKS_BOOT_ARGS" ] && [ -d /boot/loader/entries ]; then
    echo ""
    echo "[CHROOT] Updating BLS boot entries..."
    BLS_MISSING=0
    for entry in /boot/loader/entries/*.conf; do
        [ -f "$entry" ] || continue
        grep -qF "$LUKS_BOOT_ARGS" "$entry" || BLS_MISSING=$((BLS_MISSING + 1))
    done
    if [ "$BLS_MISSING" -eq 0 ]; then
        echo "[CHROOT] Every BLS entry already carries the LUKS arguments (stage 6h)."
    elif command -v grubby &>/dev/null; then
        echo "[CHROOT] Using grubby to add: $LUKS_BOOT_ARGS"
        if grubby --update-kernel=ALL --args="$LUKS_BOOT_ARGS" 2>&1; then
            echo "[CHROOT] grubby: updated ALL kernel entries."
        else
            echo "[CHROOT] WARN: grubby --update-kernel=ALL failed. Trying individually..."
            for entry in /boot/loader/entries/*.conf; do
                [ -f "$entry" ] || continue
                kpath=$(grep "^linux " "$entry" | awk '{print $2}')
                [ -n "$kpath" ] || continue
                grubby --update-kernel="$kpath" --args="$LUKS_BOOT_ARGS" 2>&1 || true
            done
        fi
    else
        echo "[CHROOT] grubby not found — patching BLS entries directly..."
    fi
    # Verify (and auto-repair by direct patch) either way
    BLS_ERRORS=0
    for entry in /boot/loader/entries/*.conf; do
        [ -f "$entry" ] || continue
        ename=$(basename "$entry")
        if grep -qF "$LUKS_BOOT_ARGS" "$entry"; then
            echo "[CHROOT]   OK: $ename"
            continue
        fi
        if grep -q "^options " "$entry"; then
            sed -i "s|^options |options $LUKS_BOOT_ARGS |" "$entry"
            if grep -qF "$LUKS_BOOT_ARGS" "$entry"; then
                echo "[CHROOT]   OK: $ename (patched directly)"
            else
                echo "[CHROOT]   FAIL: $ename — could not add LUKS args!"
                BLS_ERRORS=$((BLS_ERRORS + 1))
            fi
        else
            echo "[CHROOT]   FAIL: $ename has no 'options' line!"
            BLS_ERRORS=$((BLS_ERRORS + 1))
        fi
    done
    ERRORS=$((ERRORS + BLS_ERRORS))
fi

# ── 7b½: Kernel-module presence checks (dm-crypt hard, keyboard soft) ─────
# A missing dm-crypt.ko in an initramfs is an unopenable root at boot.
# A missing keyboard driver is worse in a subtler way: every other check can
# pass and the user still cannot TYPE the passphrase. The input check only
# warns (many kernels build HID support in), but it warns loudly.
echo ""
echo "[CHROOT] Checking initramfs kernel modules..."
if [ "$INITRAMFS_STYLE" = "dracut" ] && command -v lsinitrd &>/dev/null; then
    for initrd in /boot/initramfs-*.img; do
        [ -f "$initrd" ] || continue
        basename "$initrd" | grep -qE '(fallback|rescue)' && continue
        kver=$(basename "$initrd" | sed -n 's/initramfs-\(.*\)\.img/\1/p')
        [ -n "$kver" ] || continue
        ilist=$(lsinitrd "$initrd" 2>/dev/null || true)

        # dm-crypt: module in the image, or built into the kernel — else repair.
        if echo "$ilist" | grep -q 'dm-crypt.ko'; then
            echo "[CHROOT]   OK: $(basename "$initrd") carries dm-crypt.ko"
        elif modinfo -k "$kver" -F filename dm-crypt 2>/dev/null | grep -q 'builtin'; then
            echo "[CHROOT]   OK: dm-crypt is built into kernel $kver"
        else
            echo "[CHROOT]   FAIL: $(basename "$initrd") lacks dm-crypt — rebuilding with --add-drivers..."
            if dracut --force --add-drivers "dm-crypt" "$initrd" "$kver" 2>&1 \
               && lsinitrd "$initrd" 2>/dev/null | grep -q 'dm-crypt.ko'; then
                echo "[CHROOT]   Repair: SUCCESS — dm-crypt now included"
                ilist=$(lsinitrd "$initrd" 2>/dev/null || true)
            else
                echo "[CHROOT]   CRITICAL: cannot get dm-crypt into $initrd — the root will NOT unlock at boot!"
                ERRORS=$((ERRORS + 1))
            fi
        fi

        # Keyboard/input: usbhid/hid-generic (external), atkbd (PS/2), plus
        # laptop-specific HID transports. At least one should be in the image
        # or builtin, or the passphrase prompt is a brick wall.
        if echo "$ilist" | grep -qE '(usbhid|hid[-_]generic|atkbd|i8042|hid[-_]multitouch|applespi|spi[-_]hid)'; then
            echo "[CHROOT]   OK: $(basename "$initrd") carries keyboard/input driver(s)"
        elif modinfo -k "$kver" -F filename hid_generic 2>/dev/null | grep -q 'builtin' \
             || modinfo -k "$kver" -F filename usbhid 2>/dev/null | grep -q 'builtin'; then
            echo "[CHROOT]   OK: generic HID input is built into kernel $kver"
        else
            echo "[CHROOT]   ╔══════════════════════════════════════════════════════════╗"
            echo "[CHROOT]   ║ WARN: no keyboard/input driver found in $(basename "$initrd")"
            echo "[CHROOT]   ║ If the boot console cannot take keystrokes, you CANNOT"
            echo "[CHROOT]   ║ type the LUKS passphrase — verify before rebooting, e.g.:"
            echo "[CHROOT]   ║   lsinitrd $initrd | grep -iE 'hid|input'"
            echo "[CHROOT]   ╚══════════════════════════════════════════════════════════╝"
        fi
    done
else
    echo "[CHROOT] (module-level checks are dracut-specific — $INITRAMFS_STYLE bundles its hooks' dependencies itself)"
fi

# ── 7c½: Strip splash tokens so the passphrase prompt is visible ───────────
# With the splash active, the first-boot LUKS prompt hides behind boot
# graphics/text and looks like a hang. Distros differ: Fedora uses
# 'rhgb quiet', Debian/Ubuntu/Raspberry Pi OS use 'quiet splash'. Strip
# whichever tokens are actually present, from EVERY carrier lib-boot.sh knows
# (GRUB defaults and their drop-ins, /etc/kernel/cmdline, cmdline.d, BLS and
# systemd-boot entries wherever the ESP is, cmdline.txt, extlinux, rEFInd,
# Limine); a marker file tells post-encryption-setup.sh which ones to restore
# after the first encrypted boot. Opt out with LUKS_KEEP_SPLASH=1.
echo ""
if [ "${LUKS_KEEP_SPLASH:-0}" = "1" ]; then
    echo "[CHROOT] LUKS_KEEP_SPLASH=1 — leaving splash boot arguments in place."
elif [ ! -f /tmp/.luks-lib-boot.sh ]; then
    echo "[CHROOT] WARN: lib-boot.sh missing in the chroot — splash left in place."
else
    # shellcheck source=/dev/null
    . /tmp/.luks-lib-boot.sh
    CL_MAPPER="$LUKS_NAME"; CL_LUKS_ARGS=""; CL_ADD_ARGS=0; CL_FIX_ROOT=0
    SPLASH_FILES="/etc/default/grub"
    while IFS=$'\t' read -r ckind cpath; do
        [ -n "$cpath" ] && SPLASH_FILES="$SPLASH_FILES $cpath"
    done < <(cl_find_carriers "")
    # Which of the candidate tokens does this system actually use?
    FOUND_TOKENS=""
    for tok in rhgb quiet splash; do
        for f in $SPLASH_FILES; do
            [ -f "$f" ] || continue
            if grep -qw "$tok" "$f" 2>/dev/null; then
                FOUND_TOKENS="${FOUND_TOKENS:+$FOUND_TOKENS }$tok"
                break
            fi
        done
    done
    if [ -z "$FOUND_TOKENS" ]; then
        echo "[CHROOT] No splash tokens (rhgb/quiet/splash) found — nothing to strip."
    else
        echo "[CHROOT] Stripping '$FOUND_TOKENS' from boot args (post-encryption-setup.sh restores them)..."
        CL_STRIP_TOKENS="$FOUND_TOKENS"
        if command -v grubby &>/dev/null && [ -d /boot/loader/entries ]; then
            grubby --update-kernel=ALL --remove-args="$FOUND_TOKENS" 2>&1 \
                || echo "[CHROOT] WARN: grubby --remove-args failed (BLS entries keep the splash)."
        fi
        [ -f /etc/default/grub ] && cl_patch_file grubvar /etc/default/grub 'GRUB_CMDLINE_LINUX(_DEFAULT)?'
        while IFS=$'\t' read -r ckind cpath; do
            [ -n "$cpath" ] || continue
            case "$ckind" in
                cmdline)        cl_patch_file cmdline  "$cpath" ;;
                dropin)         cl_patch_file dropin   "$cpath" ;;
                bls)            cl_patch_file bls      "$cpath" ;;
                extlinux)       cl_patch_file extlinux "$cpath" ;;
                refind)         cl_patch_file refind   "$cpath" ;;
                limine)         cl_patch_file limine   "$cpath" ;;
                limine-default) cl_patch_file grubvar  "$cpath" 'KERNEL_CMDLINE(\[[^]]*\])?' ;;
                grubd)          cl_patch_file grubvar  "$cpath" 'GRUB_CMDLINE_LINUX(_DEFAULT)?' ;;
            esac || echo "[CHROOT] WARN: could not strip the splash from $cpath"
        done < <(cl_find_carriers "")
        mkdir -p /var/lib/linuxlocker
        echo "$FOUND_TOKENS" > /var/lib/linuxlocker/restore-splash
        echo "[CHROOT] Splash stripped; marker written for post-encryption-setup.sh."
    fi
    CL_STRIP_TOKENS=""
fi

# ── 7d: Rebuild GRUB config ───────────────────────────────────────────────
# NEVER regenerate onto /boot/efi/EFI/*/grub.cfg. On Fedora-family systems
# that file is a tiny STUB that searches for /boot by UUID and chainloads the
# real config from /boot/grub2/grub.cfg. Overwriting the stub with a full
# generated config can drop the next boot at a GRUB rescue prompt. Only the
# real config locations are regenerated here. (update-grub on Debian already
# targets /boot/grub/grub.cfg — safe by construction.)
echo ""
if [ -n "$GRUB_UPDATE_TOOL" ]; then
    echo "[CHROOT] Rebuilding GRUB config with $GRUB_UPDATE_TOOL..."
    GRUB_REBUILT=false
    case "$GRUB_UPDATE_TOOL" in
        update-grub)
            update-grub 2>&1 && GRUB_REBUILT=true
            ;;
        grub2-mkconfig|grub-mkconfig)
            GRUB_CFG_FOUND=false
            for grub_cfg in /boot/grub2/grub.cfg /boot/grub/grub.cfg; do
                [ -f "$grub_cfg" ] || continue
                GRUB_CFG_FOUND=true
                echo "[CHROOT] $GRUB_UPDATE_TOOL -o $grub_cfg"
                $GRUB_UPDATE_TOOL -o "$grub_cfg" 2>&1 && GRUB_REBUILT=true \
                    || echo "[CHROOT] WARN: $GRUB_UPDATE_TOOL exited non-zero on $grub_cfg."
                break
            done
            if ! $GRUB_CFG_FOUND; then
                # No existing real config — create one at the tool's native
                # location (still never on the ESP).
                case "$GRUB_UPDATE_TOOL" in
                    grub2-mkconfig) $GRUB_UPDATE_TOOL -o /boot/grub2/grub.cfg 2>&1 && GRUB_REBUILT=true ;;
                    grub-mkconfig)  $GRUB_UPDATE_TOOL -o /boot/grub/grub.cfg  2>&1 && GRUB_REBUILT=true ;;
                esac
            fi
            ;;
    esac
    if $GRUB_REBUILT; then
        echo "[CHROOT] GRUB config rebuilt."
    elif [ -n "$LUKS_BOOT_ARGS" ] && [ ! -d /boot/loader/entries ]; then
        # No BLS entries: grub.cfg IS the boot configuration, and it still
        # carries the pre-encryption command line without the unlock args.
        echo "[CHROOT] FAIL: Could not rebuild GRUB config, and grub.cfg is what boots this machine."
        ERRORS=$((ERRORS + 1))
    else
        echo "[CHROOT] WARN: Could not rebuild GRUB config."
    fi

    # Detect an ESP grub.cfg that has ALREADY been clobbered with a full config
    # (by an earlier tool run, or a guide-following mishap).
    for esp_cfg in /boot/efi/EFI/*/grub.cfg; do
        [ -f "$esp_cfg" ] || continue
        if grep -q '### BEGIN /etc/grub.d' "$esp_cfg"; then
            echo "[CHROOT] WARN: $esp_cfg is a FULL generated config, not a chainload stub."
            echo "[CHROOT]       Something previously ran grub-mkconfig against the ESP."
            echo "[CHROOT]       If this distro uses a stub there (Fedora-family does),"
            echo "[CHROOT]       restore it after first boot."
        fi
    done
else
    echo "[CHROOT] No GRUB on this target — skipping GRUB config rebuild."
fi

# ── 7f: Regenerate every Unified Kernel Image ──────────────────────────────
# Deliberately AFTER 7c½. The UKI bakes /etc/kernel/cmdline in, so rebuilding
# before the splash strip would bake in the pre-strip line and hide the
# passphrase prompt behind boot graphics — on a machine where the user also
# cannot see that it is asking for one.
#
# On mkinitcpio targets step 7a already ran `mkinitcpio -P`, which DOES write
# the .efi when the preset carries default_uki=. That .efi is wrong: it was
# built before the cmdline was final. This second run is what makes it right.
echo ""
if [ "${UKI_ACTIVE:-0}" = "1" ] && [ -f /tmp/.luks-lib-uki.sh ]; then
    # shellcheck source=/dev/null
    . /tmp/.luks-lib-uki.sh
    uki_find_ukis ""
    echo "[CHROOT] Regenerating ${#UKI_PATHS[@]} Unified Kernel Image(s) via ${LUKS_UKI_REGEN}..."

    # Record mtimes so an untouched .efi is an error, not a silent pass.
    UKI_MTIME_BEFORE=""
    for u in "${UKI_PATHS[@]+"${UKI_PATHS[@]}"}"; do
        UKI_MTIME_BEFORE="$UKI_MTIME_BEFORE $(stat -c '%n=%Y' "$u" 2>/dev/null)"
    done

    uki_detect_regen  "" || true
    if uki_regenerate ""; then
        echo "[CHROOT] UKI regeneration finished."
    else
        echo "[CHROOT] FAIL: UKI regeneration reported an error."
        ERRORS=$((ERRORS + 1))
    fi

    # Re-scan: kernel-install and dracut can legitimately create new filenames.
    uki_find_ukis ""
    UKI_STALE=0
    for u in "${UKI_PATHS[@]+"${UKI_PATHS[@]}"}"; do
        now=$(stat -c '%Y' "$u" 2>/dev/null || echo 0)
        was=$(echo "$UKI_MTIME_BEFORE" | tr ' ' '\n' | sed -n "s|^$u=||p")
        if [ -n "$was" ] && [ "$now" = "$was" ]; then
            echo "[CHROOT]   FAIL: $(basename "$u") was NOT rebuilt (mtime unchanged)"
            UKI_STALE=$((UKI_STALE + 1))
        else
            echo "[CHROOT]   OK: $(basename "$u") rebuilt"
        fi
    done
    ERRORS=$((ERRORS + UKI_STALE))

    # Confirm the new command line really is in there, here rather than only at
    # step 8 — a failure now is still cheap to diagnose with the tools loaded.
    if [ -n "$LUKS_BOOT_ARGS" ]; then
        for u in "${UKI_PATHS[@]+"${UKI_PATHS[@]}"}"; do
            cl=$(uki_cmdline_of "$u" 2>/dev/null || true)
            if [ -z "$cl" ]; then
                echo "[CHROOT]   (cannot read .cmdline of $(basename "$u") — no objcopy in the chroot)"
            elif echo "$cl" | grep -qF "$LUKS_BOOT_ARGS"; then
                echo "[CHROOT]   OK: $(basename "$u") .cmdline carries the LUKS arguments"
            else
                echo "[CHROOT]   FAIL: $(basename "$u") .cmdline lacks '$LUKS_BOOT_ARGS'"
                ERRORS=$((ERRORS + 1))
            fi
        done
    fi

    # ── 7g: Sign the regenerated images ────────────────────────────────────
    # Distro signing automation does NOT fire here. Arch's zz-sbctl.hook is a
    # libalpm hook, so it runs on pacman transactions and not on a bare
    # `mkinitcpio -P`; sbctl's kernel-install dropin only runs under
    # kernel-install. A UKI rebuilt above is unsigned until this signs it, and
    # with Secure Boot on, an unsigned .efi is a firmware-level refusal to boot.
    echo ""
    if [ "${LUKS_SKIP_UKI_SIGN:-0}" = "1" ]; then
        echo "[CHROOT] LUKS_SKIP_UKI_SIGN=1 — not signing. Sign before rebooting."
    elif [ "$LUKS_UKI_SIGN" = "none" ]; then
        if [ "$LUKS_SB_STATE" = "enabled" ]; then
            echo "[CHROOT] CRITICAL: Secure Boot is enabled and no signing backend exists."
            echo "[CHROOT]           The rebuilt UKI will be REFUSED by the firmware."
            ERRORS=$((ERRORS + 1))
        else
            echo "[CHROOT] No signing backend, and Secure Boot is $LUKS_SB_STATE — skipping (correct here)."
        fi
    else
        echo "[CHROOT] Signing UKI(s) with $LUKS_UKI_SIGN..."
        uki_detect_signer "" || true
        if uki_sign ""; then
            echo "[CHROOT] Signing finished."
        else
            echo "[CHROOT] FAIL: signing reported an error."
            ERRORS=$((ERRORS + 1))
        fi
        for u in "${UKI_PATHS[@]+"${UKI_PATHS[@]}"}"; do
            uki_verify_signed "$u"; vrc=$?
            case "$vrc" in
                0) echo "[CHROOT]   OK: $(basename "$u") carries a signature" ;;
                1) echo "[CHROOT]   FAIL: $(basename "$u") is UNSIGNED after signing!"
                   [ "$LUKS_SB_STATE" = "enabled" ] && ERRORS=$((ERRORS + 1)) ;;
                *) echo "[CHROOT]   (cannot verify $(basename "$u") — no sbverify/sbctl in the chroot)" ;;
            esac
        done
    fi
    rm -f /tmp/.luks-lib-uki.sh
else
    echo "[CHROOT] No Unified Kernel Images on this target — skipping UKI rebuild/signing."
fi

# ── 7e: SELinux — relabel every file this deployment wrote ─────────────────
# Files created from the live environment get labeled by the LIVE system's
# policy (or not labeled at all, if its SELinux is off). A mislabeled
# /etc/crypttab or dracut conf can fail the first boot in enforcing mode.
# restorecon runs here IN the chroot, against the target's own policy.
echo ""
if command -v restorecon &>/dev/null && [ -f /etc/selinux/config ]; then
    echo "[CHROOT] Restoring SELinux contexts on files written by this deployment..."
    restorecon -F \
        /etc/crypttab /etc/fstab /etc/fstab.pre-luks \
        /etc/default/grub /etc/default/grub.pre-luks \
        /etc/kernel/cmdline /etc/kernel/cmdline.pre-luks \
        /etc/dracut.conf.d/99-luks.conf /etc/mkinitcpio.conf \
        /boot/luks-header-backup.img 2>/dev/null || true
    restorecon -RF /boot/loader/entries 2>/dev/null || true
    # The freshly rebuilt initramfs images (and anything else the generators
    # wrote) were created from a chroot with no SELinux policy loaded — sweep
    # all of /boot and the marker dir so nothing is left unlabeled.
    restorecon -RF /boot 2>/dev/null || true
    restorecon -RF /var/lib/linuxlocker 2>/dev/null || true
    # -n -v lists anything STILL mislabeled; empty output means all clean
    RELABEL_LEFT=$(restorecon -n -v /etc/crypttab /etc/fstab /etc/default/grub \
        /etc/kernel/cmdline /etc/dracut.conf.d/99-luks.conf 2>/dev/null || true)
    if [ -n "$RELABEL_LEFT" ]; then
        echo "[CHROOT] WARN: some files could not be relabeled:"
        echo "$RELABEL_LEFT"
        echo "[CHROOT] If the first boot fails with SELinux denials, add 'enforcing=0'"
        echo "[CHROOT] to the kernel command line for one boot, then run:"
        echo "[CHROOT]     sudo restorecon -RFv /etc /boot && sudo setenforce 1"
    else
        echo "[CHROOT] SELinux contexts OK."
    fi
else
    echo "[CHROOT] SELinux not present on target (no /etc/selinux/config or restorecon) — skipping relabel."
fi

echo ""
echo "[CHROOT] ═══════════════════════════════════════════════"
echo "[CHROOT] Chroot work complete. Errors: $ERRORS"
echo "[CHROOT] ═══════════════════════════════════════════════"
exit $ERRORS
CHROOT_SCRIPT

rm -f /mnt/tmp/.luks-deploy-env 2>/dev/null || true

if [ "$CHROOT_RC" -ne 0 ]; then
    err "Chroot reported $CHROOT_RC error(s)!"
    warn "Continuing to verification to show full status..."
fi

# Sync all writes to disk
log "  Syncing all writes to disk..."
sync

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 8: Comprehensive Verification
# ═══════════════════════════════════════════════════════════════════════════════
# Checks are conditional on what this target actually uses (GRUB vs cmdline.txt,
# BLS vs none, dracut vs initramfs-tools) — a check that does not apply is
# reported as SKIP, never silently passed.
echo ""
log "[8/8] Running comprehensive verification..."
ERRORS=0
CHECKS=0

# ─── V1: crypttab ────────────────────────────────────────────────────────────
CHECKS=$((CHECKS + 1))
if grep -q "$LUKS_NAME" /mnt/etc/crypttab && grep -q "UUID=$LUKS_UUID" /mnt/etc/crypttab; then
    log "  V1 OK: crypttab has $LUKS_NAME with correct UUID"
else
    err "  V1 FAIL: crypttab missing or incorrect!"
    cat /mnt/etc/crypttab
    ERRORS=$((ERRORS + 1))
fi
if [ "$INITRAMFS_STYLE" = "initramfs-tools" ]; then
    CHECKS=$((CHECKS + 1))
    if grep -E "^${LUKS_NAME}[[:space:]]" /mnt/etc/crypttab | grep -q 'initramfs'; then
        log "  V1b OK: crypttab entry carries the 'initramfs' option (initramfs-tools needs it)"
    else
        err "  V1b FAIL: crypttab entry lacks the 'initramfs' option!"
        ERRORS=$((ERRORS + 1))
    fi
fi

# ─── V2: fstab ───────────────────────────────────────────────────────────────
CHECKS=$((CHECKS + 1))
if grep -q "/dev/mapper/$LUKS_NAME" /mnt/etc/fstab; then
    log "  V2 OK: fstab references /dev/mapper/$LUKS_NAME"
else
    err "  V2 FAIL: fstab does not reference /dev/mapper/$LUKS_NAME!"
    ERRORS=$((ERRORS + 1))
fi
if grep -q "UUID=$ORIG_FS_UUID" /mnt/etc/fstab; then
    err "  V2 FAIL: fstab still contains old UUID=$ORIG_FS_UUID!"
    ERRORS=$((ERRORS + 1))
fi

# ─── V3: /etc/default/grub ───────────────────────────────────────────────────
if [ -f /mnt/etc/default/grub ] && [ -n "$LUKS_BOOT_ARGS" ]; then
    CHECKS=$((CHECKS + 1))
    # The value grub-mkconfig uses is the one left after every
    # /etc/default/grub.d/*.cfg has been sourced, not the line in the file.
    GRUB_EFFECTIVE=$(cl_grub_effective /mnt GRUB_CMDLINE_LINUX || true)
    if cl_has_all_args "$GRUB_EFFECTIVE"; then
        log "  V3 OK: effective GRUB_CMDLINE_LINUX carries the LUKS arguments"
    else
        err "  V3 FAIL: effective GRUB_CMDLINE_LINUX lacks the LUKS arguments: '$GRUB_EFFECTIVE'"
        ERRORS=$((ERRORS + 1))
    fi
    for gd in /mnt/etc/default/grub /mnt/etc/default/grub.d/*.cfg; do
        [ -f "$gd" ] || continue
        if grep -qE '^[[:space:]]*GRUB_FORCE_PARTUUID=' "$gd"; then
            err "  V3 FAIL: ${gd#/mnt} still sets GRUB_FORCE_PARTUUID — GRUB would boot root=PARTUUID past the mapper!"
            ERRORS=$((ERRORS + 1))
        fi
    done
elif [ -f /mnt/etc/default/grub ]; then
    log "  V3 SKIP: $INITRAMFS_STYLE unlocks via crypttab — GRUB cmdline needs no LUKS args"
else
    log "  V3 SKIP: no /etc/default/grub on this target"
fi

# ─── V4: /etc/kernel/cmdline ─────────────────────────────────────────────────
if [ -f /mnt/etc/kernel/cmdline ] && [ -n "$LUKS_BOOT_ARGS" ]; then
    CHECKS=$((CHECKS + 1))
    if grep -qF "$LUKS_BOOT_ARGS" /mnt/etc/kernel/cmdline; then
        log "  V4 OK: /etc/kernel/cmdline has the LUKS arguments"
    else
        err "  V4 FAIL: /etc/kernel/cmdline missing the LUKS arguments!"
        ERRORS=$((ERRORS + 1))
    fi
else
    log "  V4 SKIP: /etc/kernel/cmdline not used on this target"
fi

# ─── V5: BLS entries ─────────────────────────────────────────────────────────
if [ -n "$LUKS_BOOT_ARGS" ] && [ -d /mnt/boot/loader/entries ]; then
    BLS_TOTAL=0
    BLS_OK=0
    for entry in /mnt/boot/loader/entries/*.conf; do
        [ -f "$entry" ] || continue
        BLS_TOTAL=$((BLS_TOTAL + 1))
        if grep -qF "$LUKS_BOOT_ARGS" "$entry"; then
            BLS_OK=$((BLS_OK + 1))
        else
            err "  V5 FAIL: $(basename "$entry") missing the LUKS arguments!"
            ERRORS=$((ERRORS + 1))
        fi
    done
    if [ "$BLS_TOTAL" -gt 0 ]; then
        CHECKS=$((CHECKS + 1))
        log "  V5 OK: $BLS_OK/$BLS_TOTAL BLS entries have the LUKS arguments"
    else
        warn "  V5 SKIP: BLS entries directory exists but is empty"
    fi
else
    log "  V5 SKIP: no BLS entries on this target (or none needed)"
fi

# ─── V6: bootloader config exists and points at the encrypted root ───────────
CHECKS=$((CHECKS + 1))
BOOTCFG_OK=0
GRUB_CFG=""
for f in /mnt/boot/grub2/grub.cfg /mnt/boot/grub/grub.cfg; do
    [ -f "$f" ] && GRUB_CFG="$f" && break
done
# The ESP grub.cfg must still be a stub, not a full generated config.
for esp_cfg in /mnt/boot/efi/EFI/*/grub.cfg; do
    [ -f "$esp_cfg" ] || continue
    if grep -q '### BEGIN /etc/grub.d' "$esp_cfg"; then
        warn "  V6 WARN: ${esp_cfg#/mnt} is a FULL generated config, not a chainload stub."
        warn "           On stub-based distros (Fedora-family), restore the stub after first boot."
    fi
done
if [ -n "$GRUB_CFG" ]; then
    log "  V6 OK: GRUB config found at ${GRUB_CFG#/mnt}"
    # On BLS systems, grub.cfg just has the blscfg command; LUKS params are in
    # the BLS entries. On Debian-family, root=/dev/mapper is generated inline.
    if grep -q "blscfg" "$GRUB_CFG"; then
        log "  V6 OK: GRUB config uses BLS (blscfg) — LUKS params come from BLS entries"
        BOOTCFG_OK=1
    elif grep -q "/dev/mapper/$LUKS_NAME" "$GRUB_CFG" \
         || { [ -n "$LUKS_BOOT_ARGS" ] && grep -qF "$LUKS_BOOT_ARGS" "$GRUB_CFG"; }; then
        log "  V6 OK: GRUB config references the encrypted root"
        BOOTCFG_OK=1
    elif [ -n "$LUKS_BOOT_ARGS" ]; then
        # This initramfs needs the arguments on the command line, grub.cfg is
        # that command line (no BLS), and they are not in it.
        err "  V6 FAIL: ${GRUB_CFG#/mnt} carries neither /dev/mapper/$LUKS_NAME nor '$LUKS_BOOT_ARGS'"
        err "           — the regenerated GRUB config would not unlock the root!"
        ERRORS=$((ERRORS + 1))
        BOOTCFG_OK=1
    else
        warn "  V6 WARN: GRUB config mentions neither blscfg nor /dev/mapper/$LUKS_NAME (crypttab-driven unlock; OK if root=UUID= is the inner filesystem)"
        BOOTCFG_OK=1     # config exists; contents warning only
    fi
fi
if [ -n "$RPI_CMDLINE" ]; then
    if grep -q "root=/dev/mapper/$LUKS_NAME" "$RPI_CMDLINE"; then
        log "  V6 OK: ${RPI_CMDLINE#/mnt} boots root=/dev/mapper/$LUKS_NAME"
        BOOTCFG_OK=1
    else
        err "  V6 FAIL: ${RPI_CMDLINE#/mnt} does not point root= at the mapper!"
        ERRORS=$((ERRORS + 1))
    fi
fi
if [ -n "$EXTLINUX_CONF" ]; then
    if grep -q "root=/dev/mapper/$LUKS_NAME" "$EXTLINUX_CONF"; then
        log "  V6 OK: ${EXTLINUX_CONF#/mnt} boots root=/dev/mapper/$LUKS_NAME"
        BOOTCFG_OK=1
    else
        err "  V6 FAIL: ${EXTLINUX_CONF#/mnt} does not point root= at the mapper!"
        ERRORS=$((ERRORS + 1))
    fi
fi
# A UKI is a bootloader configuration in its own right — the command line is
# inside it. V11 checks the contents; here it just has to count as "found", or
# an ESP-at-/efi systemd-boot box fails V6 while being perfectly configured.
if [ "$UKI_ACTIVE" -eq 1 ] && [ "$LL_HAVE_UKI_LIB" -eq 1 ] && [ "${#UKI_PATHS[@]}" -gt 0 ]; then
    log "  V6 OK: ${#UKI_PATHS[@]} Unified Kernel Image(s) carry this target's boot configuration"
    BOOTCFG_OK=1
fi
if [ "$BOOTCFG_OK" -eq 0 ] && [ -z "$RPI_CMDLINE" ] && [ -z "$EXTLINUX_CONF" ]; then
    err "  V6 FAIL: no bootloader configuration found (grub.cfg / UKI / cmdline.txt / extlinux.conf)!"
    ERRORS=$((ERRORS + 1))
fi

# ─── V7: Initramfs images ────────────────────────────────────────────────────
CHECKS=$((CHECKS + 1))
INITRD_COUNT=0
for f in /mnt/boot/initramfs-*.img /mnt/boot/initrd.img-*; do
    [ -f "$f" ] || continue
    basename "$f" | grep -qE '(fallback|rescue)' && continue
    INITRD_COUNT=$((INITRD_COUNT + 1))
done
if [ "$INITRD_COUNT" -gt 0 ]; then
    log "  V7 OK: $INITRD_COUNT non-rescue initramfs image(s) found"
elif [ "$UKI_ACTIVE" -eq 1 ] && [ "$LL_HAVE_UKI_LIB" -eq 1 ] && [ "${#UKI_PATHS[@]}" -gt 0 ]; then
    # UKI-only target: the initramfs lives in the .initrd section, not on disk.
    log "  V7 SKIP: no standalone initramfs — this target is UKI-only (V11 covers it)"
else
    err "  V7 FAIL: No initramfs images!"
    ERRORS=$((ERRORS + 1))
fi

# ─── V8: LUKS header backup ──────────────────────────────────────────────────
CHECKS=$((CHECKS + 1))
if [ -f /mnt/boot/luks-header-backup.img ]; then
    log "  V8 OK: LUKS header backup exists on target"
else
    warn "  V8 WARN: LUKS header backup missing from /boot"
fi
if [ -f "$STATE_DIR/luks-header-backup.img" ]; then
    log "  V8 OK: LUKS header backup exists on the deployment drive"
else
    warn "  V8 WARN: LUKS header backup missing from the deployment drive"
fi

# ─── V9: initramfs generator config ──────────────────────────────────────────
CHECKS=$((CHECKS + 1))
case "$INITRAMFS_STYLE" in
    dracut)
        if [ -f /mnt/etc/dracut.conf.d/99-luks.conf ] \
           && grep -q 'crypt' /mnt/etc/dracut.conf.d/99-luks.conf; then
            log "  V9 OK: dracut LUKS module config present"
        else
            err "  V9 FAIL: /etc/dracut.conf.d/99-luks.conf missing or lacks the crypt module!"
            ERRORS=$((ERRORS + 1))
        fi ;;
    mkinitcpio)
        if grep -Eq '^HOOKS=.*[( ](sd-)?encrypt[ )]' /mnt/etc/mkinitcpio.conf; then
            log "  V9 OK: mkinitcpio HOOKS contains the encrypt hook"
        else
            err "  V9 FAIL: mkinitcpio HOOKS lacks encrypt/sd-encrypt!"
            ERRORS=$((ERRORS + 1))
        fi ;;
    initramfs-tools)
        if [ -e /mnt/usr/share/initramfs-tools/hooks/cryptroot ] \
           || [ -e /mnt/etc/initramfs-tools/hooks/cryptroot ]; then
            log "  V9 OK: initramfs-tools cryptroot hook present (cryptsetup-initramfs)"
        else
            err "  V9 FAIL: cryptsetup-initramfs hook missing!"
            ERRORS=$((ERRORS + 1))
        fi ;;
esac

# ─── V10: LUKS device integrity ──────────────────────────────────────────────
CHECKS=$((CHECKS + 1))
if [ -b /dev/mapper/${LUKS_NAME} ]; then
    log "  V10 OK: /dev/mapper/${LUKS_NAME} is active"
else
    err "  V10 FAIL: /dev/mapper/${LUKS_NAME} not found!"
    ERRORS=$((ERRORS + 1))
fi

# ─── V11: UKI command line ───────────────────────────────────────────────────
# THE check whose absence made the original UKI failure silent. Every other
# check reads a file that a UKI target has correct; only this one reads the
# object the firmware actually loads.
if [ "$LL_HAVE_UKI_LIB" -eq 1 ]; then uki_find_ukis /mnt; fi
if [ "$LL_HAVE_UKI_LIB" -eq 1 ] && [ "${#UKI_PATHS[@]}" -gt 0 ]; then
    CHECKS=$((CHECKS + 1))
    UKI_OK=0; UKI_TOTAL=0; UKI_UNREADABLE=0
    for uki in "${UKI_PATHS[@]}"; do
        UKI_TOTAL=$((UKI_TOTAL + 1))
        UKI_CL=$(uki_cmdline_of "$uki" 2>/dev/null || true)
        if [ -z "$UKI_CL" ]; then
            warn "  V11 SKIP: cannot read the .cmdline section of ${uki#/mnt} (install binutils for objcopy)"
            UKI_UNREADABLE=$((UKI_UNREADABLE + 1))
            continue
        fi
        if [ -n "$LUKS_BOOT_ARGS" ] && ! echo "$UKI_CL" | grep -qF "$LUKS_BOOT_ARGS"; then
            err "  V11 FAIL: ${uki#/mnt} .cmdline lacks the LUKS arguments!"
            err "            wanted: $LUKS_BOOT_ARGS"
            ERRORS=$((ERRORS + 1))
            continue
        fi
        # root=UUID=<inner fs uuid> is CORRECT after encryption (the filesystem
        # keeps its UUID); what must not survive is root=PARTUUID=<partition>
        # or root=/dev/<partition>, which name the raw LUKS container.
        UKI_BAD=""
        for uki_tok in $UKI_CL; do
            case "$uki_tok" in
                root=*|resume=*) cl_ref_is_target "${uki_tok#*=}" && UKI_BAD="$uki_tok" ;;
            esac
        done
        if [ -n "$UKI_BAD" ]; then
            err "  V11 FAIL: ${uki#/mnt} .cmdline still has '$UKI_BAD' — the raw partition, not the mapper!"
            ERRORS=$((ERRORS + 1))
            continue
        fi
        UKI_OK=$((UKI_OK + 1))
    done
    if [ "$UKI_UNREADABLE" -eq "$UKI_TOTAL" ]; then
        warn "  V11 SKIP: none of the $UKI_TOTAL UKI(s) could be inspected"
    else
        log "  V11 OK: $UKI_OK/$UKI_TOTAL UKI(s) carry the encrypted root's boot arguments"
    fi

    # ─── V12: UKI signatures ─────────────────────────────────────────────────
    CHECKS=$((CHECKS + 1))
    if [ "${UKI_SB_STATE:-unknown}" != "enabled" ]; then
        log "  V12 SKIP: Secure Boot is ${UKI_SB_STATE:-unknown} — signatures are not required to boot"
    elif [ "${LUKS_SKIP_UKI_SIGN:-0}" = "1" ]; then
        warn "  V12 SKIP: LUKS_SKIP_UKI_SIGN=1 — sign EFI/Linux/*.efi yourself BEFORE rebooting"
    else
        SIG_OK=0; SIG_TOTAL=0; SIG_UNKNOWN=0
        for uki in "${UKI_PATHS[@]}"; do
            SIG_TOTAL=$((SIG_TOTAL + 1))
            uki_verify_signed "$uki"; SIG_RC=$?
            case "$SIG_RC" in
                0) SIG_OK=$((SIG_OK + 1)) ;;
                1) err "  V12 FAIL: ${uki#/mnt} is UNSIGNED and Secure Boot is enabled — the firmware will refuse it!"
                   ERRORS=$((ERRORS + 1)) ;;
                *) SIG_UNKNOWN=$((SIG_UNKNOWN + 1)) ;;
            esac
        done
        if [ "$SIG_UNKNOWN" -eq "$SIG_TOTAL" ]; then
            warn "  V12 SKIP: no sbverify/sbctl in the live environment — signatures unverified"
        else
            log "  V12 OK: $SIG_OK/$SIG_TOTAL UKI(s) signed"
        fi
    fi
else
    log "  V11 SKIP: no Unified Kernel Images on this target"
    log "  V12 SKIP: no Unified Kernel Images to verify signatures on"
fi

# ─── V13: systemd-boot ───────────────────────────────────────────────────────
# Confirms the thing that actually boots got configured. On a systemd-boot box
# that is either a UKI (V11) or a Type #1 entry (V5); at least one must exist.
if [ "${UKI_SDBOOT:-0}" -eq 1 ]; then
    CHECKS=$((CHECKS + 1))
    SDB_OK=0
    if [ "$LL_HAVE_UKI_LIB" -eq 1 ] && [ "${#UKI_PATHS[@]}" -gt 0 ]; then
        log "  V13 OK: systemd-boot boots ${#UKI_PATHS[@]} UKI(s) — covered by V11"
        SDB_OK=1
    fi
    for sdb_dir in /mnt/efi /mnt/boot /mnt/boot/efi; do
        [ -d "$sdb_dir/loader/entries" ] || continue
        for sdb_entry in "$sdb_dir"/loader/entries/*.conf; do
            [ -f "$sdb_entry" ] || continue
            if [ -z "$LUKS_BOOT_ARGS" ] || grep -qF "$LUKS_BOOT_ARGS" "$sdb_entry"; then
                SDB_OK=1
            fi
        done
    done
    if [ "$SDB_OK" -eq 1 ]; then
        log "  V13 OK: systemd-boot has at least one bootable entry pointing at the encrypted root"
    else
        err "  V13 FAIL: systemd-boot found ($UKI_SDBOOT_DETAIL) but nothing it can boot"
        err "            carries the LUKS arguments — the machine will not unlock!"
        ERRORS=$((ERRORS + 1))
    fi
else
    log "  V13 SKIP: systemd-boot not detected on this target"
fi

# ─── V14: every kernel command-line carrier ──────────────────────────────────
# /etc/kernel/cmdline, cmdline.d, Type #1 entries wherever the ESP is,
# extlinux, cmdline.txt, rEFInd, Limine, GRUB drop-ins: none may still name
# the raw partition in root=/resume=, and the ones an initramfs reads its
# arguments from must carry them.
V14_TOTAL=0; V14_BAD=0
while IFS=$'\t' read -r ckind cpath; do
    [ -n "$cpath" ] || continue
    V14_TOTAL=$((V14_TOTAL + 1))
    case "$ckind" in
        limine-default) BADREF=$(cl_carrier_bad_root grubvar "$cpath" 'KERNEL_CMDLINE(\[[^]]*\])?') ;;
        grubd)          BADREF=$(cl_carrier_bad_root grubvar "$cpath" 'GRUB_CMDLINE_LINUX(_DEFAULT)?') ;;
        *)              BADREF=$(cl_carrier_bad_root "$ckind" "$cpath") ;;
    esac
    if [ -n "$BADREF" ]; then
        err "  V14 FAIL: ${cpath#/mnt} still names the raw partition: $(echo "$BADREF" | tr '\n' ' ')"
        ERRORS=$((ERRORS + 1)); V14_BAD=$((V14_BAD + 1))
        continue
    fi
    if [ -n "$LUKS_BOOT_ARGS" ]; then
        case "$ckind" in
            dropin|grubd) ;;   # fragments: the arguments live in one dedicated file / the main grub file
            cmdline)
                # /etc/kernel/cmdline may legitimately leave the arguments to
                # /etc/cmdline.d/90-linuxlocker.conf, and vice versa.
                if ! cl_has_all_args "$(tr '\n' ' ' < "$cpath")" \
                   && ! { [ -f /mnt/etc/cmdline.d/90-linuxlocker.conf ] && cl_has_all_args "$(cat /mnt/etc/cmdline.d/90-linuxlocker.conf)"; }; then
                    err "  V14 FAIL: ${cpath#/mnt} lacks the LUKS arguments!"
                    ERRORS=$((ERRORS + 1)); V14_BAD=$((V14_BAD + 1))
                fi ;;
            *)
                if ! grep -qF "$LUKS_BOOT_ARGS" "$cpath"; then
                    err "  V14 FAIL: ${cpath#/mnt} ($ckind) lacks the LUKS arguments!"
                    ERRORS=$((ERRORS + 1)); V14_BAD=$((V14_BAD + 1))
                fi ;;
        esac
    fi
done < <(cl_find_carriers /mnt)
if [ "$V14_TOTAL" -gt 0 ]; then
    CHECKS=$((CHECKS + 1))
    [ "$V14_BAD" -eq 0 ] && log "  V14 OK: $V14_TOTAL command-line carrier(s) point at the mapper and carry the arguments"
else
    log "  V14 SKIP: no additional command-line carriers on this target"
fi

# Add the chroot's and stage 6's recorded problems to the total
if [ "${CONFIG_ERRORS:-0}" -gt 0 ]; then
    err "  Stage 6 recorded $CONFIG_ERRORS configuration problem(s) — see the [ERROR] lines above."
fi
ERRORS=$((ERRORS + CHROOT_RC + ${CONFIG_ERRORS:-0}))

# ─── Verification Result ─────────────────────────────────────────────────────
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
if [ "$ERRORS" -eq 0 ]; then
    echo -e "║  ${GREEN}${BOLD}ALL $CHECKS APPLICABLE CHECKS PASSED — deployment verified.${NC}  ║"
else
    echo -e "║  ${RED}${BOLD}$ERRORS ERROR(S) DETECTED — DO NOT REBOOT until fixed!${NC}      ║"
fi
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

if [ "$ERRORS" -gt 0 ]; then
    fatal "Verification failed with $ERRORS error(s). See log: $DEPLOY_LOG"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Summary & Recovery Instructions
# ═══════════════════════════════════════════════════════════════════════════════
echo "Summary of changes:"
echo "  crypttab    : $LUKS_NAME UUID=$LUKS_UUID none $CRYPTTAB_OPTS"
echo "  fstab       : /dev/mapper/$LUKS_NAME (was UUID=$ORIG_FS_UUID)"
[ -f /mnt/etc/default/grub ]     && echo "  grub default: GRUB_ENABLE_CRYPTODISK=y${LUKS_BOOT_ARGS:+ + LUKS kernel args}"
[ -f /mnt/etc/kernel/cmdline ]   && echo "  kernel cmd  : ${LUKS_BOOT_ARGS:-'(crypttab-driven)'}"
[ -d /mnt/boot/loader/entries ]  && [ -n "$LUKS_BOOT_ARGS" ] && echo "  BLS entries : ALL updated with LUKS parameters"
[ -n "$RPI_CMDLINE" ]            && echo "  cmdline.txt : root=/dev/mapper/$LUKS_NAME"
[ -n "$EXTLINUX_CONF" ]          && echo "  extlinux    : root=/dev/mapper/$LUKS_NAME"
[ "${V14_TOTAL:-0}" -gt 0 ]      && echo "  cmdline     : $V14_TOTAL carrier file(s) verified (V14)"
echo "  initramfs   : ALL kernels rebuilt via $INITRAMFS_STYLE with LUKS unlock support"
if [ "$LL_HAVE_UKI_LIB" -eq 1 ] && [ "${#UKI_PATHS[@]}" -gt 0 ]; then
    echo "  UKI         : ${#UKI_PATHS[@]} image(s) rebuilt via ${UKI_REGEN}, signed via ${UKI_SIGN} (Secure Boot: ${UKI_SB_STATE})"
fi
[ "${UKI_SDBOOT:-0}" -eq 1 ] && echo "  systemd-boot: $UKI_SDBOOT_DETAIL"
echo "  header bkup : /boot/luks-header-backup.img + $STATE_DIR/"
if [ -f "$STATE_DIR/recovery-key.txt" ]; then
    echo "  recovery key: $STATE_DIR/recovery-key.txt  ← MOVE TO SECURE OFFLINE STORAGE"
fi
echo ""

# Save log to target system's /boot (survives if USB is removed)
cp "$DEPLOY_LOG" /mnt/boot/luks-deploy.log 2>/dev/null || true
chroot /mnt /bin/sh -c 'command -v restorecon >/dev/null && restorecon -F /boot/luks-deploy.log' 2>/dev/null || true
log "Log also saved to target: /boot/luks-deploy.log"
echo ""
echo "Full log: $DEPLOY_LOG (on deployment drive)"
echo "          /boot/luks-deploy.log (on target system)"
echo ""
echo "Pre-encryption backups: $STATE_DIR/"
echo ""
MOUNT_HINT="mount /dev/mapper/${LUKS_NAME} /mnt"
[ "$IS_BTRFS" -eq 1 ] && [ -n "$ROOT_SUBVOL" ] && MOUNT_HINT="mount -o subvol=$ROOT_SUBVOL /dev/mapper/${LUKS_NAME} /mnt"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  You can now reboot. You will be prompted for your        ║"
echo "║  LUKS passphrase at boot.                                 ║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  NOTE: The password prompt may appear behind boot text.   ║"
echo "║  If the system appears hung, just type your passphrase.   ║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  If the system fails to boot:                             ║"
echo "║  1. Boot from live USB                                    ║"
echo "║  2. cryptsetup open $TARGET_ROOT ${LUKS_NAME}"
echo "║  3. $MOUNT_HINT"
echo "║  4. Mount /boot (+EFI/firmware), bind /dev /proc /sys /run║"
echo "║  5. chroot /mnt and fix configuration                     ║"
echo "║  6. Header restore if needed:                             ║"
echo "║     cryptsetup luksHeaderRestore $TARGET_ROOT \\"
echo "║       --header-backup-file /boot/luks-header-backup.img   ║"
echo "╚════════════════════════════════════════════════════════════╝"
