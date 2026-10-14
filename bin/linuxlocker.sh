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
# linuxlocker.sh — the front door. Run THIS from the live USB.
# ============================================================================
# What it does, in order:
#   1. Identifies the live environment's OS and package manager
#      (/etc/os-release + which of dnf/apt-get/pacman/zypper/apk/... exists).
#   2. Identifies every tool the requested action needs, installs whatever is
#      missing with the detected package manager, and verifies it appeared.
#   3. Hands off to the real script. Further filesystem-specific tools
#      (resize2fs, ntfsresize, ...) are resolved by luks-deploy.sh itself the
#      moment it knows which filesystem the target actually uses.
#
# Usage:
#   sudo ./linuxlocker.sh                    # deploy (the encrypter), default
#   sudo ./linuxlocker.sh deploy --dry-run   # full detection + plan, no writes
#   sudo ./linuxlocker.sh tune               # KDF tuning UI for existing LUKS2
#   sudo ./linuxlocker.sh post               # post-encryption-setup (on target)
#   sudo ./linuxlocker.sh bundle             # save a LUKS recovery bundle
#   sudo ./linuxlocker.sh diag               # read-only diagnostic bundle for
#                                            # a bug report (changes nothing)
#   ./linuxlocker.sh --help
#
# Environment knobs are documented in the header of bin/luks-deploy.sh and are
# passed straight through (LUKS_PROFILE, LUKS_TARGET_ROOT, LUKS_DRY_RUN, ...).
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    echo "linuxlocker.sh — the front door. Run THIS from the live USB."
    echo ""
    sed -n '/^# What it does, in order:/,/^# =\{20,\}$/p' "$0" | sed -e '$d' -e 's/^# \?//'
}

ACTION="deploy"
case "${1:-}" in
    -h|--help) usage; exit 0 ;;
    deploy|tune|post|bundle|diag) ACTION="$1"; shift ;;
    --*) : ;;                      # bare flags (e.g. --dry-run) go to deploy
    "") : ;;
    *) echo "linuxlocker.sh: unknown action '$1' (deploy|tune|post|bundle|diag, or --help)" >&2; exit 2 ;;
esac

# shellcheck source=lib-deps.sh
. "$SCRIPT_DIR/lib-deps.sh"

# ─── Apple Silicon / Fedora Asahi Remix — wrong tool ─────────────────────────
# Checked at the front door as well as in luks-deploy.sh, luks-tune.sh and
# post-encryption-setup.sh, so `linuxlocker.sh bundle` stops here too rather
# than describing an Asahi box with the wrong tool. Checked before the root
# check, as those three do, so it is the first thing an Asahi user sees.
#
# lib-deps.sh holds the canonical ll_detect_asahi / ll_asahi_refuse. One from
# before 1.2.0 has neither, and calling the missing function printed "command
# not found" and carried on; the identical copy below stands in when they are
# missing. tests/uki-fixture-test.sh fails if it stops matching lib-deps.sh.
# --- asahi_guard ---
if ! declare -F ll_detect_asahi >/dev/null || ! declare -F ll_asahi_refuse >/dev/null; then
    LL_ASAHI_REASON=""
    LL_ASAHILOCKER_URL="https://github.com/doug445/AsahiLocker"
    ll_detect_asahi() {
        local root="${1%/}" rel v d
        LL_ASAHI_REASON=""
        rel="$root/etc/os-release"
        [ -r "$rel" ] || rel="$root/usr/lib/os-release"
        if [ -r "$rel" ]; then
            v=$(grep -Ei '^(NAME|PRETTY_NAME|VARIANT|VARIANT_ID|ID)=' "$rel" 2>/dev/null | tr '[:upper:]' '[:lower:]')
            case "$v" in
                *asahi*) LL_ASAHI_REASON="os-release identifies Fedora Asahi Remix"; return 0 ;;
            esac
        fi
        for d in "$root"/usr/lib/modules/*asahi*/ "$root"/lib/modules/*asahi*/; do
            [ -d "$d" ] || continue
            LL_ASAHI_REASON="Asahi kernel installed ($(basename "$d"))"
            return 0
        done
        for d in "$root"/boot/efi/m1n1 "$root"/etc/default/m1n1 "$root"/usr/lib/asahi-boot; do
            [ -e "$d" ] || continue
            LL_ASAHI_REASON="m1n1 / asahi boot components present (${d#"$root"})"
            return 0
        done
        if [ -z "$root" ] && [ -r /proc/device-tree/compatible ]; then
            if tr -d '\0' < /proc/device-tree/compatible 2>/dev/null | grep -q 'apple,'; then
                LL_ASAHI_REASON="this machine is Apple Silicon (device-tree reports apple,*)"
                return 0
            fi
        fi
        return 1
    }
    ll_link() {
        printf '\033]8;;%s\033\\%s\033]8;;\033\\' "$1" "$2"
    }
    ll_asahi_refuse() {
        echo ""
        echo "╔════════════════════════════════════════════════════════════╗"
        echo "║  WRONG TOOL — use AsahiLocker for Fedora Asahi Remix       ║"
        echo "╚════════════════════════════════════════════════════════════╝"
        echo ""
        echo "  ${1:-Detected an Apple Silicon / Fedora Asahi Remix system.}"
        [ -n "$LL_ASAHI_REASON" ] && echo "  Reason: $LL_ASAHI_REASON"
        echo ""
        echo "  LinuxLocker deliberately drops the Asahi boot guards, because on"
        echo "  every other platform they are dead weight. Apple Silicon boots"
        echo "  iBoot -> m1n1 -> U-Boot -> GRUB, and its stub partitions are read"
        echo "  by the Apple firmware itself. Running this script here would"
        echo "  misidentify the boot chain and could leave the machine unbootable"
        echo "  in a way macOS recovery cannot fix for you."
        echo ""
        printf '  Use AsahiLocker instead:  '
        ll_link "$LL_ASAHILOCKER_URL" "$LL_ASAHILOCKER_URL"
        printf '\n\n'
        echo "      git clone $LL_ASAHILOCKER_URL"
        echo ""
    }
fi
# --- end asahi_guard ---
# The diagnostic bundle is the one action exempt: its job is to describe a
# machine that is already in the wrong state, so it must never be the thing
# that refuses. It still runs before the dependency installer.
if [ "$ACTION" != "diag" ] && ll_detect_asahi ""; then
    ll_asahi_refuse "This machine is Apple Silicon / Fedora Asahi Remix."
    exit 3
fi

[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo $0 ${ACTION}" >&2; exit 1; }

if [ "$ACTION" = "diag" ]; then
    exec "$SCRIPT_DIR/linuxlocker-diag.sh" "$@"
fi

echo "════════════════════════════════════════════════════════════"
echo " LinuxLocker — environment detection"
echo "════════════════════════════════════════════════════════════"
ll_detect_os
ll_detect_pkg_mgr || true
echo "  OS          : ${LL_OS_PRETTY}  (id=${LL_OS_ID:-?} family=${LL_FAMILY})"
echo "  Arch        : $(uname -m)"
echo "  Pkg manager : ${LL_PKG_MGR:-NONE FOUND}"
echo ""

if [ -z "$LL_PKG_MGR" ]; then
    echo "  WARNING: no supported package manager found. Missing tools cannot be"
    echo "  auto-installed; the scripts will stop and name anything they need."
    echo ""
fi

# Core tools every action needs. Filesystem-specific tools are resolved later
# by luks-deploy.sh once the target filesystem is known.
CORE_DEPS=(
    cryptsetup:cryptsetup
    blkid:util-linux
    lsblk:util-linux
    findmnt:util-linux
    blockdev:util-linux
)
case "$ACTION" in
    tune) CORE_DEPS+=(dialog:dialog) ;;
esac

echo "Checking core dependencies..."
ll_ensure_tools "${CORE_DEPS[@]}" || exit 1
echo "  Core dependencies OK."
echo ""

case "$ACTION" in
    deploy) exec "$SCRIPT_DIR/luks-deploy.sh" "$@" ;;
    tune)   exec "$SCRIPT_DIR/luks-tune.sh" "$@" ;;
    post)   exec "$SCRIPT_DIR/post-encryption-setup.sh" "$@" ;;
    bundle) exec "$SCRIPT_DIR/save-luks-recovery-bundle.sh" "$@" ;;
esac
