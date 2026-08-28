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

[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo $0 ${ACTION}" >&2; exit 1; }

# shellcheck source=lib-deps.sh
. "$SCRIPT_DIR/lib-deps.sh"

# The diagnostic bundle runs before every other gate — including the Asahi
# refusal and the dependency installer. Its job is to describe a machine that
# is already in the wrong state, so it must never be the thing that refuses.
if [ "$ACTION" = "diag" ]; then
    exec "$SCRIPT_DIR/linuxlocker-diag.sh" "$@"
fi

# ─── Apple Silicon / Fedora Asahi Remix — wrong tool ─────────────────────────
# Checked at the front door as well as in luks-deploy.sh, so `linuxlocker.sh
# post` and `bundle` stop here too rather than half-configuring an Asahi box.
if ll_detect_asahi ""; then
    ll_asahi_refuse "This machine is Apple Silicon / Fedora Asahi Remix."
    exit 3
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
