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
# extras/install.sh — disk-encryption status readout for fastfetch (optional)
# ============================================================================
# Installs luks-fetch-cache: prints an aligned one-line-per-volume summary of
# every LUKS and BitLocker volume attached to the box (KDF, cipher, key size,
# protector types). No key material is ever exposed — only public header
# metadata from `cryptsetup luksDump` / `bitlkDump`.
#
# fastfetch itself is installed too if it is missing, using the distro's
# package manager (detected via ../bin/lib-deps.sh).
#
#     sudo ./extras/install.sh              # install fastfetch (if needed),
#                                           # the readout + refresh timer
#     sudo ./extras/install.sh --uninstall  # removes the readout only, never
#                                           # fastfetch itself
#
# After installing, add this to ~/.config/fastfetch/config.jsonc:
#
#   { "type": "command", "key": "Disk Encryption", "text": "luks-fetch-cache 1" },
#   { "type": "command", "key": " ",               "text": "luks-fetch-cache 2" },
#   { "type": "command", "key": " ",               "text": "luks-fetch-cache 3" }
#
# fastfetch's `command` module renders output as a SINGLE line, so an embedded
# newline would escape the logo column. Hence one module per line number; a line
# number past the end prints nothing and fastfetch skips that module.
# ============================================================================
set -uo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin

G='\033[0;32m'; Y='\033[1;33m'; RED='\033[0;31m'; B='\033[1m'; N='\033[0m'
ok(){ echo -e "  ${G}[ok]${N} $*"; }; warn(){ echo -e "  ${Y}[warn]${N} $*"; }; err(){ echo -e "  ${RED}[fail]${N} $*"; }

[ "$(id -u)" -eq 0 ] || { err "run as root: sudo $0"; exit 1; }
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BIN=/usr/local/bin
UNITS=/etc/systemd/system

if [ "${1:-}" = "--uninstall" ]; then
    systemctl disable --now luks-fetch-cache.timer luks-fetch-cache.service >/dev/null 2>&1
    rm -f "$UNITS/luks-fetch-cache.timer" "$UNITS/luks-fetch-cache.service"
    rm -f "$BIN/luks-fetch-cache" /var/cache/luks-fetch.txt
    systemctl daemon-reload
    ok "luks-fetch-cache removed (fastfetch itself is left installed)"
    exit 0
fi

# ── fastfetch itself ────────────────────────────────────────────────────────
# The readout is a fastfetch module, so make sure fastfetch exists. Detection
# and package naming come from the shared dependency library; without it (or
# without a repo that carries fastfetch — e.g. Debian 12 or RHEL sans EPEL)
# this degrades to a warning with a pointer, never a hard failure: the cache
# script works standalone and fastfetch can be added later.
if command -v fastfetch >/dev/null 2>&1; then
    ok "fastfetch already installed ($(fastfetch --version 2>/dev/null | head -1 || echo version unknown))"
else
    echo -e "${B}fastfetch not found — installing...${N}"
    if [ -f "$HERE/../bin/lib-deps.sh" ]; then
        # shellcheck source=../bin/lib-deps.sh
        . "$HERE/../bin/lib-deps.sh"
        ll_detect_os
        if ll_detect_pkg_mgr && ll_ensure_tools fastfetch:fastfetch; then
            ok "fastfetch installed via $LL_PKG_MGR"
        else
            warn "could not install fastfetch with ${LL_PKG_MGR:-any package manager} —"
            warn "your distro may not package it (Debian 12, RHEL without EPEL...)."
            warn "Grab a package from https://github.com/fastfetch-cli/fastfetch/releases"
            warn "and re-run fastfetch setup later; the readout below installs anyway."
        fi
    else
        warn "../bin/lib-deps.sh not found — install fastfetch with your package manager."
    fi
fi

echo -e "${B}Installing luks-fetch-cache...${N}"
mkdir -p "$BIN"
cp -f "$HERE/bin/luks-fetch-cache" "$BIN/luks-fetch-cache" && chmod 0755 "$BIN/luks-fetch-cache" \
    && ok "installed $BIN/luks-fetch-cache" || { err "install failed"; exit 1; }
cp -f "$HERE/systemd/luks-fetch-cache.service" "$UNITS/"
cp -f "$HERE/systemd/luks-fetch-cache.timer"   "$UNITS/"
systemctl daemon-reload
systemctl enable --now luks-fetch-cache.timer >/dev/null 2>&1 \
    && ok "enabled luks-fetch-cache.timer (refreshes every 15 min)" \
    || warn "could not enable luks-fetch-cache.timer"

echo
echo -e "${B}Current readout:${N}"
"$BIN/luks-fetch-cache" | sed 's/^/    /'
echo
echo -e "${B}Now wire it into fastfetch${N} — add to ~/.config/fastfetch/config.jsonc:"
echo '    { "type": "command", "key": "Disk Encryption", "text": "luks-fetch-cache 1" },'
echo '    { "type": "command", "key": " ",               "text": "luks-fetch-cache 2" },'
echo '    { "type": "command", "key": " ",               "text": "luks-fetch-cache 3" }'
