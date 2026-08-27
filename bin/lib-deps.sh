#!/bin/bash
#
# LinuxLocker — universal in-place LUKS2 encryption for Linux (x86_64 / aarch64)
# https://github.com/doug445/LinuxLocker
#
# Copyright (c) 2026 William MacKinnon <spilled-bowline0j@icloud.com>
# SPDX-License-Identifier: MIT
#
# ============================================================================
# lib-deps.sh — shared OS / package-manager detection + dependency installer
# ============================================================================
# Sourced (not executed) by linuxlocker.sh and luks-deploy.sh. Provides:
#
#   ll_detect_os          fill LL_OS_ID / LL_OS_LIKE / LL_OS_PRETTY / LL_FAMILY
#   ll_detect_pkg_mgr     fill LL_PKG_MGR (dnf/apt-get/pacman/zypper/apk/...)
#   ll_pkg_for <logical>  translate a logical package name to this distro's name
#   ll_install_pkgs ...   install packages with the detected manager
#   ll_ensure_tools ...   "cmd:logical-pkg" pairs — install whatever is missing
#
# Everything is best-effort detection from /etc/os-release plus which package
# managers actually exist on PATH; behaviour never depends on the distro name
# alone, only on the tools that are really present.
# ============================================================================

LL_OS_ID=""
LL_OS_LIKE=""
LL_OS_PRETTY="unknown"
LL_FAMILY="unknown"
LL_PKG_MGR=""
LL_PKG_REFRESHED=0

ll_detect_os() {
    local rel=/etc/os-release
    [ -r "$rel" ] || rel=/usr/lib/os-release
    if [ -r "$rel" ]; then
        LL_OS_ID=$(awk -F= '$1=="ID"{gsub(/"/,"",$2); print $2; exit}' "$rel")
        LL_OS_LIKE=$(awk -F= '$1=="ID_LIKE"{gsub(/"/,"",$2); print $2; exit}' "$rel")
        # shellcheck disable=SC2034  # consumed by the scripts that source this library
        LL_OS_PRETTY=$(awk -F= '$1=="PRETTY_NAME"{gsub(/"/,"",$2); print $2; exit}' "$rel")
    fi
    ll_family_for "$LL_OS_ID $LL_OS_LIKE"
    LL_FAMILY="$LL_FAMILY_RESULT"
}

# ll_family_for "<id> <id_like...>" -> sets LL_FAMILY_RESULT
# Also used against a TARGET system's os-release (chroot), so it is a pure
# string classifier with no side effects on the LL_OS_* globals.
ll_family_for() {
    case " $1 " in
        *" fedora "*|*" rhel "*|*" centos "*|*" rocky "*|*" almalinux "*|*" nobara "*|*" amzn "*)
            LL_FAMILY_RESULT="redhat" ;;
        *" debian "*|*" ubuntu "*|*" raspbian "*|*" linuxmint "*|*" pop "*|*" elementary "*|*" kali "*)
            LL_FAMILY_RESULT="debian" ;;
        *" arch "*|*" archarm "*|*" manjaro "*|*" endeavouros "*|*" artix "*|*" cachyos "*)
            LL_FAMILY_RESULT="arch" ;;
        *" suse "*|*" opensuse "*|*" opensuse-tumbleweed "*|*" opensuse-leap "*|*" sles "*)
            LL_FAMILY_RESULT="suse" ;;
        *" alpine "*)  LL_FAMILY_RESULT="alpine" ;;
        *" void "*)    LL_FAMILY_RESULT="void" ;;
        *" gentoo "*)  LL_FAMILY_RESULT="gentoo" ;;
        *)             LL_FAMILY_RESULT="unknown" ;;
    esac
}

ll_detect_pkg_mgr() {
    # Prefer the manager the detected family implies, then fall back to
    # whatever exists — a live environment can carry more than one.
    local candidates=""
    case "$LL_FAMILY" in
        redhat) candidates="dnf5 dnf yum" ;;
        debian) candidates="apt-get" ;;
        arch)   candidates="pacman" ;;
        suse)   candidates="zypper" ;;
        alpine) candidates="apk" ;;
        void)   candidates="xbps-install" ;;
        gentoo) candidates="emerge" ;;
    esac
    candidates="$candidates dnf5 dnf yum apt-get pacman zypper apk xbps-install emerge"
    local m
    for m in $candidates; do
        if command -v "$m" >/dev/null 2>&1; then
            LL_PKG_MGR="$m"
            return 0
        fi
    done
    LL_PKG_MGR=""
    return 1
}

# Map a LOGICAL package name (Fedora naming used as the canonical form) to
# what this distro actually calls it.
ll_pkg_for() {
    local logical="$1"
    case "$LL_FAMILY:$logical" in
        # ── NTFS tools (ntfsresize) ─────────────────────────────────────────
        redhat:ntfsprogs)  echo "ntfsprogs" ;;
        debian:ntfsprogs)  echo "ntfs-3g" ;;
        arch:ntfsprogs)    echo "ntfs-3g" ;;
        suse:ntfsprogs)    echo "ntfsprogs" ;;
        alpine:ntfsprogs)  echo "ntfs-3g-progs" ;;
        void:ntfsprogs)    echo "ntfs-3g" ;;
        gentoo:ntfsprogs)  echo "sys-fs/ntfs3g" ;;
        # ── dialog (luks-tune UI) ───────────────────────────────────────────
        gentoo:dialog)     echo "dev-util/dialog" ;;
        # ── fastfetch (extras/luks-fetch-cache) ─────────────────────────────
        gentoo:fastfetch)  echo "app-misc/fastfetch" ;;
        # ── cryptsetup ──────────────────────────────────────────────────────
        gentoo:cryptsetup) echo "sys-fs/cryptsetup" ;;
        # ── filesystem tool collections (same name almost everywhere) ───────
        gentoo:btrfs-progs) echo "sys-fs/btrfs-progs" ;;
        gentoo:e2fsprogs)   echo "sys-fs/e2fsprogs" ;;
        gentoo:xfsprogs)    echo "sys-fs/xfsprogs" ;;
        gentoo:f2fs-tools)  echo "sys-fs/f2fs-tools" ;;
        gentoo:dosfstools)  echo "sys-fs/dosfstools" ;;
        gentoo:fatresize)   echo "sys-block/fatresize" ;;
        gentoo:util-linux)  echo "sys-apps/util-linux" ;;
        # ── default: logical name IS the package name ───────────────────────
        *) echo "$logical" ;;
    esac
}

ll_install_pkgs() {
    [ "$#" -gt 0 ] || return 0
    [ -n "$LL_PKG_MGR" ] || ll_detect_pkg_mgr || {
        echo "lib-deps: no supported package manager found (need one of: dnf, apt-get, pacman, zypper, apk, xbps-install, emerge)" >&2
        return 1
    }
    echo "  Installing with $LL_PKG_MGR: $*"
    case "$LL_PKG_MGR" in
        dnf5|dnf|yum)
            "$LL_PKG_MGR" -y install "$@" ;;
        apt-get)
            if [ "$LL_PKG_REFRESHED" -eq 0 ]; then
                DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
                LL_PKG_REFRESHED=1
            fi
            DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
        pacman)
            if [ "$LL_PKG_REFRESHED" -eq 0 ]; then
                pacman -Sy --noconfirm >/dev/null || true
                LL_PKG_REFRESHED=1
            fi
            pacman -S --noconfirm --needed "$@" ;;
        zypper)
            zypper --non-interactive install "$@" ;;
        apk)
            apk add "$@" ;;
        xbps-install)
            xbps-install -Sy "$@" ;;
        emerge)
            emerge --ask=n "$@" ;;
    esac
}

# ll_ensure_tools "cmd:logical-pkg" [...]
# For each pair, if the command is missing, queue its package; install the
# queue in one transaction; then verify every command actually appeared.
# Returns non-zero (with a clear message) if anything is still missing.
ll_ensure_tools() {
    local pair cmd logical missing_cmds=() want_pkgs=() p seen
    for pair in "$@"; do
        cmd="${pair%%:*}"
        logical="${pair#*:}"
        command -v "$cmd" >/dev/null 2>&1 && continue
        missing_cmds+=("$cmd")
        p="$(ll_pkg_for "$logical")"
        seen=0
        local q
        for q in "${want_pkgs[@]:-}"; do [ "$q" = "$p" ] && seen=1 && break; done
        [ "$seen" -eq 0 ] && want_pkgs+=("$p")
    done
    [ "${#missing_cmds[@]}" -eq 0 ] && return 0

    echo "  Missing tools: ${missing_cmds[*]}"
    if ! ll_install_pkgs "${want_pkgs[@]}"; then
        echo "lib-deps: package installation failed for: ${want_pkgs[*]}" >&2
        echo "lib-deps: install them manually and re-run." >&2
        return 1
    fi
    local still=()
    for pair in "$@"; do
        cmd="${pair%%:*}"
        command -v "$cmd" >/dev/null 2>&1 || still+=("$cmd")
    done
    if [ "${#still[@]}" -gt 0 ]; then
        echo "lib-deps: still missing after install: ${still[*]}" >&2
        return 1
    fi
    echo "  All requested tools are now present."
    return 0
}
