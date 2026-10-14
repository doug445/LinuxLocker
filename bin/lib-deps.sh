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

# ============================================================================
# Apple Silicon / Fedora Asahi Remix guard
# ============================================================================
# LinuxLocker deliberately drops the Fedora Asahi Remix boot guards that
# AsahiLocker carries. Asahi is not "Fedora on different hardware": the boot
# chain is iBoot -> m1n1 -> U-Boot -> GRUB, /boot lives in its own partition
# inside an APFS-adjacent layout the Apple firmware also reads, and the stub
# partitions must not be touched by anything that assumes a normal ESP. A run
# here would misidentify all of that. Refuse, and point at the right tool.
#
#   ll_detect_asahi <rootdir>   0 = this is Asahi / Apple Silicon; sets
#                               LL_ASAHI_REASON. <rootdir> may be "" for the
#                               live environment.
#   ll_detect_asahi_dev <dev>   0 = <dev> belongs to an Apple Silicon / Asahi
#                               system, judged without unlocking it; sets
#                               LL_ASAHI_REASON. See its own comment.
#   ll_asahi_refuse <context>   print the refusal with a clickable link.

LL_ASAHI_REASON=""
LL_ASAHILOCKER_URL="https://github.com/doug445/AsahiLocker"

ll_detect_asahi() {
    local root="${1%/}" rel v d
    LL_ASAHI_REASON=""

    # 1. os-release. Fedora Asahi Remix names itself in NAME and ID — 44 ships
    #    NAME="Fedora Linux Asahi Remix", ID=fedora-asahi-remix, ID_LIKE=fedora
    #    — while VARIANT_ID holds only the desktop edition (kde), so the
    #    variant fields alone never catch it. NAME, PRETTY_NAME, VARIANT,
    #    VARIANT_ID and ID are all read.
    rel="$root/etc/os-release"
    [ -r "$rel" ] || rel="$root/usr/lib/os-release"
    if [ -r "$rel" ]; then
        v=$(grep -Ei '^(NAME|PRETTY_NAME|VARIANT|VARIANT_ID|ID)=' "$rel" 2>/dev/null | tr '[:upper:]' '[:lower:]')
        case "$v" in
            *asahi*) LL_ASAHI_REASON="os-release identifies Fedora Asahi Remix"; return 0 ;;
        esac
    fi

    # 2. An Asahi kernel, by module directory name.
    for d in "$root"/usr/lib/modules/*asahi*/ "$root"/lib/modules/*asahi*/; do
        [ -d "$d" ] || continue
        LL_ASAHI_REASON="Asahi kernel installed ($(basename "$d"))"
        return 0
    done

    # 3. m1n1, the Apple Silicon first-stage bootloader. Nothing else ships it.
    for d in "$root"/boot/efi/m1n1 "$root"/etc/default/m1n1 "$root"/usr/lib/asahi-boot; do
        [ -e "$d" ] || continue
        LL_ASAHI_REASON="m1n1 / asahi boot components present (${d#"$root"})"
        return 0
    done

    # 4. The live environment running ON Apple Silicon, whatever the target is.
    #    Only meaningful when probing the live system (empty root).
    if [ -z "$root" ] && [ -r /proc/device-tree/compatible ]; then
        if tr -d '\0' < /proc/device-tree/compatible 2>/dev/null | grep -q 'apple,'; then
            LL_ASAHI_REASON="this machine is Apple Silicon (device-tree reports apple,*)"
            return 0
        fi
    fi

    return 1
}

# ll_detect_asahi_dev <dev> — the partition (or volume) about to be acted on,
# judged WITHOUT unlocking it, so it can run before anything is done to it.
# The live check above cannot see a disk carried over from an Asahi system;
# this looks at what such a disk shows on the outside:
#   1. Apple Silicon system partitions on the same disk. util-linux names the
#      GPT types "Apple Silicon boot" (iBootSystemContainer) and "Apple
#      Silicon recovery" (RecoveryOSContainer); an Apple Silicon Mac's disk
#      carries both, beside macOS and the Asahi stub.
#   2. A filesystem already mounted from it, or from a mapper open on it (an
#      automounting desktop, a mapper kept from an earlier run): read where
#      it already is, as the root and as the btrfs subvolumes discovery tries.
#   3. The plain partitions beside it: m1n1 at the top of a FAT partition
#      (the Asahi ESP holds m1n1/), or a kernel whose release names asahi on
#      an ext2/3/4 one (Fedora Asahi Remix keeps /boot plain ext4, and
#      AsahiLocker leaves it so). Read through an existing mountpoint, else a
#      read-only probe mount — noload on ext3/4, so no journal is replayed.
#      The selected partition itself is never probe-mounted here.
# What none of this can see: a volume that is already LUKS, with nothing
# Asahi outside it. Its own filesystem is checked once something unlocks it.
ll_detect_asahi_dev() {
    local dev="$1" self disk path type fs mp sub tmp opts hit k
    LL_ASAHI_REASON=""
    self=$(lsblk -dnpo NAME "$dev" 2>/dev/null | head -n 1)
    [ -n "$self" ] || self="$dev"
    disk=$(lsblk -dno PKNAME "$dev" 2>/dev/null | head -n 1)

    if [ -n "$disk" ]; then
        while read -r path type; do
            case "${type,,}" in
                69646961-6700-11aa-aa11-00306543ecac)
                    LL_ASAHI_REASON="its disk carries an Apple Silicon boot partition ($path, iBootSystemContainer)"
                    return 0 ;;
                52637672-7900-11aa-aa11-00306543ecac)
                    LL_ASAHI_REASON="its disk carries an Apple Silicon recovery partition ($path, RecoveryOSContainer)"
                    return 0 ;;
            esac
        done < <(lsblk -rpno NAME,PARTTYPE "/dev/$disk" 2>/dev/null)
    fi

    while read -r path; do
        [ -n "$path" ] || continue
        while read -r mp; do
            [ -n "$mp" ] || continue
            for sub in "" root @rootfs @; do
                if ll_detect_asahi "${mp%/}${sub:+/$sub}"; then
                    LL_ASAHI_REASON="it is mounted at $mp, and $LL_ASAHI_REASON"
                    return 0
                fi
            done
        done < <(findmnt -lno TARGET -S "$path" 2>/dev/null)
    done < <(lsblk -rpno NAME "$dev" 2>/dev/null)

    if [ -n "$disk" ]; then
        while read -r path type fs; do
            [ "$type" = part ] && [ "$path" != "$self" ] || continue
            case "$fs" in
                vfat)      opts=ro ;;
                ext3|ext4) opts=ro,noload ;;
                ext2)      opts=ro ;;
                *)         continue ;;
            esac
            mp=$(findmnt -lno TARGET -S "$path" 2>/dev/null | head -n 1)
            tmp=""
            if [ -z "$mp" ]; then
                tmp=$(mktemp -d /tmp/luks-asahi-probe.XXXXXX) || continue
                if mount -t "$fs" -o "$opts" "$path" "$tmp" 2>/dev/null; then
                    mp="$tmp"
                else
                    rmdir "$tmp" 2>/dev/null
                    continue
                fi
            fi
            hit=""
            if [ "$fs" = vfat ]; then
                [ -e "$mp/m1n1" ] && hit="m1n1 on the FAT partition $path"
            else
                for k in "$mp"/vmlinuz-*asahi* "$mp"/boot/vmlinuz-*asahi*; do
                    [ -e "$k" ] || continue
                    hit="an Asahi kernel on $path ($(basename "$k"))"
                    break
                done
            fi
            if [ -n "$tmp" ]; then
                umount "$tmp" 2>/dev/null
                rmdir "$tmp" 2>/dev/null
            fi
            if [ -n "$hit" ]; then
                LL_ASAHI_REASON="its disk holds $hit"
                return 0
            fi
        done < <(lsblk -rpno NAME,TYPE,FSTYPE "/dev/$disk" 2>/dev/null)
    fi

    return 1
}

# Print a clickable link where the terminal supports OSC 8, and always print
# the bare URL too — a hyperlink nobody can copy out of a screenshot is worse
# than no hyperlink.
ll_link() {   # $1 = url, $2 = link text
    printf '\033]8;;%s\033\\%s\033]8;;\033\\' "$1" "$2"
}

ll_asahi_refuse() {   # $1 = short context for the first line
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
