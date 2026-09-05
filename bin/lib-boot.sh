#!/bin/bash
#
# LinuxLocker — universal in-place LUKS2 encryption for Linux (x86_64 / aarch64)
# https://github.com/doug445/LinuxLocker
#
# Copyright (c) 2026 William MacKinnon <spilled-bowline0j@icloud.com>
# SPDX-License-Identifier: MIT
#
# ============================================================================
# lib-boot.sh — kernel command-line carriers + encrypted-/boot recognition
# ============================================================================
# Sourced (not executed) by luks-deploy.sh (live environment AND inside the
# chroot), luks-tune.sh, post-encryption-setup.sh, linuxlocker-diag.sh and
# tests/cmdline-fixture-test.sh.
#
# PART 1 — command-line carriers
#
# The kernel command line lives in more places than /etc/default/grub, and a
# target can have several of them at once. Every one that references the
# partition being encrypted by PARTUUID or device path must be rewritten to
# the mapper, every one that the initramfs reads its unlock instructions from
# must gain the LUKS arguments, and the splash tokens must be stripped from
# (and later restored to) all of them. One transform, many file formats:
#
#   kind      file                                          shape
#   cmdline   /etc/kernel/cmdline, cmdline.txt (RPi)        the whole file is one line
#   dropin    /etc/cmdline.d/*.conf (mkinitcpio UKIs)       one fragment per file
#   bls       {/boot,/efi,/boot/efi}/loader/entries/*.conf  'options ...' lines
#   extlinux  extlinux.conf (U-Boot distro-boot)            'APPEND ...' lines
#   refind    refind_linux.conf (rEFInd)                    "title" "cmdline"
#   limine    limine.conf / limine.cfg                      'cmdline: ...' lines
#   grubvar   /etc/default/grub, grub.d/*.cfg,              NAME="value" lines
#             /etc/default/limine
#
#   cl_transform <string>            apply the configured edits to one cmdline
#   cl_patch_file <kind> <file> [re] rewrite a carrier in place (inode kept)
#   cl_find_carriers <root>          list "kind<TAB>path" for a target root
#   cl_ref_is_target <spec>          does root=/resume=<spec> name the raw
#                                    partition (PARTUUID=, /dev/..., LABEL=)?
#   cl_grub_effective <root> <VAR>   VAR as grub-mkconfig would see it, after
#                                    /etc/default/grub AND grub.d/*.cfg
#
# Configure with globals before calling:
#   CL_MAPPER        mapper name (root_crypt)
#   CL_LUKS_ARGS     arguments to add ("" = none, e.g. initramfs-tools)
#   CL_TARGET_REAL   canonical raw partition path, for /dev/... references
#   CL_TARGET_PARTUUID, CL_LUKS_UUID   what PARTUUID= / UUID= must resolve to
#   CL_FS_UUID       the INNER filesystem's UUID — root=UUID=<this> is correct
#                    after encryption and is never touched
#   CL_FIX_ROOT=0    leave root=/resume= alone (default 1)
#   CL_ADD_ARGS=0    do not append CL_LUKS_ARGS (default 1)
#   CL_STRIP_TOKENS  space-separated tokens to remove (splash strip)
#   CL_ADD_TOKENS    space-separated tokens to append if absent (splash restore)
#
# PART 2 — encrypted /boot recognition
#
# LinuxLocker never sets up an encrypted /boot: GRUB has to do that unlock
# itself, single-threaded, with the firmware's contiguous heap as the memory
# ceiling. It does RECOGNISE volumes GRUB already unlocks, because two things
# would otherwise brick them: converting a LUKS1 header GRUB can only read as
# LUKS1, and re-costing a keyslot to argon2id that GRUB has no code for.
#
#   bt_grub_probe <luks-dev> [root]  -> BT_GRUB_UNLOCKS 0|1, BT_GRUB_EVIDENCE,
#                                       BT_GRUB_LUKS2 / BT_GRUB_ARGON2
#                                       yes|no|unknown, BT_GRUB_IMAGES
#   bt_grub_ms <ms>                  kernel-side unlock estimate -> GRUB's
#   bt_grub_mem_ok <kib>             within the GRUB argon2 memory ceiling?
#
# How the image is read: GRUB modules embed their names and symbols. An image
# that unlocks a LUKS2 volume with argon2id has to carry the argon2 module,
# whose one exported symbol is grub_crypto_argon2; a build without it (stock
# GRUB 2.12) still mentions "argon2id" in luks2.mod because that is where it
# prints "Argon2 not supported". Both strings were verified against a stock
# Fedora 2.12 grubaa64.efi and a self-built 2.14 image with argon2 embedded.
# ============================================================================

# All BT_/CL_ globals are read by the callers after sourcing, not within here.
# shellcheck disable=SC2034

CL_MAPPER="${CL_MAPPER:-root_crypt}"
CL_LUKS_ARGS="${CL_LUKS_ARGS:-}"
CL_TARGET_REAL="${CL_TARGET_REAL:-}"
CL_TARGET_PARTUUID="${CL_TARGET_PARTUUID:-}"
CL_LUKS_UUID="${CL_LUKS_UUID:-}"
CL_FS_UUID="${CL_FS_UUID:-}"
CL_FIX_ROOT="${CL_FIX_ROOT:-1}"
CL_ADD_ARGS="${CL_ADD_ARGS:-1}"
CL_STRIP_TOKENS="${CL_STRIP_TOKENS:-}"
CL_ADD_TOKENS="${CL_ADD_TOKENS:-}"
CL_CHANGED=0           # set by cl_patch_file: 1 when the file content changed
CL_PATCHED_FILES=""    # newline-separated list of files cl_patch_file changed

_cl_lc() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# cl_ref_is_target <spec> — does this root=/resume= value name the RAW target
# partition? After in-place encryption the inner filesystem keeps its UUID and
# LABEL, so UUID=<fs uuid> / LABEL=<fs label> still resolve correctly through
# the opened mapper and are left alone. What breaks is anything that names the
# partition itself: PARTUUID=, PARTLABEL=, /dev/nvme0n1p3, /dev/disk/by-id/…
cl_ref_is_target() {
    local spec="$1" v real
    case "$spec" in
        PARTUUID=*)
            v=${spec#PARTUUID=}
            [ -n "$CL_TARGET_PARTUUID" ] && [ "$(_cl_lc "$v")" = "$(_cl_lc "$CL_TARGET_PARTUUID")" ] ;;
        UUID=*)
            v=${spec#UUID=}
            # The LUKS container's own UUID: only ever correct for rd.luks.*,
            # never for root=. The inner filesystem's UUID is fine.
            [ -n "$CL_LUKS_UUID" ] && [ "$(_cl_lc "$v")" = "$(_cl_lc "$CL_LUKS_UUID")" ] ;;
        PARTLABEL=*)
            v=${spec#PARTLABEL=}
            [ -n "$CL_TARGET_REAL" ] && command -v blkid >/dev/null 2>&1 || return 1
            real=$(blkid -t "PARTLABEL=$v" -o device 2>/dev/null | head -1)
            [ -n "$real" ] && [ "$(readlink -f "$real" 2>/dev/null)" = "$CL_TARGET_REAL" ] ;;
        LABEL=*)
            # A filesystem label lives INSIDE the container; after encryption
            # blkid reports it on the mapper, not on the raw partition.
            return 1 ;;
        /dev/*)
            [ -n "$CL_TARGET_REAL" ] || return 1
            real=$(readlink -f "$spec" 2>/dev/null) || return 1
            [ "$real" = "$CL_TARGET_REAL" ] ;;
        *) return 1 ;;
    esac
}

# cl_has_all_args <string> — every token of CL_LUKS_ARGS already present?
cl_has_all_args() {
    local s=" $1 " tok
    [ -n "$CL_LUKS_ARGS" ] || return 0
    for tok in $CL_LUKS_ARGS; do
        case "$s" in *" $tok "*) ;; *) return 1 ;; esac
    done
    return 0
}

# cl_transform <string> — print the edited command line. Whitespace between
# tokens is normalised to single spaces; token order is preserved.
cl_transform() {
    local in="$1" tok key val s="" t
    local -a toks out=()
    in=${in//$'\r'/}          # CRLF from a Windows-edited cmdline.txt
    read -r -a toks <<< "$in"
    for tok in "${toks[@]}"; do
        case "$tok" in
            root=*|resume=*)
                key="${tok%%=*}"; val="${tok#*=}"
                if [ "$CL_FIX_ROOT" = "1" ] && cl_ref_is_target "$val"; then
                    tok="$key=/dev/mapper/$CL_MAPPER"
                fi ;;
        esac
        if [ -n "$CL_STRIP_TOKENS" ]; then
            case " $CL_STRIP_TOKENS " in *" $tok "*) continue ;; esac
        fi
        out+=("$tok")
    done
    [ "${#out[@]}" -gt 0 ] && s="${out[*]}"
    if [ "$CL_ADD_ARGS" = "1" ] && [ -n "$CL_LUKS_ARGS" ] && ! cl_has_all_args "$s"; then
        for t in $CL_LUKS_ARGS; do
            case " $s " in *" $t "*) ;; *) s="${s:+$s }$t" ;; esac
        done
    fi
    for t in $CL_ADD_TOKENS; do
        case " $s " in *" $t "*) ;; *) s="${s:+$s }$t" ;; esac
    done
    printf '%s' "$s"
}

# Strip one layer of matching quotes from a NAME=value right-hand side.
_cl_unquote() {
    local v="$1"
    case "$v" in
        \"*\") v=${v#\"}; v=${v%\"} ;;
        \'*\') v=${v#\'}; v=${v%\'} ;;
    esac
    printf '%s' "$v"
}

# cl_patch_file <kind> <file> [name-regex]
#   Rewrites the file in place. The temp file is written with `cat >` so the
#   inode, mode, owner and SELinux label survive (matters on /etc, and on a
#   FAT ESP where mv would create a fresh directory entry). Sets CL_CHANGED.
#   For kind=grubvar the third argument is an ERE for the variable name(s),
#   e.g. 'GRUB_CMDLINE_LINUX' or 'GRUB_CMDLINE_LINUX(_DEFAULT)?'.
cl_patch_file() {
    local kind="$1" file="$2" namere="${3:-}" line new tmp rc=0
    local -a lines=()
    CL_CHANGED=0
    [ -f "$file" ] || return 1
    tmp="$(dirname "$file")/.linuxlocker.$$"

    case "$kind" in
    cmdline)
        # The whole file is one command line; systemd and mkinitcpio join
        # multiple lines with spaces, and cmdline.txt must be one line.
        # Comment lines are kept where they are; only the rest is joined.
        line=""
        while IFS= read -r new || [ -n "$new" ]; do
            new=${new//$'\r'/}
            case "$new" in
                '#'*) lines+=("$new") ;;
                *)    line="${line:+$line }$new" ;;
            esac
        done < "$file"
        new=$(cl_transform "$line")
        lines+=("$new")
        printf '%s\n' "${lines[@]}" > "$tmp" || rc=1
        ;;
    dropin)
        # A fragment: fix root=, strip/add tokens, but never append the LUKS
        # arguments here — the caller puts those in one dedicated file so they
        # cannot end up duplicated across every fragment.
        while IFS= read -r line || [ -n "$line" ]; do
            line=${line//$'\r'/}
            case "$line" in
                ''|'#'*) lines+=("$line") ;;
                *) CL_ADD_ARGS=0 cl_transform_line_var new "$line"; lines+=("$new") ;;
            esac
        done < "$file"
        printf '%s\n' "${lines[@]}" > "$tmp" || rc=1
        ;;
    bls|extlinux|limine|refind|grubvar)
        while IFS= read -r line || [ -n "$line" ]; do
            _cl_patch_line "$kind" "$line" "$namere"
            lines+=("$CL_LINE")
        done < "$file"
        printf '%s\n' "${lines[@]}" > "$tmp" || rc=1
        ;;
    *)
        echo "cl_patch_file: unknown kind '$kind'" >&2
        return 2 ;;
    esac

    if [ "$rc" -ne 0 ]; then rm -f "$tmp"; return 1; fi
    # Unchanged content is left alone entirely. Without cmp (a minimal live
    # image) the file is rewritten, which is still correct, just not a no-op.
    if command -v cmp >/dev/null 2>&1 && cmp -s "$tmp" "$file"; then
        rm -f "$tmp"
        return 0
    fi
    cat "$tmp" > "$file" || { rm -f "$tmp"; return 1; }
    rm -f "$tmp"
    CL_CHANGED=1
    CL_PATCHED_FILES="${CL_PATCHED_FILES:+$CL_PATCHED_FILES
}$file"
    return 0
}

# cl_transform_line_var <varname> <string> — cl_transform into a variable
# without a subshell (keeps CL_* state, avoids a fork per line).
cl_transform_line_var() {
    local __v="$1"
    printf -v "$__v" '%s' "$(cl_transform "$2")"
}

# _cl_patch_line <kind> <line> [name-regex] -> CL_LINE
# Recognises the one line shape each carrier format uses for its command line
# and transforms only that part, leaving every other line byte-identical.
CL_LINE=""
_cl_patch_line() {
    local kind="$1" line="$2" namere="$3" pre val new
    line=${line//$'\r'/}
    CL_LINE="$line"
    case "$kind" in
    bls)
        # Boot Loader Specification Type #1: 'options <cmdline>'
        if [[ "$line" =~ ^([[:space:]]*options[[:space:]]+)(.*)$ ]]; then
            pre="${BASH_REMATCH[1]}"; val="${BASH_REMATCH[2]}"
            new=$(cl_transform "$val")
            CL_LINE="${pre}${new}"
        fi ;;
    extlinux)
        # syslinux / U-Boot distro-boot: '  APPEND <cmdline>' (either case)
        if [[ "$line" =~ ^([[:space:]]*[Aa][Pp][Pp][Ee][Nn][Dd][[:space:]]+)(.*)$ ]]; then
            pre="${BASH_REMATCH[1]}"; val="${BASH_REMATCH[2]}"
            new=$(cl_transform "$val")
            CL_LINE="${pre}${new}"
        fi ;;
    limine)
        # limine.conf: 'cmdline: <cmdline>' / 'kernel_cmdline: ...';
        # the older limine.cfg wrote 'CMDLINE=<cmdline>' / 'KERNEL_CMDLINE='.
        if [[ "$line" =~ ^([[:space:]]*([Kk][Ee][Rr][Nn][Ee][Ll]_)?[Cc][Mm][Dd][Ll][Ii][Nn][Ee][[:space:]]*[:=][[:space:]]*)(.*)$ ]]; then
            pre="${BASH_REMATCH[1]}"; val="${BASH_REMATCH[3]}"
            new=$(cl_transform "$val")
            CL_LINE="${pre}${new}"
        fi ;;
    refind)
        # refind_linux.conf: "Menu title"  "root=... ro quiet"
        if [[ "$line" =~ ^([[:space:]]*\"[^\"]*\"[[:space:]]+\")([^\"]*)(\".*)$ ]]; then
            pre="${BASH_REMATCH[1]}"; val="${BASH_REMATCH[2]}"
            new=$(cl_transform "$val")
            CL_LINE="${pre}${new}${BASH_REMATCH[3]}"
        fi ;;
    grubvar)
        # NAME="value" — /etc/default/grub, its grub.d/*.cfg drop-ins, and
        # /etc/default/limine's KERNEL_CMDLINE[default]="...". The name is an
        # ERE so one call can cover GRUB_CMDLINE_LINUX and _DEFAULT together.
        [ -n "$namere" ] || return 0
        # The name ERE may carry its own groups, so the value is the LAST
        # group, not a fixed index.
        if [[ "$line" =~ ^([[:space:]]*(${namere})=)(.*)$ ]]; then
            pre="${BASH_REMATCH[1]}"; val="${BASH_REMATCH[${#BASH_REMATCH[@]}-1]}"
            # A trailing comment after the closing quote is preserved, and so
            # is the quote style: a single-quoted value stays single-quoted
            # unless the new value itself contains a single quote.
            local rest="" q='"'
            case "$val" in
                \"*\"*) rest=${val#\"*\"}; val=${val%"$rest"} ;;
                \'*\'*) rest=${val#\'*\'}; val=${val%"$rest"}; q="'" ;;
            esac
            val=$(_cl_unquote "$val")
            new=$(cl_transform "$val")
            case "$new" in *"'"*) q='"' ;; esac
            CL_LINE="${pre}${q}${new}${q}${rest}"
        fi ;;
    esac
}

# cl_grub_var_defined <file> <VAR> — does this file define VAR (uncommented)?
cl_grub_var_defined() {
    grep -qE "^[[:space:]]*$2=" "$1" 2>/dev/null
}

# cl_grub_effective <root> <VAR> — the value grub-mkconfig would use. It
# sources /etc/default/grub and then every /etc/default/grub.d/*.cfg (Ubuntu:
# cloud images override GRUB_CMDLINE_LINUX_DEFAULT there, and some set
# GRUB_FORCE_PARTUUID), so a value written to /etc/default/grub can be
# silently replaced by a drop-in. Evaluated in a clean shell, exactly the way
# grub-mkconfig does it; the target's files are treated as the shell code
# they are, which is no more trust than running its update-grub in a chroot.
cl_grub_effective() {
    local root="${1%/}" var="$2"
    [ -f "$root/etc/default/grub" ] || return 1
    env -i sh -c '
        . "$1/etc/default/grub" 2>/dev/null
        for x in "$1"/etc/default/grub.d/*.cfg; do
            [ -e "$x" ] && . "$x" 2>/dev/null
        done
        eval "printf %s \"\$$2\""
    ' _ "$root" "$var" 2>/dev/null
}

# cl_find_carriers <root> — every command-line carrier on the target, as
# "kind<TAB>path" lines. /etc/default/grub itself is deliberately NOT listed:
# stage 6c owns it. The grub.d drop-ins are, because they can override it.
cl_find_carriers() {
    local root="${1%/}" f d
    [ -f "$root/etc/kernel/cmdline" ] && printf 'cmdline\t%s\n' "$root/etc/kernel/cmdline"
    for f in "$root"/etc/cmdline.d/*.conf; do
        [ -f "$f" ] && printf 'dropin\t%s\n' "$f"
    done
    for d in /boot /efi /boot/efi; do
        for f in "$root$d"/loader/entries/*.conf; do
            [ -f "$f" ] && printf 'bls\t%s\n' "$f"
        done
    done
    for f in "$root/boot/extlinux/extlinux.conf" "$root/extlinux/extlinux.conf"; do
        [ -f "$f" ] && { printf 'extlinux\t%s\n' "$f"; break; }
    done
    for f in "$root/boot/firmware/cmdline.txt" "$root/boot/cmdline.txt"; do
        [ -f "$f" ] && { printf 'cmdline\t%s\n' "$f"; break; }
    done
    # rEFInd reads refind_linux.conf from the directory the kernel is in.
    for f in "$root/boot/refind_linux.conf" \
             "$root"/boot/efi/EFI/*/refind_linux.conf \
             "$root"/efi/EFI/*/refind_linux.conf \
             "$root"/boot/EFI/*/refind_linux.conf; do
        [ -f "$f" ] && printf 'refind\t%s\n' "$f"
    done
    # Limine looks beside its EFI app, then /boot/limine/, /boot/, /limine/, /.
    for f in "$root"/boot/limine.conf "$root"/boot/limine.cfg \
             "$root"/boot/limine/limine.conf "$root"/boot/limine/limine.cfg \
             "$root"/boot/efi/EFI/BOOT/limine.conf "$root"/boot/efi/EFI/BOOT/limine.cfg \
             "$root"/efi/EFI/BOOT/limine.conf "$root"/efi/EFI/BOOT/limine.cfg \
             "$root"/boot/EFI/BOOT/limine.conf "$root"/boot/EFI/BOOT/limine.cfg \
             "$root"/boot/efi/limine.conf "$root"/efi/limine.conf \
             "$root"/boot/efi/limine/limine.conf "$root"/efi/limine/limine.conf; do
        [ -f "$f" ] && printf 'limine\t%s\n' "$f"
    done
    # CachyOS / limine-entry-tool regenerate limine.conf from this file.
    [ -f "$root/etc/default/limine" ] && printf 'limine-default\t%s\n' "$root/etc/default/limine"
    for f in "$root"/etc/default/grub.d/*.cfg; do
        [ -f "$f" ] && printf 'grubd\t%s\n' "$f"
    done
    return 0
}

# cl_carrier_bad_root <kind> <file> [name-regex] — print every root=/resume=
# value in the carrier that still names the raw partition. Used by the
# verification gate; empty output means clean.
cl_carrier_bad_root() {
    local kind="$1" file="$2" namere="${3:-}" line val tok spec
    [ -f "$file" ] || return 0
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line//$'\r'/}
        val=""
        case "$kind" in
            cmdline|dropin) val="$line" ;;
            bls)      [[ "$line" =~ ^[[:space:]]*options[[:space:]]+(.*)$ ]] && val="${BASH_REMATCH[1]}" ;;
            extlinux) [[ "$line" =~ ^[[:space:]]*[Aa][Pp][Pp][Ee][Nn][Dd][[:space:]]+(.*)$ ]] && val="${BASH_REMATCH[1]}" ;;
            limine)   [[ "$line" =~ ^[[:space:]]*([Kk][Ee][Rr][Nn][Ee][Ll]_)?[Cc][Mm][Dd][Ll][Ii][Nn][Ee][[:space:]]*[:=][[:space:]]*(.*)$ ]] && val="${BASH_REMATCH[2]}" ;;
            refind)   [[ "$line" =~ ^[[:space:]]*\"[^\"]*\"[[:space:]]+\"([^\"]*)\" ]] && val="${BASH_REMATCH[1]}" ;;
            grubvar|grubd|limine-default)
                [ -n "$namere" ] && [[ "$line" =~ ^[[:space:]]*(${namere})=(.*)$ ]] && val=$(_cl_unquote "${BASH_REMATCH[${#BASH_REMATCH[@]}-1]}") ;;
        esac
        [ -n "$val" ] || continue
        case "$val" in '#'*) continue ;; esac
        for tok in $val; do
            case "$tok" in
                root=*|resume=*)
                    spec="${tok#*=}"
                    cl_ref_is_target "$spec" && printf '%s\n' "$tok" ;;
            esac
        done
    done < "$file"
    return 0
}

# ============================================================================
# PART 2 — encrypted /boot recognition
# ============================================================================

BT_GRUB_UNLOCKS=0          # 1 = GRUB itself opens this volume at boot
BT_GRUB_EVIDENCE=""        # one line saying how that was concluded
BT_GRUB_CRYPTODISK=0       # 1 = a GRUB image with cryptodisk was found at all
BT_GRUB_LUKS2="unknown"    # yes|no|unknown — can that GRUB read a LUKS2 header?
BT_GRUB_ARGON2="unknown"   # yes|no|unknown — can it open an argon2id keyslot?
BT_GRUB_IMAGES=""          # newline-separated list of images inspected

# GRUB runs the KDF single-threaded with no SIMD, so a kernel-side estimate
# does not transfer. Measured: 8.5x slower than the initramfs for the same
# argon2id parameters (GRUB 2.14, 4-lane parameters, 2.0 s per GiB-pass).
# That is one machine's number; it is a multiplier for orientation, not a
# promise. Override with LUKS_GRUB_KDF_FACTOR.
BT_GRUB_KDF_FACTOR="${LUKS_GRUB_KDF_FACTOR:-8.5}"

# argon2id needs its whole memory cost as ONE contiguous allocation, and GRUB
# takes it from the firmware's heap. On x86 UEFI that heap has never reliably
# given out more than 1 GiB — 2 GiB has only been shown to work under U-Boot's
# EFI on Apple Silicon, which LinuxLocker does not target (AsahiLocker does).
# 4 GiB is impossible on every platform: argon2_init multiplies a 32-bit
# block count and wraps to zero. So the ceiling here is 1 GiB, and a volume
# GRUB unlocks is never offered more.
BT_GRUB_ARGON2_MAX_KIB="${LUKS_GRUB_ARGON2_MAX_KIB:-1048576}"

# Long uninterrupted compute inside GRUB has been seen to trip a hardware
# watchdog and reset the machine (between 40 and 80 s on Apple Silicon).
# Nothing comparable is measured on x86; the number is shown as a caution.
BT_GRUB_RESET_WALL_S=40

bt_grub_ms() {   # $1 = kernel-side unlock estimate in ms -> GRUB estimate in ms
    case "$1" in ''|*[!0-9]*) echo ""; return 1 ;; esac
    awk -v ms="$1" -v f="$BT_GRUB_KDF_FACTOR" 'BEGIN{ printf "%.0f", ms * f }'
}

bt_grub_mem_ok() {   # $1 = memory cost in KiB
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
    [ "$1" -le "$BT_GRUB_ARGON2_MAX_KIB" ]
}

# _bt_scan_image <file> <uuid-nodash>
# GRUB images and ESP grub.cfg stubs are scanned as bytes. EFI images are
# uncompressed, so module names and symbols are visible; a BIOS core.img is
# LZMA-compressed and yields nothing, which is why the mounted-root rule below
# exists as the second source of evidence.
_bt_scan_image() {
    local f="$1" nodash="$2"
    grep -aq 'cryptomount' "$f" 2>/dev/null || return 1
    BT_GRUB_CRYPTODISK=1
    BT_GRUB_IMAGES="${BT_GRUB_IMAGES:+$BT_GRUB_IMAGES
}$f"
    if grep -aq 'luks2_' "$f" 2>/dev/null || grep -aq 'luks2\.mod' "$f" 2>/dev/null; then
        [ "$BT_GRUB_LUKS2" = "unknown" ] && BT_GRUB_LUKS2="yes"
    else
        BT_GRUB_LUKS2="no"
    fi
    if grep -aq 'Argon2 not supported' "$f" 2>/dev/null; then
        BT_GRUB_ARGON2="no"
    elif grep -aq 'grub_crypto_argon2' "$f" 2>/dev/null; then
        [ "$BT_GRUB_ARGON2" = "unknown" ] && BT_GRUB_ARGON2="yes"
    else
        # cryptodisk present but no argon2 symbol: the module is not embedded.
        [ "$BT_GRUB_ARGON2" = "unknown" ] && BT_GRUB_ARGON2="no"
    fi
    if [ -n "$nodash" ] && grep -aiq "$nodash" "$f" 2>/dev/null; then
        BT_GRUB_UNLOCKS=1
        [ -n "$BT_GRUB_EVIDENCE" ] || BT_GRUB_EVIDENCE="$f names the UUID of this volume next to cryptomount"
    fi
    return 0
}

# bt_grub_probe <luks-dev> [root]
#   <root> = a directory where the volume's root filesystem is mounted (may be
#   "" for the running system, or omitted when it cannot be opened). Two
#   independent sources of evidence:
#     1. every GRUB image and grub.cfg on every vfat partition of the same
#        disk — the embedded early config names the UUID it cryptomounts;
#     2. the target itself: no separate /boot in its fstab and a GRUB
#        directory inside the volume means GRUB must open the volume to load
#        the kernel at all.
bt_grub_probe() {
    local dev="$1" root="" have_root=0 disk uuid nodash part fs mp tmp f
    if [ "$#" -ge 2 ]; then root="${2%/}"; have_root=1; fi
    BT_GRUB_UNLOCKS=0; BT_GRUB_EVIDENCE=""; BT_GRUB_CRYPTODISK=0
    BT_GRUB_LUKS2="unknown"; BT_GRUB_ARGON2="unknown"; BT_GRUB_IMAGES=""

    uuid=$(cryptsetup luksUUID "$dev" 2>/dev/null || blkid -s UUID -o value "$dev" 2>/dev/null || true)
    nodash=$(printf '%s' "$uuid" | tr -d '-' | tr '[:upper:]' '[:lower:]')
    disk=$(lsblk -dno PKNAME "$dev" 2>/dev/null | head -1)

    # 1. Images and stubs on every FAT partition of this disk.
    if [ -n "$disk" ]; then
        while read -r part fs; do
            [ -n "$part" ] && [ "$fs" = "vfat" ] || continue
            mp=$(findmnt -rno TARGET -S "/dev/$part" 2>/dev/null | head -1)
            tmp=""
            if [ -z "$mp" ]; then
                tmp=$(mktemp -d /tmp/luks-grub-probe.XXXXXX) || continue
                if mount -o ro "/dev/$part" "$tmp" 2>/dev/null; then mp="$tmp"; else rmdir "$tmp"; continue; fi
            fi
            for f in "$mp"/EFI/*/grub.cfg "$mp"/EFI/*/*.efi "$mp"/EFI/*/*.EFI "$mp"/grub/*.cfg "$mp"/grub2/*.cfg; do
                [ -f "$f" ] || continue
                _bt_scan_image "$f" "$nodash" || true
            done
            if [ -n "$tmp" ]; then umount "$tmp" 2>/dev/null; rmdir "$tmp" 2>/dev/null; fi
        done < <(lsblk -rno NAME,FSTYPE "/dev/$disk" 2>/dev/null)
    fi

    # 2. The volume's own layout, when its root is readable.
    if [ "$have_root" -eq 1 ]; then
        local fstab="$root/etc/fstab" sep_boot="" g
        if [ -f "$fstab" ]; then
            sep_boot=$(awk '$1 !~ /^#/ && $2 == "/boot" { print $1; exit }' "$fstab" 2>/dev/null)
        elif [ -z "$root" ]; then
            sep_boot=$(findmnt -no SOURCE /boot 2>/dev/null)
        fi
        if [ -z "$sep_boot" ]; then
            for g in "$root/boot/grub2/grub.cfg" "$root/boot/grub/grub.cfg"; do
                [ -f "$g" ] || continue
                BT_GRUB_UNLOCKS=1
                [ -n "$BT_GRUB_EVIDENCE" ] || BT_GRUB_EVIDENCE="no separate /boot in fstab and ${g#"$root"} is inside the volume — GRUB must open it to load the kernel"
                break
            done
        fi
        # Module files on the target say what its GRUB build CAN do, which is
        # weaker than what its installed image DOES embed — used only when
        # no image could be read (BIOS core.img is compressed).
        if [ "$BT_GRUB_CRYPTODISK" -eq 0 ] && [ "$BT_GRUB_UNLOCKS" -eq 1 ]; then
            for g in "$root"/usr/lib/grub/*/luks2.mod; do
                [ -f "$g" ] || continue
                if grep -aq 'Argon2 not supported' "$g"; then BT_GRUB_ARGON2="no"; fi
                break
            done
        fi
    fi
    return 0
}

# bt_grub_summary — a few lines for logs and menus.
bt_grub_summary() {
    if [ "$BT_GRUB_UNLOCKS" -eq 1 ]; then
        echo "GRUB unlocks this volume at boot (encrypted /boot)."
        echo "  evidence : $BT_GRUB_EVIDENCE"
        echo "  LUKS2    : $BT_GRUB_LUKS2   argon2id: $BT_GRUB_ARGON2"
        [ -n "$BT_GRUB_IMAGES" ] && printf '  images   : %s\n' "$(printf '%s' "$BT_GRUB_IMAGES" | tr '\n' ' ')"
    elif [ "$BT_GRUB_CRYPTODISK" -eq 1 ]; then
        echo "A GRUB image with cryptodisk was found, but it does not name this volume."
    else
        echo "GRUB does not unlock this volume (the initramfs does)."
    fi
}
