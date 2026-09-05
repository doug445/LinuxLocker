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
# luks-tune.sh
# ============================================================================
# An ncurses front-end for inspecting and re-costing the KDF parameters of
# keyslots on LUKS2 volumes that ALREADY EXIST. Every conversion it writes is
# argon2id; a keyslot still on pbkdf2 is listed too (memory/threads shown as
# '-') so it can be converted to argon2id from the same menu.
#
# The deploy script's KDF profiles apply at luksFormat time only. A header
# keeps whatever it was built with, so this is the tool for changing your mind
# afterwards.
#
# Offers four tiers — paranoid (4 GiB x 12), aggressive (4 GiB x 10), moderate
# (2 GiB x 8), fast (1 GiB x 9) — plus custom. Note the deploy script's menu
# ships only the lower three: paranoid is a deliberate choice made after the
# fact, not something to land on by accepting a default.
#
# What it does:      cryptsetup luksConvertKey  — re-wraps ONE keyslot's key
#                    under new argon2id parameters, with --hash sha512 so the
#                    slot keeps the AF hash luks-deploy.sh formats with. Pass
#                    no --hash and cryptsetup falls back to its compiled-in
#                    default of sha256, which silently walks a sha512 keyslot
#                    BACKWARDS every time it is re-costed.
# What it cannot do: change the volume-key digest hash. That is fixed at
#                    luksFormat time, so a header built by stock cryptsetup
#                    keeps its sha256 digest no matter what is chosen here.
# What it never does: create or destroy a keyslot, change a passphrase, touch
#                    filesystem data, offer pbkdf2, or write a KDF that is
#                    cheaper than the 'fast' floor OR cheaper than what the
#                    keyslot already has. LinuxLocker hardens; a weaker keyslot is
#                    a manual `cryptsetup luksConvertKey` run outside this tool.
#                    There is no code path here that selects pbkdf2; see
#                    README, "Never use pbkdf2".
#
# Volumes that GRUB itself unlocks (encrypted /boot) are RECOGNISED, through
# bin/lib-boot.sh: the GRUB images on the disk and the volume's own layout
# say so. On such a volume this tool offers only what GRUB can take: argon2id
# is offered only when the GRUB image demonstrably embeds the argon2 module,
# memory is capped at 1 GiB (argon2id wants one contiguous allocation and the
# x86 UEFI heap has never reliably given more), and the unlock estimate is
# multiplied by GRUB's single-threaded slowdown (8.5x, measured; override
# with LUKS_GRUB_KDF_FACTOR). It never sets up an encrypted /boot and never
# writes pbkdf2, so a GRUB without argon2 is told so and left alone.
#
# The passphrase is never read, stored or passed by this script. cryptsetup
# prompts for it directly on the terminal, outside the ncurses UI.
#
# A header backup is taken before any write and its path is shown. Keep it
# until a successful boot confirms the new parameters.
#
# Usage:
#   sudo ./bin/luks-tune.sh              # interactive
#   sudo ./bin/luks-tune.sh --dry-run    # show the command, change nothing
#   ./bin/luks-tune.sh --help            # this text; needs no root, no dialog
#
# There are no other options. An unrecognised one is rejected rather than
# ignored: silently dropping a mistyped --dry-run would convert a keyslot for
# real while you believed nothing was being written.
# ============================================================================

set -euo pipefail

# ─── Argument guard ──────────────────────────────────────────────────────────
# Parsed before everything else so --help works without root, without dialog
# installed, and without probing any device. Unknown options are refused: the
# dangerous case is a mistyped --dry-run being ignored, which would re-cost a
# keyslot for real while the caller believed it was a rehearsal.
usage() { sed -n '/^# An ncurses front-end/,/^# =\{20,\}/p' "$0" | sed -e '$d' -e 's/^# \?//'; }

DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -h|--help) usage; exit 0 ;;
        *)
            printf 'luks-tune.sh: unknown option: %s\n' "$arg" >&2
            printf 'Try: luks-tune.sh --help\n' >&2
            exit 2
            ;;
    esac
done

# ─── Profiles (mirrors luks-deploy.sh; memory in KiB) ────────────────────────
P_PARANOID_MEM=4194304;   P_PARANOID_ITER=12
P_AGGRESSIVE_MEM=4194304; P_AGGRESSIVE_ITER=10
P_MODERATE_MEM=2097152;   P_MODERATE_ITER=8
P_FAST_MEM=1048576;       P_FAST_ITER=9

# The 'fast' profile is the floor, matching luks-deploy.sh. No override:
# below this you are asking for something weaker than cryptsetup's own
# default, which this tool will not write for you.
FLOOR_MEM_KIB=$P_FAST_MEM
FLOOR_ITER=$P_FAST_ITER
P_PARALLEL=4

# AF splitter hash, pinned to the same value luks-deploy.sh passes to
# luksFormat. luksConvertKey rewrites the keyslot area, so it re-runs the
# anti-forensic split and re-stamps this field; omitting --hash lets cryptsetup
# substitute its compiled-in default (sha256), turning a re-cost into a silent
# downgrade of a sha512 slot. Always sent explicitly, never inherited.
HASH=sha512

CRYPTSETUP=/usr/sbin/cryptsetup
[ -x "$CRYPTSETUP" ] || CRYPTSETUP=/sbin/cryptsetup
[ -x "$CRYPTSETUP" ] || { echo "cryptsetup not found" >&2; exit 1; }

# Encrypted-/boot recognition lives in lib-boot.sh, next to this script.
SELFDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
if [ -f "$SELFDIR/lib-boot.sh" ]; then
    # shellcheck source=lib-boot.sh
    . "$SELFDIR/lib-boot.sh"
    HAVE_BOOT_LIB=1
else
    echo "luks-tune.sh: lib-boot.sh not found next to this script — cannot tell whether GRUB unlocks a volume; continuing without that check." >&2
    HAVE_BOOT_LIB=0
fi

# ─── UI backend ──────────────────────────────────────────────────────────────
if command -v dialog >/dev/null 2>&1; then UI=dialog
elif command -v whiptail >/dev/null 2>&1; then UI=whiptail
else
    echo "Neither 'dialog' nor 'whiptail' is installed." >&2
    echo "  dnf/apt-get/pacman/zypper install dialog   (or run linuxlocker.sh tune," >&2
    echo "  which installs it for you)" >&2
    exit 1
fi

BACKTITLE="LinuxLocker — LUKS2 KDF tuning"
ui() { "$UI" --backtitle "$BACKTITLE" "$@"; }

die() { ui --title "Error" --msgbox "$1" 12 70 || true; clear; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: sudo $0" >&2; exit 1
fi

# ─── Discover LUKS2 volumes ──────────────────────────────────────────────────
mapfile -t CANDIDATES < <(lsblk -rpno NAME,FSTYPE | awk '$2=="crypto_LUKS"{print $1}')
[ "${#CANDIDATES[@]}" -gt 0 ] || die "No LUKS volumes found on this system."

MENU_ITEMS=()
for dev in "${CANDIDATES[@]}"; do
    "$CRYPTSETUP" isLuks --type luks2 "$dev" 2>/dev/null || continue
    size=$(lsblk -dno SIZE "$dev" 2>/dev/null | tr -d ' ')
    label=$("$CRYPTSETUP" luksDump "$dev" 2>/dev/null | awk -F': *' '/^Label:/{print $2}')
    [ -n "$label" ] && [ "$label" != "(no label)" ] || label="no label"
    MENU_ITEMS+=("$dev" "$size  $label")
done
[ "${#MENU_ITEMS[@]}" -gt 0 ] || die "Found LUKS volumes, but none are LUKS2.\n\nluksConvertKey applies to LUKS2 headers only."

DEV=$(ui --title "Select a LUKS2 volume" \
         --menu "Keyslot parameters are per-volume." 16 74 6 \
         "${MENU_ITEMS[@]}" 3>&1 1>&2 2>&3) || { clear; exit 0; }

# ─── Does GRUB itself unlock this volume? ────────────────────────────────────
# Its mapper may be the running root ("" = this system), mounted somewhere
# else (a live USB with the target at /mnt), or closed (image scan only).
GRUB_MODE=0
if [ "$HAVE_BOOT_LIB" -eq 1 ]; then
    PROBE_ROOT=""; HAVE_PROBE_ROOT=0
    DEV_MAPPER=$(lsblk -rno NAME,TYPE "$DEV" 2>/dev/null | awk '$2=="crypt"{print $1; exit}')
    if [ -n "$DEV_MAPPER" ]; then
        ROOT_SRC=$(findmnt -no SOURCE / 2>/dev/null | sed 's/\[.*//')
        if [ "$ROOT_SRC" = "/dev/mapper/$DEV_MAPPER" ]; then
            HAVE_PROBE_ROOT=1
        else
            PROBE_ROOT=$(findmnt -rno TARGET -S "/dev/mapper/$DEV_MAPPER" 2>/dev/null | head -1)
            [ -n "$PROBE_ROOT" ] && [ -f "$PROBE_ROOT/etc/fstab" ] && HAVE_PROBE_ROOT=1
        fi
    fi
    if [ "$HAVE_PROBE_ROOT" -eq 1 ]; then bt_grub_probe "$DEV" "$PROBE_ROOT"; else bt_grub_probe "$DEV"; fi
    if [ "$BT_GRUB_UNLOCKS" -eq 1 ]; then
        GRUB_MODE=1
        if [ "$BT_GRUB_ARGON2" != "yes" ]; then
            ui --title "GRUB unlocks this volume — argon2id not available" --msgbox \
"GRUB itself opens $DEV at boot (encrypted /boot):
  $BT_GRUB_EVIDENCE

Its GRUB image could not be shown to embed the argon2 module
(result: $BT_GRUB_ARGON2). Stock GRUB 2.12 prints 'Argon2 not
supported'; a keyslot re-costed to argon2id would be one GRUB
cannot open, and the machine would not boot.

LinuxLocker never sets up or re-embeds an encrypted /boot, and it
hardens only: it never writes pbkdf2 or any weaker KDF, so nothing
is offered here. A weaker keyslot is a manual cryptsetup
luksConvertKey you run yourself, outside this tool.
To strengthen this volume: build or install a GRUB with argon2
support, re-run grub-install so the image embeds it, then come
back. See docs/BOOTLOADERS.md, 'Encrypted /boot'." 20 74 || true
            clear; exit 1
        fi
        ui --title "GRUB unlocks this volume" --msgbox \
"GRUB itself opens $DEV at boot (encrypted /boot):
  $BT_GRUB_EVIDENCE

Its GRUB image embeds the argon2 module, so argon2id keyslots
can be re-costed — within what GRUB can do:

  memory   capped at $(( BT_GRUB_ARGON2_MAX_KIB / 1024 )) MiB. argon2id needs its whole
           memory cost as ONE contiguous allocation from the
           firmware heap; x86 UEFI has never reliably given
           more than 1 GiB (4 GiB overflows GRUB outright).
  time     GRUB runs the KDF single-threaded with no SIMD. The
           unlock estimates below are multiplied by ${BT_GRUB_KDF_FACTOR}
           (measured on one machine; LUKS_GRUB_KDF_FACTOR overrides).
  wall     long uninterrupted compute inside GRUB has tripped a
           firmware watchdog past ~${BT_GRUB_RESET_WALL_S} s on some hardware.

Only the 1 GiB profile and a custom cost within the cap are offered." 22 74 || { clear; exit 0; }
    fi
fi

# ─── Show current state ──────────────────────────────────────────────────────
slot_table() {   # $1 = device; emits "slot<TAB>kdf<TAB>mem_kib<TAB>iter<TAB>threads<TAB>afhash"
    # Every LUKS2 keyslot ends on 'Area offset:' whatever its KDF, so that is
    # the record terminator; fields absent for a given KDF keep the '-' they
    # were reset to. argon2id carries Time cost/Memory/Threads, pbkdf2 carries
    # none of them and puts its count on 'Iterations:' instead — a pbkdf2 slot
    # is still listed so it can be converted to argon2id from the same menu.
    # A pbkdf2 slot also has its own 'Hash:' line, which is the PBKDF2 hash and
    # NOT the AF hash; the capital H keeps those two patterns apart. ('Hash:'
    # and 'Iterations:' also occur in the Digests section, but slot is "" by
    # then, so neither can false-fire.)
    "$CRYPTSETUP" luksDump "$1" | awk '
        /^[[:space:]]+[0-9]+: luks2/ { slot=$1; sub(":","",slot); k="-"; m="-"; i="-"; t="-"; h="-"; next }
        slot!="" && /^[[:space:]]+PBKDF:/      { k=$2 }
        slot!="" && /^[[:space:]]+Time cost:/  { i=$3 }
        slot!="" && /^[[:space:]]+Memory:/     { m=$2 }
        slot!="" && /^[[:space:]]+Threads:/    { t=$2 }
        slot!="" && /^[[:space:]]+Iterations:/ { i=$2 }
        slot!="" && /^[[:space:]]+AF hash:/    { h=$3 }
        slot!="" && /^[[:space:]]+Area offset:/ {
            printf "%s\t%s\t%s\t%s\t%s\t%s\n", slot, k, m, i, t, h; slot=""
        }
    '
}

# The volume-key digest hash, read from the Digests section rather than a
# keyslot. luksConvertKey cannot change it, so it is reported, never written.
digest_hash() {   # $1 = device
    "$CRYPTSETUP" luksDump "$1" | awk '
        /^Digests:/ { d=1; next }
        d && /^[[:space:]]+Hash:/ { print $2; exit }
    '
}

# dialog refuses to draw a box taller than the terminal, and this script's
# confirmation text is long. Size the tall boxes from their own content and
# clamp to what the terminal can actually show.
box_height() {   # $1 = text, $2 = lines of chrome (title, buttons, padding)
    local n term
    n=$(printf '%s\n' "$1" | wc -l)
    n=$(( n + ${2:-7} ))
    term=$(tput lines 2>/dev/null) || term=24
    case "$term" in ''|*[!0-9]*) term=24;; esac
    [ "$n" -gt $((term - 2)) ] && n=$((term - 2))
    [ "$n" -lt 10 ] && n=10
    printf '%s' "$n"
}

human_mem() {
    case "$1" in ''|*[!0-9]*) printf '%s' "${1:--}"; return;; esac   # pbkdf2 slots carry '-'
    awk -v k="$1" 'BEGIN{ if (k>=1048576) printf "%.0f GiB", k/1048576; else printf "%.0f MiB", k/1024 }'
}

render_slots() {
    printf '%-5s %-9s %-8s %-6s %-8s %s\n' SLOT KDF MEMORY ITER THREADS 'AF HASH'
    printf '%s\n' "-------------------------------------------------------"
    while IFS=$'\t' read -r s k m i t h; do
        printf '%-5s %-9s %-8s %-6s %-8s %s\n' "$s" "$k" "$(human_mem "$m")" "$i" "$t" "$h"
    done
}

mapfile -t SLOTS < <(slot_table "$DEV")
[ "${#SLOTS[@]}" -gt 0 ] || die "Could not read any keyslots from $DEV."

SUMMARY=$(printf '%s\n' "${SLOTS[@]}" | render_slots)
DIGEST_HASH=$(digest_hash "$DEV"); [ -n "$DIGEST_HASH" ] || DIGEST_HASH="unknown"
ui --title "$DEV — current keyslots" \
   --msgbox "$SUMMARY

Volume-key digest: $DIGEST_HASH  (header-wide, set at luksFormat time)

Each keyslot carries its own parameters. A passphrase slot and a
keyfile slot on the same volume are commonly different. Re-costing
a slot here also rewrites its AF hash to $HASH." 20 74 || { clear; exit 0; }

# ─── Pick a slot ─────────────────────────────────────────────────────────────
SLOT_ITEMS=()
while IFS=$'\t' read -r s k m i t h; do
    SLOT_ITEMS+=("$s" "$k  $(human_mem "$m")  t=$i  threads=$t  $h")
done < <(printf '%s\n' "${SLOTS[@]}")

SLOT=$(ui --title "Select a keyslot to re-cost" \
          --menu "Only the chosen slot is changed." 16 74 6 \
          "${SLOT_ITEMS[@]}" 3>&1 1>&2 2>&3) || { clear; exit 0; }

CUR=$(printf '%s\n' "${SLOTS[@]}" | awk -F'\t' -v s="$SLOT" '$1==s')
CUR_KDF=$(echo "$CUR" | cut -f2); CUR_MEM=$(echo "$CUR" | cut -f3)
CUR_ITER=$(echo "$CUR" | cut -f4); CUR_PAR=$(echo "$CUR" | cut -f5)
CUR_HASH=$(echo "$CUR" | cut -f6)

# ─── Pick new parameters ─────────────────────────────────────────────────────
if [ "$GRUB_MODE" -eq 1 ]; then
    CHOICE=$(ui --title "New argon2id cost for slot $SLOT (GRUB-unlocked volume)" --menu \
"GRUB opens this volume, so memory is capped at $(( BT_GRUB_ARGON2_MAX_KIB / 1024 )) MiB — one
contiguous allocation from the firmware heap. Within that cap,
iterations are the only lever, and every one of them is paid
single-threaded inside GRUB at every boot." 16 74 2 \
    fast       "1 GiB x  9  at/above stock cryptsetup — ~24 GPU guesses at once" \
    custom     "1 GiB max; set iterations / threads yourself" \
    3>&1 1>&2 2>&3) || { clear; exit 0; }
else
    CHOICE=$(ui --title "New argon2id cost for slot $SLOT" --menu \
"Memory cost is the thing an attacker cannot buy their way around.
argon2id needs its full memory for EVERY guess, so a 24 GB GPU that
would run thousands of guesses at once against a weak KDF gets ~6
against 4 GiB. More memory is strictly stronger, but 4 GiB is
argon2id's maximum, so past it only iterations raise the price." 22 74 6 \
    paranoid   "4 GiB x 12  maximum — same ~6 guesses, each 20% dearer" \
    aggressive "4 GiB x 10  strongest shipped profile — ~6 at once" \
    moderate   "2 GiB x  8  strong — ~12 at once on that same GPU" \
    fast       "1 GiB x  9  at/above stock cryptsetup — ~24 at once" \
    custom     "set memory / iterations / threads yourself" \
    3>&1 1>&2 2>&3) || { clear; exit 0; }
fi

case "$CHOICE" in
    paranoid)   NEW_MEM=$P_PARANOID_MEM;   NEW_ITER=$P_PARANOID_ITER;   NEW_PAR=$P_PARALLEL ;;
    aggressive) NEW_MEM=$P_AGGRESSIVE_MEM; NEW_ITER=$P_AGGRESSIVE_ITER; NEW_PAR=$P_PARALLEL ;;
    moderate)   NEW_MEM=$P_MODERATE_MEM;   NEW_ITER=$P_MODERATE_ITER;   NEW_PAR=$P_PARALLEL ;;
    fast)       NEW_MEM=$P_FAST_MEM;       NEW_ITER=$P_FAST_ITER;       NEW_PAR=$P_PARALLEL ;;
    custom)
        # Prefill from the slot's current values where they are numeric; a
        # pbkdf2 slot carries '-' for memory/threads, so fall back to the
        # 'fast' profile's numbers there.
        DEF_MIB=$((P_FAST_MEM / 1024)); DEF_ITER="$CUR_ITER"; DEF_PAR=$P_PARALLEL
        case "$CUR_MEM"  in ''|*[!0-9]*) ;; *) DEF_MIB=$((CUR_MEM / 1024));; esac
        case "$CUR_ITER" in ''|*[!0-9]*) DEF_ITER=$P_FAST_ITER;; esac
        case "$CUR_PAR"  in ''|*[!0-9]*) ;; *) DEF_PAR="$CUR_PAR";; esac
        MIB=$(ui --title "Memory cost" --inputbox \
            "Memory in MiB (cryptsetup wants KiB; this converts for you).\n\nCurrent: $(human_mem "$CUR_MEM")" \
            12 70 "$DEF_MIB" 3>&1 1>&2 2>&3) || { clear; exit 0; }
        NEW_ITER=$(ui --title "Iteration cost" --inputbox \
            "Iterations (argon2id 'time cost').\n\nCurrent: $CUR_ITER" \
            12 70 "$DEF_ITER" 3>&1 1>&2 2>&3) || { clear; exit 0; }
        NEW_PAR=$(ui --title "Parallelism" --inputbox \
            "Threads (lanes).\n\nCurrent: $CUR_PAR" \
            12 70 "$DEF_PAR" 3>&1 1>&2 2>&3) || { clear; exit 0; }
        case "$MIB"      in ''|*[!0-9]*) die "Memory must be a whole number of MiB." ;; esac
        case "$NEW_ITER" in ''|*[!0-9]*) die "Iterations must be a whole number." ;; esac
        case "$NEW_PAR"  in ''|*[!0-9]*) die "Threads must be a whole number." ;; esac
        NEW_MEM=$((MIB * 1024))
        ;;
esac

# ─── Refuse accidentally-weak parameters ─────────────────────────────────────
if [ "$NEW_MEM" -lt "$FLOOR_MEM_KIB" ] \
   || [ $((NEW_MEM * NEW_ITER)) -lt $((FLOOR_MEM_KIB * FLOOR_ITER)) ]; then
    ui --title "Below the floor — refused" --msgbox \
"$(human_mem "$NEW_MEM") / $NEW_ITER iterations is below the 'fast'
profile ($(human_mem "$FLOOR_MEM_KIB") / $FLOOR_ITER iterations), which is this
tool's hard floor.

cryptsetup's own default is argon2id at ~1 GiB with iterations
tuned to 2000 ms. Anything cheaper than 'fast' would leave the
keyslot weaker than a plain luksFormat with no arguments — so
there is no 'proceed anyway' here.

A slip like 1048 where you meant 1048576 also lands here.

LinuxLocker hardens; it never writes a weaker KDF. A weaker keyslot is a
manual  cryptsetup luksConvertKey  you run yourself, outside this tool." 18 70
    clear; exit 1
fi

# ─── Never weaker than the slot is now ──────────────────────────────────────
# The static floor above catches cheap parameters; this catches a re-cost
# that is cheaper than what the keyslot ALREADY has (an aggressive slot taken
# down to fast, say). Either the memory drops, or the total work does — both
# make the slot easier to attack, and this tool exists to do the opposite.
# A pbkdf2 slot has no comparable memory cost: any argon2id is a hardening.
if [ "$CUR_KDF" = "argon2id" ]; then
    CUR_MEM_N=0; CUR_ITER_N=0
    case "$CUR_MEM"  in ''|*[!0-9]*) ;; *) CUR_MEM_N=$CUR_MEM ;; esac
    case "$CUR_ITER" in ''|*[!0-9]*) ;; *) CUR_ITER_N=$CUR_ITER ;; esac
    if [ "$CUR_MEM_N" -gt 0 ] && [ "$CUR_ITER_N" -gt 0 ] \
       && { [ "$NEW_MEM" -lt "$CUR_MEM_N" ] || [ $((NEW_MEM * NEW_ITER)) -lt $((CUR_MEM_N * CUR_ITER_N)) ]; }; then
        ui --title "Weaker than the slot is now — refused" --msgbox \
"Slot $SLOT already runs argon2id at $(human_mem "$CUR_MEM_N") x $CUR_ITER_N iterations.
$(human_mem "$NEW_MEM") x $NEW_ITER iterations is cheaper per guess — lower
memory, or less total work — and would make this keyslot easier
to attack than it is today.

LinuxLocker hardens; it never writes a weaker KDF. A weaker keyslot is a
manual  cryptsetup luksConvertKey  you run yourself, outside this tool." 16 70
        clear; exit 1
    fi
fi

# ─── Refuse what GRUB cannot open ───────────────────────────────────────────
if [ "$GRUB_MODE" -eq 1 ] && ! bt_grub_mem_ok "$NEW_MEM"; then
    ui --title "Above GRUB's ceiling — refused" --msgbox \
"$(human_mem "$NEW_MEM") is more than GRUB can allocate for argon2id on
this volume's unlock path. The ceiling is $(( BT_GRUB_ARGON2_MAX_KIB / 1024 )) MiB: argon2id wants
its whole memory cost as one contiguous block from the firmware
heap, and x86 UEFI has never reliably handed out more than 1 GiB.
(4 GiB overflows GRUB's 32-bit block count on every platform.)

A keyslot written above the ceiling is one GRUB cannot open, and
the machine would not boot. Raise iterations instead, or re-run
with LUKS_GRUB_ARGON2_MAX_KIB set if you have MEASURED a higher
allocation succeeding in GRUB on this exact machine." 18 74
    clear; exit 1
fi

# ─── Confirm ─────────────────────────────────────────────────────────────────
UUID=$("$CRYPTSETUP" luksUUID "$DEV")

# The digest hash is header-wide and luksConvertKey has no way to rewrite it,
# so it is stated rather than changed — otherwise a header left on sha256 by a
# stock luksFormat would look fully upgraded once the AF hash moved.
if [ "$DIGEST_HASH" = "$HASH" ]; then
    DIGEST_NOTE="The volume-key digest is already $DIGEST_HASH."
else
    DIGEST_NOTE="The volume-key digest stays $DIGEST_HASH: it is fixed at luksFormat
time and luksConvertKey cannot rewrite it. Only the AF hash moves."
fi
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP="/root/luks-header-${UUID}-${STAMP}.bin"

# Estimate what the new cost means as unlock latency on THIS machine, by
# calibrating against cryptsetup's own benchmark. It reports how many
# iterations fit in ~2000 ms, and CLAMPS the memory it will benchmark to what
# it can allocate right now — so above that clamp this is scaled from a
# smaller measurement, not measured outright.
kdf_estimate_ms() {   # $1 = mem KiB, $2 = iterations, $3 = threads -> milliseconds
    local out bi bm
    out=$("$CRYPTSETUP" benchmark --pbkdf argon2id --pbkdf-memory "$1" \
              --pbkdf-parallel "$3" 2>/dev/null | grep -m1 argon2id) || return 1
    bi=$(echo "$out" | awk '{print $2}'); bm=$(echo "$out" | awk '{print $4}')
    case "$bi" in ''|*[!0-9]*) return 1;; esac
    case "$bm" in ''|*[!0-9]*) return 1;; esac
    [ "$bi" -gt 0 ] && [ "$bm" -gt 0 ] || return 1
    awk -v ti="$2" -v tm="$1" -v bi="$bi" -v bm="$bm" \
        'BEGIN{ printf "%.0f", 2000.0 * (ti*tm) / (bi*bm) }'
}
fmt_s() { case "$1" in ''|*[!0-9]*) printf '?';; *) awk -v m="$1" 'BEGIN{ printf "%.1f s", m/1000 }';; esac; }

EST_CUR_MS=$(kdf_estimate_ms "$CUR_MEM" "$CUR_ITER" "$CUR_PAR" || echo "")
EST_NEW_MS=$(kdf_estimate_ms "$NEW_MEM" "$NEW_ITER" "$NEW_PAR" || echo "")
# What the operator waits for: the kernel-side figure, or GRUB's when GRUB
# does the unlock. The attacker-cost table below always uses kernel-side
# numbers — a cracking rig is not slowed down by the victim's bootloader.
UNLOCK_WHERE="in the initramfs"
if [ "$GRUB_MODE" -eq 1 ]; then
    UNLOCK_WHERE="in GRUB (x${BT_GRUB_KDF_FACTOR})"
    EST_CUR=$(fmt_s "$(bt_grub_ms "$EST_CUR_MS" || echo "")")
    EST_NEW=$(fmt_s "$(bt_grub_ms "$EST_NEW_MS" || echo "")")
else
    EST_CUR=$(fmt_s "$EST_CUR_MS")
    EST_NEW=$(fmt_s "$EST_NEW_MS")
fi

# What the cost is actually FOR. Attacker model, stated in the UI so the
# figure can be checked rather than taken on faith: 1000 top-end GPUs, each
# with 24 GiB of VRAM, each running as many concurrent guesses as this memory
# cost leaves room for, each guess costing the same work measured above.
# The KDF sets the price per guess; the passphrase sets how many guesses.
crack_years() {   # $1 = mem KiB, $2 = seconds per guess, $3 = passphrase bits
    awk -v mem="$1" -v t="$2" -v bits="$3" 'BEGIN{
        if (t <= 0 || mem <= 0) { print "?"; exit }
        vram = 24 * 1024 * 1024                       # KiB of VRAM per GPU
        lanes = int(vram / mem); if (lanes < 1) lanes = 1
        rate  = 1000 * lanes / t                      # guesses per second, whole fleet
        yrs   = (2 ^ (bits - 1)) / rate / 31557600    # half the keyspace, in years
        e = log(yrs) / log(10)
        printf "%d", int(e + 0.5)
    }'
}

# Anchor an exponent to something a person can picture. Keyed off the computed
# exponent, not the profile, so it stays true whatever parameters are chosen.
# The universe is ~1.4e10 years old; the later marks follow the standard
# stelliferous / degenerate / black-hole era sequence.
cosmic() {   # $1 = base-10 exponent of the crack time in years
    if   [ "$1" -lt 10 ]; then echo "less than the age of the universe"
    elif [ "$1" -lt 14 ]; then echo "long past the age of the universe"
    elif [ "$1" -lt 18 ]; then echo "every star has burned out"
    elif [ "$1" -lt 22 ]; then echo "galaxies have evaporated"
    elif [ "$1" -lt 31 ]; then echo "protons may have decayed"
    else                       echo "only black holes remain"
    fi
}

EST_NEW_S=$(awk -v m="${EST_NEW_MS:-0}" 'BEGIN{ printf "%.3f", m/1000 }')
strength_row() {   # $1 = label, $2 = passphrase bits
    local e; e=$(crack_years "$NEW_MEM" "$EST_NEW_S" "$2")
    case "$e" in ''|*[!0-9-]*) printf '  %-22s %s\n' "$1" "(not estimated)"; return;; esac
    printf '  %-22s 10^%-4s %s\n' "$1" "$e" "$(cosmic "$e")"
}
STRENGTH=$(
  strength_row "6 words   (77 bit)"  77
  strength_row "8 words  (103 bit)"  103
  strength_row "10 words (129 bit)"  129
)

CONFIRM="$(printf 'Device : %s\nUUID   : %s\nSlot   : %s' "$DEV" "$UUID" "$SLOT")

$(
  printf '  %-12s %-14s %s\n' '' 'now' 'after'
  printf '  %-12s %-14s %s\n' 'KDF'        "$CUR_KDF"                 'argon2id'
  printf '  %-12s %-14s %s\n' 'memory'     "$(human_mem "$CUR_MEM")"  "$(human_mem "$NEW_MEM")"
  printf '  %-12s %-14s %s\n' 'iterations' "$CUR_ITER"                "$NEW_ITER"
  printf '  %-12s %-14s %s\n' 'threads'    "$CUR_PAR"                 "$NEW_PAR"
  printf '  %-12s %-14s %s\n' 'AF hash'    "$CUR_HASH"                "$HASH"
  printf '  %-12s %-14s %s\n' 'unlock'     "~$EST_CUR"                "~$EST_NEW  $UNLOCK_WHERE"
)
$( if [ "$GRUB_MODE" -eq 1 ]; then
     printf '\nGRUB does this unlock: single-threaded, no SIMD, so the kernel-side\n'
     printf 'estimate is multiplied by %s (measured on one machine). ' "$BT_GRUB_KDF_FACTOR"
     GW=$(bt_grub_ms "${EST_NEW_MS:-0}" || echo 0)
     if [ "${GW:-0}" -ge $((BT_GRUB_RESET_WALL_S * 1000)) ]; then
       printf 'That is past\nthe ~%s s after which firmware watchdogs have RESET machines mid-\nunlock on some hardware. Consider fewer iterations.\n' "$BT_GRUB_RESET_WALL_S"
     else
       printf '\n'
     fi
   fi )

What that buys, against 1000 GPUs with 24 GiB each, all guessing
(years to search half the keyspace, and what has happened by then):

$STRENGTH

The universe is about 10^10 years old. Those numbers come from the
memory cost and your passphrase together — the KDF sets the price
of one guess, the passphrase sets how many guesses are needed. A
short or reused passphrase collapses the whole table; no KDF cost
can rescue it.

Unlock times are estimated on THIS machine and shift with load. At
boot the machine is idle, so real unlocks land at the fast end.

The header is backed up first to:
  $BACKUP

cryptsetup will prompt for the passphrase of slot $SLOT on the
terminal. This script never sees it.

The AF hash is written as $HASH explicitly. Left unset, cryptsetup
would substitute sha256 and this re-cost would quietly downgrade
the slot. $DIGEST_NOTE

Only this keyslot changes. Your passphrase does not change and no
filesystem data is touched."

if [ "$DRY_RUN" -eq 1 ]; then
    ui --title "Dry run — nothing will be changed" --msgbox \
"$CONFIRM

Command that would run:

  cryptsetup luksConvertKey -S $SLOT --hash $HASH --pbkdf argon2id \\
    --pbkdf-memory $NEW_MEM --pbkdf-force-iterations $NEW_ITER \\
    --pbkdf-parallel $NEW_PAR $DEV" "$(box_height "$CONFIRM" 12)" 76 || true
    clear; exit 0
fi

ui --title "Confirm" --yesno "$CONFIRM" "$(box_height "$CONFIRM" 7)" 76 || { clear; exit 0; }

# ─── Back up the header, then convert ────────────────────────────────────────
clear
umask 077
if ! "$CRYPTSETUP" luksHeaderBackup "$DEV" --header-backup-file "$BACKUP"; then
    echo "Header backup FAILED — refusing to modify the keyslot." >&2
    exit 1
fi
echo "Header backed up to $BACKUP"
echo ""
echo "Re-costing slot $SLOT on $DEV to $(human_mem "$NEW_MEM") / $NEW_ITER iterations, AF hash $HASH."
echo "cryptsetup will now ask for the passphrase that opens slot $SLOT."
echo ""

if "$CRYPTSETUP" luksConvertKey -S "$SLOT" --hash "$HASH" --pbkdf argon2id \
        --pbkdf-memory "$NEW_MEM" --pbkdf-force-iterations "$NEW_ITER" \
        --pbkdf-parallel "$NEW_PAR" "$DEV"; then
    RESULT=$(slot_table "$DEV" | render_slots)
    ui --title "Done — $DEV" --msgbox \
"$RESULT

Header backup kept at:
  $BACKUP

Keep it until a successful boot confirms the new parameters, then
delete it — it wraps your key under the OLD, cheaper cost." 20 76 || true
    clear
else
    echo ""
    echo "luksConvertKey FAILED. The keyslot is unchanged."
    echo "Header backup: $BACKUP"
    exit 1
fi
