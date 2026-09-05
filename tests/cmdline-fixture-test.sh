#!/bin/bash
#
# LinuxLocker — universal in-place LUKS2 encryption for Linux (x86_64 / aarch64)
# https://github.com/doug445/LinuxLocker
#
# Copyright (c) 2026 William MacKinnon <spilled-bowline0j@icloud.com>
# SPDX-License-Identifier: MIT
#
# ============================================================================
# cmdline-fixture-test.sh — exercise bin/lib-boot.sh against synthetic files.
#
# The kernel command line lives in a dozen file formats and a target can carry
# several at once. Every one that names the raw partition in root= has to be
# rewritten, every one the initramfs reads has to gain the unlock arguments,
# the splash has to come out of all of them and go back in later — and none
# of that may corrupt a file it does not understand. These fixtures are the
# exact line shapes of each format; the same functions run against them
# unmodified.
#
# What it proves:
#   1.  cl_transform: root=/resume= naming the raw partition become the
#       mapper; root=UUID=<inner fs> is left alone; arguments are appended
#       once; splash tokens strip and restore; CRLF is tolerated
#   2.  every carrier format round-trips: bls, extlinux, refind, limine,
#       grubvar (double/single quotes, trailing comment), cmdline, dropin
#   3.  patching is idempotent (a second run changes nothing) and preserves
#       the inode
#   4.  cl_find_carriers sees every layout, and cl_carrier_bad_root reports
#       exactly the stale references
#   5.  cl_grub_effective honours /etc/default/grub.d/*.cfg overrides
#   6.  bt_grub_probe: image strings classify a stock GRUB 2.12 (no argon2)
#       and a 2.14 build with argon2; the UUID-in-image rule and the
#       /boot-inside-the-volume rule both fire; the memory ceiling and the
#       unlock-time factor apply
#
# Run:  bash tests/cmdline-fixture-test.sh        (no root, no disk, no network)
# ============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
# shellcheck source=../bin/lib-boot.sh
. "$REPO/bin/lib-boot.sh"

PASS=0; FAIL=0; SKIP=0
pass() { echo "  PASS: $*"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP: $*"; SKIP=$((SKIP+1)); }
eq() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1: expected '$2', got '$3'"; fi; }

TMP=$(mktemp -d /tmp/luks-cmdline-fixture.XXXXXX)
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

# A fake raw partition: /dev/null is a real device node, so readlink -f and
# the /dev/... comparison behave exactly as they would with /dev/nvme0n1p3.
# (consumed by the lib-boot.sh functions)
# shellcheck disable=SC2034
CL_MAPPER=root_crypt
# shellcheck disable=SC2034
CL_TARGET_REAL=/dev/null
# shellcheck disable=SC2034
CL_TARGET_PARTUUID=aaaa-bbbb
# shellcheck disable=SC2034
CL_LUKS_UUID=LUKSUUID
# shellcheck disable=SC2034
CL_FS_UUID=fs-uuid-inner
CL_LUKS_ARGS="rd.luks.uuid=LUKSUUID rd.luks.name=LUKSUUID=root_crypt"
ARGS="$CL_LUKS_ARGS"

echo "═══════════════════════════════════════════════════════════════"
echo " LinuxLocker — kernel command-line carrier fixture tests"
echo "═══════════════════════════════════════════════════════════════"

# ─── 1. cl_transform ─────────────────────────────────────────────────────────
echo ""
echo "[1] cl_transform"
eq "root=PARTUUID=<target> becomes the mapper, args appended" \
   "root=/dev/mapper/root_crypt ro $ARGS" "$(cl_transform "root=PARTUUID=aaaa-bbbb ro")"
eq "PARTUUID comparison is case-insensitive" \
   "root=/dev/mapper/root_crypt $ARGS" "$(cl_transform "root=PARTUUID=AAAA-BBBB")"
eq "root=UUID=<inner fs> is correct after encryption and untouched" \
   "root=UUID=fs-uuid-inner ro $ARGS" "$(cl_transform "root=UUID=fs-uuid-inner ro")"
eq "root=UUID=<LUKS container> is wrong and becomes the mapper" \
   "root=/dev/mapper/root_crypt $ARGS" "$(cl_transform "root=UUID=LUKSUUID")"
eq "root=/dev/<partition> and resume=/dev/<partition> both rewritten" \
   "root=/dev/mapper/root_crypt resume=/dev/mapper/root_crypt rw $ARGS" \
   "$(cl_transform "root=/dev/null resume=/dev/null rw")"
eq "root=/dev/<other device> is left alone" \
   "root=/dev/zero rw $ARGS" "$(cl_transform "root=/dev/zero rw")"
eq "root=LABEL= is a filesystem label and is left alone" \
   "root=LABEL=fedora $ARGS" "$(cl_transform "root=LABEL=fedora")"
eq "arguments already present are not duplicated" \
   "root=UUID=fs-uuid-inner $ARGS" "$(cl_transform "root=UUID=fs-uuid-inner $ARGS")"
eq "partial arguments are completed, not duplicated" \
   "rd.luks.uuid=LUKSUUID ro rd.luks.name=LUKSUUID=root_crypt" \
   "$(cl_transform "rd.luks.uuid=LUKSUUID ro")"
eq "empty input yields just the arguments" "$ARGS" "$(cl_transform "")"
eq "CL_ADD_ARGS=0 appends nothing" "root=UUID=x" "$(CL_ADD_ARGS=0 cl_transform "root=UUID=x")"
eq "CL_FIX_ROOT=0 leaves root= alone" "root=PARTUUID=aaaa-bbbb $ARGS" \
   "$(CL_FIX_ROOT=0 cl_transform "root=PARTUUID=aaaa-bbbb")"
eq "splash strip removes every listed token, wherever it sits" \
   "root=UUID=x splash" \
   "$(CL_ADD_ARGS=0 CL_STRIP_TOKENS="rhgb quiet" cl_transform "quiet root=UUID=x rhgb quiet splash")"
eq "splash restore appends missing tokens once" \
   "root=UUID=x quiet rhgb" \
   "$(CL_ADD_ARGS=0 CL_ADD_TOKENS="rhgb quiet" cl_transform "root=UUID=x quiet")"
eq "CRLF input is normalised" "root=/dev/mapper/root_crypt ro $ARGS" \
   "$(cl_transform $'root=PARTUUID=aaaa-bbbb ro\r')"
eq "a quoted value with spaces survives token round-trip" \
   "systemd.setenv=\"A B\" root=UUID=x $ARGS" \
   "$(cl_transform "systemd.setenv=\"A B\"  root=UUID=x")"
eq "initramfs-tools: empty CL_LUKS_ARGS appends nothing" \
   "root=/dev/mapper/root_crypt ro" "$(CL_LUKS_ARGS="" cl_transform "root=/dev/null ro")"

# ─── 2. Carrier formats round-trip ───────────────────────────────────────────
echo ""
echo "[2] carrier formats"
R="$TMP/root"
mkdir -p "$R/etc/kernel" "$R/etc/cmdline.d" "$R/boot/loader/entries" "$R/efi/loader/entries" \
         "$R/boot/efi/loader/entries" "$R/boot/extlinux" "$R/boot/firmware" "$R/boot/limine" \
         "$R/boot/efi/EFI/arch" "$R/etc/default/grub.d"

printf 'title Arch\nlinux /vmlinuz-linux\ninitrd /initramfs-linux.img\noptions root=PARTUUID=aaaa-bbbb rw quiet\n' > "$R/boot/loader/entries/arch.conf"
cl_patch_file bls "$R/boot/loader/entries/arch.conf"
eq "bls: options line rewritten, other lines intact" \
   "title Arch|linux /vmlinuz-linux|initrd /initramfs-linux.img|options root=/dev/mapper/root_crypt rw quiet $ARGS" \
   "$(paste -sd'|' "$R/boot/loader/entries/arch.conf")"
eq "bls: CL_CHANGED set" "1" "$CL_CHANGED"

printf 'LABEL Fedora\n  KERNEL /vmlinuz\n  APPEND root=/dev/null ro console=ttyS0\nLABEL two\n  append root=PARTUUID=aaaa-bbbb\n' > "$R/boot/extlinux/extlinux.conf"
cl_patch_file extlinux "$R/boot/extlinux/extlinux.conf"
eq "extlinux: APPEND and append both rewritten" \
   "  APPEND root=/dev/mapper/root_crypt ro console=ttyS0 $ARGS|  append root=/dev/mapper/root_crypt $ARGS" \
   "$(grep -i append "$R/boot/extlinux/extlinux.conf" | paste -sd'|')"

printf '"Boot with standard options"  "root=PARTUUID=aaaa-bbbb rw quiet"\n"Boot to single-user mode"    "root=PARTUUID=aaaa-bbbb rw single"\n' > "$R/boot/refind_linux.conf"
cl_patch_file refind "$R/boot/refind_linux.conf"
eq "refind: second quoted string rewritten, title untouched" \
   "\"Boot with standard options\"  \"root=/dev/mapper/root_crypt rw quiet $ARGS\"" \
   "$(head -1 "$R/boot/refind_linux.conf")"

printf 'timeout: 5\n\n/ CachyOS\n    protocol: linux\n    path: boot():/vmlinuz-linux\n    cmdline: root=PARTUUID=aaaa-bbbb rw\n    module_path: boot():/initramfs-linux.img\n' > "$R/boot/limine/limine.conf"
cl_patch_file limine "$R/boot/limine/limine.conf"
eq "limine.conf: cmdline: rewritten" "    cmdline: root=/dev/mapper/root_crypt rw $ARGS" \
   "$(grep 'cmdline:' "$R/boot/limine/limine.conf")"
printf ':Arch\n    PROTOCOL=linux\n    CMDLINE=root=/dev/null rw\n' > "$R/boot/limine.cfg"
cl_patch_file limine "$R/boot/limine.cfg"
eq "limine.cfg (legacy): CMDLINE= rewritten" "    CMDLINE=root=/dev/mapper/root_crypt rw $ARGS" \
   "$(grep 'CMDLINE=' "$R/boot/limine.cfg")"
printf 'KERNEL_CMDLINE[default]="quiet root=PARTUUID=aaaa-bbbb"\nKERNEL_CMDLINE[fallback]="root=PARTUUID=aaaa-bbbb"\n' > "$R/etc/default/limine"
cl_patch_file grubvar "$R/etc/default/limine" 'KERNEL_CMDLINE(\[[^]]*\])?'
eq "/etc/default/limine: every KERNEL_CMDLINE[...] rewritten" \
   "KERNEL_CMDLINE[default]=\"quiet root=/dev/mapper/root_crypt $ARGS\"|KERNEL_CMDLINE[fallback]=\"root=/dev/mapper/root_crypt $ARGS\"" \
   "$(paste -sd'|' "$R/etc/default/limine")"

printf 'GRUB_DEFAULT=0\nGRUB_CMDLINE_LINUX_DEFAULT="quiet splash"\nGRUB_CMDLINE_LINUX=""\n#GRUB_CMDLINE_LINUX="commented"\n' > "$R/etc/default/grub"
cl_patch_file grubvar "$R/etc/default/grub" 'GRUB_CMDLINE_LINUX'
eq "grubvar: only GRUB_CMDLINE_LINUX touched, _DEFAULT and comment intact" \
   "GRUB_DEFAULT=0|GRUB_CMDLINE_LINUX_DEFAULT=\"quiet splash\"|GRUB_CMDLINE_LINUX=\"$ARGS\"|#GRUB_CMDLINE_LINUX=\"commented\"" \
   "$(paste -sd'|' "$R/etc/default/grub")"
printf "GRUB_CMDLINE_LINUX='root=/dev/null ro' # keep me\n" > "$R/etc/default/grub.d/50-x.cfg"
cl_patch_file grubvar "$R/etc/default/grub.d/50-x.cfg" 'GRUB_CMDLINE_LINUX'
eq "grubvar: single quotes and trailing comment preserved" \
   "GRUB_CMDLINE_LINUX='root=/dev/mapper/root_crypt ro $ARGS' # keep me" \
   "$(cat "$R/etc/default/grub.d/50-x.cfg")"
printf 'GRUB_CMDLINE_LINUX_DEFAULT="rhgb quiet"\nGRUB_CMDLINE_LINUX="rhgb quiet rd.x"\n' > "$R/etc/default/grub-strip"
CL_ADD_ARGS=0 CL_STRIP_TOKENS="rhgb quiet" cl_patch_file grubvar "$R/etc/default/grub-strip" 'GRUB_CMDLINE_LINUX(_DEFAULT)?'
eq "grubvar: splash stripped from BOTH variables via the name regex" \
   "GRUB_CMDLINE_LINUX_DEFAULT=\"\"|GRUB_CMDLINE_LINUX=\"rd.x\"" \
   "$(paste -sd'|' "$R/etc/default/grub-strip")"

printf '# generated\nroot=PARTUUID=aaaa-bbbb ro\nrootflags=subvol=root\n' > "$R/etc/kernel/cmdline"
cl_patch_file cmdline "$R/etc/kernel/cmdline"
eq "cmdline: lines joined into one, comment kept, root fixed, args added" \
   "# generated|root=/dev/mapper/root_crypt ro rootflags=subvol=root $ARGS" \
   "$(paste -sd'|' "$R/etc/kernel/cmdline")"
printf 'console=serial0,115200 root=PARTUUID=aaaa-bbbb rw quiet\r\n' > "$R/boot/firmware/cmdline.txt"
cl_patch_file cmdline "$R/boot/firmware/cmdline.txt"
eq "cmdline.txt: CRLF stripped, single line, root fixed" \
   "console=serial0,115200 root=/dev/mapper/root_crypt rw quiet $ARGS" "$(cat "$R/boot/firmware/cmdline.txt")"
[ "$(wc -l < "$R/boot/firmware/cmdline.txt")" = "1" ] && pass "cmdline.txt is exactly one line" || fail "cmdline.txt has more than one line"

printf '# fragment\nroot=/dev/null rw\nquiet splash\n' > "$R/etc/cmdline.d/10-root.conf"
cl_patch_file dropin "$R/etc/cmdline.d/10-root.conf"
eq "dropin: root fixed per line, NO arguments appended, comment kept" \
   "# fragment|root=/dev/mapper/root_crypt rw|quiet splash" "$(paste -sd'|' "$R/etc/cmdline.d/10-root.conf")"

printf 'title x\noptions root=UUID=fs-uuid-inner\n' > "$R/nonl.conf"; printf 'title y' >> "$R/nonl.conf"   # no trailing newline
cl_patch_file bls "$R/nonl.conf"
eq "a file without a trailing newline keeps its last line" "title y" "$(tail -1 "$R/nonl.conf")"

printf 'nothing here\n' > "$R/plain.txt"
cl_patch_file bls "$R/plain.txt"
eq "a file with no matching line is left byte-identical" "0" "$CL_CHANGED"
eq "an unknown kind is rejected" "2" "$(cl_patch_file bogus "$R/plain.txt" >/dev/null 2>&1; echo $?)"
eq "a missing file is a soft failure" "1" "$(cl_patch_file bls "$R/does-not-exist"; echo $?)"

# ─── 3. Idempotency and inode preservation ───────────────────────────────────
echo ""
echo "[3] idempotency"
INO_BEFORE=$(stat -c %i "$R/boot/loader/entries/arch.conf")
cl_patch_file bls "$R/boot/loader/entries/arch.conf"
eq "second pass over the same bls entry changes nothing" "0" "$CL_CHANGED"
eq "the inode is preserved across a rewrite" "$INO_BEFORE" "$(stat -c %i "$R/boot/loader/entries/arch.conf")"
cl_patch_file cmdline "$R/etc/kernel/cmdline"; eq "second pass over /etc/kernel/cmdline changes nothing" "0" "$CL_CHANGED"
cl_patch_file refind "$R/boot/refind_linux.conf"; eq "second pass over refind_linux.conf changes nothing" "0" "$CL_CHANGED"
cl_patch_file limine "$R/boot/limine/limine.conf"; eq "second pass over limine.conf changes nothing" "0" "$CL_CHANGED"

# ─── 4. Discovery and stale-reference detection ──────────────────────────────
echo ""
echo "[4] cl_find_carriers / cl_carrier_bad_root"
printf 'title esp\noptions root=PARTUUID=aaaa-bbbb rw\n' > "$R/efi/loader/entries/esp.conf"
printf 'title esp2\noptions root=UUID=fs-uuid-inner rw\n' > "$R/boot/efi/loader/entries/esp2.conf"
printf '"Boot" "root=/dev/null"\n' > "$R/boot/efi/EFI/arch/refind_linux.conf"
KINDS=$(cl_find_carriers "$R" | cut -f1 | sort | uniq -c | awk '{print $2"="$1}' | paste -sd' ')
eq "every layout is discovered" \
   "bls=3 cmdline=2 dropin=1 extlinux=1 grubd=1 limine=2 limine-default=1 refind=2" "$KINDS"
eq "stale root=PARTUUID in an /efi Type #1 entry is reported" "root=PARTUUID=aaaa-bbbb" \
   "$(cl_carrier_bad_root bls "$R/efi/loader/entries/esp.conf")"
eq "root=UUID=<inner fs> is not reported" "" "$(cl_carrier_bad_root bls "$R/boot/efi/loader/entries/esp2.conf")"
eq "stale root=/dev/<partition> in a nested refind_linux.conf is reported" "root=/dev/null" \
   "$(cl_carrier_bad_root refind "$R/boot/efi/EFI/arch/refind_linux.conf")"
eq "a patched carrier reports nothing" "" "$(cl_carrier_bad_root cmdline "$R/etc/kernel/cmdline")"
eq "grubvar carrier: stale reference inside the quoted value is reported" "root=/dev/null" \
   "$(printf 'GRUB_CMDLINE_LINUX="ro root=/dev/null"\n' > "$R/g2"; cl_carrier_bad_root grubvar "$R/g2" 'GRUB_CMDLINE_LINUX')"
eq "cl_has_all_args: partial set is not 'all'" "1" "$(cl_has_all_args "rd.luks.uuid=LUKSUUID"; echo $?)"
eq "cl_has_all_args: complete set in any order" "0" "$(cl_has_all_args "rd.luks.name=LUKSUUID=root_crypt x rd.luks.uuid=LUKSUUID"; echo $?)"

# ─── 5. Effective GRUB value after drop-ins ──────────────────────────────────
echo ""
echo "[5] cl_grub_effective"
G="$TMP/grubroot"; mkdir -p "$G/etc/default/grub.d"
printf 'GRUB_CMDLINE_LINUX="from-main"\nGRUB_CMDLINE_LINUX_DEFAULT="quiet"\n' > "$G/etc/default/grub"
eq "no drop-ins: the main file's value" "from-main" "$(cl_grub_effective "$G" GRUB_CMDLINE_LINUX)"
printf 'GRUB_CMDLINE_LINUX="from-dropin"\n' > "$G/etc/default/grub.d/50-cloud.cfg"
eq "a drop-in defining the variable overrides the main file" "from-dropin" "$(cl_grub_effective "$G" GRUB_CMDLINE_LINUX)"
printf 'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX extra"\n' > "$G/etc/default/grub.d/60-append.cfg"
eq "drop-ins are sourced in order and may extend the value" "from-dropin extra" "$(cl_grub_effective "$G" GRUB_CMDLINE_LINUX)"
eq "an unrelated variable is untouched by drop-ins" "quiet" "$(cl_grub_effective "$G" GRUB_CMDLINE_LINUX_DEFAULT)"
eq "cl_grub_var_defined: commented definition does not count" "1" \
   "$(printf '#GRUB_FORCE_PARTUUID=x\n' > "$G/c.cfg"; cl_grub_var_defined "$G/c.cfg" GRUB_FORCE_PARTUUID; echo $?)"
eq "the appending drop-in keeps the reference through a patch" \
   "GRUB_CMDLINE_LINUX=\"\$GRUB_CMDLINE_LINUX extra $ARGS\"" \
   "$(cl_patch_file grubvar "$G/etc/default/grub.d/60-append.cfg" GRUB_CMDLINE_LINUX; cat "$G/etc/default/grub.d/60-append.cfg")"

# ─── 6. Encrypted-/boot recognition ──────────────────────────────────────────
echo ""
echo "[6] bt_grub_probe"
# Synthetic "images": the byte strings the classifier keys on, nothing else.
IMG="$TMP/img"; mkdir -p "$IMG"
printf 'normal\0cryptomount\0luks2_scan\0argon2id\0Argon2 not supported\0' > "$IMG/stock-2.12.efi"
printf 'normal\0cryptomount\0luks2_scan\0argon2id\0grub_crypto_argon2\0cryptomount -u deadbeefcafe\0' > "$IMG/custom-2.14.efi"
printf 'normal\0cryptomount\0luks_scan\0' > "$IMG/luks1-only.efi"
printf 'shim\0' > "$IMG/shim.efi"

BT_GRUB_UNLOCKS=0; BT_GRUB_EVIDENCE=""; BT_GRUB_CRYPTODISK=0; BT_GRUB_LUKS2=unknown; BT_GRUB_ARGON2=unknown
_bt_scan_image "$IMG/stock-2.12.efi" "deadbeefcafe"
eq "stock 2.12: cryptodisk present, LUKS2 yes, argon2 NO" "1/yes/no" "$BT_GRUB_CRYPTODISK/$BT_GRUB_LUKS2/$BT_GRUB_ARGON2"
eq "stock 2.12: image does not name this volume -> not 'unlocks'" "0" "$BT_GRUB_UNLOCKS"

BT_GRUB_UNLOCKS=0; BT_GRUB_EVIDENCE=""; BT_GRUB_CRYPTODISK=0; BT_GRUB_LUKS2=unknown; BT_GRUB_ARGON2=unknown
_bt_scan_image "$IMG/custom-2.14.efi" "deadbeefcafe"
eq "custom 2.14 with argon2: LUKS2 yes, argon2 YES" "yes/yes" "$BT_GRUB_LUKS2/$BT_GRUB_ARGON2"
eq "the volume's UUID inside the image proves GRUB unlocks it" "1" "$BT_GRUB_UNLOCKS"
case "$BT_GRUB_EVIDENCE" in *custom-2.14.efi*) pass "evidence names the image" ;; *) fail "evidence: '$BT_GRUB_EVIDENCE'" ;; esac

BT_GRUB_UNLOCKS=0; BT_GRUB_EVIDENCE=""; BT_GRUB_CRYPTODISK=0; BT_GRUB_LUKS2=unknown; BT_GRUB_ARGON2=unknown
_bt_scan_image "$IMG/luks1-only.efi" ""
eq "a LUKS1-only GRUB (pre-2.06): LUKS2 no" "no" "$BT_GRUB_LUKS2"
BT_GRUB_CRYPTODISK=0
_bt_scan_image "$IMG/shim.efi" "" && fail "shim scanned as a GRUB image" || pass "an image without cryptomount is ignored"

# The /boot-inside-the-volume rule, against a fixture root (no devices needed:
# a fixture path is not a LUKS device, the disk lookup fails, the image scan
# finds nothing, and the root rule is what decides).
V="$TMP/vol"; mkdir -p "$V/etc" "$V/boot/grub2"
printf 'UUID=x / ext4 defaults 0 1\nUUID=y /boot/efi vfat umask=0077 0 2\n' > "$V/etc/fstab"
: > "$V/boot/grub2/grub.cfg"
bt_grub_probe "$V/not-a-device" "$V"
eq "no separate /boot + grub.cfg inside the volume -> GRUB unlocks it" "1" "$BT_GRUB_UNLOCKS"
case "$BT_GRUB_EVIDENCE" in *"/boot/grub2/grub.cfg"*) pass "evidence names the grub.cfg inside the volume" ;; *) fail "evidence: '$BT_GRUB_EVIDENCE'" ;; esac
printf 'UUID=x / ext4 defaults 0 1\nUUID=b /boot ext4 defaults 0 2\n' > "$V/etc/fstab"
bt_grub_probe "$V/not-a-device" "$V"
eq "a separate /boot in fstab -> the initramfs unlocks it" "0" "$BT_GRUB_UNLOCKS"
mkdir -p "$V/usr/lib/grub/x86_64-efi"; printf 'Argon2 not supported\0' > "$V/usr/lib/grub/x86_64-efi/luks2.mod"
printf 'UUID=x / ext4 defaults 0 1\n' > "$V/etc/fstab"
bt_grub_probe "$V/not-a-device" "$V"
eq "no image readable: the target's own luks2.mod says argon2 is unsupported" "1/no" "$BT_GRUB_UNLOCKS/$BT_GRUB_ARGON2"

eq "GRUB ceiling: 1 GiB accepted" "0" "$(bt_grub_mem_ok 1048576; echo $?)"
eq "GRUB ceiling: 2 GiB refused" "1" "$(bt_grub_mem_ok 2097152; echo $?)"
eq "GRUB ceiling: LUKS_GRUB_ARGON2_MAX_KIB is honoured" "0" "$(BT_GRUB_ARGON2_MAX_KIB=2097152 bt_grub_mem_ok 2097152; echo $?)"
eq "unlock estimate x factor (8.5 default)" "17000" "$(bt_grub_ms 2000)"
eq "unlock estimate: factor override" "4000" "$(BT_GRUB_KDF_FACTOR=2 bt_grub_ms 2000)"
eq "unlock estimate: garbage in, empty out" "" "$(bt_grub_ms abc)"

# ─── Result ──────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " $PASS passed, $FAIL failed, $SKIP skipped"
echo "═══════════════════════════════════════════════════════════════"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
