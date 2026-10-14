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
# loopback-core-test.sh — exercise the encryption core against throwaway
# file-backed loop devices. No real disk is ever touched; safe to run in CI.
#
# What it proves (the exact cryptsetup/filesystem sequence luks-deploy.sh
# runs, with CI-sized argon2id parameters):
#   1. the shrink-idempotency guard (fs-size gap check) fires correctly (btrfs)
#   2. in-place `cryptsetup reencrypt --encrypt` with our flags succeeds
#   3. the result is LUKS2/argon2id, opens, and the inner btrfs (subvols,
#      files) survived intact
#   4. recovery-key enrollment (luksAddKey via key-files) unlocks the volume,
#      and the new keyslot keeps the sha512 AF hash (luksAddKey without
#      --hash stamps cryptsetup's sha256 default — a silent downgrade)
#   5. an initialized-but-unfinished reencrypt carries the online-reencrypt
#      flag and finishes with --resume-only  (built with --init-only, so it
#      is deterministic — no race against a live reencrypt)
#   5b. a hard-killed reencrypt demands `cryptsetup repair` before it will
#      resume  (best-effort: the kill is inherently timing-dependent, so
#      unreachable states are reported and skipped, never asserted against)
#   6. btrfs resize max reclaims the container
#   7. the ext4 path: dumpe2fs gap probe, resize2fs shrink, reencrypt,
#      content survival, resize2fs grow — the same handlers luks-deploy.sh
#      uses for every ext2/3/4 target
#   8. LUKS1 → LUKS2 conversion + argon2id keyslot re-costing (the
#      convert_luks1 sequence) on a LUKS1-formatted volume, AF hash pinned
#
# Run as root:  sudo bash tests/loopback-core-test.sh
# Requires: cryptsetup >= 2.4, btrfs-progs, e2fsprogs, util-linux (losetup).
# ============================================================================
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
for c in cryptsetup btrfs losetup blockdev mkfs.btrfs mkfs.ext4 resize2fs dumpe2fs e2fsck; do
    command -v "$c" >/dev/null || { echo "missing tool: $c"; exit 1; }
done

WORK=$(mktemp -d "${TMPDIR:-/tmp}/luks-loopback-test.XXXXXX")
MAP1="lbtest1-$$"
MAP2="lbtest2-$$"
LOOP1=""; LOOP2=""; LOOP3=""; LOOP4=""; LOOP5=""
PASS=0; FAIL=0
pass() { echo "  PASS: $*"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }

cleanup() {
    set +e
    umount "$WORK/mnt" 2>/dev/null
    cryptsetup close "$MAP1" 2>/dev/null
    cryptsetup close "$MAP2" 2>/dev/null
    for l in "$LOOP1" "$LOOP2" "$LOOP3" "$LOOP4" "$LOOP5" ${LOOPS_EXTRA:-}; do
        [ -n "$l" ] && losetup -d "$l" 2>/dev/null
    done
    rm -rf "$WORK"
}
trap cleanup EXIT

# CI-sized KDF (the point here is the mechanics, not KDF strength)
KDF=(--pbkdf argon2id --pbkdf-memory 65536 --pbkdf-parallel 2 --pbkdf-force-iterations 4)
printf 'loopback-test-passphrase' > "$WORK/pass"; chmod 600 "$WORK/pass"

btrfs_gap() { # $1 = device; prints (device bytes - btrfs total_bytes)
    local dev_b fs_b
    dev_b=$(blockdev --getsize64 "$1")
    fs_b=$(btrfs inspect-internal dump-super "$1" | awk '/^total_bytes/{print $2; exit}')
    echo $(( dev_b - fs_b ))
}

ext4_bytes() { # $1 = device; the ext4 filesystem's own size (the fs_bytes probe)
    local bc bs
    bc=$(dumpe2fs -h "$1" 2>/dev/null | awk -F': *' '/^Block count:/{print $2; exit}')
    bs=$(dumpe2fs -h "$1" 2>/dev/null | awk -F': *' '/^Block size:/{print $2; exit}')
    echo $(( bc * bs ))
}

has_reenc_flag() { # $1 = device; true when the LUKS2 header still requires reencryption
    cryptsetup luksDump "$1" 2>/dev/null | grep -q 'online-reencrypt'
}

mk_shrunk_btrfs() { # $1 = device; fresh btrfs with 32M of slack at the end
    mkfs.btrfs -q -f "$1"
    mount "$1" "$WORK/mnt"
    btrfs -q filesystem resize -32M "$WORK/mnt"
    umount "$WORK/mnt"
}

assert_unlocks() { # $1 = device, $2 = mapper name, $3 = label
    if cryptsetup open --key-file "$WORK/pass" "$1" "$2"; then
        pass "$3 unlocks"
        cryptsetup close "$2" 2>/dev/null || true
    else
        fail "$3 cannot unlock"
    fi
}

echo "== setup: 1200M image, btrfs with root/home subvols + a sentinel file =="
truncate -s 1200M "$WORK/disk1.img"
LOOP1=$(losetup --show -f "$WORK/disk1.img")
mkfs.btrfs -q -f "$LOOP1"
mkdir -p "$WORK/mnt"
mount "$LOOP1" "$WORK/mnt"
btrfs -q subvolume create "$WORK/mnt/root"
btrfs -q subvolume create "$WORK/mnt/home"
mkdir -p "$WORK/mnt/root/etc"
echo "sentinel-fstab-content" > "$WORK/mnt/root/etc/fstab"

echo "== 1. shrink-idempotency guard (btrfs) =="
GAP=$(btrfs_gap "$LOOP1")
if [ "$GAP" -lt $((32*1024*1024)) ]; then
    pass "fresh fs: gap ${GAP}B < 32M — guard would allow the shrink"
else
    fail "fresh fs already has a ${GAP}B gap (mkfs layout changed?)"
fi
btrfs -q filesystem resize -32M "$WORK/mnt"
umount "$WORK/mnt"
GAP=$(btrfs_gap "$LOOP1")
if [ "$GAP" -ge $((32*1024*1024)) ]; then
    pass "after shrink: gap ${GAP}B >= 32M — guard would SKIP a re-shrink"
else
    fail "gap ${GAP}B still < 32M after resize -32M"
fi

echo "== 2. in-place reencrypt with luks-deploy's flags =="
cryptsetup reencrypt --encrypt --type luks2 \
    --cipher aes-xts-plain64 --key-size 512 \
    "${KDF[@]}" --hash sha512 \
    --reduce-device-size 32M --resilience checksum \
    --key-file "$WORK/pass" --batch-mode -q "$LOOP1"
pass "reencrypt --encrypt completed"

echo "== 3. header + content survival =="
DUMP=$(cryptsetup luksDump "$LOOP1")
echo "$DUMP" | grep -q 'Version:.*2'        && pass "LUKS2 header"        || fail "not LUKS2"
echo "$DUMP" | grep -q 'argon2id'           && pass "argon2id KDF"        || fail "argon2id missing"
echo "$DUMP" | grep -q 'aes-xts-plain64'    && pass "aes-xts-plain64"     || fail "cipher wrong"
cryptsetup open --key-file "$WORK/pass" "$LOOP1" "$MAP1"
INNER=$(blkid -s TYPE -o value "/dev/mapper/$MAP1")
[ "$INNER" = "btrfs" ] && pass "inner fs is btrfs" || fail "inner fs is '$INNER'"
mount -o subvol=root "/dev/mapper/$MAP1" "$WORK/mnt"
grep -q 'sentinel-fstab-content' "$WORK/mnt/etc/fstab" \
    && pass "subvol=root content intact through encryption" \
    || fail "sentinel file lost/corrupt"
umount "$WORK/mnt"

echo "== 6. btrfs resize max reclaims the container ==" # (while open)
mount "/dev/mapper/$MAP1" "$WORK/mnt"
btrfs -q filesystem resize max "$WORK/mnt"
umount "$WORK/mnt"
pass "resize max ok"

echo "== 4. recovery-key enrollment (luks-deploy's luksAddKey shape) =="
od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > "$WORK/rk"; chmod 600 "$WORK/rk"
cryptsetup luksAddKey --key-file "$WORK/pass" "$LOOP1" "$WORK/rk" --hash sha512 "${KDF[@]}"
cryptsetup close "$MAP1"
cryptsetup open --key-file "$WORK/rk" "$LOOP1" "$MAP1" \
    && pass "recovery key unlocks the volume" \
    || fail "recovery key cannot unlock"
cryptsetup close "$MAP1"
# Every keyslot must carry the AF hash luksFormat/reencrypt was given; a slot
# added without --hash comes back as sha256 (verified on cryptsetup 2.8.7).
AF_HASHES=$(cryptsetup luksDump "$LOOP1" | awk '/^[[:space:]]+AF hash:/{print $3}' | sort -u | paste -sd,)
[ "$AF_HASHES" = "sha512" ] \
    && pass "every keyslot (passphrase + recovery) has AF hash sha512" \
    || fail "AF hashes after luksAddKey: $AF_HASHES (expected only sha512)"

echo "== 5. an unfinished reencrypt carries the resume flag and finishes =="
truncate -s 1200M "$WORK/disk2.img"
LOOP2=$(losetup --show -f "$WORK/disk2.img")
mk_shrunk_btrfs "$LOOP2"
ENCRYPT_ARGS=(--encrypt --type luks2 "${KDF[@]}"
              --reduce-device-size 32M --resilience checksum
              --key-file "$WORK/pass" --batch-mode -q)

# --init-only writes the header and the online-reencrypt requirement without
# moving a byte of data: exactly the on-disk state an interrupted run leaves,
# reached deterministically.
cryptsetup reencrypt "${ENCRYPT_ARGS[@]}" --init-only "$LOOP2"
if has_reenc_flag "$LOOP2"; then
    pass "--init-only left the online-reencrypt requirement flag"
else
    fail "--init-only left no online-reencrypt requirement flag"
fi
cryptsetup reencrypt --resume-only --key-file "$WORK/pass" --batch-mode -q "$LOOP2"
if has_reenc_flag "$LOOP2"; then
    fail "flag still present after --resume-only"
else
    pass "--resume-only finished the encryption"
fi
assert_unlocks "$LOOP2" "$MAP2" "resumed volume"

echo "== 5b. a hard-killed reencrypt demands repair before it resumes =="
truncate -s 1200M "$WORK/disk3.img"
LOOP3=$(losetup --show -f "$WORK/disk3.img")
mk_shrunk_btrfs "$LOOP3"
# The repair path is only reachable by killing the *initial* --encrypt run:
# a kill during --resume-only leaves the checksum journal clean and resumes
# without complaint. Every state the kill can land in is classified by a full
# header parse (luksDump), never by isLuks, and a state we did not manage to
# build is reported instead of asserted against. Test 5 above already covers
# the resume mechanics deterministically, so a skip here costs no coverage.
cryptsetup reencrypt "${ENCRYPT_ARGS[@]}" "$LOOP3" &
RPID=$!
for _ in $(seq 1 200); do
    if has_reenc_flag "$LOOP3"; then
        sleep 0.2          # let some data actually move before pulling the plug
        break
    fi
    if ! kill -0 "$RPID" 2>/dev/null; then break; fi
    sleep 0.05
done
if kill -9 "$RPID" 2>/dev/null; then wait "$RPID" 2>/dev/null || true; fi
sync

if ! cryptsetup luksDump "$LOOP3" >/dev/null 2>&1; then
    # The kill caught cryptsetup before or during the header write. Nothing to
    # assert — but print the evidence, so a failure here explains itself.
    echo "  SKIP: kill left no readable header — repair path not exercised"
    echo "        luksDump: $(cryptsetup luksDump "$LOOP3" 2>&1 | head -1)"
    echo "        isLuks:   $(cryptsetup isLuks "$LOOP3" 2>/dev/null && echo yes || echo no)"
elif has_reenc_flag "$LOOP3"; then
    pass "interrupt left the online-reencrypt requirement flag"
    # A hard kill leaves the reencryption journal dirty: --resume-only refuses
    # with "Device requires reencryption recovery. Run repair first."
    # This mirrors luks-deploy.sh's resume path: repair, then resume.
    if cryptsetup reencrypt --resume-only --key-file "$WORK/pass" --batch-mode -q "$LOOP3" 2>/dev/null; then
        echo "  NOTE: --resume-only succeeded without repair (journal was clean)"
    else
        pass "--resume-only correctly demanded repair after a hard kill"
        cryptsetup repair --key-file "$WORK/pass" --batch-mode -q "$LOOP3"
        pass "cryptsetup repair cleaned the reencryption journal"
        cryptsetup reencrypt --resume-only --key-file "$WORK/pass" --batch-mode -q "$LOOP3"
    fi
    if has_reenc_flag "$LOOP3"; then
        fail "flag still present after repair + --resume-only"
    else
        pass "repair + --resume-only finished the encryption"
    fi
    assert_unlocks "$LOOP3" "$MAP2" "repaired volume"
else
    echo "  SKIP: reencrypt finished before the kill landed — repair path not exercised"
    assert_unlocks "$LOOP3" "$MAP2" "completed volume"
fi

echo "== 7. the ext4 path: probe, shrink, encrypt, survive, grow =="
truncate -s 1200M "$WORK/disk4.img"
LOOP4=$(losetup --show -f "$WORK/disk4.img")
mkfs.ext4 -q -F "$LOOP4"
mount "$LOOP4" "$WORK/mnt"
mkdir -p "$WORK/mnt/etc"
echo "sentinel-ext4-content" > "$WORK/mnt/etc/fstab"
umount "$WORK/mnt"
DEV_B=$(blockdev --getsize64 "$LOOP4")
FS_B=$(ext4_bytes "$LOOP4")
if [ $((DEV_B - FS_B)) -lt $((32*1024*1024)) ]; then
    pass "fresh ext4: gap $((DEV_B - FS_B))B < 32M — guard would allow the shrink"
else
    fail "fresh ext4 already has a $((DEV_B - FS_B))B gap"
fi
# The exact shrink sequence fs_shrink uses for ext*
e2fsck -f -p "$LOOP4" >/dev/null
NEW_K=$(( (FS_B - 32*1024*1024) / 1024 ))
resize2fs "$LOOP4" "${NEW_K}K" >/dev/null 2>&1
FS_B2=$(ext4_bytes "$LOOP4")
if [ $((DEV_B - FS_B2)) -ge $((32*1024*1024)) ]; then
    pass "resize2fs shrink opened a $(( (DEV_B - FS_B2)/1024/1024 ))M gap — guard would SKIP a re-shrink"
else
    fail "gap $((DEV_B - FS_B2))B still < 32M after resize2fs"
fi
cryptsetup reencrypt --encrypt --type luks2 \
    --cipher aes-xts-plain64 --key-size 512 \
    "${KDF[@]}" --hash sha512 \
    --reduce-device-size 32M --resilience checksum \
    --key-file "$WORK/pass" --batch-mode -q "$LOOP4"
pass "ext4 in-place reencrypt completed"
cryptsetup open --key-file "$WORK/pass" "$LOOP4" "$MAP1"
INNER=$(blkid -s TYPE -o value "/dev/mapper/$MAP1")
[ "$INNER" = "ext4" ] && pass "inner fs is ext4" || fail "inner fs is '$INNER'"
mount "/dev/mapper/$MAP1" "$WORK/mnt"
grep -q 'sentinel-ext4-content' "$WORK/mnt/etc/fstab" \
    && pass "ext4 content intact through encryption" \
    || fail "ext4 sentinel file lost/corrupt"
umount "$WORK/mnt"
# The exact grow sequence fs_grow_max uses for ext*
e2fsck -f -p "/dev/mapper/$MAP1" >/dev/null 2>&1 || true
resize2fs "/dev/mapper/$MAP1" >/dev/null 2>&1 \
    && pass "resize2fs grow reclaimed the container" \
    || fail "resize2fs grow failed"
cryptsetup close "$MAP1"

echo "== 8. LUKS1 → LUKS2 conversion + argon2id re-costing =="
truncate -s 200M "$WORK/disk5.img"
LOOP5=$(losetup --show -f "$WORK/disk5.img")
cryptsetup luksFormat --type luks1 --key-file "$WORK/pass" --batch-mode -q "$LOOP5"
V=$(cryptsetup luksDump "$LOOP5" | awk '/^Version:/{print $2; exit}')
[ "$V" = "1" ] && pass "formatted a LUKS1 volume" || fail "expected LUKS1, got version '$V'"
# The exact sequence convert_luks1 runs: convert, then per-slot luksConvertKey
cryptsetup convert --type luks2 --batch-mode "$LOOP5"
V=$(cryptsetup luksDump "$LOOP5" | awk '/^Version:/{print $2; exit}')
[ "$V" = "2" ] && pass "convert --type luks2 succeeded" || fail "still version '$V' after convert"
cryptsetup luksDump "$LOOP5" | grep -q 'pbkdf2' \
    && pass "keyslot still pbkdf2 after conversion (as expected)" \
    || fail "expected a pbkdf2 keyslot right after conversion"
cryptsetup luksConvertKey -S 0 --hash sha512 "${KDF[@]}" --key-file "$WORK/pass" "$LOOP5"
cryptsetup luksDump "$LOOP5" | grep -q 'argon2id' \
    && pass "luksConvertKey re-costed slot 0 to argon2id" \
    || fail "slot 0 is not argon2id after luksConvertKey"
AF5=$(cryptsetup luksDump "$LOOP5" | awk '/^[[:space:]]+AF hash:/{print $3; exit}')
[ "$AF5" = "sha512" ] \
    && pass "re-costed slot carries AF hash sha512 (--hash pinned)" \
    || fail "re-costed slot AF hash is '$AF5'"
assert_unlocks "$LOOP5" "$MAP2" "converted LUKS1→LUKS2 volume"

echo "== 9. 4096-byte encryption sectors: a 4Kn device and a 512-byte one =="
# Every filesystem here writes 4096-byte blocks; luks-deploy passes
# --sector-size 4096 whenever the block size allows it. Both device geometries
# must take it in place, and the content must survive.
for LSS in 4096 512; do
    IMG="$WORK/disk-ss$LSS.img"; truncate -s 600M "$IMG"
    if ! L9=$(losetup --show -f --sector-size "$LSS" "$IMG" 2>/dev/null); then
        echo "  SKIP: losetup --sector-size $LSS unsupported here"; continue
    fi
    LOOPS_EXTRA="${LOOPS_EXTRA:-} $L9"
    mkfs.btrfs -q -f "$L9"; mount "$L9" "$WORK/mnt"; echo "ss-sentinel-$LSS" > "$WORK/mnt/f"
    btrfs -q filesystem resize -32M "$WORK/mnt"; umount "$WORK/mnt"
    if cryptsetup reencrypt --encrypt --type luks2 "${KDF[@]}" --cipher aes-xts-plain64 --key-size 512 --hash sha512 --sector-size 4096 \
           --reduce-device-size 32M --resilience checksum --key-file "$WORK/pass" --batch-mode -q "$L9"; then
        pass "reencrypt --encrypt --sector-size 4096 on a $LSS-byte device"
    else
        fail "reencrypt --sector-size 4096 refused on a $LSS-byte device"; continue
    fi
    cryptsetup open --key-file "$WORK/pass" "$L9" "$MAP2"
    [ "$(cryptsetup status "$MAP2" | awk '/sector size:/{print $3; exit}')" = 4096 ] && pass "container encrypts in 4096-byte sectors ($LSS-byte device)" || fail "sector size wrong"
    mount "/dev/mapper/$MAP2" "$WORK/mnt" && grep -q "ss-sentinel-$LSS" "$WORK/mnt/f" && pass "content intact through 4096-byte-sector encryption" || fail "content lost"
    umount "$WORK/mnt" 2>/dev/null; cryptsetup close "$MAP2"
done

echo "== 10. the last partition of a 512-byte-sector GPT disk: 33 sectors short, aligned, encrypted in 4096-byte sectors =="
# GPT reserves 33 sectors at the end of the disk, so an installer's rest-of-the-
# disk root partition never has a size that is a multiple of 4096 — and
# cryptsetup refuses --sector-size 4096 on it. luks-deploy's align_partition_end
# moves the end down by the remainder after the shrink; it is run here exactly
# as the script defines it (sed markers), against a real GPT loop image.
IMG10="$WORK/gpt.img"; truncate -s 320M "$IMG10"
sgdisk -n 1:2048:0 -t 1:8300 -c 1:root "$IMG10" >/dev/null 2>&1
if L10=$(losetup --show -f --partscan "$IMG10" 2>/dev/null) && sleep 1 && [ -b "${L10}p1" ]; then
    LOOPS_EXTRA="${LOOPS_EXTRA:-} $L10"
    SZ=$(blockdev --getsize64 "${L10}p1")
    [ $((SZ % 4096)) -ne 0 ] && pass "the rest-of-the-disk partition is $((SZ % 4096)) bytes past a 4096-byte multiple (GPT's reserved tail)" || fail "partition size unexpectedly aligned ($SZ)"
    # -b 4096: mkfs.ext4 gives a filesystem this small 1024-byte blocks, and
    # cryptsetup refuses --sector-size 4096 against an ext4 superblock with
    # smaller blocks ("incompatible with ext4 superblock") — which is exactly
    # why luks-deploy reads the block size (fs_block_size) before choosing.
    # A real root filesystem (>= 512 MiB) gets 4096-byte blocks by default.
    mkfs.ext4 -q -F -b 4096 "${L10}p1"; mount "${L10}p1" "$WORK/mnt"; echo "align-sentinel" > "$WORK/mnt/f"; umount "$WORK/mnt"
    BS10=$(dumpe2fs -h "${L10}p1" 2>/dev/null | awk -F': *' '/^Block size:/{print $2; exit}')
    [ "$BS10" = 4096 ] && pass "ext4 block size 4096 (the size the sector must not exceed)" || fail "ext4 block size $BS10"
    e2fsck -f -p "${L10}p1" >/dev/null; resize2fs "${L10}p1" "$(( ($(ext4_bytes "${L10}p1") - 32*1024*1024) / 1024 ))K" >/dev/null 2>&1
    ALIGN_FN=$(sed -n '/^# --- align_partition_end ---/,/^# --- end align_partition_end ---/p' "$(dirname "$0")/../bin/luks-deploy.sh")
    [ -n "$ALIGN_FN" ] || fail "align_partition_end not found in luks-deploy.sh"
    ( set -e; log() { :; }; warn() { echo "  WARN $*"; }; fatal() { echo "  FATAL $*"; exit 1; }
      fs_bytes() { ext4_bytes "$1"; }
      # the eval'd function reads these (shellcheck cannot see that)
      # shellcheck disable=SC2034
      STATE_DIR="$WORK"
      # shellcheck disable=SC2034
      TARGET_ROOT="${L10}p1"
      # shellcheck disable=SC2034
      ORIG_FSTYPE=ext4
      # shellcheck disable=SC2034
      LUKS_SECTOR_SIZE=4096
      eval "$ALIGN_FN"; align_partition_end ) && pass "align_partition_end ran (table backed up to $WORK/gpt-backup-*.bin)" || fail "align_partition_end failed"
    SZ2=$(blockdev --getsize64 "${L10}p1")
    [ $((SZ2 % 4096)) -eq 0 ] && [ $((SZ - SZ2)) -lt 4096 ] && pass "partition now $SZ2 bytes: a 4096-byte multiple, $((SZ - SZ2)) bytes shorter" || fail "partition after alignment: $SZ2 (was $SZ)"
    N10=$(sgdisk -i 1 "$L10" | sed -n "s/^Partition name: '\(.*\)'\$/\1/p")
    [ "$N10" = root ] && pass "partition name kept ($N10)" || fail "partition name changed: '$N10'"
    if cryptsetup reencrypt --encrypt --type luks2 "${KDF[@]}" --cipher aes-xts-plain64 --key-size 512 --hash sha512 --sector-size 4096 \
           --reduce-device-size 32M --resilience checksum --key-file "$WORK/pass" --batch-mode -q "${L10}p1"; then
        pass "reencrypt --encrypt --sector-size 4096 on the aligned ext4 partition"
        cryptsetup open --key-file "$WORK/pass" "${L10}p1" "$MAP2"
        mount "/dev/mapper/$MAP2" "$WORK/mnt" && grep -q align-sentinel "$WORK/mnt/f" && pass "ext4 content intact after alignment + encryption" || fail "content lost"
        umount "$WORK/mnt" 2>/dev/null; cryptsetup close "$MAP2"
    else
        fail "reencrypt still refused after alignment"
    fi
else
    echo "  SKIP: cannot create a partitioned loop device here"
fi

echo "== 11. an Apple Silicon disk: the partition you select is refused before anything is done to it =="
# luks-deploy.sh checks the partition you select before it unmounts, converts,
# resumes, tunes, shrinks or encrypts anything, from what needs no passphrase:
# the partition types on its disk and the plain partitions beside it. A GPT
# image laid out like an Apple Silicon Mac's disk — an "Apple Silicon boot"
# (iBootSystemContainer) partition, an ESP holding m1n1/, an ext4 /boot
# holding an Asahi kernel, a LUKS root — is put to ll_detect_asahi_dev one
# signal at a time, with the ESP and /boot hashed before and after to prove
# the read-only probe mounts write nothing. Then the real luks-deploy.sh is
# pointed at the LUKS root with --dry-run, in a private mount namespace, in
# each state a LUKS partition can be in — LUKS1 (the conversion path), LUKS2
# mid-encryption (the resume path), finished LUKS2 (the tune/config menu) —
# and must refuse with its header untouched.
BIN="$(cd "$(dirname "$0")/../bin" && pwd)"
IMG11="$WORK/apple.img"; truncate -s 512M "$IMG11"
IBOOT=69646961-6700-11AA-AA11-00306543ECAC
L11=""
attach11() {   # (re)attach the image with its partitions; sets L11
    L11=$(losetup --show -f --partscan "$IMG11") || return 1
    LOOPS_EXTRA="${LOOPS_EXTRA:-} $L11"
    refresh11
    [ -b "${L11}p4" ]
}
refresh11() {   # let udev re-read what mkfs and sgdisk changed (lsblk reads udev)
    udevadm trigger --action=change "$L11" "$L11"p? 2>/dev/null || true
    udevadm settle 2>/dev/null || sleep 1
}
retype11() {   # $1 = GPT type for partition 1; re-attaches the image
    losetup -d "$L11" 2>/dev/null || true
    sgdisk -t "1:$1" "$IMG11" >/dev/null && attach11
}
dev_check() {   # $1 = device -> "rc|reason" from lib-deps.sh's ll_detect_asahi_dev
    bash -c '. "$1"; if ll_detect_asahi_dev "$2"; then echo "0|$LL_ASAHI_REASON"; else echo "1|"; fi' _ "$BIN/lib-deps.sh" "$1"
}
side_hash() {   # the ESP and /boot, byte for byte
    sha256sum "${L11}p2" "${L11}p3" | awk '{ print $1 }' | paste -sd' '
}
probes() { find /tmp -maxdepth 1 -name 'luks-asahi-probe.*' 2>/dev/null | wc -l; }
expect_dev() {   # $1 = label, $2 = expected "rc|reason"
    local h0 h1 p0 got
    h0=$(side_hash); p0=$(probes)
    got=$(dev_check "${L11}p4")
    h1=$(side_hash)
    if [ "$got" != "$2" ]; then fail "$1: expected '$2', got '$got'"
    elif [ "$h0" != "$h1" ]; then fail "$1: the ESP or /boot CHANGED during the check"
    elif [ -n "$(findmnt -rno TARGET -S "${L11}p2" 2>/dev/null)$(findmnt -rno TARGET -S "${L11}p3" 2>/dev/null)" ]; then fail "$1: a probe mount was left behind"
    elif [ "$(probes)" != "$p0" ]; then fail "$1: a probe directory was left in /tmp"
    else pass "$1"; fi
}
if ! command -v sgdisk >/dev/null || ! command -v mkfs.vfat >/dev/null; then
    echo "  SKIP: sgdisk or mkfs.vfat missing"
elif ! sgdisk -n 1:2048:+8M -t "1:$IBOOT" -c 1:iBootSystemContainer \
              -n 2:0:+64M -t 2:EF00 -c 2:EFI \
              -n 3:0:+64M -t 3:8300 -c 3:BOOT \
              -n 4:0:0 -t 4:8300 -c 4:root "$IMG11" >/dev/null 2>&1 || ! attach11; then
    echo "  SKIP: cannot create a partitioned loop device here"
else
    mkfs.vfat -n EFI "${L11}p2" >/dev/null
    mount "${L11}p2" "$WORK/mnt"; mkdir -p "$WORK/mnt/m1n1"; : > "$WORK/mnt/m1n1/boot.bin"; umount "$WORK/mnt"
    mkfs.ext4 -q -F -L BOOT "${L11}p3"
    mount "${L11}p3" "$WORK/mnt"; : > "$WORK/mnt/vmlinuz-7.1.13-402.asahi.fc44.aarch64+16k"; umount "$WORK/mnt"
    cryptsetup luksFormat --type luks1 --iter-time 100 --key-file "$WORK/pass" --batch-mode -q "${L11}p4"
    refresh11
    VIEW=$(lsblk -rno NAME,PARTTYPE,FSTYPE "$L11" 2>/dev/null || true)
    if ! awk -v t="${IBOOT,,}" '$1 ~ /p1$/ && tolower($2) == t { a = 1 }
                                $1 ~ /p2$/ && $3 == "vfat" { b = 1 }
                                $1 ~ /p3$/ && $3 == "ext4" { c = 1 }
                                END { exit !(a && b && c) }' <<< "$VIEW"; then
        echo "  SKIP: lsblk does not show the image's partition types and filesystems here:"
        printf '%s\n' "$VIEW" | sed 's/^/    /'
    else
        expect_dev "the Apple Silicon boot partition alone flags the LUKS root, nothing mounted" \
            "0|its disk carries an Apple Silicon boot partition (${L11}p1, iBootSystemContainer)"
        if retype11 8300; then
            expect_dev "no Apple partition: m1n1 on the ESP flags it (ESP probe-mounted ro, unchanged, unmounted)" \
                "0|its disk holds m1n1 on the FAT partition ${L11}p2"
            mount "${L11}p2" "$WORK/mnt"; rm -rf "$WORK/mnt/m1n1"; umount "$WORK/mnt"; refresh11
            expect_dev "no m1n1 either: the Asahi kernel on the ext4 /boot flags it (ro,noload, unchanged, unmounted)" \
                "0|its disk holds an Asahi kernel on ${L11}p3 (vmlinuz-7.1.13-402.asahi.fc44.aarch64+16k)"
            mount "${L11}p3" "$WORK/mnt"; rm -f "$WORK/mnt"/vmlinuz-*; umount "$WORK/mnt"; refresh11
            expect_dev "nothing Asahi on the disk: not flagged, and both probes left no trace" "1|"
            mount "${L11}p2" "$WORK/mnt"; mkdir -p "$WORK/mnt/m1n1"; umount "$WORK/mnt"
            mount "${L11}p3" "$WORK/mnt"; : > "$WORK/mnt/vmlinuz-7.1.13-402.asahi.fc44.aarch64+16k"; umount "$WORK/mnt"
        else
            fail "could not re-type partition 1"
        fi
        # The real script. Never on a machine that is itself Asahi: there the
        # live check refuses first, which is right but tests nothing here.
        if bash -c '. "$1"; ll_detect_asahi ""' _ "$BIN/lib-deps.sh"; then
            echo "  SKIP: this machine is Asahi / Apple Silicon — luks-deploy.sh refuses it before any partition is chosen"
        elif ! command -v unshare >/dev/null; then
            echo "  SKIP: no unshare(1) for a private mount namespace"
        elif ! retype11 "$IBOOT"; then
            fail "could not restore the Apple Silicon boot partition type"
        else
            mkdir -p "$WORK/kit"; cp "$BIN"/*.sh "$WORK/kit/"
            TO11=(); command -v timeout >/dev/null && TO11=(timeout 300)
            deploy_refuses() {   # $1 = label
                local out rc=0 h0 h1
                h0=$(head -c 16M "${L11}p4" | sha256sum)
                out=$(cd "$WORK/kit" && "${TO11[@]}" unshare --mount --propagation private \
                        env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME="$WORK" \
                        LUKS_TARGET_ROOT="${L11}p4" LUKS_LIVE_OVERRIDE=LIVE \
                        LUKS_BATTERY_OVERRIDE=BATTERY LUKS_EXISTING=quit \
                        bash ./luks-deploy.sh --dry-run </dev/null 2>&1) || rc=$?
                h1=$(head -c 16M "${L11}p4" | sha256sum)
                if [ "$rc" -eq 3 ] && grep -q 'The partition you selected belongs to an Apple Silicon' <<< "$out" \
                   && grep -q 'Reason: its disk carries an Apple Silicon boot partition' <<< "$out" \
                   && [ "$h0" = "$h1" ]; then
                    pass "$1"
                else
                    fail "$1: exit $rc, header $([ "$h0" = "$h1" ] && echo unchanged || echo CHANGED): $(tail -n 4 <<< "$out" | tr '\n' ' ')"
                fi
            }
            deploy_refuses "luks-deploy.sh refuses a LUKS1 root on it before the conversion path, header untouched"
            mk_shrunk_btrfs "${L11}p4"
            cryptsetup reencrypt "${ENCRYPT_ARGS[@]}" --init-only "${L11}p4"
            refresh11
            deploy_refuses "luks-deploy.sh refuses a LUKS2 root mid-encryption before the resume path, header untouched"
            has_reenc_flag "${L11}p4" \
                && pass "the interrupted encryption was left for AsahiLocker to resume" \
                || fail "the online-reencrypt flag is gone: something resumed it"
            cryptsetup luksFormat --type luks2 "${KDF[@]}" --key-file "$WORK/pass" --batch-mode -q "${L11}p4"
            refresh11
            deploy_refuses "luks-deploy.sh refuses a finished LUKS2 root before the tune/config menu, header untouched"
        fi
    fi
fi

echo ""
echo "==================================================="
echo "  $PASS passed, $FAIL failed"
echo "==================================================="
[ "$FAIL" -eq 0 ]
