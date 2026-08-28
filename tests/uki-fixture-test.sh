#!/bin/bash
#
# LinuxLocker — universal in-place LUKS2 encryption for Linux (x86_64 / aarch64)
# https://github.com/doug445/LinuxLocker
#
# Copyright (c) 2026 William MacKinnon <spilled-bowline0j@icloud.com>
# SPDX-License-Identifier: MIT
#
# ============================================================================
# uki-fixture-test.sh — exercise the UKI / systemd-boot / Secure Boot logic in
# bin/lib-uki.sh against synthetic target trees.
#
# Why fixtures and not a real deployment: the code under test decides whether a
# machine will boot again. The interesting cases are the COMBINATIONS — ESP at
# /efi vs /boot/efi vs /boot, mkinitcpio-preset vs kernel-install vs dracut,
# sbctl vs sbsign vs nothing, Secure Boot on vs off — and building one real
# machine per combination is not something CI can do. Each fixture below is a
# directory tree that looks exactly like the part of a target root that
# detection reads, so the same functions run against it unmodified.
#
# What it proves:
#   1.  UKI discovery finds EFI/Linux/*.efi in all three ESP layouts
#   2.  the regeneration backend is picked correctly, and mkinitcpio's preset
#       is only claimed when it actually carries a _uki= line
#   3.  the signing backend is picked correctly, and sbctl is NOT claimed
#       without keys (an sbctl with no keys signs nothing and exits 0)
#   4.  uki_regenerate / uki_sign emit the right commands (UKI_DRY=1)
#   5.  the refusal matrix: no backend, or Secure Boot on with no signer
#   6.  a real PE binary round-trips through uki_cmdline_of
#   7.  detection against THIS machine matches what it really runs, when this
#       machine is itself a UKI target (skipped everywhere else)
#
# Run:  bash tests/uki-fixture-test.sh        (no root, no disk, no network)
# ============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"

# shellcheck source=../bin/lib-uki.sh
. "$REPO/bin/lib-uki.sh"
# shellcheck source=../bin/lib-deps.sh
. "$REPO/bin/lib-deps.sh"

PASS=0; FAIL=0; SKIP=0
pass() { echo "  PASS: $*"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP: $*"; SKIP=$((SKIP+1)); }

TMP=$(mktemp -d /tmp/luks-uki-fixture.XXXXXX)
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

# Assert helper: $1 = what, $2 = expected, $3 = actual
eq() {
    if [ "$2" = "$3" ]; then pass "$1 = $3"
    else fail "$1: expected '$2', got '$3'"; fi
}

# ─── Fixture builder ─────────────────────────────────────────────────────────
# Builds a fake target root. Flags are "key=value" words:
#   esp=/efi|/boot/efi|/boot   where EFI/Linux lives
#   uki=yes|no                 put a .efi there
#   regen=mkinitcpio|kernel-install|dracut|ukify|none
#   sign=sbctl|sbctl-nokeys|sbsign|mok|pesign|none
#   sdboot=yes|no
make_fixture() {
    local name="$1"; shift
    local root="$TMP/$name" esp="/boot/efi" uki=no regen=none sign=none sdboot=no kv
    for kv in "$@"; do
        case "$kv" in
            esp=*)    esp="${kv#esp=}" ;;
            uki=*)    uki="${kv#uki=}" ;;
            regen=*)  regen="${kv#regen=}" ;;
            sign=*)   sign="${kv#sign=}" ;;
            sdboot=*) sdboot="${kv#sdboot=}" ;;
        esac
    done
    mkdir -p "$root/etc" "$root/usr/bin" "$root/usr/lib/modules/6.18.0-test"
    : > "$root/usr/lib/modules/6.18.0-test/vmlinuz"
    echo 'root=UUID=old ro quiet' > "$root/etc/kernel-cmdline-tmp"
    mkdir -p "$root/etc/kernel"; echo 'root=UUID=old ro quiet' > "$root/etc/kernel/cmdline"

    if [ "$uki" = "yes" ]; then
        mkdir -p "$root$esp/EFI/Linux"
        : > "$root$esp/EFI/Linux/test-6.18.0-test.efi"
    fi

    case "$regen" in
        mkinitcpio)
            mkdir -p "$root/etc/mkinitcpio.d"
            printf 'ALL_kver="/boot/vmlinuz-test"\nPRESETS=(default)\ndefault_uki="%s/EFI/Linux/test-6.18.0-test.efi"\n' \
                "$esp" > "$root/etc/mkinitcpio.d/linux.preset" ;;
        mkinitcpio-nouki)
            # mkinitcpio present, but a plain image preset — must NOT be claimed
            mkdir -p "$root/etc/mkinitcpio.d"
            printf 'PRESETS=(default)\ndefault_image="/boot/initramfs-linux.img"\n' \
                > "$root/etc/mkinitcpio.d/linux.preset" ;;
        kernel-install)
            : > "$root/usr/bin/kernel-install"; chmod +x "$root/usr/bin/kernel-install"
            mkdir -p "$root/usr/lib/kernel/install.d"
            : > "$root/usr/lib/kernel/install.d/90-uki-copy.install" ;;
        dracut)
            printf '#!/bin/sh\n# supports --uki-file for UKI builds\n' > "$root/usr/bin/dracut"
            chmod +x "$root/usr/bin/dracut" ;;
        ukify)
            : > "$root/usr/bin/ukify"; chmod +x "$root/usr/bin/ukify" ;;
    esac

    case "$sign" in
        sbctl)
            : > "$root/usr/bin/sbctl"; chmod +x "$root/usr/bin/sbctl"
            mkdir -p "$root/var/lib/sbctl/keys/db"
            : > "$root/var/lib/sbctl/keys/db/db.key"
            : > "$root/var/lib/sbctl/keys/db/db.pem" ;;
        sbctl-nokeys)
            : > "$root/usr/bin/sbctl"; chmod +x "$root/usr/bin/sbctl" ;;
        sbsign)
            : > "$root/usr/bin/sbsign"; chmod +x "$root/usr/bin/sbsign"
            mkdir -p "$root/etc/secureboot/keys/db"
            : > "$root/etc/secureboot/keys/db/db.key"
            : > "$root/etc/secureboot/keys/db/db.crt" ;;
        mok)
            : > "$root/usr/bin/sbsign"; chmod +x "$root/usr/bin/sbsign"
            mkdir -p "$root/var/lib/shim-signed/mok"
            : > "$root/var/lib/shim-signed/mok/MOK.priv"
            : > "$root/var/lib/shim-signed/mok/MOK.der" ;;
        pesign)
            : > "$root/usr/bin/pesign"; chmod +x "$root/usr/bin/pesign" ;;
    esac

    if [ "$sdboot" = "yes" ]; then
        mkdir -p "$root$esp/EFI/systemd" "$root$esp/loader/entries"
        : > "$root$esp/EFI/systemd/systemd-bootx64.efi"
        : > "$root$esp/loader/loader.conf"
    fi
    printf '%s' "$root"
}

# Run detection against a fixture with a clean slate every time. The env
# overrides must be cleared too — a leaked LUKS_UKI_REGEN would make every
# subsequent case pass for the wrong reason.
detect() {
    local root="$1"
    unset LUKS_UKI_REGEN LUKS_UKI_SIGN LUKS_SB_KEY LUKS_SB_CERT LUKS_SB_STATE
    uki_reset
    uki_find_ukis     "$root"
    uki_detect_regen  "$root" >/dev/null 2>&1
    uki_detect_signer "$root" >/dev/null 2>&1
    uki_detect_sdboot "$root" >/dev/null 2>&1
}

echo "═══════════════════════════════════════════════════════════════"
echo " LinuxLocker — UKI / systemd-boot / Secure Boot fixture tests"
echo "═══════════════════════════════════════════════════════════════"

# ─── 1. Discovery across the three ESP layouts ───────────────────────────────
echo ""
echo "[1] UKI discovery across ESP layouts"
for layout in /efi /boot/efi /boot; do
    R=$(make_fixture "disc$(echo "$layout" | tr -d /)" "esp=$layout" uki=yes regen=mkinitcpio)
    detect "$R"
    eq "ESP at $layout: UKIs found" "1" "${#UKI_PATHS[@]}"
done
R=$(make_fixture "disc-none" esp=/boot/efi uki=no regen=none)
detect "$R"
eq "no UKI present: UKIs found" "0" "${#UKI_PATHS[@]}"

# ─── 2. Regeneration backend selection ───────────────────────────────────────
echo ""
echo "[2] Regeneration backend detection"
R=$(make_fixture regen-mk    esp=/efi uki=yes regen=mkinitcpio);     detect "$R"; eq "mkinitcpio preset with _uki=" "mkinitcpio-preset" "$UKI_REGEN"
R=$(make_fixture regen-ki    esp=/boot/efi uki=yes regen=kernel-install); detect "$R"; eq "kernel-install + uki dropin" "kernel-install" "$UKI_REGEN"
R=$(make_fixture regen-dr    esp=/boot/efi uki=yes regen=dracut);    detect "$R"; eq "dracut supporting --uki-file" "dracut-uki" "$UKI_REGEN"
R=$(make_fixture regen-uk    esp=/boot/efi uki=yes regen=ukify);     detect "$R"; eq "ukify only" "ukify" "$UKI_REGEN"
R=$(make_fixture regen-none  esp=/boot/efi uki=yes regen=none);      detect "$R"; eq "no backend at all" "none" "$UKI_REGEN"

# The regression that matters most: a normal Arch box has mkinitcpio and
# presets, but builds no UKI. Claiming mkinitcpio-preset there would make the
# tool run `mkinitcpio -P` expecting an .efi that never appears.
R=$(make_fixture regen-mk-nouki esp=/boot/efi uki=no regen=mkinitcpio-nouki); detect "$R"
eq "mkinitcpio preset WITHOUT _uki= is not claimed" "none" "$UKI_REGEN"

# ─── 3. Signing backend selection ────────────────────────────────────────────
echo ""
echo "[3] Signing backend detection"
R=$(make_fixture sign-sbctl  esp=/efi uki=yes regen=mkinitcpio sign=sbctl);  detect "$R"; eq "sbctl with keys" "sbctl" "$UKI_SIGN"
R=$(make_fixture sign-sbsign esp=/efi uki=yes regen=mkinitcpio sign=sbsign); detect "$R"; eq "sbsign with db key pair" "sbsign" "$UKI_SIGN"
R=$(make_fixture sign-mok    esp=/efi uki=yes regen=mkinitcpio sign=mok);    detect "$R"; eq "sbsign with shim MOK pair" "sbsign" "$UKI_SIGN"
R=$(make_fixture sign-none   esp=/efi uki=yes regen=mkinitcpio sign=none);   detect "$R"; eq "no signer" "none" "$UKI_SIGN"

# sbctl installed but never initialised: `sbctl sign` exits 0 having signed
# nothing, so claiming it would produce a silently-unsigned UKI.
R=$(make_fixture sign-nokeys esp=/efi uki=yes regen=mkinitcpio sign=sbctl-nokeys); detect "$R"
eq "sbctl WITHOUT keys is not claimed" "none" "$UKI_SIGN"

R=$(make_fixture sign-pesign esp=/boot/efi uki=yes regen=kernel-install sign=pesign); detect "$R"
eq "pesign is not claimed as a signer" "none" "$UKI_SIGN"
case "$UKI_SIGN_DETAIL" in
    *pesign*) pass "pesign is reported in UKI_SIGN_DETAIL for the refusal message" ;;
    *)        fail "pesign present but not named in UKI_SIGN_DETAIL (got '$UKI_SIGN_DETAIL')" ;;
esac

# ─── 4. Environment overrides win over detection ─────────────────────────────
echo ""
echo "[4] Environment overrides"
R=$(make_fixture env-over esp=/efi uki=yes regen=mkinitcpio sign=sbctl)
uki_reset; LUKS_UKI_REGEN=dracut uki_detect_regen "$R" >/dev/null 2>&1
eq "LUKS_UKI_REGEN=dracut overrides mkinitcpio" "dracut-uki" "$UKI_REGEN"
uki_reset; LUKS_SB_KEY=/k LUKS_SB_CERT=/c uki_detect_signer "$R" >/dev/null 2>&1
eq "LUKS_SB_KEY/CERT force sbsign over sbctl" "sbsign" "$UKI_SIGN"
eq "  and the pinned key is used" "/k" "$UKI_SB_KEY"
uki_reset; LUKS_UKI_REGEN=bogus uki_detect_regen "$R" >/dev/null 2>&1; rc=$?
eq "an unknown LUKS_UKI_REGEN is rejected" "2" "$rc"
unset LUKS_UKI_REGEN LUKS_SB_KEY LUKS_SB_CERT

# ─── 5. systemd-boot detection ───────────────────────────────────────────────
echo ""
echo "[5] systemd-boot detection"
R=$(make_fixture sdb-yes esp=/efi uki=yes regen=mkinitcpio sdboot=yes); detect "$R"
eq "systemd-boot loader on the ESP" "1" "$UKI_SDBOOT"
R=$(make_fixture sdb-no  esp=/boot/efi uki=no regen=none sdboot=no);    detect "$R"
eq "no systemd-boot" "0" "$UKI_SDBOOT"

# ─── 6. Dry-run command dispatch ─────────────────────────────────────────────
echo ""
echo "[6] Regeneration and signing dispatch (UKI_DRY=1)"
R=$(make_fixture dry-mk esp=/efi uki=yes regen=mkinitcpio sign=sbctl); detect "$R"
OUT=$(UKI_DRY=1 uki_regenerate "$R" 2>&1)
case "$OUT" in *"DRY: mkinitcpio -P"*) pass "mkinitcpio backend runs 'mkinitcpio -P'" ;;
               *) fail "mkinitcpio dispatch wrong: $OUT" ;; esac
OUT=$(UKI_DRY=1 uki_sign "$R" 2>&1)
case "$OUT" in *"DRY: sbctl sign -s"*) pass "sbctl backend runs 'sbctl sign -s'" ;;
               *) fail "sbctl dispatch wrong: $OUT" ;; esac

R=$(make_fixture dry-ki esp=/boot/efi uki=yes regen=kernel-install); detect "$R"
OUT=$(UKI_DRY=1 uki_regenerate "$R" 2>&1)
case "$OUT" in *"DRY: kernel-install add 6.18.0-test"*) pass "kernel-install backend adds each kernel version" ;;
               *) fail "kernel-install dispatch wrong: $OUT" ;; esac

R=$(make_fixture dry-dr esp=/boot/efi uki=yes regen=dracut); detect "$R"
OUT=$(UKI_DRY=1 uki_regenerate "$R" 2>&1)
case "$OUT" in *"DRY: dracut --force --uki-file"*) pass "dracut backend passes --uki-file" ;;
               *) fail "dracut dispatch wrong: $OUT" ;; esac
# The whole point of 7f's placement: the cmdline must be read at build time.
case "$OUT" in *"--kernel-cmdline"*) pass "dracut backend passes --kernel-cmdline from /etc/kernel/cmdline" ;;
               *) fail "dracut backend did not pass --kernel-cmdline: $OUT" ;; esac

R=$(make_fixture dry-sbsign esp=/efi uki=yes regen=mkinitcpio sign=sbsign); detect "$R"
OUT=$(UKI_DRY=1 uki_sign "$R" 2>&1)
case "$OUT" in *"DRY: sbsign --key"*) pass "sbsign backend runs 'sbsign --key ... --cert ...'" ;;
               *) fail "sbsign dispatch wrong: $OUT" ;; esac
# sbsign cannot sign in place, so the move back is part of being correct.
case "$OUT" in *"DRY: mv -f"*) pass "sbsign backend moves the .signed output over the original" ;;
               *) fail "sbsign backend never moved its output into place: $OUT" ;; esac

R=$(make_fixture dry-nosign esp=/efi uki=yes regen=mkinitcpio sign=none); detect "$R"
OUT=$(UKI_DRY=1 uki_sign "$R" 2>&1)
eq "no signer emits no commands" "" "$(echo "$OUT" | grep -c 'DRY:' | tr -d ' ' | sed 's/^0$//')"

# ─── 7. The refusal matrix ───────────────────────────────────────────────────
# Mirrors the decision in luks-deploy.sh's UKI guard. Kept here as a table so a
# change to that logic that loosens a refusal fails loudly in CI.
echo ""
echo "[7] Refusal matrix"
would_refuse() {   # $1 = root, $2 = secure boot state -> prints refuse|proceed
    local root="$1" sb="$2"
    detect "$root"
    if [ "${#UKI_PATHS[@]}" -eq 0 ]; then echo "proceed"; return; fi
    if [ "$UKI_REGEN" = "none" ]; then echo "refuse"; return; fi
    if [ "$sb" = "enabled" ] && [ "$UKI_SIGN" = "none" ]; then echo "refuse"; return; fi
    echo "proceed"
}
R=$(make_fixture ref-ok    esp=/efi uki=yes regen=mkinitcpio sign=sbctl)
eq "UKI + backend + signer + SB on"          "proceed" "$(would_refuse "$R" enabled)"
R=$(make_fixture ref-nosign esp=/boot/efi uki=yes regen=kernel-install sign=none)
eq "UKI + backend, no signer, SB ON"         "refuse"  "$(would_refuse "$R" enabled)"
eq "UKI + backend, no signer, SB OFF"        "proceed" "$(would_refuse "$R" disabled)"
R=$(make_fixture ref-noregen esp=/boot/efi uki=yes regen=none sign=sbctl)
eq "UKI but no rebuild backend, SB off"      "refuse"  "$(would_refuse "$R" disabled)"
R=$(make_fixture ref-nouki  esp=/boot/efi uki=no regen=none sign=none)
eq "no UKI at all (untouched code path)"     "proceed" "$(would_refuse "$R" enabled)"

# ─── 8. Reading a real PE binary ─────────────────────────────────────────────
echo ""
echo "[8] .cmdline extraction from a real PE binary"
if command -v objcopy >/dev/null 2>&1; then
    STUB="$TMP/stub.efi"
    # Build a tiny PE with a .cmdline section, the same way a UKI carries one.
    if printf 'int main(void){return 0;}' > "$TMP/s.c" 2>/dev/null \
       && command -v gcc >/dev/null 2>&1 \
       && gcc -c -o "$TMP/s.o" "$TMP/s.c" 2>/dev/null; then
        printf 'root=/dev/mapper/root_crypt rd.luks.uuid=DEADBEEF ro' > "$TMP/cmdline.txt"
        if objcopy --add-section .cmdline="$TMP/cmdline.txt" \
                   --set-section-flags .cmdline=noload,readonly \
                   "$TMP/s.o" "$STUB" 2>/dev/null; then
            GOT=$(uki_cmdline_of "$STUB" || true)
            case "$GOT" in
                *"rd.luks.uuid=DEADBEEF"*) pass "uki_cmdline_of reads back the .cmdline section" ;;
                *) fail "uki_cmdline_of returned '$GOT'" ;;
            esac
        else
            skip "objcopy could not add a .cmdline section here"
        fi
    else
        skip "no gcc to build a PE fixture"
    fi
    # An .efi with no .cmdline at all must report "cannot inspect" (2), never
    # "absent" (1) — the difference decides SKIP vs FAIL at check V11.
    : > "$TMP/empty.efi"
    uki_cmdline_of "$TMP/empty.efi" >/dev/null 2>&1; rc=$?
    eq "a file with no .cmdline reports 'cannot inspect'" "2" "$rc"
else
    skip "objcopy not installed — .cmdline extraction untested"
fi

# ─── 9. Apple Silicon / Fedora Asahi Remix guard ─────────────────────────────
echo ""
echo "[9] Fedora Asahi Remix detection"
A="$TMP/asahi"; mkdir -p "$A/etc"
cat > "$A/etc/os-release" <<'OSR'
NAME="Fedora Linux Asahi Remix"
ID=fedora
VARIANT="Asahi Remix"
VARIANT_ID=asahi
OSR
if ll_detect_asahi "$A"; then pass "Fedora Asahi Remix detected via VARIANT_ID"
else fail "Fedora Asahi Remix NOT detected (ID=fedora alone must not fool it)"; fi

F="$TMP/plainfedora"; mkdir -p "$F/etc"
printf 'NAME="Fedora Linux"\nID=fedora\nVARIANT_ID=workstation\n' > "$F/etc/os-release"
if ll_detect_asahi "$F"; then fail "plain Fedora wrongly flagged as Asahi"
else pass "plain Fedora is not flagged as Asahi"; fi

M="$TMP/m1n1"; mkdir -p "$M/etc" "$M/boot/efi/m1n1"
printf 'NAME="Some Distro"\nID=other\n' > "$M/etc/os-release"
if ll_detect_asahi "$M"; then pass "m1n1 boot components detected without os-release help"
else fail "m1n1 present but not detected"; fi

# ─── 10. This machine, if it is itself a UKI target ──────────────────────────
# The fixtures prove the logic; this proves the logic matches reality on at
# least one real, in-service UKI + Secure Boot machine.
echo ""
echo "[10] Live self-check (this machine)"
unset LUKS_UKI_REGEN LUKS_UKI_SIGN LUKS_SB_KEY LUKS_SB_CERT LUKS_SB_STATE
uki_reset
uki_find_ukis ""
UKI_DIR_EXISTS=0
for d in /boot/EFI/Linux /efi/EFI/Linux /boot/efi/EFI/Linux; do
    [ -d "$d" ] && UKI_DIR_EXISTS=1
done
if [ "${#UKI_PATHS[@]}" -eq 0 ] && [ "$UKI_DIR_EXISTS" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
    # The directory is there but unreadable: an ESP is typically mounted
    # 0700 root. Saying "no UKI" here would be a false negative.
    skip "EFI/Linux exists but is not readable as $(id -un) — re-run with sudo to self-check"
elif [ "${#UKI_PATHS[@]}" -eq 0 ]; then
    skip "this machine does not boot a UKI — nothing to self-check"
else
    uki_detect_regen  "" >/dev/null 2>&1
    uki_detect_signer "" >/dev/null 2>&1
    uki_detect_sdboot "" >/dev/null 2>&1
    uki_detect_sb
    echo "       found ${#UKI_PATHS[@]} UKI(s); regen=$UKI_REGEN sign=$UKI_SIGN sb=$UKI_SB_STATE sdboot=$UKI_SDBOOT"
    [ "$UKI_REGEN" != "none" ] \
        && pass "a regeneration backend was identified ($UKI_REGEN: $UKI_REGEN_DETAIL)" \
        || fail "this machine boots a UKI but no rebuild backend was found"
    case "$UKI_SB_STATE" in
        enabled|disabled) pass "Secure Boot state read from firmware: $UKI_SB_STATE" ;;
        *) skip "Secure Boot state could not be determined" ;;
    esac
    if [ "$UKI_SB_STATE" = "enabled" ]; then
        [ "$UKI_SIGN" != "none" ] \
            && pass "Secure Boot is on and a signer was identified ($UKI_SIGN)" \
            || fail "Secure Boot is on but no signing backend was found — a real run here would refuse"
    fi
    # Reading the live UKI needs root on most layouts; not a failure if not.
    if CL=$(uki_cmdline_of "${UKI_PATHS[0]}" 2>/dev/null) && [ -n "$CL" ]; then
        case "$CL" in
            *root=*) pass "the live UKI's .cmdline is readable and contains root=" ;;
            *) fail "the live UKI's .cmdline has no root= (got: ${CL:0:60})" ;;
        esac
    else
        skip "cannot read the live UKI's .cmdline (needs root, or no objcopy)"
    fi
fi

# ─── Result ──────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " $PASS passed, $FAIL failed, $SKIP skipped"
echo "═══════════════════════════════════════════════════════════════"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
