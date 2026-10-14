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
#   8.  the Fedora Asahi Remix guard: every signal it reads; the copies that
#       luks-deploy.sh, luks-tune.sh, post-encryption-setup.sh and
#       linuxlocker.sh carry are identical to lib-deps.sh's and give the same
#       verdicts; no check is gated on a library being present; and each
#       script, run unprivileged with no lib-deps.sh (or a pre-1.2.0 one)
#       beside it, refuses on an Asahi / Apple Silicon machine and gets past
#       the check cleanly everywhere else
#   9.  the partition check (ll_detect_asahi_dev) against fake disks with
#       lsblk/findmnt/mount mocked — Apple Silicon partition types, mounted
#       filesystems, m1n1 / an Asahi kernel on the plain partitions beside it,
#       the read-only probe options — its copies in luks-deploy.sh and
#       luks-tune.sh, the line order that puts it before every action on the
#       selected partition, and this machine's own disks when one is Apple's
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
# A synthetic os-release that names Asahi everywhere but ID (a real Fedora
# Asahi Remix 44 has ID=fedora-asahi-remix and VARIANT_ID=kde — see the f44
# fixture below): detection must not depend on any one field.
A="$TMP/asahi"; mkdir -p "$A/etc"
cat > "$A/etc/os-release" <<'OSR'
NAME="Fedora Linux Asahi Remix"
ID=fedora
VARIANT="Asahi Remix"
VARIANT_ID=asahi
OSR
if ll_detect_asahi "$A"; then pass "Asahi named in NAME/VARIANT/VARIANT_ID with ID=fedora is detected"
else fail "Asahi named in NAME/VARIANT/VARIANT_ID with ID=fedora was NOT detected"; fi

F="$TMP/plainfedora"; mkdir -p "$F/etc"
printf 'NAME="Fedora Linux"\nID=fedora\nVARIANT_ID=workstation\n' > "$F/etc/os-release"
if ll_detect_asahi "$F"; then fail "plain Fedora wrongly flagged as Asahi"
else pass "plain Fedora is not flagged as Asahi"; fi

M="$TMP/m1n1"; mkdir -p "$M/etc" "$M/boot/efi/m1n1"
printf 'NAME="Some Distro"\nID=other\n' > "$M/etc/os-release"
if ll_detect_asahi "$M"; then pass "m1n1 boot components detected without os-release help"
else fail "m1n1 present but not detected"; fi

# One fixture per remaining signal, each behind an os-release that says
# nothing, so the signal under test is the only thing that can fire.
asahi_fx() {   # $1 = name -> path of a fresh root holding a neutral os-release
    local r="$TMP/asahi-fx/$1"
    mkdir -p "$r/etc"
    printf 'NAME="Some Distro"\nID=other\n' > "$r/etc/os-release"
    printf '%s' "$r"
}
FX_ROOTS=(); FX_WANT=(); FX_WHAT=()
fx() { FX_ROOTS+=("$1"); FX_WANT+=("$2"); FX_WHAT+=("$3"); }   # root, 0=Asahi|1=not, label
R=$(asahi_fx f44)   # what a real Fedora Asahi Remix 44 install ships: VARIANT_ID is the edition
printf '%s\n' 'NAME="Fedora Linux Asahi Remix"' 'ID=fedora-asahi-remix' \
    'PRETTY_NAME="Fedora Linux Asahi Remix 44 (KDE Plasma Desktop Edition)"' \
    'VARIANT="KDE Plasma Desktop Edition"' 'VARIANT_ID=kde' > "$R/etc/os-release"
fx "$R" 0 "Fedora Asahi Remix 44 os-release (ID=fedora-asahi-remix, VARIANT_ID=kde)"
R=$(asahi_fx usrlib); rm -f "$R/etc/os-release"; mkdir -p "$R/usr/lib"
printf 'NAME="Fedora Linux Asahi Remix"\nID=fedora-asahi-remix\n' > "$R/usr/lib/os-release"
fx "$R" 0 "os-release only at /usr/lib/os-release"
R=$(asahi_fx kmod-usr); mkdir -p "$R/usr/lib/modules/7.1.13-402.asahi.fc44.aarch64+16k"
fx "$R" 0 "an Asahi kernel in /usr/lib/modules"
R=$(asahi_fx kmod-lib); mkdir -p "$R/lib/modules/7.1.13-402.asahi.fc44.aarch64+16k"
fx "$R" 0 "an Asahi kernel in /lib/modules"
R=$(asahi_fx default-m1n1); mkdir -p "$R/etc/default"; : > "$R/etc/default/m1n1"
fx "$R" 0 "/etc/default/m1n1"
R=$(asahi_fx asahi-boot); mkdir -p "$R/usr/lib/asahi-boot"
fx "$R" 0 "/usr/lib/asahi-boot"
R=$(asahi_fx debian); printf 'NAME="Debian GNU/Linux"\nID=debian\n' > "$R/etc/os-release"
mkdir -p "$R/usr/lib/modules/6.12.0-1-arm64"
fx "$R" 1 "Debian on arm64 with a stock kernel"
R="$TMP/asahi-fx/empty"; mkdir -p "$R"
fx "$R" 1 "an empty root (no os-release, no kernel)"
for i in "${!FX_ROOTS[@]}"; do
    if ll_detect_asahi "${FX_ROOTS[$i]}"; then got=0; else got=1; fi
    if [ "$got" = "${FX_WANT[$i]}" ]; then
        if [ "$got" = 0 ]; then pass "${FX_WHAT[$i]}: detected ($LL_ASAHI_REASON)"
        else pass "${FX_WHAT[$i]}: not flagged"; fi
    else
        if [ "$got" = 0 ]; then fail "${FX_WHAT[$i]}: wrongly flagged ($LL_ASAHI_REASON)"
        else fail "${FX_WHAT[$i]}: NOT detected"; fi
    fi
done
ALL_FX=("$A" "$F" "$M" "${FX_ROOTS[@]}")

# ─── 9b. The copies of the guard agree with lib-deps.sh ──────────────────────
# luks-deploy.sh, luks-tune.sh, post-encryption-setup.sh and linuxlocker.sh
# each carry the guard between '# --- asahi_guard ---' markers, so the refusal
# still fires when lib-deps.sh was not copied along, or is a pre-1.2.0 one
# without the guard (until 1.6.4 luks-deploy.sh skipped it silently then, and
# until 1.6.5 linuxlocker.sh printed "command not found" and carried on).
# Each block is loaded into a fresh bash holding nothing else
# and compared with lib-deps.sh: the functions as bash itself prints them
# (comments and layout ignored), then the verdict and the reason on every
# fixture above and on this machine.
echo ""
echo "[9b] The scripts' own copies of the Asahi guard match lib-deps.sh"
guard_defs() {   # $1 = shell code to load -> the guard's functions and URL, as bash prints them
    env -u BASH_ENV bash -c 'set -euo pipefail; eval "$1"
        declare -f ll_detect_asahi ll_link ll_asahi_refuse
        printf "URL=%s\n" "$LL_ASAHILOCKER_URL"' _ "$1" 2>&1
}
guard_verdicts() {   # $1 = shell code to load, rest = roots -> "root|rc|reason" for each
    env -u BASH_ENV bash -c 'set -euo pipefail; eval "$1"; shift
        for r in "$@"; do
            if ll_detect_asahi "$r"; then rc=0; else rc=1; fi
            printf "%s|%s|%s\n" "$r" "$rc" "$LL_ASAHI_REASON"
        done' _ "$@" 2>&1
}
guard_block() {   # $1 = script under bin/ -> its asahi_guard block
    sed -n '/^# --- asahi_guard ---$/,/^# --- end asahi_guard ---$/p' "$REPO/bin/$1"
}
CANON=". \"$REPO/bin/lib-deps.sh\""
CANON_DEFS=$(guard_defs "$CANON")
CANON_VERDICTS=$(guard_verdicts "$CANON" "${ALL_FX[@]}" "")
for s in luks-deploy.sh luks-tune.sh post-encryption-setup.sh linuxlocker.sh; do
    BLOCK=$(guard_block "$s")
    if [ -z "$BLOCK" ]; then fail "$s: no '# --- asahi_guard ---' block"; continue; fi
    GOT=$(guard_defs "$BLOCK")
    if [ "$GOT" = "$CANON_DEFS" ]; then
        pass "$s: ll_detect_asahi, ll_link, ll_asahi_refuse and the URL are identical to lib-deps.sh's"
    else
        fail "$s: its copy of the guard differs from lib-deps.sh's:"
        diff <(printf '%s\n' "$CANON_DEFS") <(printf '%s\n' "$GOT") | head -20 | sed 's/^/        /'
    fi
    GOT=$(guard_verdicts "$BLOCK" "${ALL_FX[@]}" "")
    if [ "$GOT" = "$CANON_VERDICTS" ]; then
        pass "$s: same verdict and reason as lib-deps.sh on ${#ALL_FX[@]} fixtures and on this machine"
    else
        fail "$s: its verdicts differ from lib-deps.sh's:"
        diff <(printf '%s\n' "$CANON_VERDICTS") <(printf '%s\n' "$GOT") | head -20 | sed 's/^/        /'
    fi
done
# A lib-deps.sh from before 1.2.0 has no guard in it at all. Sourcing one must
# not leave a script without the check: the block sees the missing functions
# and defines its own.
STALE_LIB="$TMP/lib-deps-pre-1.2.0.sh"
sed '/^# Apple Silicon \/ Fedora Asahi Remix guard$/,$d' "$REPO/bin/lib-deps.sh" > "$STALE_LIB"
if grep -q 'll_detect_asahi()' "$STALE_LIB" || ! grep -q 'll_ensure_tools()' "$STALE_LIB"; then
    fail "could not build a guard-less lib-deps.sh fixture"
else
    GOT=$(guard_verdicts ". \"$STALE_LIB\"
$(guard_block luks-deploy.sh)" "${ALL_FX[@]}" "")
    if [ "$GOT" = "$CANON_VERDICTS" ]; then
        pass "a guard-less (pre-1.2.0) lib-deps.sh does not disable the check: the block stands in"
    else
        fail "with a guard-less lib-deps.sh loaded, the block did not stand in:"
        diff <(printf '%s\n' "$CANON_VERDICTS") <(printf '%s\n' "$GOT") | head -20 | sed 's/^/        /'
    fi
fi

# ─── 9c. No Asahi check hangs on a library being present ─────────────────────
# The defect fixed in 1.6.4: both checks in luks-deploy.sh were written
# `[ "$LL_HAVE_DEPS_LIB" -eq 1 ] && ll_detect_asahi ...`, so a copy without
# lib-deps.sh skipped the refusal without a word.
echo ""
echo "[9c] Every Asahi check is unconditional"
for s in linuxlocker.sh luks-deploy.sh luks-tune.sh post-encryption-setup.sh; do
    CALLS=$(grep -nE '^[^#]*ll_detect_asahi "' "$REPO/bin/$s")
    if [ -z "$CALLS" ]; then fail "$s: never calls ll_detect_asahi"; continue; fi
    if printf '%s\n' "$CALLS" | grep -q 'HAVE_'; then
        fail "$s: an Asahi check is gated on a library flag: $(printf '%s\n' "$CALLS" | grep -m1 'HAVE_')"
    else
        pass "$s: $(printf '%s\n' "$CALLS" | wc -l | tr -d ' ') Asahi check(s), none gated on a library being present"
    fi
done

# ─── 9d. Standalone runs: no lib-deps.sh next to the script ──────────────────
# The end-to-end form of 9b: each script copied into a directory WITHOUT
# lib-deps.sh (or with the guard-less one) and run for real. On an Asahi or
# Apple Silicon machine every run must refuse — exit 3, the reason, the
# AsahiLocker link — before anything else; everywhere else every run must get
# past the check cleanly and stop at its next gate. Unprivileged only, with an
# empty environment and stdin from /dev/null, so no LUKS_* pin can leak in and
# a regressed guard still stops at the root check: these runs never reach a
# device.
echo ""
echo "[9d] Standalone runs without lib-deps.sh (unprivileged)"
if [ "$(id -u)" -eq 0 ]; then
    skip "running as root — the standalone runs are made unprivileged only, so a regressed guard can never reach a device"
else
    if ll_detect_asahi ""; then
        HOST_ASAHI=1; HOST_REASON="$LL_ASAHI_REASON"
        echo "       this machine is Asahi / Apple Silicon ($HOST_REASON): every run must refuse"
    else
        HOST_ASAHI=0; HOST_REASON=""
        echo "       this machine is not Asahi: every run must pass the check and stop at its next gate"
    fi
    TO=(); command -v timeout >/dev/null 2>&1 && TO=(timeout 120)
    OUT=""; RC=0
    run_alone() {   # $1 = directory, $2 = script, rest = arguments -> OUT, RC
        local dir="$1" s="$2"; shift 2
        OUT=$(cd "$dir" && "${TO[@]}" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME="$dir" \
                  bash "./$s" "$@" </dev/null 2>&1)
        RC=$?
    }
    check_alone() {   # $1 = label, $2 = exit expected off Asahi, $3 = ERE that run must print
        local err
        err=$(printf '%s\n' "$OUT" | grep -m1 -E 'command not found|unbound variable|syntax error')
        if [ -n "$err" ]; then fail "$1: the run hit a shell error: $err"; return; fi
        if [ "$HOST_ASAHI" -eq 1 ]; then
            if [ "$RC" -eq 3 ] && [[ "$OUT" == *"WRONG TOOL"* ]] \
               && [[ "$OUT" == *"Reason: $HOST_REASON"* ]] && [[ "$OUT" == *"$LL_ASAHILOCKER_URL"* ]]; then
                pass "$1: refused — exit 3, the reason and the AsahiLocker link"
            else
                fail "$1: expected the Asahi refusal (exit 3), got exit $RC: $(printf '%s\n' "$OUT" | tail -3 | tr '\n' ' ')"
            fi
        elif [ "$RC" -eq "$2" ] && [[ "$OUT" != *"WRONG TOOL"* ]] && printf '%s\n' "$OUT" | grep -qE "$3"; then
            pass "$1: past the Asahi check, stopped at its next gate (exit $RC)"
        else
            fail "$1: expected exit $2 matching /$3/, got exit $RC: $(printf '%s\n' "$OUT" | tail -3 | tr '\n' ' ')"
        fi
    }
    D="$TMP/alone-deploy"; mkdir -p "$D"
    cp "$REPO/bin/luks-deploy.sh" "$REPO/bin/lib-boot.sh" "$REPO/bin/lib-uki.sh" "$D/"
    run_alone "$D" luks-deploy.sh --dry-run
    check_alone "luks-deploy.sh beside lib-boot.sh and lib-uki.sh, no lib-deps.sh" 1 'Must run as root'
    D="$TMP/alone-deploy-only"; mkdir -p "$D"
    cp "$REPO/bin/luks-deploy.sh" "$D/"
    run_alone "$D" luks-deploy.sh --dry-run
    check_alone "luks-deploy.sh entirely alone" 1 'lib-boot\.sh not found'
    D="$TMP/stale-deploy"; mkdir -p "$D"
    cp "$REPO/bin/luks-deploy.sh" "$REPO/bin/lib-boot.sh" "$REPO/bin/lib-uki.sh" "$D/"
    cp "$STALE_LIB" "$D/lib-deps.sh"
    run_alone "$D" luks-deploy.sh --dry-run
    check_alone "luks-deploy.sh beside a guard-less (pre-1.2.0) lib-deps.sh" 1 'Must run as root'
    D="$TMP/alone-tune"; mkdir -p "$D"
    cp "$REPO/bin/luks-tune.sh" "$D/"
    run_alone "$D" luks-tune.sh --dry-run
    check_alone "luks-tune.sh entirely alone" 1 "Run as root|cryptsetup not found|Neither 'dialog' nor 'whiptail'"
    D="$TMP/alone-post"; mkdir -p "$D"
    cp "$REPO/bin/post-encryption-setup.sh" "$D/"
    run_alone "$D" post-encryption-setup.sh
    check_alone "post-encryption-setup.sh entirely alone" 1 'run as root'
    # The front door cannot run without lib-deps.sh at all; what it must
    # survive is a pre-1.2.0 one, whose missing detector used to print
    # "command not found" and let the run carry on.
    D="$TMP/stale-front"; mkdir -p "$D"
    cp "$REPO/bin/linuxlocker.sh" "$D/"
    cp "$STALE_LIB" "$D/lib-deps.sh"
    run_alone "$D" linuxlocker.sh
    check_alone "linuxlocker.sh beside a guard-less (pre-1.2.0) lib-deps.sh" 1 'Run as root'
    D="$TMP/front"; mkdir -p "$D"
    cp "$REPO/bin/linuxlocker.sh" "$REPO/bin/lib-deps.sh" "$D/"
    run_alone "$D" linuxlocker.sh
    check_alone "linuxlocker.sh beside lib-deps.sh" 1 'Run as root'
fi

# ─── 9e. The partition check, against fake disks ─────────────────────────────
# ll_detect_asahi_dev judges the partition about to be acted on without its
# passphrase: Apple Silicon partition types on its disk, filesystems already
# mounted from it, and the plain partitions beside it (m1n1 on a FAT one, an
# Asahi kernel on an ext2/3/4 one), probe-mounted read-only when not mounted.
# It reads all of that through lsblk, findmnt and mount; here those commands
# (and umount) are shell functions answering from a table, so the real
# function runs unmodified, with no root and no block device. Each table row:
#   path|parent name|type|parttype|fstype|mountpoint|what a probe mount shows
# The probe mounts are logged with their options, so the log is checked too:
# vfat ro, ext3/4 ro,noload (no journal replay), and never the selected
# partition itself. The copies in luks-deploy.sh and luks-tune.sh must give
# exactly what lib-deps.sh gives, case by case.
echo ""
echo "[9e] The partition check, against fake disks (lsblk/findmnt/mount mocked)"
MK="$TMP/devfx"; C="$MK/content"
mkdir -p "$C/esp-m1n1/m1n1" "$C/esp-m1n1/EFI/BOOT" "$C/esp-plain/EFI/BOOT" "$C/esp-ubuntu/EFI/ubuntu" \
         "$C/boot-asahi" "$C/boot-generic" "$C/btrfs-top/root/etc" "$C/btrfs-top/home" "$C/root-asahi/etc"
: > "$C/esp-m1n1/m1n1/boot.bin"; : > "$C/esp-m1n1/EFI/BOOT/BOOTAA64.EFI"
: > "$C/esp-plain/EFI/BOOT/BOOTAA64.EFI"; : > "$C/esp-ubuntu/EFI/ubuntu/grubx64.efi"
: > "$C/boot-asahi/vmlinuz-7.1.13-402.asahi.fc44.aarch64+16k"
: > "$C/boot-asahi/config-7.1.13-402.asahi.fc44.aarch64+16k"
: > "$C/boot-generic/vmlinuz-6.8.0-45-generic"
printf 'NAME="Fedora Linux Asahi Remix"\nID=fedora-asahi-remix\nVARIANT_ID=kde\n' > "$C/btrfs-top/root/etc/os-release"
cp "$C/btrfs-top/root/etc/os-release" "$C/root-asahi/etc/os-release"
BOOT_T=c12a7328-f81f-11d2-ba4b-00a0c93ec93b; LIN_T=0fc63daf-8483-4772-8e79-3d69d8477de4
APFS_T=7c3457ef-0000-11aa-aa11-00306543ecac
IBOOT_T=69646961-6700-11aa-aa11-00306543ecac; RECOV_T=52637672-7900-11aa-aa11-00306543ecac
spec() {   # $1 = case name, rest = rows
    local n="$1"; shift
    printf '%s\n' "$@" > "$MK/$n.spec"
}
# The layout of a real Apple Silicon Mac running Fedora Asahi Remix (the
# author's M2 Max, read with lsblk): iBoot system container, macOS, the Asahi
# stub, the ESP, /boot, the LUKS root, the recovery container.
spec apple "/dev/fk1||disk|-|-|-|-" "/dev/fk1p1|fk1|part|$IBOOT_T|apfs|-|-" \
    "/dev/fk1p2|fk1|part|$APFS_T|apfs|-|-" "/dev/fk1p3|fk1|part|$APFS_T|apfs|-|-" \
    "/dev/fk1p4|fk1|part|$BOOT_T|vfat|-|$C/esp-m1n1" "/dev/fk1p5|fk1|part|$LIN_T|ext4|-|$C/boot-asahi" \
    "/dev/fk1p6|fk1|part|$LIN_T|crypto_LUKS|-|-" "/dev/fk1p7|fk1|part|$RECOV_T|apfs|-|-"
spec recovery "/dev/fk2||disk|-|-|-|-" "/dev/fk2p1|fk2|part|$APFS_T|apfs|-|-" \
    "/dev/fk2p2|fk2|part|$LIN_T|crypto_LUKS|-|-" "/dev/fk2p3|fk2|part|$RECOV_T|apfs|-|-"
spec usb-boot "/dev/fk3||disk|-|-|-|-" "/dev/fk3p1|fk3|part|$BOOT_T|vfat|-|$C/esp-plain" \
    "/dev/fk3p2|fk3|part|$LIN_T|ext4|-|$C/boot-asahi" "/dev/fk3p3|fk3|part|$LIN_T|crypto_LUKS|-|-"
spec esp-m1n1 "/dev/fk4||disk|-|-|-|-" "/dev/fk4p1|fk4|part|$BOOT_T|vfat|-|$C/esp-m1n1" \
    "/dev/fk4p2|fk4|part|$LIN_T|crypto_LUKS|-|-"
spec esp-mounted "/dev/fk5||disk|-|-|-|-" "/dev/fk5p1|fk5|part|$BOOT_T|vfat|$C/esp-m1n1|-" \
    "/dev/fk5p2|fk5|part|$LIN_T|crypto_LUKS|-|-"
spec open-mapper "/dev/fk6||disk|-|-|-|-" "/dev/fk6p1|fk6|part|$LIN_T|crypto_LUKS|-|-" \
    "/dev/mapper/fk6crypt|fk6p1|crypt|-|btrfs|$C/btrfs-top|-"
spec plain-mounted "/dev/fk7||disk|-|-|-|-" "/dev/fk7p1|fk7|part|$BOOT_T|vfat|-|$C/esp-plain" \
    "/dev/fk7p2|fk7|part|$LIN_T|ext4|$C/root-asahi|-"
spec x86 "/dev/fk8||disk|-|-|-|-" "/dev/fk8p1|fk8|part|$BOOT_T|vfat|-|$C/esp-ubuntu" \
    "/dev/fk8p2|fk8|part|$LIN_T|ext4|-|$C/boot-generic" "/dev/fk8p3|fk8|part|$LIN_T|crypto_LUKS|-|-"
spec ext2-boot "/dev/fk9||disk|-|-|-|-" "/dev/fk9p1|fk9|part|$LIN_T|ext2|-|$C/boot-asahi" \
    "/dev/fk9p2|fk9|part|$LIN_T|crypto_LUKS|-|-"
spec whole-disk "/dev/fk10||disk|-|crypto_LUKS|-|-"
spec self-only "/dev/fk11||disk|-|-|-|-" "/dev/fk11p1|fk11|part|$LIN_T|ext4|-|$C/boot-asahi"
spec xfs-boot "/dev/fk12||disk|-|-|-|-" "/dev/fk12p1|fk12|part|$LIN_T|xfs|-|$C/boot-asahi" \
    "/dev/fk12p2|fk12|part|$LIN_T|crypto_LUKS|-|-"
spec mount-fails "/dev/fk13||disk|-|-|-|-" "/dev/fk13p1|fk13|part|$BOOT_T|vfat|-|-" \
    "/dev/fk13p2|fk13|part|$LIN_T|crypto_LUKS|-|-"
cat > "$MK/mocks.sh" <<'MOCKS'
# Answers lsblk / findmnt / mount / umount from $MOCK_SPEC; logs to $MOCK_LOG.
mock_tree() {   # $1 = device path -> its row, then every descendant's
    awk -F'|' -v d="$1" '
        { row[NR] = $0; p[NR] = $1; n = $1; sub(/^.*\//, "", n); nm[NR] = n; par[NR] = $2 }
        END {
            for (i = 1; i <= NR; i++) if (p[i] == d) { want[nm[i]] = 1; print row[i] }
            for (k = 0; k < 3; k++)
                for (i = 1; i <= NR; i++)
                    if ((par[i] in want) && !(nm[i] in done)) { done[nm[i]] = 1; want[nm[i]] = 1; print row[i] }
        }' "$MOCK_SPEC"
}
mock_field() {   # $1 = device path, $2 = field number -> that field of its row
    awk -F'|' -v d="$1" -v f="$2" '$1 == d { print $f; exit }' "$MOCK_SPEC"
}
lsblk() {
    local d="${*: -1}"
    case "$*" in
        "-dnpo NAME $d")           mock_field "$d" 1 ;;
        "-dno PKNAME $d")          mock_field "$d" 2 ;;
        "-rpno NAME,PARTTYPE $d")  mock_tree "$d" | awk -F'|' '{ print $1 " " ($4 == "-" ? "" : $4) }' ;;
        "-rpno NAME $d")           mock_tree "$d" | cut -d'|' -f1 ;;
        "-rpno NAME,TYPE,FSTYPE $d") mock_tree "$d" | awk -F'|' '{ print $1 " " $3 " " ($5 == "-" ? "" : $5) }' ;;
        *) echo "mock lsblk: unexpected arguments: $*" >&2; return 99 ;;
    esac
}
findmnt() {
    case "$*" in
        "-lno TARGET -S "*) local m; m=$(mock_field "${*: -1}" 6); [ -n "$m" ] && [ "$m" != "-" ] && printf '%s\n' "$m" ;;
        *) echo "mock findmnt: unexpected arguments: $*" >&2; return 99 ;;
    esac
}
mount() {   # mount -t FS -o OPTS SRC DIR
    [ "$#" -eq 6 ] && [ "$1" = -t ] && [ "$3" = -o ] || { echo "mock mount: unexpected arguments: $*" >&2; return 99; }
    local content; content=$(mock_field "$5" 7)
    if [ -z "$content" ] || [ "$content" = "-" ]; then echo "mount-failed $5" >> "$MOCK_LOG"; return 32; fi
    cp -R "$content/." "$6/" && echo "mount $5 $2 $4" >> "$MOCK_LOG"
}
umount() {
    find "$1" -mindepth 1 -delete && echo "umount" >> "$MOCK_LOG"
}
MOCKS
dev_defs() {   # $1 = shell code to load -> ll_detect_asahi_dev as bash prints it
    env -u BASH_ENV bash -c 'set -euo pipefail; eval "$1"; declare -f ll_detect_asahi_dev' _ "$1" 2>&1
}
dev_verdicts() {   # $1 = shell code to load, rest = "case:device" -> "case|rc|reason|probe log"
    env -u BASH_ENV MK="$MK" bash -c 'set -euo pipefail; eval "$1"; shift
        . "$MK/mocks.sh"
        MOCK_LOG="$MK/mock.log"
        for c in "$@"; do
            MOCK_SPEC="$MK/${c%%:*}.spec"; : > "$MOCK_LOG"
            if ll_detect_asahi_dev "${c#*:}"; then rc=0; else rc=1; fi
            printf "%s|%s|%s|%s\n" "${c%%:*}" "$rc" "$LL_ASAHI_REASON" "$(paste -sd";" "$MOCK_LOG")"
        done' _ "$@" 2>&1
}
dev_block() {   # $1 = script under bin/ -> its asahi_dev_guard block
    sed -n '/^# --- asahi_dev_guard ---$/,/^# --- end asahi_dev_guard ---$/p' "$REPO/bin/$1"
}
DEV_CASES=(apple:/dev/fk1p6 recovery:/dev/fk2p2 usb-boot:/dev/fk3p3 esp-m1n1:/dev/fk4p2
           esp-mounted:/dev/fk5p2 open-mapper:/dev/fk6p1 plain-mounted:/dev/fk7p2 x86:/dev/fk8p3
           ext2-boot:/dev/fk9p2 whole-disk:/dev/fk10 self-only:/dev/fk11p1 xfs-boot:/dev/fk12p2
           mount-fails:/dev/fk13p2)
PROBES_BEFORE=$(find /tmp -maxdepth 1 -name 'luks-asahi-probe.*' 2>/dev/null | wc -l)
CANON_DEV=$(dev_verdicts "$CANON" "${DEV_CASES[@]}")
# What lib-deps.sh must say, case by case: "case|rc|reason glob|probe log glob".
DEV_WANT=(
  "apple|0|its disk carries an Apple Silicon boot partition (/dev/fk1p1, iBootSystemContainer)|"
  "recovery|0|its disk carries an Apple Silicon recovery partition (/dev/fk2p3, RecoveryOSContainer)|"
  "usb-boot|0|its disk holds an Asahi kernel on /dev/fk3p2 (vmlinuz-7.1.13-402.asahi.fc44.aarch64+16k)|mount /dev/fk3p1 vfat ro;umount;mount /dev/fk3p2 ext4 ro,noload;umount"
  "esp-m1n1|0|its disk holds m1n1 on the FAT partition /dev/fk4p1|mount /dev/fk4p1 vfat ro;umount"
  "esp-mounted|0|its disk holds m1n1 on the FAT partition /dev/fk5p1|"
  "open-mapper|0|it is mounted at $C/btrfs-top, and os-release identifies Fedora Asahi Remix|"
  "plain-mounted|0|it is mounted at $C/root-asahi, and os-release identifies Fedora Asahi Remix|"
  "x86|1||mount /dev/fk8p1 vfat ro;umount;mount /dev/fk8p2 ext4 ro,noload;umount"
  "ext2-boot|0|its disk holds an Asahi kernel on /dev/fk9p1 (vmlinuz-7.1.13-402.asahi.fc44.aarch64+16k)|mount /dev/fk9p1 ext2 ro;umount"
  "whole-disk|1||"
  "self-only|1||"
  "xfs-boot|1||"
  "mount-fails|1||mount-failed /dev/fk13p1"
)
DEV_WHAT=(
  "the real Apple Silicon layout: refused from the partition table alone, nothing mounted"
  "an Apple Silicon recovery container alone is enough"
  "an Asahi disk with no Apple partitions: the plain ext4 /boot beside it names an Asahi kernel (ESP ro, /boot ro,noload)"
  "m1n1 on the FAT partition beside it (probe-mounted ro)"
  "m1n1 on an ESP that is already mounted: read there, no probe mount"
  "a LUKS volume whose mapper is open and mounted: the btrfs 'root' subvolume is read where it is"
  "a plain partition already mounted (an automounting desktop): read where it is"
  "an x86 disk (Ubuntu ESP, generic kernel): not flagged, both probes mounted read-only and unmounted"
  "an ext2 /boot is probe-mounted ro (ext2 has no journal to skip)"
  "a whole-disk volume with no partition table: nothing beside it to read"
  "the selected partition itself is never probe-mounted"
  "an xfs /boot is not probed (only FAT and ext2/3/4 are) — the documented limit"
  "a sibling that will not mount is skipped, and its probe directory removed"
)
for i in "${!DEV_WANT[@]}"; do
    want="${DEV_WANT[$i]}"
    line=$(printf '%s\n' "$CANON_DEV" | awk -F'|' -v n="${want%%|*}" '$1 == n { print; exit }')
    if [ "$line" = "$want" ]; then pass "${DEV_WHAT[$i]}"
    else fail "${DEV_WHAT[$i]}: expected '$want', got '${line:-no answer}'"; fi
done
CASE_RE=$(printf '%s\n' "${DEV_CASES[@]}" | cut -d: -f1 | paste -sd'|')
STRAY=$(printf '%s\n' "$CANON_DEV" | grep -vE "^($CASE_RE)\|" | head -n 3)
[ -z "$STRAY" ] || fail "lib-deps.sh printed something besides its answers: $STRAY"
for s in luks-deploy.sh luks-tune.sh; do
    BLOCK="$(guard_block "$s")
$(dev_block "$s")"
    if [ -z "$(dev_block "$s")" ]; then fail "$s: no '# --- asahi_dev_guard ---' block"; continue; fi
    GOT=$(dev_defs "$BLOCK")
    if [ "$GOT" = "$(dev_defs "$CANON")" ]; then
        pass "$s: ll_detect_asahi_dev is identical to lib-deps.sh's"
    else
        fail "$s: its ll_detect_asahi_dev differs from lib-deps.sh's:"
        diff <(dev_defs "$CANON") <(printf '%s\n' "$GOT") | head -20 | sed 's/^/        /'
    fi
    GOT=$(dev_verdicts "$BLOCK" "${DEV_CASES[@]}")
    if [ "$GOT" = "$CANON_DEV" ]; then
        pass "$s: same verdict, reason and probe mounts as lib-deps.sh on ${#DEV_CASES[@]} fake disks"
    else
        fail "$s: its partition check differs from lib-deps.sh's:"
        diff <(printf '%s\n' "$CANON_DEV") <(printf '%s\n' "$GOT") | head -20 | sed 's/^/        /'
    fi
done
PROBES_AFTER=$(find /tmp -maxdepth 1 -name 'luks-asahi-probe.*' 2>/dev/null | wc -l)
eq "probe directories left behind in /tmp" "$PROBES_BEFORE" "$PROBES_AFTER"

# ─── 9f. Every action on the selected partition comes after its check ────────
# luks-deploy.sh runs top to bottom, so "checked before any action" is a fact
# about line order: the check on the partition you select must come before
# the kept-mapper cross-check, the unmount, the LUKS mode decision, the LUKS1
# conversion, the hand-off to luks-tune.sh and the resumed encryption; the
# mapper an earlier run left open is checked before it is unmounted; the
# inside of a LUKS1 volume before its header is converted; and luks-tune.sh
# checks the volume picked before it backs up or re-costs anything.
echo ""
echo "[9f] The Asahi checks come before the actions they guard"
first_line() {   # $1 = file, $2 = fixed string -> line of its first occurrence, or 0
    local n; n=$(grep -nF -- "$2" "$1" | head -n 1 | cut -d: -f1)
    printf '%s' "${n:-0}"
}
before() {   # $1 = label, $2 = file, $3 = the check, $4 = the action
    local c a; c=$(first_line "$2" "$3"); a=$(first_line "$2" "$4")
    if [ "$c" -gt 0 ] && [ "$a" -gt 0 ] && [ "$c" -lt "$a" ]; then pass "$1 (line $c, then $a)"
    else fail "$1: check at line $c ('$3') must come before line $a ('$4')"; fi
}
D="$REPO/bin/luks-deploy.sh"; T="$REPO/bin/luks-tune.sh"
SEL='ll_detect_asahi_dev "$TARGET_ROOT"'
before "luks-deploy.sh: the partition you select is checked before a kept mapper is cross-checked and closed" "$D" "$SEL" 'MAPPER_BACKING=$(cryptsetup status'
before "... before it is unmounted" "$D" "$SEL" 'ensure_unmounted "$TARGET_ROOT"'
before "... before its LUKS header decides the mode" "$D" "$SEL" "if blkid \"\$TARGET_ROOT\" | grep -q 'TYPE=\"crypto_LUKS\"'"
before "... before a LUKS1 conversion" "$D" "$SEL" 'convert_luks1 "$TARGET_ROOT"'
before "... before the hand-off to luks-tune.sh" "$D" "$SEL" 'exec "$SCRIPT_DIR/luks-tune.sh"'
before "... before an interrupted encryption is resumed" "$D" "$SEL" 'cryptsetup reencrypt --resume-only --verbose'
before "... before the discovery mount" "$D" "$SEL" 'mount -o subvolid=5,ro "$DISCOVERY_DEV"'
before "luks-deploy.sh: a mapper an earlier run left open is checked before it is unmounted" "$D" 'll_detect_asahi_dev "$STALE_BACKING"' 'umount -R /mnt 2>/dev/null'
before "luks-deploy.sh: the inside of a LUKS1 volume is checked before its header is converted" "$D" 'if ll_detect_asahi "/mnt_temp/${psub%/}"' 'cryptsetup convert --type luks2 --batch-mode'
before "luks-tune.sh: the volume picked is checked before its header is backed up" "$T" 'll_detect_asahi_dev "$DEV"' '"$CRYPTSETUP" luksHeaderBackup'
before "luks-tune.sh: ... before a keyslot is re-costed" "$T" 'll_detect_asahi_dev "$DEV"' '"$CRYPTSETUP" luksConvertKey -S'

# ─── 9g. The partition check on this machine's own disks ─────────────────────
# Where a disk here carries an Apple Silicon system partition, the canonical
# check must flag another partition on it from the partition table alone.
# Real lsblk and findmnt; mount is replaced by a function that refuses and
# records, so this can never probe-mount anything, even if the check broke.
echo ""
echo "[9g] The partition check against this machine's disks"
APPLE_PART=$(lsblk -rpno NAME,PARTTYPE 2>/dev/null \
    | awk -v a="$IBOOT_T" -v r="$RECOV_T" 'tolower($2) == a || tolower($2) == r { print $1; exit }')
if [ -z "$APPLE_PART" ]; then
    skip "no disk here carries an Apple Silicon system partition"
else
    APPLE_DISK=$(lsblk -dno PKNAME "$APPLE_PART" 2>/dev/null | head -n 1)
    VICTIM=$(lsblk -rpno NAME,TYPE,FSTYPE "/dev/$APPLE_DISK" 2>/dev/null | awk '$2 == "part" && $3 == "crypto_LUKS" { print $1; exit }')
    [ -n "$VICTIM" ] || VICTIM=$(lsblk -rpno NAME,TYPE "/dev/$APPLE_DISK" 2>/dev/null | awk -v a="$APPLE_PART" '$2 == "part" && $1 != a { print $1; exit }')
    GOT=$(env -u BASH_ENV bash -c '. "$1"; mount() { echo "MOUNT-ATTEMPT $*"; return 1; }
        if ll_detect_asahi_dev "$2"; then echo "rc=0 $LL_ASAHI_REASON"; else echo "rc=1"; fi' _ "$REPO/bin/lib-deps.sh" "$VICTIM" 2>&1)
    case "$GOT" in
        *MOUNT-ATTEMPT*) fail "$VICTIM: the check tried to mount something: $GOT" ;;
        "rc=0 its disk carries an Apple Silicon "*) pass "$VICTIM on this machine: ${GOT#rc=0 }" ;;
        *) fail "$VICTIM sits beside $APPLE_PART but was not flagged: $GOT" ;;
    esac
fi

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
