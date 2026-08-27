# Contributing to LinuxLocker

This project takes **serious bugs** and **new filesystem support**. That is the
whole list.

It is deliberately narrow. The tooling rewrites a live root filesystem and its
bootloader, every added code path is a path that can lose someone's disk, and
there is one maintainer to reason about all of them. Refactors, style changes,
new options and general feature requests will be declined regardless of quality
— not because they are bad, but because the review cost lands on the same
person who has to be sure the encrypt path still works afterwards.

## What counts as a serious bug

- **Data loss or an unbootable system**, or a path that could produce either.
- **The verification gate lying** — reporting success on a system that is not
  encrypted, will not boot, or on a check that never ran. A SKIP counted as a
  PASS is the same bug.
- **Key material somewhere it should not be** — but that is a security report,
  not an issue. Read [`SECURITY.md`](SECURITY.md) and email it.
- **Wrong device touched.** Anything writing outside the detected target.
- **A resume or LUKS1 conversion acting on state it did not verify.**
- **A read-only tool that writes**, `--dry-run` included.

Cosmetic output, a menu that could be nicer, a distro whose boot stack is not
handled — those are not bugs. The last one is a gap, and it is fine to say so
in an issue; it is just not going to be treated as urgent.

## Reporting one

Say **which distro you ran it from and which distro you ran it against.** Those
are different code paths through the same script, and a report without both is
usually not actionable.

Then run this. It is read-only, distro-neutral, and changes nothing:

```bash
OUT="linuxlocker-diag-$(date +%Y%m%d-%H%M%S).txt" && { \
  echo "=== os ==="; cat /etc/os-release; \
  echo "=== kernel ==="; uname -a; \
  echo "=== version ==="; git describe --tags --always --dirty 2>/dev/null; \
  echo "=== cryptsetup ==="; cryptsetup --version; \
  echo "=== initramfs generator ==="; for t in dracut mkinitcpio update-initramfs; do \
    command -v "$t" >/dev/null && echo "$t: $($t --version 2>&1 | head -1)"; done; \
  echo "=== resize tools ==="; for t in resize2fs btrfs resize.f2fs ntfsresize fatresize xfs_growfs; do \
    command -v "$t" >/dev/null && echo "present: $t"; done; \
  echo "=== block layout ==="; lsblk -o NAME,SIZE,TYPE,FSTYPE,LABEL,UUID,MOUNTPOINT; \
  echo "=== fstab ==="; grep -v '^#' /etc/fstab | grep -v '^$'; \
  echo "=== crypttab ==="; sudo grep -v '^#' /etc/crypttab 2>/dev/null || echo none; \
  echo "=== cmdline (running) ==="; cat /proc/cmdline; \
  echo "=== grub defaults ==="; sudo grep -v '^#' /etc/default/grub 2>/dev/null || echo none; \
  echo "=== BLS entries ==="; sudo grep -H '' /boot/loader/entries/*.conf 2>/dev/null || echo none; \
  echo "=== mkinitcpio HOOKS ==="; grep -s '^HOOKS' /etc/mkinitcpio.conf || echo none; \
  echo "=== dracut luks conf ==="; sudo cat /etc/dracut.conf.d/*luks*.conf 2>/dev/null || echo none; \
  echo "=== rpi cmdline.txt ==="; sudo cat /boot/firmware/cmdline.txt /boot/cmdline.txt 2>/dev/null || echo none; \
  echo "=== extlinux ==="; sudo cat /boot/extlinux/extlinux.conf 2>/dev/null || echo none; \
} > "$OUT" 2>&1 && echo "wrote $OUT"
```

If the deploy itself failed, say which stage it stopped at — the script prints
stage numbers — and include the recovery command list it printed on exit; the
cleanup trap tailors that list to how far the run got.

**Never paste `luksDump --dump-master-key`, and never upload a header backup
image.** Either one hands over your disk. Plain `sudo cryptsetup luksDump
/dev/<root>` is safe: cipher, KDF and slot metadata, no key material.

## Adding filesystem support

This is the contribution most likely to be merged. A filesystem is supported
**in place** when it can be shrunk by 32 MiB for the LUKS2 header, or already
has that much slack. See [`docs/FILESYSTEMS.md`](docs/FILESYSTEMS.md) for how
the existing six are classified.

A handler has to do four things, and a patch that skips any of them will be
sent back:

1. **Probe the size offline**, without mounting, so the idempotency guard can
   tell "not yet shrunk" from "already shrunk" on a re-run.
2. **Shrink by exactly the header gap**, and fail rather than guess when the
   tool cannot confirm the resulting size. Shrinking past the used extent is
   data loss, not a resize bug.
3. **Grow back to fill the container** after re-encryption.
4. **Decline cleanly** when the filesystem cannot do this, with the workaround
   named — the way xfs, exfat, udf and swap already do. A documented refusal is
   a supported outcome here, not a failure.

Name the tool it needs in `bin/lib-deps.sh` for every package manager you can,
and **add a leg to `tests/loopback-core-test.sh`** — the ext4 and btrfs legs are
the template. A filesystem handler with no loopback coverage will not be merged;
the whole point of that suite is that the recovery paths are tested rather than
assumed.

## Before opening a pull request

Run what CI runs:

```bash
shellcheck -S warning $(git ls-files '*.sh') extras/bin/luks-fetch-cache
sudo bash tests/loopback-core-test.sh
```

Expect `29 passed, 0 failed`. A `SKIP` or `NOTE` line in stage 5b is normal and
lowers the count to as low as 24 without any failure — that stage races a hard
kill against a live re-encryption and reports honestly when it did not manage
to build the state it wanted. **`0 failed` is the invariant**, not the number.

`sudo ./bin/luks-deploy.sh --dry-run` runs the entire read-only half and stops
before the point of no return; use it to check a change end-to-end without
risking anything.

Beyond that:

- **Shell only**, `set -euo pipefail`, and every script carries the MIT header
  immediately after the shebang — these get copied onto live USBs and pulled out
  of the repo individually, so a bare "see LICENSE" would leave a standalone
  copy with no terms attached. Copy the block verbatim from any existing script.
- **Never assert on a cheaper probe than the one you are testing.**
  `cryptsetup isLuks` accepts headers that `cryptsetup open` rejects; they
  disagree on partially written headers, and that disagreement has produced a
  false CI pass before.
- **Build test state deterministically.** Do not race a `kill` and then guess
  what state you produced — stage 5 uses `reencrypt --init-only` for this reason.
- **Do not weaken the KDF to work around a limitation.** Substituting pbkdf2 to
  satisfy an old bootloader is not an acceptable fix in this repo.
- **State what you tested**, on what distro and what hardware. Documenting an
  unverified failure mode as though it were observed is worse than documenting
  nothing.

## Testing

**Never test changes against a system you care about.** The loopback harness
exercises the real encrypt / resume / repair / recovery-key sequence against a
throwaway file-backed device. `luks-deploy.sh` refusing to encrypt the
filesystem it is booted from is a backstop, not a substitute for judgement.

## Security issues

Do not open a public issue. See [`SECURITY.md`](SECURITY.md).

## Conduct

Technical disagreement is welcome — say why something is wrong and what you
tested. See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
