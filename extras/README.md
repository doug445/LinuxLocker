# extras — `luks-fetch-cache`

Optional. An aligned, one-line-per-volume summary of every LUKS and BitLocker
encrypted volume attached to the machine, for use as a fastfetch module. The
installer also installs **fastfetch itself** if it is missing, using your
distro's package manager (via `bin/lib-deps.sh`).

```bash
sudo ./install.sh
sudo ./install.sh --uninstall     # removes the readout; fastfetch stays
```

Example output:

```
nvme0n1p3  LUKS2 argon2id, 2 GiB, 4 threads, t=8, sha512
sdb1       LUKS2 argon2id, 1 GiB, 4 threads, t=9, sha512
sdc2       BitLocker v2 AES-256 XTS, 476.9 GiB, recovery+passphrase
```

Only **public header metadata** is read — `cryptsetup luksDump` and `bitlkDump`
report cipher, key size and KDF parameters. No key material is exposed.

## Wiring it into fastfetch

Add to `~/.config/fastfetch/config.jsonc`:

```jsonc
{ "type": "command", "key": "Disk Encryption", "text": "luks-fetch-cache 1" },
{ "type": "command", "key": " ",               "text": "luks-fetch-cache 2" },
{ "type": "command", "key": " ",               "text": "luks-fetch-cache 3" }
```

fastfetch's `command` module renders its output as a **single line**, so an
embedded newline would escape the logo column and garble every device after the
first. Instead it is called once per line number; asking for a line past the end
prints nothing and fastfetch skips that module. Add as many as the maximum number
of encrypted volumes you expect.

## Notes

- The systemd timer refreshes a world-readable cache at `/var/cache/luks-fetch.txt`
  every 15 minutes (and shortly after boot), so the fastfetch calls are instant
  and never wake idle USB disks themselves.
- Concurrent per-line calls serialize on a lock; the first one rescans, the rest
  slice the fresh cache.
- Volumes that GRUB itself unlocks (rare; encrypted `/boot` setups) can be
  tagged `(GRUB boot)` in the output via the `GRUB_UUIDS` environment variable —
  see the header of `bin/luks-fetch-cache` for the KDF constraints that
  distinction carries.
- If your distro doesn't package fastfetch (Debian 12, RHEL without EPEL),
  the installer says so and continues — grab a package from
  [fastfetch releases](https://github.com/fastfetch-cli/fastfetch/releases)
  and the readout is already in place.
