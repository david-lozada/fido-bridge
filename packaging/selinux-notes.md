# SELinux notes (Fedora)

`fido-bridged` normally runs as a systemd **user** service in `unconfined_u` / `unconfined_t`, which can open `/dev/uhid` once udev grants group/`uaccess` permissions.

If you see denials:

```bash
sudo ausearch -m avc -ts recent | grep -E 'uhid|fido'
sudo ausearch -m avc -ts recent -i | grep uhid
```

Generate a local module (do **not** set the system to permissive):

```bash
sudo ausearch -c fido-bridged -m avc -ts recent | audit2allow -M fidobridge_local
sudo semodule -i fidobridge_local.pp
```

Typical needed allows:

- `allow unconfined_t uhid_device_t:chr_file { open read write ioctl };`

After installing the udev rule, confirm:

```bash
ls -l /dev/uhid
# expect group fidobridge and mode 0660 (or uaccess ACLs)
```
