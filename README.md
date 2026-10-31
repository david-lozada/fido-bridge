# FIDO Bridge — phone as a WebAuthn biometric authenticator

Turn an Android phone into a FIDO2/WebAuthn security key for **Firefox** and **Brave** on **Fedora 44**. A Linux daemon creates a virtual USB HID FIDO device (`/dev/uhid`) and relays CTAP2 requests over a paired, encrypted LAN WebSocket to the phone. The phone signs with Android Keystore keys after a biometric prompt.

## Why this exists

- Firefox on Linux has no phone/QR (hybrid) passkey flow.
- Brave's phone-as-security-key flow is unreliable (depends on Google services Brave strips; [open issues](https://github.com/brave/brave-browser/issues/16096)).
- Both browsers talk to USB security keys via `/dev/hidraw*`, so one virtual key works for both.

## Architecture

```
Browser (Firefox / Brave)
    │  CTAPHID over /dev/hidrawN
    ▼
fido-bridged (Fedora)  ── mTLS WebSocket / LAN ──►  Android app
    │                                                      │
  /dev/uhid                                         BiometricPrompt
                                                    Android Keystore
```

See [docs/protocol.md](docs/protocol.md) for the wire format.

## Fedora setup

### Dependencies

```bash
sudo dnf install rust cargo openssl-devel avahi firewalld
# Or use rustup: curl https://sh.rustup.rs -sSf | sh
```

### Build and install

```bash
cd daemon && cargo build --release && cd ..
sudo ./packaging/install-fedora.sh
# re-login so group `fidobridge` applies
newgrp fidobridge
```

Or manually:

```bash
sudo groupadd -r fidobridge
sudo usermod -aG fidobridge $USER
sudo cp packaging/udev/99-fido-bridge.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger --name-match=uhid
sudo install -m 0755 daemon/target/release/fido-bridged /usr/bin/
sudo cp packaging/systemd/fido-bridged.service /usr/lib/systemd/user/
sudo cp packaging/firewalld/fidobridge.xml /usr/lib/firewalld/services/
sudo firewall-cmd --permanent --add-service=fidobridge --add-service=mdns
sudo firewall-cmd --reload
```

### Run

```bash
# Terminal A — pair once
fido-bridged pair          # shows QR + JSON; scan with the Android app

# Terminal B — daemon (or: systemctl --user enable --now fido-bridged)
fido-bridged run
```

Config and certs live under `~/.config/fido-bridged/` and `~/.local/share/fido-bridged/`.

### Verify the virtual key

With the daemon running:

```bash
ls /sys/bus/hid/devices/ | grep -i 1209
# or
ls -l /dev/hidraw*
```

Open **Firefox (RPM)** or **Brave** → https://webauthn.io / https://webauthn.passwordless.id/demos/ and register. You should see a security-key prompt; after pairing, the phone asks for biometrics.

**Brave Flatpak** needs device access (`flatpak override --user --device=all com.brave.Browser`) or use a native Brave build. Firefox from Fedora RPM works without that.

### SELinux

If `/dev/uhid` open is denied:

```bash
ausearch -m avc -ts recent | grep uhid
# Generate a local module — do NOT set permissive globally
```

## Android app

Open `android/` in Android Studio (SDK 35, minSdk 30). Build/run on a device with a strong biometric.

1. Tap **Pair with PC** and scan the QR from `fido-bridged pair`.
2. Keep the app (foreground service) running on the same LAN.
3. Optionally tap **Find PCs on LAN** (mDNS `_fidobridge._tcp`).

## Dummy phone (protocol test without Android)

```bash
# After `fido-bridged pair` writes pairing JSON, save the printed JSON to /tmp/pair.json
fido-bridged dummy-phone --pair-json /tmp/pair.json
# Then with daemon running:
fido-bridged dummy-phone
```

The dummy answers with CTAP `OPERATION_DENIED` for make/get (no keys); use it to verify pairing, TLS, and WebSocket.

## Security notes

- Private keys never leave the phone Keystore.
- The phone UI shows the RP ID before biometric confirmation.
- Pairing uses a one-time secret + certificate fingerprint pinning; mutual TLS afterward.
- Attestation format is `none` (personal use). Enterprise RPs that require attested authenticators will reject it.
- Rate limit: 30 auth attempts / 5 minutes; one outstanding request at a time.
- Audit log: `~/.local/share/fido-bridged/audit.log`

## Commands

| Command | Purpose |
|---------|---------|
| `fido-bridged run` | Start virtual key + relay |
| `fido-bridged pair` | Show QR and accept one phone |
| `fido-bridged list` | List paired phone fingerprints |
| `fido-bridged revoke <fp>` | Remove a paired phone |
| `fido-bridged dummy-phone` | CLI stand-in for the app |

## Out of scope (v1)

CTAP1/U2F, synced passkeys, iOS, Bluetooth/USB transports, PAM/GDM login (possible later via `pam-u2f` against this virtual device).

## License

MIT
