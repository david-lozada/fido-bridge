#!/usr/bin/env bash
# Install FIDO Bridge on Fedora 44 (run with sudo for system pieces).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_SRC="${BIN_SRC:-}"

if [[ $EUID -ne 0 ]]; then
  echo "Re-run with sudo for udev/firewalld/systemd install."
  echo "Building daemon as user first..."
  source "$HOME/.cargo/env" 2>/dev/null || true
  (cd "$ROOT/daemon" && cargo build --release)
  echo
  echo "Now run: sudo $0"
  echo "Or: sudo BIN_SRC=$ROOT/daemon/target/release/fido-bridged $0"
  exit 1
fi

if [[ -z "$BIN_SRC" ]]; then
  if [[ -x "$ROOT/daemon/target/release/fido-bridged" ]]; then
    BIN_SRC="$ROOT/daemon/target/release/fido-bridged"
  else
    echo "Build the daemon first: (cd daemon && cargo build --release)"
    exit 1
  fi
fi

getent group fidobridge >/dev/null || groupadd -r fidobridge
# Add invoking user if SUDO_USER set
if [[ -n "${SUDO_USER:-}" ]]; then
  usermod -aG fidobridge "$SUDO_USER"
fi

install -D -m 0755 "$BIN_SRC" /usr/bin/fido-bridged
install -D -m 0644 "$ROOT/packaging/udev/99-fido-bridge.rules" /etc/udev/rules.d/99-fido-bridge.rules
install -D -m 0644 "$ROOT/packaging/firewalld/fidobridge.xml" /usr/lib/firewalld/services/fidobridge.xml
install -D -m 0644 "$ROOT/packaging/systemd/fido-bridged.service" /usr/lib/systemd/user/fido-bridged.service

udevadm control --reload-rules
udevadm trigger --name-match=uhid || true
# Apply mode now
if [[ -e /dev/uhid ]]; then
  chgrp fidobridge /dev/uhid || true
  chmod 0660 /dev/uhid || true
fi

firewall-cmd --permanent --add-service=fidobridge || true
firewall-cmd --permanent --add-service=mdns || true
firewall-cmd --reload || true

echo
echo "Installed. Re-login (or: newgrp fidobridge), then:"
echo "  systemctl --user daemon-reload"
echo "  systemctl --user enable --now fido-bridged.service"
echo "  fido-bridged pair"
echo
echo "SELinux: if /dev/uhid is denied, check:"
echo "  ausearch -m avc -ts recent | grep uhid"
