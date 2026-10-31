Name:           fido-bridge
Version:        0.1.0
Release:        1%{?dist}
Summary:        Phone WebAuthn biometric bridge for Fedora

License:        MIT
URL:            https://github.com/local/fido-bridge
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  openssl-devel
Requires:       avahi
Requires:       firewalld

%description
Exposes a virtual FIDO2 HID security key on Linux and relays CTAP2
requests over a paired, encrypted LAN link to an Android phone that
performs biometric user verification with hardware-backed keys.

%prep
%autosetup -n %{name}-%{version}

%build
cd daemon
cargo build --release

%install
install -D -m 0755 daemon/target/release/fido-bridged %{buildroot}%{_bindir}/fido-bridged
install -D -m 0644 packaging/udev/99-fido-bridge.rules %{buildroot}%{_udevrulesdir}/99-fido-bridge.rules
install -D -m 0644 packaging/systemd/fido-bridged.service %{buildroot}%{_userunitdir}/fido-bridged.service
install -D -m 0644 packaging/firewalld/fidobridge.xml %{buildroot}%{_prefix}/lib/firewalld/services/fidobridge.xml
install -D -m 0644 README.md %{buildroot}%{_pkgdocdir}/README.md
install -D -m 0644 docs/protocol.md %{buildroot}%{_pkgdocdir}/protocol.md

%pre
getent group fidobridge >/dev/null || groupadd -r fidobridge

%post
%udev_rules_update
%firewalld_reload
echo "Add your user to group fidobridge, then re-login:"
echo "  sudo usermod -aG fidobridge \$USER"

%files
%{_bindir}/fido-bridged
%{_udevrulesdir}/99-fido-bridge.rules
%{_userunitdir}/fido-bridged.service
%{_prefix}/lib/firewalld/services/fidobridge.xml
%{_pkgdocdir}/README.md
%{_pkgdocdir}/protocol.md

%changelog
* Sat Oct 31 2026 FIDO Bridge Maintainers <dev@localhost> - 0.1.0-1
- Initial package
