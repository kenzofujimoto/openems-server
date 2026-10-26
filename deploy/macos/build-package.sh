#!/bin/sh
set -eu
if [ "$(uname -s)" != "Darwin" ]; then echo 'Package creation requires macOS.' >&2; exit 1; fi
if [ "$#" -ne 2 ]; then echo 'Usage: build-package.sh SIGNED-AGENT OUTPUT.pkg' >&2; exit 1; fi
: "${OPENEMS_INSTALLER_IDENTITY:?Set the Developer ID Installer identity already present in the keychain}"
agent="$1"
output="$2"
case "$output" in /*) ;; *) output="$PWD/$output" ;; esac
file "$agent" | grep -q 'Mach-O' || { echo 'A native macOS Mach-O binary is required.' >&2; exit 1; }
codesign --verify --strict "$agent"
work="$(mktemp -d "${TMPDIR:-/tmp/}openems-pkg.XXXXXX")"
trap 'echo "Build staging retained at $work" >&2' EXIT
install -d -m 0755 "$work/root/usr/local/libexec" "$work/root/Library/LaunchDaemons" "$work/scripts"
install -m 0755 "$agent" "$work/root/usr/local/libexec/openems-agent"
install -m 0644 "$(dirname "$0")/com.openems.agent.plist" "$work/root/Library/LaunchDaemons/com.openems.agent.plist"
cat > "$work/scripts/postinstall" <<'SCRIPT'
#!/bin/sh
set -eu
install -d -o root -g wheel -m 0700 /etc/openems /var/lib/openems
echo 'Configure compatibility mode before loading com.openems.agent; no network or security extension was installed.'
SCRIPT
chmod 0755 "$work/scripts/postinstall"
pkgbuild --root "$work/root" --scripts "$work/scripts" --identifier com.openems.agent --version 0.5.0 "$work/unsigned.pkg"
productsign --sign "$OPENEMS_INSTALLER_IDENTITY" "$work/unsigned.pkg" "$output"
pkgutil --check-signature "$output"
echo 'Signed installer built; notarization, Mac execution and native extension acceptance remain pending.'
