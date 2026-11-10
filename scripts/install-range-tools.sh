#!/usr/bin/env bash
# install-range-tools.sh — install QEMU, swtpm, and OVMF into a user prefix
# WITHOUT root access. Works on Arch Linux hosts (packages match system libs);
# other distros should use their native package manager instead.
#
# Result: ~/barzakh-tools/usr/bin/{qemu-system-x86_64,swtpm,...} plus OVMF
# firmware in ~/barzakh-tools/usr/share/edk2/x64/.
#
# Usage:
#   ./scripts/install-range-tools.sh          # install to ~/barzakh-tools
#   PREFIX=~/.local ./scripts/install-range-tools.sh
set -euo pipefail

PREFIX="${PREFIX:-$HOME/barzakh-tools}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Packages required for the cyber range (Phase 2 of docs/ROADMAP.md).
# edk2-ovmf is arch "any"; the rest are x86_64.
PACKAGES=(
  "extra/x86_64/qemu-system-x86"
  "extra/x86_64/swtpm"
  "extra/x86_64/libtpms"
  "extra/any/edk2-ovmf"
  # Shared-library dependencies of qemu-system-x86 that a minimal host
  # may not have installed system-wide.
  "core/x86_64/libaio"
  "extra/x86_64/capstone"
  "extra/x86_64/ndctl"
  "extra/x86_64/dtc"
  "extra/x86_64/rdma-core"
  "extra/x86_64/libslirp"
  "extra/x86_64/vde2"
  "extra/x86_64/libxdp"
)

echo "▶ Installing Barzakh cyber-range tools into: $PREFIX"
mkdir -p "$PREFIX"

for pkg in "${PACKAGES[@]}"; do
  name="$(basename "$pkg")"
  file="$WORK/$name.pkg.tar.zst"
  echo "  ↓ $name"
  curl -sL -o "$file" "https://archlinux.org/packages/$pkg/download/"
  if ! file "$file" | grep -q "Zstandard"; then
    echo "✗ failed to download $name (not a package — check the URL)" >&2
    exit 1
  fi
  bsdtar -xf "$file" -C "$PREFIX"
done

BIN="$PREFIX/usr/bin"
LIBS="$PREFIX/usr/lib:$PREFIX/usr/lib/swtpm"
SHARE="$PREFIX/usr/share"

cat <<EOF

✓ Range tools installed.

Add to your shell (or export before running the range):

  export PATH="$BIN:\$PATH"
  export LD_LIBRARY_PATH="$LIBS\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"

QEMU ROM search path (pass to qemu via -L):
  $SHARE/qemu

OVMF firmware:
  $SHARE/edk2/x64/OVMF_CODE.4m.fd  (read-only code pflash)
  $SHARE/edk2/x64/OVMF_VARS.4m.fd  (writable vars pflash — copy per run)

Verify:
  qemu-system-x86_64 --version
  swtpm --version
EOF
