#!/usr/bin/env bash
set -euo pipefail

# meshguard installer
# Usage: curl -fsSL https://raw.githubusercontent.com/igorls/meshguard/main/install.sh | bash
#
# Resolves the latest release once, downloads the binary for this machine,
# verifies it against that release's checksums.txt, installs it to
# /usr/local/bin and, on systemd hosts, installs the service files from the
# same release.

REPO="igorls/meshguard"
INSTALL_DIR="/usr/local/bin"
BINARY="meshguard"

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  ARTIFACT="meshguard-linux-amd64" ;;
  aarch64) ARTIFACT="meshguard-linux-arm64" ;;
  *)
    echo "Error: unsupported architecture: $ARCH"
    echo "Supported: x86_64 (amd64), aarch64 (arm64)"
    exit 1
    ;;
esac

# Detect OS
OS=$(uname -s)
if [ "$OS" != "Linux" ]; then
  echo "Error: unsupported OS: $OS (only Linux is supported)"
  exit 1
fi

for tool in curl sha256sum mktemp; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Error: $tool is required"
    exit 1
  fi
done

echo "meshguard installer"
echo "  arch: $ARCH → $ARTIFACT"

# Resolve the latest release tag once, so the binary, its checksum and the
# service files all come from the same release.
RELEASE_URL=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest")
TAG="${RELEASE_URL##*/}"
case "$TAG" in
  v[0-9]*) ;;
  *)
    echo "Error: could not determine the latest release. Check https://github.com/${REPO}/releases"
    exit 1
    ;;
esac
BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"
echo "  release: $TAG"
echo ""

# Check for libsodium. The Linux amd64 release uses libsodium as its AVX2
# accelerator; the Linux arm64 release is built with std.crypto/no-sodium.
if [ "$ARTIFACT" = "meshguard-linux-amd64" ] && ! /sbin/ldconfig -p 2>/dev/null | grep libsodium >/dev/null 2>&1; then
  echo "⚠ libsodium not found. Installing..."
  if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq && sudo apt-get install -y -qq libsodium23 2>/dev/null || sudo apt-get install -y -qq libsodium26 2>/dev/null
  elif command -v dnf &>/dev/null; then
    sudo dnf install -y libsodium
  elif command -v pacman &>/dev/null; then
    sudo pacman -S --noconfirm libsodium
  elif command -v apk &>/dev/null; then
    sudo apk add libsodium
  else
    echo "Error: could not install libsodium. Please install it manually."
    exit 1
  fi
  echo ""
fi

# Download into a private temporary directory (mktemp -d is mode 0700), so
# nothing else on the machine can swap the file between verification and install.
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT
TMPFILE="$WORK_DIR/$ARTIFACT"
CHECKSUMS="$WORK_DIR/checksums.txt"

echo "⬇ Downloading ${ARTIFACT}..."
if ! curl -fSL --progress-bar -o "$TMPFILE" "${BASE_URL}/${ARTIFACT}"; then
  echo ""
  echo "Error: download failed. Check https://github.com/${REPO}/releases for available versions."
  exit 1
fi
if ! curl -fsSL -o "$CHECKSUMS" "${BASE_URL}/checksums.txt"; then
  echo "Error: could not download checksums.txt for ${TAG}; refusing to install an unverified binary."
  exit 1
fi

# Verify the download against the release checksums (sha256sum format:
# "<hex>  <name>"; a leading '*' marks binary mode).
EXPECTED=$(awk -v name="$ARTIFACT" '{ f = $2; sub(/^\*/, "", f); if (f == name) { print $1; exit } }' "$CHECKSUMS")
if [ -z "$EXPECTED" ]; then
  echo "Error: checksums.txt for ${TAG} has no entry for ${ARTIFACT}; refusing to install."
  exit 1
fi
ACTUAL=$(sha256sum "$TMPFILE" | awk '{ print $1 }')
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "Error: checksum mismatch for ${ARTIFACT}"
  echo "  expected: $EXPECTED"
  echo "  actual:   $ACTUAL"
  echo "The download is corrupt or has been tampered with. Nothing was installed."
  exit 1
fi
echo "✓ checksum verified"

chmod 755 "$TMPFILE"

# Install binary
echo "📦 Installing to ${INSTALL_DIR}/${BINARY}..."
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMPFILE" "${INSTALL_DIR}/${BINARY}"
else
  sudo mv "$TMPFILE" "${INSTALL_DIR}/${BINARY}"
fi

# Install systemd service (if systemd is present)
if command -v systemctl &>/dev/null; then
  echo "🔧 Installing systemd service..."
  DIST_URL="https://raw.githubusercontent.com/${REPO}/${TAG}/dist"
  sudo curl -fsSL -o /etc/systemd/system/meshguard.service "${DIST_URL}/meshguard.service"
  if [ ! -f /etc/default/meshguard ]; then
    sudo curl -fsSL -o /etc/default/meshguard "${DIST_URL}/meshguard.default"
  fi

  # Setup /etc/meshguard config directory
  sudo mkdir -p /etc/meshguard/authorized_keys /etc/meshguard/trusted_orgs
  sudo chmod 700 /etc/meshguard
  USER_CONFIG="${HOME}/.config/meshguard"
  if [ -d "$USER_CONFIG" ] && [ ! -f /etc/meshguard/identity.key ]; then
    echo "  copying identity from ${USER_CONFIG}/ → /etc/meshguard/"
    sudo cp -n "${USER_CONFIG}/identity.key" /etc/meshguard/ 2>/dev/null || true
    sudo cp -n "${USER_CONFIG}/identity.pub" /etc/meshguard/ 2>/dev/null || true
    sudo cp -rn "${USER_CONFIG}/authorized_keys/"* /etc/meshguard/authorized_keys/ 2>/dev/null || true
    sudo cp -rn "${USER_CONFIG}/trusted_orgs/"* /etc/meshguard/trusted_orgs/ 2>/dev/null || true
    sudo cp -n "${USER_CONFIG}/node.cert" /etc/meshguard/ 2>/dev/null || true
    sudo chmod 600 /etc/meshguard/identity.key 2>/dev/null || true
  fi

  sudo systemctl daemon-reload
  SYSTEMD_INSTALLED=true
else
  SYSTEMD_INSTALLED=false
fi

# Verify
echo ""
if command -v meshguard &>/dev/null; then
  echo "✓ $(meshguard version 2>&1 || echo 'meshguard installed')"
  echo "  location: $(which meshguard)"
else
  echo "✓ Installed to ${INSTALL_DIR}/${BINARY}"
  echo "  Make sure ${INSTALL_DIR} is in your PATH."
fi

echo ""
echo "Get started:"
echo "  meshguard keygen                  # generate identity"
echo "  meshguard --help                  # see all commands"
if [ "$SYSTEMD_INSTALLED" = true ]; then
  echo ""
  echo "Run as a service:"
  echo "  sudo vi /etc/default/meshguard    # set seed peers"
  echo "  sudo systemctl enable meshguard   # start on boot"
  echo "  sudo systemctl start meshguard    # start now"
  echo "  sudo journalctl -u meshguard -f   # view logs"
fi
