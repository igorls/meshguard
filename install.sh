#!/usr/bin/env bash
set -euo pipefail

# meshguard installer
# Usage: curl -fsSL https://raw.githubusercontent.com/igorls/meshguard/main/install.sh | bash

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

echo "meshguard installer"
echo "  arch: $ARCH → $ARTIFACT"
echo ""

# Check for libsodium
if ! ldconfig -p 2>/dev/null | grep -q libsodium; then
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

# Download latest release
URL="https://github.com/${REPO}/releases/latest/download/${ARTIFACT}"
TMPFILE=$(mktemp)
echo "⬇ Downloading ${ARTIFACT}..."
if ! curl -fSL --progress-bar -o "$TMPFILE" "$URL"; then
  echo ""
  echo "Error: download failed. Check https://github.com/${REPO}/releases for available versions."
  rm -f "$TMPFILE"
  exit 1
fi

# Verify it's actually a binary (not an HTML error page)
if file "$TMPFILE" | grep -q "text"; then
  echo "Error: downloaded file is not a binary. The release may not exist yet."
  rm -f "$TMPFILE"
  exit 1
fi

chmod +x "$TMPFILE"

# Install
echo "📦 Installing to ${INSTALL_DIR}/${BINARY}..."
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMPFILE" "${INSTALL_DIR}/${BINARY}"
else
  sudo mv "$TMPFILE" "${INSTALL_DIR}/${BINARY}"
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
echo "  meshguard keygen       # generate identity"
echo "  meshguard --help       # see all commands"
