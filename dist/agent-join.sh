#!/bin/sh
set -e

# MeshGuard Agent Onboarding ("Google Meet Link" for Agents)
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/igorls/meshguard/main/dist/agent-join.sh | bash -s -- <INVITE_TOKEN>

TOKEN="$1"
if [ -z "$TOKEN" ]; then
  echo "Error: missing invite token argument."
  echo "Usage: $0 <INVITE_TOKEN>"
  exit 1
fi

echo "================================================================"
echo "  MeshGuard Agent Onboarding"
echo "================================================================"

# Check if meshguard is installed in PATH (or local override requested)
MESHGUARD=""
if command -v meshguard >/dev/null 2>&1; then
  MESHGUARD="meshguard"
elif [ -n "$MESHGUARD_LOCAL" ] && [ -x "./meshguard" ]; then
  MESHGUARD="./meshguard"
fi

if [ -z "$MESHGUARD" ]; then
  echo "[agent-join] Downloading standalone static meshguard binary (v0.9.0)..."
  OS="$(uname -s)"
  ARCH="$(uname -m)"

  TARGET_DIR="."
  if [ ! -w "$TARGET_DIR" ]; then
    TARGET_DIR="/tmp"
  fi

  BIN_NAME="meshguard"
  ASSET="meshguard-linux-amd64-static"
  case "$OS" in
    Linux)
      case "$ARCH" in
        x86_64|amd64)
          ASSET="meshguard-linux-amd64-static"
          ;;
        aarch64|arm64)
          ASSET="meshguard-linux-arm64-static"
          ;;
        *)
          ASSET="meshguard-linux-amd64-static"
          ;;
      esac
      ;;
    Darwin)
      case "$ARCH" in
        arm64)
          ASSET="meshguard-macos-arm64"
          ;;
        *)
          ASSET="meshguard-macos-amd64"
          ;;
      esac
      ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT)
      ASSET="meshguard-windows-amd64.exe"
      BIN_NAME="meshguard.exe"
      ;;
  esac

  TARGET_BIN="$TARGET_DIR/$BIN_NAME"
  URL="https://github.com/igorls/meshguard/releases/download/v0.9.0/${ASSET}"
  echo "[agent-join] Fetching $URL -> $TARGET_BIN..."

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$URL" -o "$TARGET_BIN"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$TARGET_BIN" "$URL"
  else
    echo "Error: curl or wget is required to download meshguard."
    exit 1
  fi

  chmod +x "$TARGET_BIN"
  MESHGUARD="$TARGET_BIN"
  echo "[agent-join] ✓ Binary ready: $TARGET_BIN"
fi

echo "[agent-join] Joining MeshGuard room..."
exec "$MESHGUARD" join "$TOKEN"
