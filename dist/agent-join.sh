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

# Check if meshguard is installed in PATH or present in working directory
MESHGUARD=""
if command -v meshguard >/dev/null 2>&1; then
  MESHGUARD="meshguard"
elif [ -x "./meshguard" ]; then
  MESHGUARD="./meshguard"
fi

if [ -z "$MESHGUARD" ]; then
  echo "[agent-join] Downloading standalone static meshguard binary (v0.9.0)..."
  OS="$(uname -s)"
  ARCH="$(uname -m)"

  ASSET="meshguard-linux-amd64-static"
  if [ "$OS" = "Linux" ]; then
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
  elif [ "$OS" = "Darwin" ]; then
    case "$ARCH" in
      arm64)
        ASSET="meshguard-macos-arm64"
        ;;
      *)
        ASSET="meshguard-macos-amd64"
        ;;
    esac
  fi

  URL="https://github.com/igorls/meshguard/releases/download/v0.9.0/${ASSET}"
  echo "[agent-join] Fetching $URL -> ./meshguard..."

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$URL" -o ./meshguard
  elif command -v wget >/dev/null 2>&1; then
    wget -qO ./meshguard "$URL"
  else
    echo "Error: curl or wget is required to download meshguard."
    exit 1
  fi

  chmod +x ./meshguard
  MESHGUARD="./meshguard"
  echo "[agent-join] ✓ Binary ready: ./meshguard"
fi

echo "[agent-join] Joining MeshGuard room..."
exec "$MESHGUARD" join "$TOKEN"
