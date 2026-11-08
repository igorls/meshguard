#!/bin/sh
set -e

# MeshGuard Agent Onboarding (join a host via an invite token)
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/igorls/meshguard/main/dist/agent-join.sh | bash -s -- <INVITE_TOKEN>
#
# Downloads the latest release binary for this machine, verifies it against
# that release's checksums.txt, then runs `meshguard join <token>`.

TOKEN="$1"
if [ -z "$TOKEN" ]; then
  echo "Error: missing invite token argument."
  echo "Usage: $0 <INVITE_TOKEN>"
  exit 1
fi

REPO="igorls/meshguard"

echo "================================================================"
echo "  MeshGuard Agent Onboarding"
echo "================================================================"

if ! command -v curl >/dev/null 2>&1; then
  echo "Error: curl is required to download meshguard."
  exit 1
fi

# If an older lingering daemon was running, terminate it cleanly to ensure fresh seed state
if [ -z "$MESHGUARD_KEEP_RUNNING" ]; then
  pkill -f "meshguard up" 2>/dev/null || true
  pkill -f "meshguard agent" 2>/dev/null || true
  sleep 0.5
fi

OS="$(uname -s)"
ARCH="$(uname -m)"

TARGET_DIR="."
if [ ! -w "$TARGET_DIR" ]; then
  TARGET_DIR="/tmp"
fi

BIN_NAME="meshguard"
case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64|amd64) ASSET="meshguard-linux-amd64" ;;
      aarch64|arm64) ASSET="meshguard-linux-arm64" ;;
      *)
        echo "Error: unsupported Linux architecture: $ARCH (amd64 and arm64 releases are available)."
        exit 1
        ;;
    esac
    ;;
  Darwin)
    case "$ARCH" in
      arm64) ASSET="meshguard-macos-arm64" ;;
      x86_64) ASSET="meshguard-macos-amd64" ;;
      *)
        echo "Error: unsupported macOS architecture: $ARCH."
        exit 1
        ;;
    esac
    ;;
  MINGW*|MSYS*|CYGWIN*|Windows_NT)
    ASSET="meshguard-windows-amd64.exe"
    BIN_NAME="meshguard.exe"
    ;;
  *)
    echo "Error: unsupported operating system: $OS."
    exit 1
    ;;
esac

# Resolve the latest release once, so the binary and its checksum come from the same release.
RELEASE_URL="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/${REPO}/releases/latest")"
TAG="${RELEASE_URL##*/}"
case "$TAG" in
  v[0-9]*) ;;
  *)
    echo "Error: could not determine the latest meshguard release."
    exit 1
    ;;
esac
BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"

TARGET_BIN="$TARGET_DIR/$BIN_NAME"
TMP_BIN="${TARGET_BIN}.tmp.$$"
TMP_SUMS="${TARGET_DIR}/.meshguard-checksums.$$"
cleanup() { rm -f "$TMP_BIN" "$TMP_SUMS"; }
trap cleanup EXIT

echo "[agent-join] Downloading meshguard ${TAG} (${ASSET})..."
curl -fsSL "${BASE_URL}/${ASSET}" -o "$TMP_BIN"
curl -fsSL "${BASE_URL}/checksums.txt" -o "$TMP_SUMS"

# Verify against the release manifest ("<sha256 hex>  <name>"; a leading '*' marks binary mode).
EXPECTED="$(awk -v name="$ASSET" '{ f = $2; sub(/^\*/, "", f); if (f == name) { print $1; exit } }' "$TMP_SUMS")"
if [ -z "$EXPECTED" ]; then
  echo "Error: checksums.txt for ${TAG} has no entry for ${ASSET}; refusing to run an unverified binary."
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "$TMP_BIN" | awk '{ print $1 }')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL="$(shasum -a 256 "$TMP_BIN" | awk '{ print $1 }')"
else
  echo "Error: sha256sum or shasum is required to verify the download."
  exit 1
fi
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "Error: checksum mismatch for ${ASSET}"
  echo "  expected: $EXPECTED"
  echo "  actual:   $ACTUAL"
  echo "The download is corrupt or has been tampered with. Nothing was run."
  exit 1
fi
echo "[agent-join] ✓ Checksum verified."

chmod +x "$TMP_BIN"
mv -f "$TMP_BIN" "$TARGET_BIN"
rm -f "$TMP_SUMS"
trap - EXIT
MESHGUARD="$TARGET_BIN"
echo "[agent-join] ✓ Binary ready: $TARGET_BIN"

echo "[agent-join] Joining MeshGuard room..."
exec "$MESHGUARD" join "$TOKEN"
