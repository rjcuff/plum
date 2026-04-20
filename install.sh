#!/usr/bin/env bash
set -euo pipefail

REPO="rjcuff/plum"
BIN_NAME="plum"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }

bold "plum installer"
echo ""

# Detect OS and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux*)   os="linux" ;;
  Darwin*)  os="macos" ;;
  *)        red "Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
  x86_64)          arch="x86_64" ;;
  aarch64|arm64)   arch="aarch64" ;;
  *)               red "Unsupported architecture: $ARCH"; exit 1 ;;
esac

ASSET="${BIN_NAME}-${os}-${arch}"

# Fetch the latest release tag
echo "Fetching latest release..."
TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' \
  | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')

if [ -z "$TAG" ]; then
  red "Could not determine latest release tag."
  exit 1
fi

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${ASSET}"

echo "Downloading ${BIN_NAME} ${TAG} for ${os}/${arch}..."
TMP=$(mktemp)
curl -fsSL "$DOWNLOAD_URL" -o "$TMP"
chmod +x "$TMP"

# Install
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP" "${INSTALL_DIR}/${BIN_NAME}"
else
  echo "Requires sudo to install to ${INSTALL_DIR}"
  sudo mv "$TMP" "${INSTALL_DIR}/${BIN_NAME}"
fi

green "Installed ${BIN_NAME} ${TAG} to ${INSTALL_DIR}/${BIN_NAME}"
echo ""
echo "Try it:"
echo "  plum lodash"
echo "  plum install express"
