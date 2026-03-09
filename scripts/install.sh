#!/usr/bin/env bash
set -euo pipefail

REPO="gbiagomba/WeakSSL"
INSTALL_DIR="/usr/local/bin"
BIN_NAME="handshaker"
VERSION="${HANDSHAKER_VERSION:-}"
USE_SOURCE="${HANDSHAKER_USE_SOURCE:-}"

need_cmd() { command -v "$1" >/dev/null 2>&1; }
say() { echo "[install] $*"; }
err() { echo "[install][error] $*" >&2; }

detect_target() {
  local os arch
  os=$(uname -s)
  arch=$(uname -m)
  case "$os" in
    Linux)  os="linux" ;;
    Darwin) os="macos" ;;
    *) err "Unsupported OS: $os"; exit 1;;
  esac
  case "$arch" in
    x86_64|amd64) arch="X64" ;;
    aarch64|arm64) arch="ARM64" ;;
    *) err "Unsupported arch: $arch"; exit 1;;
  esac
  echo "$os-$arch"
}

install_from_binary() {
  if ! need_cmd curl; then err "curl is required to download releases"; return 1; fi
  local target asset url tmp
  target=$(detect_target)
  asset="${BIN_NAME}-${target}"
  if [[ "$target" == windows-* ]]; then asset+=".exe"; fi
  if [[ -z "$VERSION" ]]; then
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/ *"tag_name": *"\(.*\)".*/\1/p')
  fi
  if [[ -z "$VERSION" ]]; then err "Could not determine latest version"; return 1; fi
  url="https://github.com/${REPO}/releases/download/${VERSION}/${asset}"
  say "Downloading ${url}"
  tmp=$(mktemp)
  curl -fL "$url" -o "$tmp"
  chmod +x "$tmp"
  if [[ $EUID -ne 0 ]]; then
    say "Installing to ${INSTALL_DIR} with sudo"
    sudo install -m 0755 "$tmp" "${INSTALL_DIR}/${BIN_NAME}"
  else
    install -m 0755 "$tmp" "${INSTALL_DIR}/${BIN_NAME}"
  fi
  rm -f "$tmp"
  say "Installed ${BIN_NAME} to ${INSTALL_DIR}/${BIN_NAME}"
}

install_from_source() {
  if ! need_cmd cargo; then err "cargo is required for source install"; exit 1; fi
  say "Building from source (release)"
  cargo build --release
  local src="target/release/${BIN_NAME}"
  if [[ ! -f "$src" ]]; then err "Build failed: ${src} not found"; exit 1; fi
  if [[ $EUID -ne 0 ]]; then
    say "Installing to ${INSTALL_DIR} with sudo"
    sudo install -m 0755 "$src" "${INSTALL_DIR}/${BIN_NAME}"
  else
    install -m 0755 "$src" "${INSTALL_DIR}/${BIN_NAME}"
  fi
  say "Installed ${BIN_NAME} to ${INSTALL_DIR}/${BIN_NAME}"
}

main() {
  if [[ "${USE_SOURCE}" == "1" ]]; then
    install_from_source
  else
    if ! install_from_binary; then
      say "Falling back to source build"
      install_from_source
    fi
  fi
}

main "$@"
