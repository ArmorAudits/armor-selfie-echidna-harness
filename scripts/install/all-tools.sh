#!/usr/bin/env bash
set -euo pipefail

OS="$(uname -s)"
ARCH="$(uname -m)"

have() { command -v "$1" >/dev/null 2>&1; }
ensure_brew() { if ! have brew; then echo "Homebrew not found; see https://brew.sh"; exit 1; fi; }
ensure_pipx() { if ! have pipx; then python3 -m pip install --user pipx && python3 -m pipx ensurepath; fi; }
ensure_go()  { if ! have go; then echo "Go not found; install Go first: https://go.dev/dl/"; fi; }
ensure_cargo(){ if ! have cargo; then echo "Rust not found; install rustup: https://rustup.rs"; fi; }
ensure_npm() { if ! have npm; then echo "npm not found; install Node.js (fnm/nvm/brew)"; fi; }

# --- Core supply-chain + SAST ---
install_core() {
  ensure_brew
  brew install anchore/syft/syft anchore/grype/grype || true
  brew install semgrep hadolint trufflehog conftest rekor licensee || true
  # OSV-Scanner (brew)
  brew install osv-scanner || true

  # Python SAST/Secrets
  ensure_pipx
  pipx install bandit || true
  pipx install detect-secrets || true

  # Go SAST
  ensure_brew || true
  brew install gosec || true

  # Rust policy helpers
  ensure_cargo || true
  cargo install cargo-vet || true
  cargo install cargo-crev || true

  # CodeQL CLI (download latest release tarball)
  if ! have codeql; then
    tmp="$(mktemp -d)"
    echo "Installing CodeQL CLI…"
    # Pick latest release artifact name by OS/ARCH
    case "$OS-$ARCH" in
      Darwin-arm64)  ART="codeql-osx64.zip" ;; # Apple Silicon ships x64 zip; Rosetta handles it fine
      Darwin-x86_64) ART="codeql-osx64.zip" ;;
      Linux-x86_64)  ART="codeql-linux64.zip" ;;
      *) echo "Unsupported platform for CodeQL auto-install; install manually."; return 0 ;;
    esac
    curl -sSL -o "$tmp/$ART" "https://github.com/github/codeql-cli-binaries/releases/latest/download/$ART"
    unzip -q "$tmp/$ART" -d "$tmp"
    sudo mv "$tmp"/codeql*/codeql /usr/local/bin/codeql
    rm -rf "$tmp"
    echo "codeql installed at /usr/local/bin/codeql"
  fi
}

# --- EVM helpers ---
install_evm() {
  ensure_npm
  npm i -g surya || true

  # hevm via nix (preferred) or Docker fallback
  if have nix; then
    echo 'Use: nix shell github:dapphub/dapptools#hevm' 
  elif have docker; then
    cat <<'EOF' | sudo tee /usr/local/bin/hevm >/dev/null
#!/usr/bin/env bash
exec docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:$PWD" -w "$PWD" ghcr.io/dapphub/hevm:latest "$@"
EOF
    sudo chmod +x /usr/local/bin/hevm
    echo "hevm wrapper installed (Docker)."
  else
    echo "Install hevm via Nix or enable Docker; building from source is heavy."
  fi
}

# --- ZK stack ---
install_zk() {
  ensure_npm
  npm i -g snarkjs || true

  # gnark (Go)
  ensure_go || true
  go install github.com/ConsenSys/gnark/cmd/gnark@latest || true

  # halo2 is a Rust lib; many users build per-project. (No global CLI needed.)
  # circom: prefer release binaries when available; fallback: build from source
  if ! have circom; then
    echo "Attempting circom install (release binary)…"
    tmp="$(mktemp -d)"
    case "$OS-$ARCH" in
      Darwin-arm64)  URL="https://github.com/iden3/circom/releases/latest/download/circom-macos-arm64" ;;
      Darwin-x86_64) URL="https://github.com/iden3/circom/releases/latest/download/circom-macos-x64" ;;
      Linux-x86_64)  URL="https://github.com/iden3/circom/releases/latest/download/circom-linux-amd64" ;;
      *) URL="" ;;
    esac
    if [ -n "$URL" ]; then
      curl -sSL -o "$tmp/circom" "$URL" && chmod +x "$tmp/circom" && sudo mv "$tmp/circom" /usr/local/bin/circom && echo "circom installed."
    else
      echo "No prebuilt circom for $OS/$ARCH; consider Docker or manual build."
    fi
    rm -rf "$tmp"
  fi

  # rapidsnark: best via Docker wrapper
  if have docker; then
    cat <<'EOF' | sudo tee /usr/local/bin/rapidsnark >/dev/null
#!/usr/bin/env bash
exec docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:$PWD" -w "$PWD" iden3/rapidsnark:latest "$@"
EOF
    sudo chmod +x /usr/local/bin/rapidsnark
    echo "rapidsnark wrapper installed (Docker)."
  else
    echo "rapidsnark: enable Docker or build from source."
  fi
}

# --- Starknet / Cairo ---
install_starknet() {
  # Aderyn: Python package publishes a CLI
  ensure_pipx
  pipx install aderyn || true
}

# --- TON ---
install_ton() {
  ensure_pipx
  pipx install toncli || true
  echo "tvm-linker & fift live in ton-blockchain/ton; building from source is required (cmake)."
}

# --- Bitcoin ---
install_bitcoin() {
  if have brew; then brew install bitcoin || true; else echo "Install Bitcoin Core manually if not on macOS."; fi
  ensure_cargo || true
  cargo install miniscript || true   # binary name may vary; library still useful
}

# Run all
install_core
install_evm
install_zk
install_starknet
install_ton
install_bitcoin

echo "✅ Done. Open a new shell so PATH changes from pipx are active (or run: pipx ensurepath)."
