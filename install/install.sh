#!/usr/bin/env bash
# aegis adapter installer
# Downloads and installs the aegis CLI for your platform.

set -euo pipefail

VERSION="${AEGIS_VERSION:-latest}"
INSTALL_DIR="${AEGIS_INSTALL_DIR:-$HOME/.aegis/bin}"
DATA_DIR="${AEGIS_DATA_DIR:-$HOME/.aegis/data}"
REPO="LCatGA12/neural-commons"

# Colors (if terminal supports them)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' NC=''
fi

info()  { echo -e "${GREEN}[aegis]${NC} $*"; }
warn()  { echo -e "${YELLOW}[aegis]${NC} $*"; }
error() { echo -e "${RED}[aegis]${NC} $*" >&2; }

# --- Platform detection ---

detect_platform() {
    local os arch

    case "$(uname -s)" in
        Linux*)  os="linux" ;;
        Darwin*) os="darwin" ;;
        MINGW*|MSYS*|CYGWIN*) os="windows" ;;
        *)
            error "Unsupported OS: $(uname -s)"
            exit 1
            ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *)
            error "Unsupported architecture: $(uname -m)"
            exit 1
            ;;
    esac

    echo "${os}-${arch}"
}

# --- Download binary ---

download_binary() {
    local platform="$1"
    local ext=""
    [[ "$platform" == windows-* ]] && ext=".exe"

    local binary_name="aegis-${platform}${ext}"
    local url

    if [ "$VERSION" = "latest" ]; then
        url="https://github.com/${REPO}/releases/latest/download/${binary_name}"
    else
        url="https://github.com/${REPO}/releases/download/${VERSION}/${binary_name}"
    fi

    info "Downloading aegis for ${platform}..."
    info "  URL: ${url}"

    mkdir -p "$INSTALL_DIR"
    local target="${INSTALL_DIR}/aegis${ext}"

    if command -v curl >/dev/null 2>&1; then
        curl -fSL "$url" -o "$target" || {
            error "Download failed. Release binaries may not be published yet."
            error "To build from source: cargo install --path adapter/aegis-cli"
            exit 1
        }
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$target" || {
            error "Download failed."
            exit 1
        }
    else
        error "Neither curl nor wget found. Install one and retry."
        exit 1
    fi

    chmod +x "$target"
    info "Installed: ${target}"
}

# --- Identity generation ---

generate_identity() {
    mkdir -p "$DATA_DIR"

    if [ -f "${DATA_DIR}/identity.key" ]; then
        info "Identity key already exists at ${DATA_DIR}/identity.key"
        return
    fi

    info "Generating Ed25519 identity keypair..."
    if command -v "${INSTALL_DIR}/aegis" >/dev/null 2>&1; then
        # Use aegis itself to generate identity on first run
        info "Identity will be generated on first adapter start."
    else
        info "Identity will be generated on first adapter start."
    fi
}

# --- PATH setup ---

add_to_path() {
    local shell_rc=""
    local current_shell
    current_shell="$(basename "${SHELL:-bash}")"

    case "$current_shell" in
        zsh)  shell_rc="$HOME/.zshrc" ;;
        bash) shell_rc="$HOME/.bashrc" ;;
        fish) shell_rc="$HOME/.config/fish/config.fish" ;;
        *)    shell_rc="$HOME/.profile" ;;
    esac

    if [ -n "$shell_rc" ] && [ -f "$shell_rc" ]; then
        if ! grep -q "$INSTALL_DIR" "$shell_rc" 2>/dev/null; then
            echo "" >> "$shell_rc"
            echo "# aegis adapter" >> "$shell_rc"
            if [ "$current_shell" = "fish" ]; then
                echo "set -gx PATH $INSTALL_DIR \$PATH" >> "$shell_rc"
            else
                echo "export PATH=\"${INSTALL_DIR}:\$PATH\"" >> "$shell_rc"
            fi
            info "Added ${INSTALL_DIR} to PATH in ${shell_rc}"
            info "Run: source ${shell_rc}"
        else
            info "${INSTALL_DIR} already in PATH"
        fi
    fi
}

# --- SLM model prompt ---

prompt_slm_model() {
    echo ""
    info "Optional: Download a small language model for injection screening."
    info "This requires Ollama (https://ollama.ai) to be installed."
    echo ""

    if ! command -v ollama >/dev/null 2>&1; then
        warn "Ollama not found. SLM screening will use heuristic fallback."
        warn "Install Ollama later and run: ollama pull llama3.2:1b"
        return
    fi

    read -r -p "Download llama3.2:1b for SLM screening? [y/N] " response
    case "$response" in
        [yY]|[yY][eE][sS])
            info "Pulling llama3.2:1b..."
            ollama pull llama3.2:1b || warn "Model pull failed. You can retry later."
            ;;
        *)
            info "Skipped. Run 'ollama pull llama3.2:1b' later to enable SLM screening."
            ;;
    esac
}

# --- Framework setup prompt ---

prompt_framework_setup() {
    echo ""
    info "Optional: Configure your bot framework to use aegis."
    echo ""
    echo "  1) OpenClaw (Claude Code)"
    echo "  2) Skip for now"
    echo ""

    read -r -p "Select framework [1-2]: " choice
    case "$choice" in
        1)
            if command -v "${INSTALL_DIR}/aegis" >/dev/null 2>&1; then
                "${INSTALL_DIR}/aegis" setup openclaw --dry-run
                read -r -p "Apply this configuration? [y/N] " apply
                case "$apply" in
                    [yY]*) "${INSTALL_DIR}/aegis" setup openclaw ;;
                    *) info "Skipped. Run 'aegis setup openclaw' later." ;;
                esac
            else
                info "Run 'aegis setup openclaw' after adding aegis to PATH."
            fi
            ;;
        *)
            info "Skipped. Run 'aegis setup <framework>' later."
            ;;
    esac
}

# --- Main ---

main() {
    echo ""
    echo -e "${CYAN}  aegis adapter installer${NC}"
    echo -e "${CYAN}  neural commons trust infrastructure${NC}"
    echo ""

    local platform
    platform="$(detect_platform)"
    info "Detected platform: ${platform}"

    download_binary "$platform"
    generate_identity
    add_to_path

    # Create default config if none exists
    local config_dir="$HOME/.aegis/config"
    if [ ! -f "${config_dir}/config.toml" ]; then
        mkdir -p "$config_dir"
        cat > "${config_dir}/config.toml" << 'CONFIGEOF'
# Aegis Shield Configuration

[proxy]
listen_addr = "127.0.0.1:3141"
upstream_url = "https://api.anthropic.com"
# allow_any_provider = false

[slm]
enabled = true
engine = "ollama"
ollama_url = "http://localhost:11434"
model = "llama3.2:1b"
fallback_to_heuristics = true
# Switch engine: aegis slm engine openai
# Switch model:  aegis slm use qwen2.5:1.5b
# Set server:    aegis slm server http://localhost:1234
CONFIGEOF
        info "Default config: ${config_dir}/config.toml"
    fi

    # Run first vulnerability scan if binary is available
    export PATH="${INSTALL_DIR}:${PATH}"
    if command -v aegis >/dev/null 2>&1; then
        info "Running first vulnerability scan..."
        aegis scan . 2>&1 || true
        echo ""
    fi

    # Interactive prompts (skip in CI)
    if [ -t 0 ]; then
        prompt_slm_model
        prompt_framework_setup
    fi

    echo ""
    echo "================================================================"
    echo "            Aegis Shield — Installed                            "
    echo "================================================================"
    echo ""
    echo "  Next steps:"
    echo ""
    echo "  1. Connect to OpenClaw:"
    echo "     aegis setup openclaw"
    echo ""
    echo "  2. Start protection:"
    echo "     aegis"
    echo ""
    echo "  3. View dashboard:"
    echo "     http://localhost:3141/dashboard"
    echo ""
    echo "  Other commands:"
    echo "     aegis scan           — vulnerability scan"
    echo "     aegis status         — adapter status"
    echo "     aegis --enforce      — enable blocking mode"
    echo "     aegis --help         — all options"
    echo ""

    warn "Binary signature verification not yet implemented."
    warn "Verify checksums manually: https://github.com/${REPO}/releases"
    echo ""
}

main "$@"
