#!/usr/bin/env bash
# aegis adapter installer
# Downloads and installs the aegis CLI for your platform.

set -euo pipefail

VERSION="${AEGIS_VERSION:-latest}"
INSTALL_DIR="${AEGIS_INSTALL_DIR:-$HOME/.aegis/bin}"
DATA_DIR="${AEGIS_DATA_DIR:-$HOME/.aegis/data}"
REPO="AEGIS-GB/neural-commons"

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

    # Verify SHA-256 checksum
    local checksum_url="${url}.sha256"
    local checksum_file="${target}.sha256"
    info "Verifying SHA-256 checksum..."

    if command -v curl >/dev/null 2>&1; then
        curl -fSL "$checksum_url" -o "$checksum_file" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$checksum_url" -O "$checksum_file" 2>/dev/null
    fi

    if [ -f "$checksum_file" ]; then
        # checksum file contains: <hash>  <filename>
        # We need to verify against the downloaded binary
        local expected_hash
        expected_hash=$(awk '{print $1}' "$checksum_file")
        local actual_hash
        if command -v sha256sum >/dev/null 2>&1; then
            actual_hash=$(sha256sum "$target" | awk '{print $1}')
        elif command -v shasum >/dev/null 2>&1; then
            actual_hash=$(shasum -a 256 "$target" | awk '{print $1}')
        else
            warn "No sha256sum or shasum found — skipping checksum verification"
            rm -f "$checksum_file"
            chmod +x "$target"
            info "Installed: ${target} (checksum NOT verified)"
            return
        fi

        if [ "$expected_hash" = "$actual_hash" ]; then
            info "Checksum verified: ${expected_hash:0:16}..."
        else
            error "CHECKSUM MISMATCH — binary may be tampered!"
            error "  Expected: ${expected_hash}"
            error "  Actual:   ${actual_hash}"
            rm -f "$target" "$checksum_file"
            exit 1
        fi
        rm -f "$checksum_file"
    else
        warn "Checksum file not available — verify manually: https://github.com/${REPO}/releases"
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

# --- NER PII model download ---

download_ner_model() {
    local models_dir="${DATA_DIR}/models/distilbert-ner"
    local ner_base="https://huggingface.co/dslim/distilbert-NER/resolve/main/onnx"

    # Also accept legacy pii-ner model
    if [ -f "${models_dir}/model.onnx" ] || [ -f "${DATA_DIR}/models/pii-ner/model.onnx" ]; then
        info "NER PII model already installed."
        return
    fi

    info "Downloading NER PII detection model (DistilBERT-NER, ~250 MB)..."
    info "Detects person names in LLM responses using GDPR/NIST-compliant filtering."
    echo ""

    mkdir -p "$models_dir"
    local failed=0

    for file in model.onnx tokenizer.json config.json; do
        info "  Fetching ${file}..."
        if command -v curl >/dev/null 2>&1; then
            curl -fSL "${ner_base}/${file}" -o "${models_dir}/${file}" || { warn "Failed to download ${file}"; failed=1; }
        elif command -v wget >/dev/null 2>&1; then
            wget -q "${ner_base}/${file}" -O "${models_dir}/${file}" || { warn "Failed to download ${file}"; failed=1; }
        fi
    done

    if [ "$failed" -eq 0 ] && [ -f "${models_dir}/model.onnx" ]; then
        info "NER PII model installed at ${models_dir}"
    else
        warn "NER model download incomplete. PII detection will be disabled."
        warn "Retry later: aegis setup ner"
    fi
}

# --- SLM model prompt ---

prompt_slm_model() {
    echo ""
    info "Optional: Enable SLM injection screening."
    info "This adds local AI-powered prompt injection detection."
    info "Without it, Aegis still protects you with heuristic patterns."
    echo ""

    read -r -p "Set up SLM screening now? [y/N] " response
    case "$response" in
        [yY]|[yY][eE][sS]) ;;
        *)
            info "Skipped. You can enable SLM later:"
            info "  aegis slm engine ollama"
            info "  aegis slm use llama3.2:1b"
            return
            ;;
    esac

    echo ""
    echo "  Which SLM server do you use?"
    echo ""
    echo "  1) Ollama        (most common — ollama.ai)"
    echo "  2) LM Studio     (OpenAI-compatible — lmstudio.ai)"
    echo "  3) Other OpenAI-compatible server (vLLM, llama.cpp, LocalAI)"
    echo ""

    read -r -p "Select [1-3]: " engine_choice
    case "$engine_choice" in
        2)
            "${INSTALL_DIR}/aegis" slm engine openai 2>/dev/null || true
            read -r -p "LM Studio server URL [http://localhost:1234]: " lms_url
            lms_url="${lms_url:-http://localhost:1234}"
            "${INSTALL_DIR}/aegis" slm server "$lms_url" 2>/dev/null || true
            read -r -p "Model name (as shown in LM Studio): " model_name
            if [ -n "$model_name" ]; then
                "${INSTALL_DIR}/aegis" slm use "$model_name" 2>/dev/null || true
            fi
            info "SLM configured for LM Studio."
            info "Start with: aegis  (not --no-slm)"
            return
            ;;
        3)
            "${INSTALL_DIR}/aegis" slm engine openai 2>/dev/null || true
            read -r -p "Server URL: " server_url
            if [ -n "$server_url" ]; then
                "${INSTALL_DIR}/aegis" slm server "$server_url" 2>/dev/null || true
            fi
            read -r -p "Model name: " model_name
            if [ -n "$model_name" ]; then
                "${INSTALL_DIR}/aegis" slm use "$model_name" 2>/dev/null || true
            fi
            info "SLM configured for OpenAI-compatible server."
            info "Start with: aegis  (not --no-slm)"
            return
            ;;
        *)
            # Default: Ollama
            ;;
    esac

    # Ollama path
    if ! command -v ollama >/dev/null 2>&1; then
        info "Ollama is not installed. To set up SLM with Ollama:"
        echo ""
        echo "  1. Install Ollama:  curl -fsSL https://ollama.com/install.sh | sh"
        echo "  2. Install model:   aegis slm install"
        echo "  3. Start Aegis:     aegis"
        echo ""
        info "Run these after the installer finishes."
        return
    fi

    echo ""
    echo "  Which screening model?"
    echo ""
    echo "  1) aegis-screen:4b  (~3.9GB — RECOMMENDED: fine-tuned for injection detection, 99%+ recall)"
    echo "  2) gemma3:4b        (~3.3GB — generic Gemma3, good with KB context)"
    echo "  3) llama3.2:1b      (~1.3GB — fast but lower accuracy)"
    echo "  4) qwen2.5:1.5b     (~1.5GB — multilingual support)"
    echo "  5) Custom model name"
    echo ""

    read -r -p "Select [1-5]: " model_choice
    local model
    case "$model_choice" in
        2) model="gemma3:4b" ;;
        3) model="llama3.2:1b" ;;
        4) model="qwen2.5:1.5b" ;;
        5)
            read -r -p "Model name: " model
            if [ -z "$model" ]; then
                model="aegis-screen:4b"
            fi
            ;;
        *) model="aegis-screen:4b" ;;
    esac

    if [ "$model" = "aegis-screen:4b" ]; then
        download_aegis_screen_model
    else
        info "Pulling ${model}..."
        ollama pull "$model" || {
            warn "Model pull failed. Try later: ollama pull ${model}"
            return
        }
    fi

    "${INSTALL_DIR}/aegis" slm use "$model" 2>/dev/null || true
    info "SLM configured: engine=ollama model=${model}"
    info "Start with: aegis  (not --no-slm)"
}

# --- Download aegis-screen:4b from HuggingFace and import into Ollama ---

download_aegis_screen_model() {
    local hf_url="https://huggingface.co/Loksh/aegis-screen-4b-gguf/resolve/main/aegis-screen-4b-q8_0.gguf"
    local models_dir="${DATA_DIR}/models"
    local gguf_path="${models_dir}/aegis-screen-4b-q8_0.gguf"
    local modelfile_path="${models_dir}/Modelfile.aegis-screen"

    # Check if already imported
    if ollama list 2>/dev/null | grep -q "aegis-screen:4b"; then
        info "aegis-screen:4b already installed in Ollama."
        return 0
    fi

    # Check if GGUF already downloaded
    if [ ! -f "$gguf_path" ]; then
        mkdir -p "$models_dir"
        info "Downloading aegis-screen:4b from HuggingFace (~3.9GB)..."
        info "This is a Gemma3-4B model fine-tuned for prompt injection detection."
        echo ""

        if command -v curl >/dev/null 2>&1; then
            curl -fSL --progress-bar "$hf_url" -o "$gguf_path" || {
                warn "Download failed. Try manually:"
                echo "  curl -fSL $hf_url -o $gguf_path"
                return 1
            }
        elif command -v wget >/dev/null 2>&1; then
            wget --show-progress -q "$hf_url" -O "$gguf_path" || {
                warn "Download failed. Try manually:"
                echo "  wget $hf_url -O $gguf_path"
                return 1
            }
        else
            warn "Neither curl nor wget available. Download manually:"
            echo "  $hf_url"
            return 1
        fi

        info "Downloaded: ${gguf_path} ($(du -h "$gguf_path" | cut -f1))"
    else
        info "GGUF already downloaded: ${gguf_path}"
    fi

    # Create Modelfile and import into Ollama
    cat > "$modelfile_path" << MFEOF
FROM ${gguf_path}
PARAMETER temperature 0.1
PARAMETER num_ctx 4096
MFEOF

    info "Importing into Ollama as aegis-screen:4b..."
    ollama create aegis-screen:4b -f "$modelfile_path" || {
        warn "Ollama import failed. Try manually:"
        echo "  ollama create aegis-screen:4b -f $modelfile_path"
        return 1
    }

    info "aegis-screen:4b installed successfully!"
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

# --- Gateway binary (for cluster operators) ---

download_gateway_binary() {
    local platform="$1"
    local ext=""
    [[ "$platform" == windows-* ]] && ext=".exe"

    local binary_name="aegis-gateway-${platform}${ext}"
    local url

    if [ "$VERSION" = "latest" ]; then
        url="https://github.com/${REPO}/releases/latest/download/${binary_name}"
    else
        url="https://github.com/${REPO}/releases/download/${VERSION}/${binary_name}"
    fi

    info "Downloading aegis-gateway for ${platform}..."
    local target="${INSTALL_DIR}/aegis-gateway${ext}"

    if command -v curl >/dev/null 2>&1; then
        curl -fSL "$url" -o "$target" 2>/dev/null || {
            warn "Gateway binary not available — skip if you don't need cluster mode."
            return 0
        }
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$target" 2>/dev/null || {
            warn "Gateway binary not available — skip if you don't need cluster mode."
            return 0
        }
    fi

    chmod +x "$target"
    info "Installed gateway: ${target}"

    # Generate default gateway config
    generate_gateway_config
}

generate_gateway_config() {
    local config_dir="$HOME/.aegis/config"
    local gateway_config="${config_dir}/gateway.toml"

    if [ -f "$gateway_config" ]; then
        info "Gateway config already exists at ${gateway_config}"
        return
    fi

    mkdir -p "$config_dir"
    cat > "$gateway_config" << 'GWEOF'
# Aegis Gateway Configuration
# Start with: aegis-gateway -c ~/.aegis/config/gateway.toml --embedded

listen_addr = "127.0.0.1:9090"
nats_url = "nats://127.0.0.1:4222"

# Embedded mode: run Mesh Relay + TRUSTMARK Engine + Botawiki in one process
embedded = true

# Optional: SLM screening for Mesh Relay (Layer 3)
# slm_server_url = "http://localhost:11434"
# slm_model = "aegis-screen:4b"

# Optional: PromptGuard classifier for Mesh Relay (Layer 2)
# prompt_guard_model_dir = "/path/to/protectai-v2"
GWEOF
    info "Gateway config: ${gateway_config}"
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
    download_gateway_binary "$platform"
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
model = "aegis-screen:4b"
fallback_to_heuristics = true
# Switch engine: aegis slm engine openai
# Switch model:  aegis slm use gemma3:4b  (generic alternative)
# Set server:    aegis slm server http://localhost:1234
CONFIGEOF
        info "Default config: ${config_dir}/config.toml"
    fi

    # Download NER PII model
    download_ner_model

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
    echo "  What's active:"
    echo "     5-layer injection screening (heuristic + classifier + SLM + NER PII + metaprompt)"
    echo "     NER PII detection (names, phone numbers, SSNs, credit cards, addresses)"
    echo "     Evidence chain, write barrier, credential vault, memory monitor"
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
    echo "  Cluster mode (single command):"
    echo "     aegis-gateway -c ~/.aegis/config/gateway.toml --embedded"
    echo ""
    echo "  Other commands:"
    echo "     aegis scan           — vulnerability scan"
    echo "     aegis status         — adapter status"
    echo "     aegis --enforce      — enable blocking mode"
    echo "     aegis --help         — all options"
    echo ""

    echo ""
}

main "$@"
