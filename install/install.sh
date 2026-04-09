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

# --- Engine detection helpers ---

# Check if a server is responding on a given URL
check_server() {
    local url="$1"
    if command -v curl >/dev/null 2>&1; then
        curl -sf --max-time 2 "$url" >/dev/null 2>&1
    elif command -v wget >/dev/null 2>&1; then
        wget -q --timeout=2 -O /dev/null "$url" 2>/dev/null
    else
        return 1
    fi
}

# Detect all available SLM engines on this machine.
# Sets: HAS_OLLAMA, HAS_OLLAMA_RUNNING, HAS_LMSTUDIO, HAS_VLLM, HAS_LLAMACPP, HAS_ANTHROPIC_KEY
# Also: OLLAMA_MODELS (list of installed models), EXISTING_AEGIS_SCREEN
detect_engines() {
    HAS_OLLAMA=0
    HAS_OLLAMA_RUNNING=0
    HAS_LMSTUDIO=0
    HAS_VLLM=0
    HAS_LLAMACPP=0
    HAS_ANTHROPIC_KEY=0
    OLLAMA_MODELS=""
    EXISTING_AEGIS_SCREEN=0

    # Ollama binary installed?
    if command -v ollama >/dev/null 2>&1; then
        HAS_OLLAMA=1
        # Ollama running?
        if check_server "http://localhost:11434/api/tags"; then
            HAS_OLLAMA_RUNNING=1
            OLLAMA_MODELS=$(ollama list 2>/dev/null | tail -n +2 | awk '{print $1}' | tr '\n' ',' | sed 's/,$//')
            if ollama list 2>/dev/null | grep -q "aegis-screen:4b"; then
                EXISTING_AEGIS_SCREEN=1
            fi
        fi
    fi

    # LM Studio (default port 1234)
    check_server "http://localhost:1234/v1/models" && HAS_LMSTUDIO=1 || true

    # vLLM (default port 8000)
    check_server "http://localhost:8000/v1/models" && HAS_VLLM=1 || true

    # llama.cpp server (default port 8080)
    check_server "http://localhost:8080/health" && HAS_LLAMACPP=1 || true

    # Anthropic API key set?
    [ -n "${ANTHROPIC_API_KEY:-}" ] && HAS_ANTHROPIC_KEY=1 || true
}

# --- SLM model prompt ---

prompt_slm_model() {
    echo ""
    info "━━━ SLM Injection Screening Setup ━━━"
    info "Aegis uses a local AI model to detect prompt injection attacks."
    info "Scanning for available engines..."
    echo ""

    detect_engines

    # ── Fast path: aegis-screen:4b already in Ollama ──
    if [ "$EXISTING_AEGIS_SCREEN" -eq 1 ]; then
        info "✓ Found aegis-screen:4b in Ollama — already installed!"
        "${INSTALL_DIR}/aegis" slm engine ollama 2>/dev/null || true
        "${INSTALL_DIR}/aegis" slm use aegis-screen:4b 2>/dev/null || true
        info "SLM configured: aegis-screen:4b (fine-tuned, 99%+ recall)"
        return
    fi

    # ── Show what we found ──
    local found_something=0
    local options=()
    local option_num=0

    echo -e "  ${CYAN}Detected engines:${NC}"
    echo ""

    if [ "$HAS_OLLAMA" -eq 1 ]; then
        found_something=1
        if [ "$HAS_OLLAMA_RUNNING" -eq 1 ]; then
            echo -e "    ${GREEN}✓${NC} Ollama (running on localhost:11434)"
            if [ -n "$OLLAMA_MODELS" ]; then
                echo "      Models: ${OLLAMA_MODELS}"
            fi
        else
            echo -e "    ${YELLOW}○${NC} Ollama (installed but not running)"
        fi
    fi

    if [ "$HAS_LMSTUDIO" -eq 1 ]; then
        found_something=1
        echo -e "    ${GREEN}✓${NC} LM Studio (running on localhost:1234)"
    fi

    if [ "$HAS_VLLM" -eq 1 ]; then
        found_something=1
        echo -e "    ${GREEN}✓${NC} vLLM (running on localhost:8000)"
    fi

    if [ "$HAS_LLAMACPP" -eq 1 ]; then
        found_something=1
        echo -e "    ${GREEN}✓${NC} llama.cpp (running on localhost:8080)"
    fi

    if [ "$HAS_ANTHROPIC_KEY" -eq 1 ]; then
        found_something=1
        echo -e "    ${GREEN}✓${NC} Anthropic API key (ANTHROPIC_API_KEY is set)"
    fi

    if [ "$found_something" -eq 0 ]; then
        echo -e "    ${YELLOW}○${NC} No engines detected"
    fi

    echo ""

    # ── Build menu based on what's available ──
    echo "  How would you like to run injection screening?"
    echo ""

    # Option A: Ollama with aegis-screen:4b (always show — it's the recommended path)
    option_num=$((option_num + 1))
    options+=("ollama_aegis")
    if [ "$HAS_OLLAMA" -eq 1 ]; then
        echo "  ${option_num}) Install aegis-screen:4b via Ollama  (~3.9GB download)"
        echo "     RECOMMENDED — fine-tuned for Aegis, 99%+ recall, runs locally"
    else
        echo "  ${option_num}) Install Ollama + aegis-screen:4b    (~3.9GB download)"
        echo "     RECOMMENDED — installs Ollama first, then our fine-tuned model"
    fi
    echo ""

    # Option B: LM Studio (if detected)
    if [ "$HAS_LMSTUDIO" -eq 1 ]; then
        option_num=$((option_num + 1))
        options+=("lmstudio")
        echo "  ${option_num}) Use LM Studio (localhost:1234)"
        echo "     Load aegis-screen-4b-q8_0.gguf in LM Studio, Aegis connects automatically"
        echo ""
    fi

    # Option C: vLLM (if detected)
    if [ "$HAS_VLLM" -eq 1 ]; then
        option_num=$((option_num + 1))
        options+=("vllm")
        echo "  ${option_num}) Use vLLM (localhost:8000)"
        echo "     Point Aegis at your running vLLM server"
        echo ""
    fi

    # Option D: llama.cpp (if detected)
    if [ "$HAS_LLAMACPP" -eq 1 ]; then
        option_num=$((option_num + 1))
        options+=("llamacpp")
        echo "  ${option_num}) Use llama.cpp (localhost:8080)"
        echo "     Point Aegis at your running llama.cpp server"
        echo ""
    fi

    # Option E: Anthropic API (if key set, or as cloud option)
    option_num=$((option_num + 1))
    options+=("anthropic")
    if [ "$HAS_ANTHROPIC_KEY" -eq 1 ]; then
        echo "  ${option_num}) Use Anthropic API (cloud, no GPU needed)"
        echo "     ANTHROPIC_API_KEY detected — uses Claude Haiku for screening"
    else
        echo "  ${option_num}) Use Anthropic API (cloud, no GPU needed)"
        echo "     Requires ANTHROPIC_API_KEY — uses Claude Haiku for screening"
    fi
    echo ""

    # Option F: Use existing Ollama model (if other models found)
    if [ "$HAS_OLLAMA_RUNNING" -eq 1 ] && [ -n "$OLLAMA_MODELS" ]; then
        option_num=$((option_num + 1))
        options+=("ollama_existing")
        echo "  ${option_num}) Use an existing Ollama model (${OLLAMA_MODELS})"
        echo "     Skip download — use a model you already have (lower accuracy)"
        echo ""
    fi

    # Option G: Skip
    option_num=$((option_num + 1))
    options+=("skip")
    echo "  ${option_num}) Skip for now"
    echo "     Aegis still protects with heuristic + classifier screening (no SLM)"
    echo ""

    read -r -p "Select [1-${option_num}, default=1]: " engine_choice
    engine_choice="${engine_choice:-1}"

    # Validate input
    if ! [[ "$engine_choice" =~ ^[0-9]+$ ]] || [ "$engine_choice" -lt 1 ] || [ "$engine_choice" -gt "$option_num" ]; then
        engine_choice=1
    fi

    local selected="${options[$((engine_choice - 1))]}"

    case "$selected" in
        ollama_aegis)
            setup_ollama_aegis_screen
            ;;
        lmstudio)
            info "Configuring LM Studio as SLM engine..."
            "${INSTALL_DIR}/aegis" slm engine openai 2>/dev/null || true
            "${INSTALL_DIR}/aegis" slm server http://localhost:1234 2>/dev/null || true
            "${INSTALL_DIR}/aegis" slm use aegis-screen:4b 2>/dev/null || true
            echo ""
            info "To use the fine-tuned model in LM Studio:"
            echo "  1. Download: https://huggingface.co/Loksh/aegis-screen-4b-gguf/resolve/main/aegis-screen-4b-q8_0.gguf"
            echo "  2. Load it in LM Studio"
            echo "  3. Aegis will connect to localhost:1234 automatically"
            echo ""
            info "Or use any model already loaded in LM Studio — Aegis adapts."
            ;;
        vllm)
            info "Configuring vLLM as SLM engine..."
            "${INSTALL_DIR}/aegis" slm engine openai 2>/dev/null || true
            "${INSTALL_DIR}/aegis" slm server http://localhost:8000 2>/dev/null || true
            "${INSTALL_DIR}/aegis" slm use aegis-screen:4b 2>/dev/null || true
            info "SLM configured: engine=openai server=http://localhost:8000"
            echo ""
            info "Load aegis-screen-4b or any model in vLLM."
            ;;
        llamacpp)
            info "Configuring llama.cpp as SLM engine..."
            "${INSTALL_DIR}/aegis" slm engine openai 2>/dev/null || true
            "${INSTALL_DIR}/aegis" slm server http://localhost:8080 2>/dev/null || true
            "${INSTALL_DIR}/aegis" slm use aegis-screen:4b 2>/dev/null || true
            info "SLM configured: engine=openai server=http://localhost:8080"
            echo ""
            info "Load aegis-screen-4b-q8_0.gguf in llama.cpp for best results."
            info "Download: https://huggingface.co/Loksh/aegis-screen-4b-gguf"
            ;;
        anthropic)
            if [ "$HAS_ANTHROPIC_KEY" -eq 0 ]; then
                warn "ANTHROPIC_API_KEY is not set."
                echo "  Set it with: export ANTHROPIC_API_KEY=sk-ant-..."
                echo "  Then restart Aegis."
                echo ""
            fi
            "${INSTALL_DIR}/aegis" slm engine anthropic 2>/dev/null || true
            "${INSTALL_DIR}/aegis" slm server https://api.anthropic.com 2>/dev/null || true
            "${INSTALL_DIR}/aegis" slm use claude-haiku-4-5-20251001 2>/dev/null || true
            info "SLM configured: engine=anthropic model=claude-haiku-4-5-20251001"
            info "Cloud-based screening — no GPU needed, ~$0.001 per screening call."
            ;;
        ollama_existing)
            echo ""
            echo "  Available models: ${OLLAMA_MODELS}"
            read -r -p "  Model name: " chosen_model
            if [ -z "$chosen_model" ]; then
                info "Skipped."
                return
            fi
            "${INSTALL_DIR}/aegis" slm engine ollama 2>/dev/null || true
            "${INSTALL_DIR}/aegis" slm use "$chosen_model" 2>/dev/null || true
            info "SLM configured: engine=ollama model=${chosen_model}"
            warn "Generic models have lower accuracy than aegis-screen:4b."
            echo "  Upgrade later: aegis slm install"
            ;;
        skip)
            info "Skipped SLM setup. Aegis will use heuristic + classifier screening."
            echo "  Configure later:"
            echo "    aegis slm install              # install aegis-screen:4b"
            echo "    aegis slm engine <engine>      # ollama / openai / anthropic"
            echo "    aegis slm use <model>          # set model"
            ;;
    esac
}

# --- Install Ollama (if needed) + aegis-screen:4b ---

setup_ollama_aegis_screen() {
    # Install Ollama if not present
    if [ "$HAS_OLLAMA" -eq 0 ]; then
        info "Installing Ollama..."
        if command -v curl >/dev/null 2>&1; then
            curl -fsSL https://ollama.com/install.sh | sh || {
                warn "Ollama installation failed."
                echo "  Install manually: https://ollama.com/download"
                echo "  Then run: aegis slm install"
                return
            }
        else
            warn "curl not available for Ollama install."
            echo "  Install manually: https://ollama.com/download"
            echo "  Then run: aegis slm install"
            return
        fi
        info "Ollama installed."

        # Start Ollama if not running
        if ! check_server "http://localhost:11434/api/tags"; then
            info "Starting Ollama..."
            if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ollama 2>/dev/null; then
                : # Already running via systemd
            else
                ollama serve >/dev/null 2>&1 &
                sleep 2
            fi
        fi
    elif [ "$HAS_OLLAMA_RUNNING" -eq 0 ]; then
        info "Starting Ollama..."
        if command -v systemctl >/dev/null 2>&1; then
            systemctl start ollama 2>/dev/null || ollama serve >/dev/null 2>&1 &
        else
            ollama serve >/dev/null 2>&1 &
        fi
        sleep 2
    fi

    # Download and import aegis-screen:4b
    download_aegis_screen_model

    "${INSTALL_DIR}/aegis" slm engine ollama 2>/dev/null || true
    "${INSTALL_DIR}/aegis" slm use aegis-screen:4b 2>/dev/null || true
    info "SLM configured: engine=ollama model=aegis-screen:4b (fine-tuned, 99%+ recall)"
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

# --- NATS server install helper (for cluster mode) ---

install_nats() {
    if command -v nats-server >/dev/null 2>&1; then
        local nats_version
        nats_version=$(nats-server --version 2>/dev/null | head -1)
        info "NATS already installed: ${nats_version}"
        return 0
    fi

    local nats_ver="2.10.24"
    local os arch

    case "$(uname -s)" in
        Linux*)  os="linux" ;;
        Darwin*) os="darwin" ;;
        *)
            warn "NATS auto-install not supported on $(uname -s). Install manually: https://nats.io/download"
            return 0
            ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64)   arch="amd64" ;;
        aarch64|arm64)  arch="arm64" ;;
        *)
            warn "NATS auto-install not supported on $(uname -m)."
            return 0
            ;;
    esac

    local nats_url="https://github.com/nats-io/nats-server/releases/download/v${nats_ver}/nats-server-v${nats_ver}-${os}-${arch}.tar.gz"
    local tmp_dir
    tmp_dir=$(mktemp -d)

    info "Downloading NATS server v${nats_ver}..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$nats_url" | tar xz -C "$tmp_dir" || {
            warn "NATS download failed. Install manually: https://nats.io/download"
            rm -rf "$tmp_dir"
            return 0
        }
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "$nats_url" | tar xz -C "$tmp_dir" || {
            warn "NATS download failed."
            rm -rf "$tmp_dir"
            return 0
        }
    fi

    local nats_bin
    nats_bin=$(find "$tmp_dir" -name nats-server -type f | head -1)
    if [ -n "$nats_bin" ]; then
        cp "$nats_bin" "${INSTALL_DIR}/nats-server"
        chmod +x "${INSTALL_DIR}/nats-server"
        info "NATS installed: ${INSTALL_DIR}/nats-server"
    else
        warn "Could not find nats-server binary in download."
    fi
    rm -rf "$tmp_dir"
}

# --- ProtectAI classifier download (Layer 2 screening) ---

download_protectai_classifier() {
    local models_dir="${DATA_DIR}/models/protectai-v2"
    local hf_base="https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/resolve/main/onnx"

    if [ -f "${models_dir}/model.onnx" ] || [ -f "${models_dir}/model.quant.onnx" ]; then
        info "ProtectAI classifier already installed."
        return 0
    fi

    info "Downloading ProtectAI prompt injection classifier (~700 MB)..."
    info "DeBERTa-v3 binary classifier for fast injection detection (Layer 2, ~15ms)."
    echo ""

    mkdir -p "$models_dir"
    local failed=0

    for file in model.onnx tokenizer.json config.json; do
        info "  Fetching ${file}..."
        if command -v curl >/dev/null 2>&1; then
            curl -fSL --progress-bar "${hf_base}/${file}" -o "${models_dir}/${file}" || { warn "Failed to download ${file}"; failed=1; }
        elif command -v wget >/dev/null 2>&1; then
            wget --show-progress -q "${hf_base}/${file}" -O "${models_dir}/${file}" || { warn "Failed to download ${file}"; failed=1; }
        fi
    done

    if [ "$failed" -eq 0 ] && [ -f "${models_dir}/model.onnx" ]; then
        info "ProtectAI classifier installed at ${models_dir}"
    else
        warn "ProtectAI download incomplete. Layer 2 classifier will be disabled."
        warn "Retry later or download manually from: https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2"
    fi
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
    cat > "$gateway_config" << GWEOF
# Aegis Gateway Configuration
# Start with: aegis-gateway -c ~/.aegis/config/gateway.toml --embedded

listen_addr = "127.0.0.1:9090"
nats_url = "nats://127.0.0.1:4222"

# Embedded mode: run Mesh Relay + TRUSTMARK Engine + Botawiki in one process
embedded = true

# SLM screening for Mesh Relay (Layer 3) — uses same Ollama as the adapter
slm_server_url = "http://localhost:11434"
slm_model = "aegis-screen:4b"

# ProtectAI classifier for Mesh Relay (Layer 2, ~15ms)
prompt_guard_model_dir = "${DATA_DIR}/models/protectai-v2"
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
    install_nats
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
# Engine options:
#   aegis slm engine ollama      # Ollama (default, recommended)
#   aegis slm engine openai      # LM Studio, vLLM, llama.cpp, any OpenAI-compatible
#   aegis slm engine anthropic   # Anthropic API (cloud, no GPU needed)
# Switch model:  aegis slm use aegis-screen:4b
# Set server:    aegis slm server http://localhost:1234
CONFIGEOF
        info "Default config: ${config_dir}/config.toml"
    fi

    # Download ML models
    download_ner_model
    download_protectai_classifier

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
    echo ""
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${CYAN}              Aegis Shield — Installed${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
    echo "  Binaries:"
    echo "     aegis              adapter CLI + proxy"
    echo "     aegis-gateway      cluster gateway (embedded mode)"
    [ -f "${INSTALL_DIR}/nats-server" ] && \
    echo "     nats-server        NATS JetStream message bus"
    echo ""
    echo "  Models:"
    [ -f "${DATA_DIR}/models/distilbert-ner/model.onnx" ] || [ -f "${DATA_DIR}/models/pii-ner/model.onnx" ] && \
    echo "     NER PII            DistilBERT-NER (~250 MB)"
    [ -f "${DATA_DIR}/models/protectai-v2/model.onnx" ] && \
    echo "     ProtectAI          DeBERTa-v3 classifier (~700 MB)"
    command -v ollama >/dev/null 2>&1 && ollama list 2>/dev/null | grep -q "aegis-screen" && \
    echo "     aegis-screen:4b    Gemma3-4B fine-tuned SLM (~3.9 GB)"
    echo ""
    echo "  Screening layers:"
    echo "     Layer 1  heuristic       regex patterns (<1ms)"
    [ -f "${DATA_DIR}/models/protectai-v2/model.onnx" ] && \
    echo "     Layer 2  ProtectAI       DeBERTa classifier (~15ms)" || \
    echo "     Layer 2  ProtectAI       not installed (optional)"
    echo "     Layer 3  aegis-screen    deep SLM analysis (2-3s)"
    [ -f "${DATA_DIR}/models/distilbert-ner/model.onnx" ] || [ -f "${DATA_DIR}/models/pii-ner/model.onnx" ] && \
    echo "     Layer 4  NER PII         name/SSN/phone detection (~2ms)" || \
    echo "     Layer 4  NER PII         not installed (optional)"
    echo "     Layer 5  metaprompt      system prompt hardening (0ms)"
    echo ""
    echo "  Quick start:"
    echo ""
    echo "     aegis setup openclaw     connect to your agent"
    echo "     aegis                    start protection"
    echo "     open http://localhost:3141/dashboard"
    echo ""
    echo "  Cluster mode (single command):"
    echo ""
    echo "     nats-server -js &"
    echo "     aegis-gateway --embedded -c ~/.aegis/config/gateway.toml"
    echo ""
}

main "$@"
