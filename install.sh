#!/usr/bin/env bash
# =============================================================================
# rvs — AI Agent Setup & Synchronization Tool
# =============================================================================
set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true

# Signal trap for clean exit on interrupt
trap 'echo -e "\nAborted by user."; exit 130' INT TERM

# Dynamic directory detection (resolves real physical path for current user/system)
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_DIR="$SCRIPT_DIR"
HARNESS_PATH="$REPO_DIR/rvs_agent_harness.py"
SKILL_SRC="$REPO_DIR/SKILL.md"
RVS_BIN="$REPO_DIR/target/release/rvs"
CACHE_DIR="$HOME/.cache/rvs"
LAST_CHECK_FILE="$CACHE_DIR/last_update_check"
PENDING_UPDATE_FILE="$CACHE_DIR/pending_update"
MANUAL_CONFIG_FILE="$REPO_DIR/rvs_mcp_config.json"

# Formatting
C_RESET=$'\033[0m'
C_BOLD=$'\033[1m'
C_DIM=$'\033[2m'
C_RED=$'\033[0;31m'
C_GREEN=$'\033[0;32m'
C_YELLOW=$'\033[1;33m'
C_BLUE=$'\033[0;34m'
C_CYAN=$'\033[0;36m'

log()     { echo -e "${C_BLUE}[*]${C_RESET} $*"; }
info()    { echo -e "${C_CYAN}[i]${C_RESET} $*"; }
success() { echo -e "${C_GREEN}[✓]${C_RESET} ${C_BOLD}$*${C_RESET}"; }
warn()    { echo -e "${C_YELLOW}[!]${C_RESET} $*"; }
error()   { echo -e "${C_RED}[✗]${C_RESET} ${C_BOLD}$*${C_RESET}" >&2; }

check_and_print_pending_notification() {
    if [[ -f "$PENDING_UPDATE_FILE" ]]; then
        local pending_tag
        pending_tag=$(cat "$PENDING_UPDATE_FILE" 2>/dev/null || true)
        if [[ -n "$pending_tag" ]]; then
            local head_tag
            head_tag=$(git -C "$REPO_DIR" describe --tags --exact-match 2>/dev/null || true)
            if [[ "$head_tag" == "$pending_tag" ]]; then
                rm -f "$PENDING_UPDATE_FILE"
                return 0
            fi
            echo -e "${C_YELLOW}🔔 Notice: A new release ${C_BOLD}${pending_tag}${C_RESET}${C_YELLOW} is available on GitHub!${C_RESET}"
            echo -e "   Select Option 3 (Check GitHub Update) to review and upgrade."
            echo -e "${C_DIM}------------------------------------------------------------${C_RESET}"
        fi
    fi
}

print_banner() {
    echo -e "${C_BOLD}rvs — AI Agent Setup & Sync${C_RESET}"
    echo -e "${C_DIM}------------------------------------------------------------${C_RESET}"
    check_and_print_pending_notification
}

# Portable timeout runner
run_with_timeout() {
    local duration="$1"
    shift
    if command -v timeout &>/dev/null; then
        timeout "$duration" "$@"
    elif command -v gtimeout &>/dev/null; then
        gtimeout "$duration" "$@"
    else
        "$@"
    fi
}

# Prompt user for input with safe default fallback and EOF resilience
prompt_input() {
    local prompt="$1"
    local default_val="$2"
    local var_name="$3"

    local input=""
    if ! read -r -p "$prompt" input; then
        echo ""
        input="$default_val"
    fi
    printf -v "$var_name" "%s" "${input:-$default_val}"
}

# =============================================================================
# 1. Pre-flight Dependency & Agent Diagnostic (Notification-Only, No Auto-Install)
# =============================================================================
run_preflight_diagnostics() {
    local show_summary="${1:-false}"
    local has_errors=false
    local missing_required=()
    local missing_warnings=()

    # 1. Python 3 Check (Version >= 3.9)
    local py_status="${C_RED}Missing${C_RESET}"
    if command -v python3 &>/dev/null; then
        local py_ver
        py_ver=$(python3 -c 'import sys; print(f"v{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")' 2>/dev/null || echo "detected")
        if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
            py_status="${C_GREEN}OK${C_RESET} ($py_ver)"
        else
            py_status="${C_YELLOW}Outdated${C_RESET} ($py_ver, requires >= 3.9)"
            missing_required+=("python3 (>= 3.9)")
            has_errors=true
        fi
    else
        missing_required+=("python3")
        has_errors=true
    fi

    # 2. radare2 (r2) Check
    local r2_status="${C_YELLOW}Not found${C_RESET}"
    if command -v radare2 &>/dev/null; then
        local r2_ver
        r2_ver=$(radare2 -v 2>/dev/null | head -n1 | awk '{print $2}' || echo "detected")
        r2_status="${C_GREEN}OK${C_RESET} (v$r2_ver)"
    else
        missing_warnings+=("radare2 (binary analysis/ESIL emulation will not work without r2)")
    fi

    # 3. Core CLI tools (git, jq)
    local git_status="${C_RED}Missing${C_RESET}"
    if command -v git &>/dev/null; then
        git_status="${C_GREEN}OK${C_RESET}"
    else
        missing_required+=("git")
        has_errors=true
    fi

    local jq_status="${C_RED}Missing${C_RESET}"
    if command -v jq &>/dev/null; then
        jq_status="${C_GREEN}OK${C_RESET}"
    else
        missing_required+=("jq")
        has_errors=true
    fi

    # 4. Cargo (Optional, for building from source)
    local cargo_status="${C_DIM}Not found (pre-built binary download fallback)${C_RESET}"
    if command -v cargo &>/dev/null; then
        local cargo_ver
        cargo_ver=$(cargo --version 2>/dev/null | awk '{print $2}' || echo "detected")
        cargo_status="${C_GREEN}OK${C_RESET} ($cargo_ver)"
    fi

    # 5. Agent Detection
    local has_antigravity=false
    local has_claude=false
    local has_cursor=false

    [[ -d "$HOME/.gemini" ]] && has_antigravity=true
    (command -v claude &>/dev/null || [[ -d "$HOME/.config/Claude" || -d "$HOME/Library/Application Support/Claude" ]]) && has_claude=true
    ([[ -d "$HOME/.cursor" || -d "$HOME/Library/Application Support/Cursor" || -d "$HOME/.config/Cursor" ]]) && has_cursor=true

    # Display Diagnostic Table
    if [[ "$show_summary" == true || "$has_errors" == true ]]; then
        echo -e "${C_BOLD}System Environment & Dependencies:${C_RESET}"
        echo -e "  - Current User    : ${C_CYAN}${USER:-$(whoami)}${C_RESET}"
        echo -e "  - Repository Path : ${C_CYAN}$REPO_DIR${C_RESET}"
        echo -e "  - Python 3        : $py_status"
        echo -e "  - radare2 (r2)    : $r2_status"
        echo -e "  - Git             : $git_status"
        echo -e "  - jq              : $jq_status"
        echo -e "  - Cargo (Rust)    : $cargo_status"
        echo ""
        echo -e "${C_BOLD}Detected AI Agents:${C_RESET}"
        echo -e "  - Google Antigravity : $([[ "$has_antigravity" == true ]] && echo "${C_GREEN}Detected${C_RESET}" || echo "${C_DIM}Not found${C_RESET}")"
        echo -e "  - Claude (Desktop/CLI): $([[ "$has_claude" == true ]] && echo "${C_GREEN}Detected${C_RESET}" || echo "${C_DIM}Not found${C_RESET}")"
        echo -e "  - Cursor IDE         : $([[ "$has_cursor" == true ]] && echo "${C_GREEN}Detected${C_RESET}" || echo "${C_DIM}Not found${C_RESET}")"
        echo -e "${C_DIM}------------------------------------------------------------${C_RESET}"

        if [[ ${#missing_required[@]} -gt 0 ]]; then
            echo ""
            error "Missing required dependencies: ${missing_required[*]}"
            echo "Please install them manually using your system package manager:"
            echo "  - Debian/Ubuntu : sudo apt install ${missing_required[*]}"
            echo "  - macOS (Homebrew): brew install ${missing_required[*]}"
            echo "  - Arch Linux    : sudo pacman -S ${missing_required[*]}"
            echo ""
            return 1
        fi

        if [[ ${#missing_warnings[@]} -gt 0 ]]; then
            warn "Notice: ${missing_warnings[*]}"
            echo "  (Install manually if you plan to perform local static/dynamic analysis: https://radare.org)"
            echo ""
        fi
    fi

    return 0
}

# =============================================================================
# 2. MCP Proxy (Non-blocking background launcher for Agents)
# =============================================================================
run_mcp_launcher() {
    local now
    now=$(date +%s)
    local last=0

    if [[ -f "$LAST_CHECK_FILE" ]]; then
        local raw_last
        raw_last=$(cat "$LAST_CHECK_FILE" 2>/dev/null || echo 0)
        [[ "$raw_last" =~ ^[0-9]+$ ]] && last="$raw_last"
    fi

    # Check update at most once per 24h (86400s) in background (notify-only)
    if (( (now - last) >= 86400 )); then
        mkdir -p "$CACHE_DIR"
        echo "$now" > "$LAST_CHECK_FILE"
        ( bash "$REPO_DIR/install.sh" --check-update-silent >/dev/null 2>&1 & )
    fi

    exec python3 "$HARNESS_PATH" --mcp
}

# =============================================================================
# 3. Binary Resolution (Pre-built download or fast Cargo build)
# =============================================================================
download_prebuilt_binary() {
    local tag="${1:-latest}"
    local os_arch=""

    case "$(uname -s)-$(uname -m)" in
        Linux-x86_64)   os_arch="linux-x86_64" ;;
        Linux-aarch64)  os_arch="linux-aarch64" ;;
        Darwin-arm64)   os_arch="macos-arm64" ;;
        Darwin-x86_64)  os_arch="macos-x86_64" ;;
        *)              return 1 ;;
    esac

    # Sanitize tag parameter to prevent command/URL manipulation
    if [[ ! "$tag" =~ ^(latest|v?[0-9]+(\.[0-9]+)*([a-zA-Z0-9._-]+)?)$ ]]; then
        warn "Invalid release tag format: $tag"
        return 1
    fi

    local base_url="https://github.com/Anhdeface/rvs/releases/download/${tag}"
    [[ "$tag" == "latest" ]] && base_url="https://github.com/Anhdeface/rvs/releases/latest/download"
    local download_url="${base_url}/rvs-${os_arch}"
    local checksum_url="${download_url}.sha256"

    log "Checking pre-built binary ($os_arch)..."
    mkdir -p -m 755 "$REPO_DIR/target/release"
    local temp_bin="$REPO_DIR/target/release/rvs.tmp.$$"

    if run_with_timeout 10 curl -fsSL -o "$temp_bin" "$download_url" 2>/dev/null; then
        # Optional Supply-chain integrity check: verify SHA256 if available
        local temp_sha="${temp_bin}.sha256"
        if run_with_timeout 5 curl -fsSL -o "$temp_sha" "$checksum_url" 2>/dev/null; then
            local expected_hash actual_hash
            expected_hash=$(awk '{print $1}' "$temp_sha" 2>/dev/null || true)
            if command -v sha256sum &>/dev/null; then
                actual_hash=$(sha256sum "$temp_bin" | awk '{print $1}')
            elif command -v shasum &>/dev/null; then
                actual_hash=$(shasum -a 256 "$temp_bin" | awk '{print $1}')
            fi

            rm -f "$temp_sha"
            if [[ -n "$expected_hash" && -n "$actual_hash" && "$expected_hash" != "$actual_hash" ]]; then
                error "Integrity check failed for $download_url (SHA256 mismatch)!"
                rm -f "$temp_bin"
                return 1
            fi
            info "SHA256 checksum verified."
        fi

        mv -f "$temp_bin" "$RVS_BIN"
        chmod 755 "$RVS_BIN"
        success "Downloaded pre-built binary: $RVS_BIN"
        return 0
    fi

    rm -f "$temp_bin" "${temp_bin}.sha256"
    return 1
}

build_rvs_binary() {
    # 1. Try downloading pre-compiled release binary first (fast, 0 CPU overhead)
    local current_tag
    current_tag=$(git describe --tags --exact-match 2>/dev/null || echo "latest")
    if download_prebuilt_binary "$current_tag"; then
        return 0
    fi

    # 2. Fallback to Cargo (scoped to --bin rvs, skipping test/dev dependencies)
    if ! command -v cargo &>/dev/null; then
        warn "Pre-built binary not found and Cargo is not installed. Skipping build."
        return 0
    fi

    log "Building target/release/rvs via cargo (fast --bin rvs mode)..."
    if (cd "$REPO_DIR" && cargo build --release --bin rvs); then
        success "Binary ready: $RVS_BIN"
    else
        warn "Cargo build failed. Continuing with harness/existing binary."
    fi
}

setup_terminal_shortcut() {
    if [[ -f "$RVS_BIN" ]]; then
        mkdir -p "$HOME/.local/bin"
        ln -sfn "$RVS_BIN" "$HOME/.local/bin/rvs"
        success "Linked $HOME/.local/bin/rvs -> $RVS_BIN"
    else
        warn "Binary not found at $RVS_BIN. Skipping shortcut."
    fi
}

# =============================================================================
# 4. Sparse-Checkout Management (Include / Exclude Test Suites)
# =============================================================================
configure_test_suite_sparse() {
    local include_tests="$1"
    if ! git rev-parse --is-inside-work-tree &>/dev/null; then
        return 0
    fi

    if [[ "$include_tests" == false ]]; then
        log "Excluding test suites to optimize disk space and future pulls..."
        if git sparse-checkout set --no-cone '/*' '!/tests' '!/.agents' 2>/dev/null; then
            success "Tests excluded (future updates will NOT fetch tests/ or .agents/)."
        else
            rm -rf "$REPO_DIR/tests" "$REPO_DIR/.agents"
            info "Cleaned test folders locally."
        fi
    else
        log "Restoring test suites..."
        git sparse-checkout disable 2>/dev/null || true
        success "Test suites included."
    fi
}

# =============================================================================
# 5. Manual Setup Export (Zero automated modifications)
# =============================================================================
export_manual_mcp_config() {
    # Dynamically generated config with exact local user paths
    cat << JSON_EOF > "$MANUAL_CONFIG_FILE"
{
  "mcpServers": {
    "rvs": {
      "command": "python3",
      "args": [
        "$HARNESS_PATH",
        "--mcp"
      ]
    }
  }
}
JSON_EOF

    echo ""
    echo -e "${C_BOLD}Manual MCP Configuration Snippet:${C_RESET}"
    echo -e "${C_DIM}Dynamic Path for User: ${USER:-$(whoami)} (Repository: $REPO_DIR)${C_RESET}"
    echo ""
    echo -e "${C_CYAN}$(cat "$MANUAL_CONFIG_FILE")${C_RESET}"
    echo ""
    echo "Saved to: $MANUAL_CONFIG_FILE"
    echo ""
    echo "Add the 'rvs' block above into your Agent configuration file:"
    echo "  - Antigravity : ~/.gemini/config/mcp_config.json"
    echo "  - Claude Desktop: ~/.config/Claude/claude_desktop_config.json"
    echo "  - Claude Code CLI: claude mcp add rvs -- python3 \"$HARNESS_PATH\" --mcp"
    echo "  - Cursor IDE    : ~/.cursor/mcp.json"
    echo ""
    echo "To attach the skill manually, copy or link:"
    echo "  $SKILL_SRC"
    echo ""
    info "Note: Manual setup does not enable automatic background updates."
}

# =============================================================================
# 6. Core Agent Configuration
# =============================================================================
attach_skill_to_dir() {
    local target_dir="$1"
    local agent_name="$2"
    local mode="$3"

    mkdir -p "$target_dir"
    local target_file="$target_dir/SKILL.md"

    if [[ "$mode" == "copy" ]]; then
        cp -f "$SKILL_SRC" "$target_file"
        info "[$agent_name] Copied SKILL.md"
    else
        ln -sfn "$SKILL_SRC" "$target_file"
        info "[$agent_name] Symlinked SKILL.md"
    fi
}

get_mcp_cmd_and_args() {
    local use_lazy="$1"
    if [[ "$use_lazy" == true ]]; then
        echo "$REPO_DIR/install.sh"
        echo '["--mcp-proxy"]'
    else
        echo "python3"
        echo "[\"$HARNESS_PATH\", \"--mcp\"]"
    fi
}

safe_merge_mcp_config() {
    local config_file="$1"
    local mcp_cmd="$2"
    local mcp_args="$3"

    local config_dir
    config_dir="$(dirname -- "$config_file")"
    mkdir -p -m 755 "$config_dir"

    # Avoid writing through unexpected or dangling symlinks
    if [[ -L "$config_file" ]]; then
        local resolved_target
        resolved_target="$(readlink -f "$config_file" 2>/dev/null || true)"
        if [[ -n "$resolved_target" ]]; then
            config_file="$resolved_target"
        fi
    fi

    if [[ ! -s "$config_file" ]] || ! jq empty "$config_file" 2>/dev/null; then
        echo '{"mcpServers":{}}' > "$config_file"
    fi

    cp -f "$config_file" "${config_file}.bak"

    local updated_json
    if updated_json=$(jq \
        --arg cmd "$mcp_cmd" \
        --argjson args "$mcp_args" \
        '.mcpServers.rvs = { "command": $cmd, "args": $args }' \
        "$config_file" 2>/dev/null); then
        if [[ -n "$updated_json" ]] && echo "$updated_json" | jq empty 2>/dev/null; then
            local temp_cfg="${config_file}.tmp.$$"
            echo "$updated_json" > "$temp_cfg"
            mv -f "$temp_cfg" "$config_file"
            chmod 644 "$config_file" 2>/dev/null || true
            return 0
        fi
    fi

    error "Failed to generate valid JSON for $config_file. Restored backup."
    cp -f "${config_file}.bak" "$config_file"
    return 1
}

configure_antigravity_core() {
    local use_lazy="$1"
    local skill_mode="$2"

    local cmd args_json
    { read -r cmd; read -r args_json; } < <(get_mcp_cmd_and_args "$use_lazy")

    local config_file="$HOME/.gemini/config/mcp_config.json"
    safe_merge_mcp_config "$config_file" "$cmd" "$args_json"

    local schemas_dir="$HOME/.gemini/antigravity-cli/mcp/rvs"
    mkdir -p "$schemas_dir"
    local tools_json
    if tools_json=$(python3 "$HARNESS_PATH" --export-tools mcp 2>/dev/null); then
        echo "$tools_json" | jq -c '.[] | {name, description, parameters: .inputSchema}' | while read -r tool; do
            local tool_name
            tool_name=$(echo "$tool" | jq -r .name)
            echo "$tool" > "$schemas_dir/${tool_name}.json"
        done
    fi

    attach_skill_to_dir "$HOME/.gemini/config/skills/rvs" "Antigravity" "$skill_mode"
    success "Antigravity configured."
}

configure_claude_core() {
    local use_lazy="$1"
    local skill_mode="$2"

    local cmd args_json
    { read -r cmd; read -r args_json; } < <(get_mcp_cmd_and_args "$use_lazy")

    local claude_desktop_cfg="$HOME/.config/Claude/claude_desktop_config.json"
    [[ "$(uname -s)" == "Darwin" ]] && claude_desktop_cfg="$HOME/Library/Application Support/Claude/claude_desktop_config.json"

    if [[ -d "$(dirname -- "$claude_desktop_cfg")" || -f "$claude_desktop_cfg" ]]; then
        safe_merge_mcp_config "$claude_desktop_cfg" "$cmd" "$args_json"
    fi

    if command -v claude &>/dev/null; then
        claude mcp remove rvs -s user &>/dev/null || true
        if [[ "$use_lazy" == true ]]; then
            claude mcp add -s user rvs -- "$REPO_DIR/install.sh" --mcp-proxy &>/dev/null || true
        else
            claude mcp add -s user rvs -- python3 "$HARNESS_PATH" --mcp &>/dev/null || true
        fi
    fi

    attach_skill_to_dir "$HOME/.claude/skills/rvs" "Claude Code" "$skill_mode"
    success "Claude configured."
}

configure_cursor_core() {
    local use_lazy="$1"
    local cmd args_json
    { read -r cmd; read -r args_json; } < <(get_mcp_cmd_and_args "$use_lazy")

    local cursor_cfg="$HOME/.cursor/mcp.json"
    safe_merge_mcp_config "$cursor_cfg" "$cmd" "$args_json"
    success "Cursor configured."
}

# =============================================================================
# 7. GitHub Release Tag Auto-Update (Notify-Only Detection & On-Demand Upgrade)
# =============================================================================
check_update_silent() {
    cd -- "$REPO_DIR" || return 0

    if ! git rev-parse --is-inside-work-tree &>/dev/null; then
        return 0
    fi

    local latest_tag
    latest_tag=$(run_with_timeout 5 git ls-remote --tags --sort="v:refname" origin 2>/dev/null | grep -v '\^{}' | tail -n1 | sed 's/.*refs\/tags\///' || true)

    if [[ -z "$latest_tag" ]]; then
        return 0
    fi

    # Strictly sanitize tag format to prevent command/argument injection
    if [[ ! "$latest_tag" =~ ^v?[0-9]+(\.[0-9]+)*([a-zA-Z0-9._-]+)?$ ]]; then
        return 0
    fi

    local current_commit head_tag
    current_commit=$(git rev-parse HEAD 2>/dev/null || true)
    head_tag=$(git describe --tags --exact-match 2>/dev/null || true)

    local is_up_to_date=false
    if [[ -n "$head_tag" && "$head_tag" == "$latest_tag" ]]; then
        is_up_to_date=true
    fi

    local tag_commit
    tag_commit=$(git rev-list -n 1 "refs/tags/$latest_tag" 2>/dev/null || true)
    if [[ -n "$tag_commit" && "$current_commit" == "$tag_commit" ]]; then
        is_up_to_date=true
    fi

    mkdir -p -m 700 "$CACHE_DIR"
    if [[ "$is_up_to_date" == false ]]; then
        local temp_pending="${PENDING_UPDATE_FILE}.tmp.$$"
        echo "$latest_tag" > "$temp_pending"
        mv -f "$temp_pending" "$PENDING_UPDATE_FILE"
        chmod 600 "$PENDING_UPDATE_FILE" 2>/dev/null || true
    else
        rm -f "$PENDING_UPDATE_FILE"
    fi
}

perform_update() {
    local silent="${1:-false}"
    cd -- "$REPO_DIR"

    if ! git rev-parse --is-inside-work-tree &>/dev/null; then
        [[ "$silent" == false ]] && error "Not a Git repository."
        return 1
    fi

    if [[ -n "$(git status --porcelain -uno 2>/dev/null)" ]]; then
        [[ "$silent" == false ]] && warn "Uncommitted changes found. Skipping update."
        return 0
    fi

    [[ "$silent" == false ]] && log "Checking latest release on GitHub..."

    local latest_tag
    latest_tag=$(run_with_timeout 5 git ls-remote --tags --sort="v:refname" origin 2>/dev/null | grep -v '\^{}' | tail -n1 | sed 's/.*refs\/tags\///' || true)

    if [[ -z "$latest_tag" ]]; then
        [[ "$silent" == false ]] && warn "Unable to fetch remote tags."
        return 0
    fi

    # Strictly sanitize tag format
    if [[ ! "$latest_tag" =~ ^v?[0-9]+(\.[0-9]+)*([a-zA-Z0-9._-]+)?$ ]]; then
        [[ "$silent" == false ]] && warn "Untrusted or invalid tag format from remote: $latest_tag"
        return 0
    fi

    local current_commit head_tag
    current_commit=$(git rev-parse HEAD 2>/dev/null || true)
    head_tag=$(git describe --tags --exact-match 2>/dev/null || true)

    local is_up_to_date=false
    if [[ -n "$head_tag" && "$head_tag" == "$latest_tag" ]]; then
        is_up_to_date=true
    fi

    local tag_commit
    tag_commit=$(git rev-list -n 1 "refs/tags/$latest_tag" 2>/dev/null || true)
    if [[ -n "$tag_commit" && "$current_commit" == "$tag_commit" ]]; then
        is_up_to_date=true
    fi

    if [[ "$silent" == false ]]; then
        echo "  Current: ${head_tag:-$current_commit}"
        echo "  Latest : $latest_tag"
    fi

    if [[ "$is_up_to_date" == false ]]; then
        if [[ "$silent" == false ]]; then
            local do_up="Y"
            prompt_input "Upgrade to $latest_tag? [Y/n]: " "Y" do_up
            if [[ ! "$do_up" =~ ^[Yy]$ ]]; then
                info "Canceled."
                return 0
            fi
        fi

        [[ "$silent" == false ]] && log "Pulling $latest_tag..."
        git fetch --tags origin -q 2>/dev/null || return 0
        git checkout "tags/$latest_tag" -q 2>/dev/null || return 0

        # Try fast pre-built binary download first, then cargo --bin rvs
        build_rvs_binary

        if [[ -d "$HOME/.gemini/antigravity-cli/mcp/rvs" ]]; then
            local tools_json
            if tools_json=$(python3 "$HARNESS_PATH" --export-tools mcp 2>/dev/null); then
                echo "$tools_json" | jq -c '.[] | {name, description, parameters: .inputSchema}' | while read -r tool; do
                    local tool_name
                    tool_name=$(echo "$tool" | jq -r .name)
                    echo "$tool" > "$HOME/.gemini/antigravity-cli/mcp/rvs/${tool_name}.json"
                done
            fi
        fi

        rm -f "$PENDING_UPDATE_FILE"
        [[ "$silent" == false ]] && success "Updated to $latest_tag."
    else
        rm -f "$PENDING_UPDATE_FILE"
        [[ "$silent" == false ]] && success "Already up to date ($latest_tag)."
    fi
}

# =============================================================================
# 8. Clean Uninstall
# =============================================================================
perform_uninstall() {
    echo ""
    echo -e "${C_YELLOW}This removes rvs MCP servers and skills from all agents.${C_RESET}"
    local confirm="N"
    prompt_input "Proceed? [y/N]: " "N" confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        info "Canceled."
        return 0
    fi

    local config_file="$HOME/.gemini/config/mcp_config.json"
    if [[ -f "$config_file" ]]; then
        local tmp_gemini="${config_file}.tmp.$$"
        if jq 'del(.mcpServers.rvs)' "$config_file" > "$tmp_gemini" 2>/dev/null; then
            mv -f "$tmp_gemini" "$config_file"
        else
            rm -f "$tmp_gemini"
        fi
    fi
    rm -rf "$HOME/.gemini/antigravity-cli/mcp/rvs"
    rm -rf "$HOME/.gemini/config/skills/rvs"

    local claude_cfg="$HOME/.config/Claude/claude_desktop_config.json"
    [[ "$(uname -s)" == "Darwin" ]] && claude_cfg="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
    if [[ -f "$claude_cfg" ]]; then
        local tmp_claude="${claude_cfg}.tmp.$$"
        if jq 'del(.mcpServers.rvs)' "$claude_cfg" > "$tmp_claude" 2>/dev/null; then
            mv -f "$tmp_claude" "$claude_cfg"
        else
            rm -f "$tmp_claude"
        fi
    fi
    command -v claude &>/dev/null && claude mcp remove rvs -s user &>/dev/null || true
    rm -rf "$HOME/.claude/skills/rvs"

    local cursor_cfg="$HOME/.cursor/mcp.json"
    if [[ -f "$cursor_cfg" ]]; then
        local tmp_cursor="${cursor_cfg}.tmp.$$"
        if jq 'del(.mcpServers.rvs)' "$cursor_cfg" > "$tmp_cursor" 2>/dev/null; then
            mv -f "$tmp_cursor" "$cursor_cfg"
        else
            rm -f "$tmp_cursor"
        fi
    fi

    rm -f "$HOME/.local/bin/rvs" "$MANUAL_CONFIG_FILE"
    rm -rf "$CACHE_DIR"

    success "Uninstalled rvs from all agents."
}

# =============================================================================
# 9. Interactive Setup Wizard
# =============================================================================
run_installation_wizard() {
    # Step 1: Test Suites Configuration
    echo ""
    echo -e "${C_BOLD}[1/6] Test Suites & Fixtures${C_RESET}"
    echo "  Tests are only needed for core development, not for running agents."
    local inc_tests="N"
    prompt_input "  Keep test suites in workspace? [y/N] (N excludes tests from future pulls): " "N" inc_tests
    local include_tests=false
    [[ "$inc_tests" =~ ^[Yy]$ ]] && include_tests=true

    # Step 2: Binary Build
    echo ""
    echo -e "${C_BOLD}[2/6] Rust Core Binary${C_RESET}"
    local do_build="Y"
    if [[ -f "$RVS_BIN" ]]; then
        echo "  Binary exists at target/release/rvs."
        prompt_input "  Rebuild from source? [y/N]: " "N" do_build
    else
        prompt_input "  Fetch or build target/release/rvs? [Y/n]: " "Y" do_build
    fi

    # Step 3: Target Agents
    echo ""
    echo -e "${C_BOLD}[3/6] Target Agents${C_RESET}"
    echo "  1) All detected agents"
    echo "  2) Google Antigravity only"
    echo "  3) Claude only"
    echo "  4) Cursor only"
    echo "  5) Manual export only (creates rvs_mcp_config.json, no auto-config)"
    echo "  6) Skip"
    local agent_choice="1"
    prompt_input "  Select [1-6] (default: 1): " "1" agent_choice

    # Step 4: Skill Linking Method (if not manual or skip)
    local skill_mode="symlink"
    if [[ "$agent_choice" =~ ^[1-4]$ ]]; then
        echo ""
        echo -e "${C_BOLD}[4/6] Skill Linking Mode${C_RESET}"
        echo "  1) Symlink (recommended - auto-syncs on git pull)"
        echo "  2) Copy (independent file)"
        local skill_choice="1"
        prompt_input "  Select [1-2] (default: 1): " "1" skill_choice
        [[ "$skill_choice" == "2" ]] && skill_mode="copy"
    fi

    # Step 5: Background Update Check
    local use_lazy=false
    if [[ "$agent_choice" =~ ^[1-4]$ ]]; then
        echo ""
        echo -e "${C_BOLD}[5/6] Auto-Update Check${C_RESET}"
        echo "  Checks GitHub tags in background when MCP launches (max once/24h, non-blocking)."
        echo "  Only notifies you upon opening install.sh — does NOT modify source code automatically."
        local lazy_choice="Y"
        prompt_input "  Enable background check? [Y/n]: " "Y" lazy_choice
        [[ "$lazy_choice" =~ ^[Yy]$ ]] && use_lazy=true
    fi

    # Step 6: CLI Shortcut
    echo ""
    echo -e "${C_BOLD}[6/6] CLI Shortcut${C_RESET}"
    local bin_choice="Y"
    prompt_input "  Link binary to ~/.local/bin/rvs? [Y/n]: " "Y" bin_choice

    # Summary
    echo ""
    echo -e "${C_DIM}------------------------------------------------------------${C_RESET}"
    echo "Summary:"
    echo "  - Test suites      : $([ "$include_tests" = true ] && echo "kept" || echo "excluded (sparse)")"
    echo "  - Build binary     : $([[ "$do_build" =~ ^[Yy]$ ]] && echo "yes" || echo "skip")"
    echo "  - Target agents    : Option $agent_choice"
    [[ "$agent_choice" =~ ^[1-4]$ ]] && echo "  - Skill mode       : $skill_mode"
    [[ "$agent_choice" =~ ^[1-4]$ ]] && echo "  - Auto-update check: $([ "$use_lazy" = true ] && echo "enabled (notify-only, 24h)" || echo "disabled")"
    echo "  - CLI shortcut     : $([[ "$bin_choice" =~ ^[Yy]$ ]] && echo "yes" || echo "no")"
    echo -e "${C_DIM}------------------------------------------------------------${C_RESET}"

    local confirm_apply="Y"
    prompt_input "Apply changes? [Y/n]: " "Y" confirm_apply
    if [[ ! "$confirm_apply" =~ ^[Yy]$ ]]; then
        info "Aborted."
        return 0
    fi

    echo ""
    configure_test_suite_sparse "$include_tests"

    if [[ "$do_build" =~ ^[Yy]$ ]]; then
        build_rvs_binary
    fi

    local has_antigravity=false
    local has_claude=false
    local has_cursor=false
    [[ -d "$HOME/.gemini" ]] && has_antigravity=true
    (command -v claude &>/dev/null || [[ -d "$HOME/.config/Claude" || -d "$HOME/Library/Application Support/Claude" ]]) && has_claude=true
    ([[ -d "$HOME/.cursor" || -d "$HOME/Library/Application Support/Cursor" || -d "$HOME/.config/Cursor" ]]) && has_cursor=true

    case "$agent_choice" in
        1)
            [[ "$has_antigravity" == true ]] && configure_antigravity_core "$use_lazy" "$skill_mode"
            [[ "$has_claude" == true ]] && configure_claude_core "$use_lazy" "$skill_mode"
            [[ "$has_cursor" == true ]] && configure_cursor_core "$use_lazy"
            if [[ "$has_antigravity" == false && "$has_claude" == false && "$has_cursor" == false ]]; then
                configure_antigravity_core "$use_lazy" "$skill_mode"
                configure_claude_core "$use_lazy" "$skill_mode"
            fi
            ;;
        2)
            configure_antigravity_core "$use_lazy" "$skill_mode"
            ;;
        3)
            configure_claude_core "$use_lazy" "$skill_mode"
            ;;
        4)
            configure_cursor_core "$use_lazy"
            ;;
        5)
            export_manual_mcp_config
            ;;
        6)
            info "Skipped agent configuration."
            ;;
        *)
            warn "Invalid agent selection, skipping configuration."
            ;;
    esac

    if [[ "$bin_choice" =~ ^[Yy]$ ]]; then
        setup_terminal_shortcut
    fi

    echo ""
    success "Setup complete."
}

# =============================================================================
# 10. Main Menu
# =============================================================================
interactive_menu() {
    while true; do
        local update_badge=""
        if [[ -f "$PENDING_UPDATE_FILE" ]]; then
            local pending_tag
            pending_tag=$(cat "$PENDING_UPDATE_FILE" 2>/dev/null || true)
            [[ -n "$pending_tag" ]] && update_badge=" ${C_YELLOW}(${pending_tag} available)${C_RESET}"
        fi

        echo ""
        echo "1) Setup / Configure Agents (Interactive Wizard)"
        echo "2) Manual Setup (Export MCP Config Snippet)"
        echo -e "3) Check GitHub Update${update_badge}"
        echo "4) Toggle Test Suites (Exclude or Include)"
        echo "5) System & Agent Diagnostic"
        echo "6) Uninstall"
        echo "0) Exit"
        echo ""
        local main_choice=""
        if ! read -r -p "Select [0-6]: " main_choice; then
            echo ""
            exit 0
        fi

        case "$main_choice" in
            1)
                run_installation_wizard
                echo ""
                prompt_input "Press Enter to return..." "" unused
                ;;
            2)
                export_manual_mcp_config
                echo ""
                prompt_input "Press Enter to return..." "" unused
                ;;
            3)
                echo ""
                perform_update false
                echo ""
                prompt_input "Press Enter to return..." "" unused
                ;;
            4)
                echo ""
                echo -e "${C_BOLD}Toggle Test Suites & Fixtures:${C_RESET}"
                echo "  1) Exclude tests (sparse-checkout: saves disk & speeds up git pulls)"
                echo "  2) Include tests (full checkout: restores tests/ and .agents/)"
                local t_choice="1"
                prompt_input "Select [1-2]: " "1" t_choice
                if [[ "$t_choice" == "1" ]]; then
                    configure_test_suite_sparse false
                else
                    configure_test_suite_sparse true
                fi
                echo ""
                prompt_input "Press Enter to return..." "" unused
                ;;
            5)
                echo ""
                run_preflight_diagnostics true
                echo ""
                prompt_input "Press Enter to return..." "" unused
                ;;
            6)
                perform_uninstall
                echo ""
                prompt_input "Press Enter to return..." "" unused
                ;;
            0|q|Q)
                exit 0
                ;;
            *)
                warn "Invalid selection."
                sleep 1
                ;;
        esac
    done
}

# =============================================================================
# 11. Entrypoint
# =============================================================================
main() {
    if [[ "${1:-}" == "--mcp-proxy" ]]; then
        run_mcp_launcher
        exit 0
    fi

    if [[ "${1:-}" == "--check-update-silent" || "${1:-}" == "--update-silent" ]]; then
        check_update_silent
        exit 0
    fi

    print_banner

    # Pre-flight diagnostic layer: only notifies, never auto-installs
    if ! run_preflight_diagnostics true; then
        exit 1
    fi

    interactive_menu
}

main "$@"
