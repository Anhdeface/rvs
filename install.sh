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
OPENCODE_CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/opencode"

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

check_repo_sync_status() {
    cd -- "$REPO_DIR" || return 0

    if ! git rev-parse --is-inside-work-tree &>/dev/null; then
        return 0
    fi

    if ! git remote get-url origin &>/dev/null; then
        return 0
    fi

    local current_branch local_commit
    current_branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
    local_commit=$(git rev-parse HEAD 2>/dev/null || true)
    [[ -z "$local_commit" ]] && return 0

    # 1. Check remote branch status
    local remote_branch_commit=""
    if [[ "$current_branch" != "HEAD" ]]; then
        remote_branch_commit=$(run_with_timeout 4 git ls-remote origin "refs/heads/$current_branch" 2>/dev/null | awk '{print $1}')
    fi

    # 2. Check latest remote release tag
    local latest_tag tag_commit=""
    latest_tag=$(run_with_timeout 4 git ls-remote --tags --sort="v:refname" origin 2>/dev/null | grep -v '\^{}' | tail -n1 | sed 's/.*refs\/tags\///' || true)
    if [[ -n "$latest_tag" && "$latest_tag" =~ ^v?[0-9]+(\.[0-9]+)*([a-zA-Z0-9._-]+)?$ ]]; then
        tag_commit=$(run_with_timeout 4 git ls-remote --tags origin "refs/tags/$latest_tag*" 2>/dev/null | tail -n1 | awk '{print $1}')
    fi

    local is_synced=true
    local update_reason=""

    # Check if remote branch has new commits not contained in local
    if [[ -n "$remote_branch_commit" && "$remote_branch_commit" != "$local_commit" ]]; then
        if ! git merge-base --is-ancestor "$remote_branch_commit" "$local_commit" 2>/dev/null; then
            is_synced=false
            update_reason="Branch $current_branch updated"
        fi
    fi

    # Check if remote has a release tag not contained in local
    if [[ -n "$tag_commit" && "$tag_commit" != "$local_commit" ]]; then
        if ! git merge-base --is-ancestor "$tag_commit" "$local_commit" 2>/dev/null; then
            is_synced=false
            update_reason="New release ${latest_tag}"
        fi
    fi

    mkdir -p -m 700 "$CACHE_DIR"
    if [[ "$is_synced" == false ]]; then
        local temp_pending="${PENDING_UPDATE_FILE}.tmp.$$"
        echo "${update_reason}" > "$temp_pending"
        mv -f "$temp_pending" "$PENDING_UPDATE_FILE"
        chmod 600 "$PENDING_UPDATE_FILE" 2>/dev/null || true
    else
        rm -f "$PENDING_UPDATE_FILE"
    fi
}

check_and_print_pending_notification() {
    # Check sync dynamically with rate-limit
    local now
    now=$(date +%s)
    local last=0
    [[ -f "$LAST_CHECK_FILE" ]] && last=$(cat "$LAST_CHECK_FILE" 2>/dev/null || echo 0)
    [[ "$last" =~ ^[0-9]+$ ]] || last=0

    if (( (now - last) >= 300 )) || [[ ! -f "$PENDING_UPDATE_FILE" ]]; then
        mkdir -p "$CACHE_DIR"
        echo "$now" > "$LAST_CHECK_FILE"
        check_repo_sync_status
    fi

    if [[ -f "$PENDING_UPDATE_FILE" ]]; then
        local pending_msg
        pending_msg=$(cat "$PENDING_UPDATE_FILE" 2>/dev/null || true)
        if [[ -n "$pending_msg" ]]; then
            echo -e "${C_YELLOW}${pending_msg}${C_RESET}"
            echo "  Choose option 4 to review and sync."
            echo -e "${C_DIM}------------------------------------------------------------${C_RESET}"
        fi
    fi
}

print_banner() {
    echo -e "${C_BOLD}rvs — AI Agent Setup & Sync${C_RESET}"
    echo -e "${C_DIM}------------------------------------------------------------${C_RESET}"
    check_and_print_pending_notification
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

# Set AG_* flags once; shared by diagnostics and the setup wizard.
detect_agents() {
    AG_ANTIGRAVITY=false
    AG_CLAUDE=false
    AG_CURSOR=false
    AG_OPENCODE=false

    [[ -d "$HOME/.gemini" ]] && AG_ANTIGRAVITY=true
    (command -v claude &>/dev/null || [[ -d "$HOME/.config/Claude" || -d "$HOME/Library/Application Support/Claude" ]]) && AG_CLAUDE=true
    ([[ -d "$HOME/.cursor" || -d "$HOME/Library/Application Support/Cursor" || -d "$HOME/.config/Cursor" ]]) && AG_CURSOR=true
    (command -v opencode &>/dev/null || [[ -d "$OPENCODE_CONFIG_DIR" ]]) && AG_OPENCODE=true
    return 0
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
    local py_status="${C_RED}missing${C_RESET}"
    if command -v python3 &>/dev/null; then
        local py_ver
        py_ver=$(python3 -c 'import sys; print(f"v{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")' 2>/dev/null || echo "detected")
        if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
            py_status="${C_GREEN}OK${C_RESET} ($py_ver)"
        else
            py_status="${C_YELLOW}outdated${C_RESET} ($py_ver, need >= 3.9)"
            missing_required+=("python3")
            has_errors=true
        fi
    else
        missing_required+=("python3")
        has_errors=true
    fi

    # 2. radare2 (r2) Check
    local r2_status="${C_YELLOW}not found${C_RESET}"
    if command -v radare2 &>/dev/null; then
        local r2_ver
        r2_ver=$(radare2 -v 2>/dev/null | head -n1 | awk '{print $2}' || echo "detected")
        r2_status="${C_GREEN}OK${C_RESET} (v$r2_ver)"
    else
        missing_warnings+=("radare2 is missing; static/ESIL analysis will be limited.")
    fi

    # 3. Core CLI tools (git, jq)
    local git_status="${C_RED}missing${C_RESET}"
    if command -v git &>/dev/null; then
        git_status="${C_GREEN}OK${C_RESET}"
    else
        missing_required+=("git")
        has_errors=true
    fi

    local jq_status="${C_RED}missing${C_RESET}"
    if command -v jq &>/dev/null; then
        jq_status="${C_GREEN}OK${C_RESET}"
    else
        missing_required+=("jq")
        has_errors=true
    fi

    # 4. Cargo (Optional, for building from source)
    local cargo_status="${C_DIM}not found${C_RESET}"
    if command -v cargo &>/dev/null; then
        local cargo_ver
        cargo_ver=$(cargo --version 2>/dev/null | awk '{print $2}' || echo "detected")
        cargo_status="${C_GREEN}OK${C_RESET} ($cargo_ver)"
    fi

    # 5. rvs CLI Shortcut & Symlink Diagnostic
    local rvs_cli_status="${C_DIM}not installed${C_RESET}"
    if [[ -L "$HOME/.local/bin/rvs" ]]; then
        local link_dest
        link_dest="$(readlink "$HOME/.local/bin/rvs" 2>/dev/null || echo "symlink")"
        rvs_cli_status="${C_GREEN}OK${C_RESET} (symlink -> $link_dest)"
    elif [[ -e "$HOME/.local/bin/rvs" ]]; then
        rvs_cli_status="${C_YELLOW}static binary (symlink recommended)${C_RESET}"
        missing_warnings+=("$HOME/.local/bin/rvs is not a symlink; re-link it to $RVS_BIN.")
    fi

    # 6. Agent Detection
    detect_agents

    # Display Diagnostic Table
    if [[ "$show_summary" == true || "$has_errors" == true ]]; then
        echo -e "${C_BOLD}Environment${C_RESET}"
        echo -e "  User      : ${C_CYAN}${USER:-$(whoami)}${C_RESET}"
        echo -e "  Repo      : ${C_CYAN}$REPO_DIR${C_RESET}"
        echo -e "  rvs CLI   : $rvs_cli_status"
        echo -e "  Python 3  : $py_status"
        echo -e "  radare2   : $r2_status"
        echo -e "  Git       : $git_status"
        echo -e "  jq        : $jq_status"
        echo -e "  Cargo     : $cargo_status"
        echo ""
        echo -e "${C_BOLD}Agents${C_RESET}"
        echo -e "  Antigravity : $([[ "$AG_ANTIGRAVITY" == true ]] && echo "${C_GREEN}yes${C_RESET}" || echo "${C_DIM}no${C_RESET}")"
        echo -e "  Claude      : $([[ "$AG_CLAUDE" == true ]] && echo "${C_GREEN}yes${C_RESET}" || echo "${C_DIM}no${C_RESET}")"
        echo -e "  Cursor      : $([[ "$AG_CURSOR" == true ]] && echo "${C_GREEN}yes${C_RESET}" || echo "${C_DIM}no${C_RESET}")"
        echo -e "  OpenCode    : $([[ "$AG_OPENCODE" == true ]] && echo "${C_GREEN}yes${C_RESET}" || echo "${C_DIM}no${C_RESET}")"
        echo -e "${C_DIM}------------------------------------------------------------${C_RESET}"

        if [[ ${#missing_required[@]} -gt 0 ]]; then
            echo ""
            error "Missing required dependencies: ${missing_required[*]}"
            echo "Install them with your package manager:"
            echo "  Debian/Ubuntu : sudo apt install ${missing_required[*]}"
            echo "  macOS         : brew install ${missing_required[*]}"
            echo "  Arch Linux    : sudo pacman -S ${missing_required[*]}"
            echo ""
            return 1
        fi

        if [[ ${#missing_warnings[@]} -gt 0 ]]; then
            warn "${missing_warnings[*]}"
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

    log "Downloading pre-built binary ($os_arch)..."
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
                error "Checksum mismatch for $download_url"
                rm -f "$temp_bin"
                return 1
            fi
            info "Checksum verified."
        fi

        mv -f "$temp_bin" "$RVS_BIN"
        chmod 755 "$RVS_BIN"
        success "Binary downloaded: $RVS_BIN"
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
        warn "Pre-built binary unavailable and Cargo is not installed. Skipping build."
        return 0
    fi

    log "Building rvs with cargo..."
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

ensure_rvs_cli_setup() {
    local interactive="${1:-true}"
    local rvs_target="$HOME/.local/bin/rvs"

    if [[ -L "$rvs_target" ]]; then
        local link_dest
        link_dest="$(readlink "$rvs_target" 2>/dev/null || echo "target/release/rvs")"
        info "rvs CLI already linked ($rvs_target -> $link_dest)."
        if [[ ! -f "$RVS_BIN" ]]; then
            log "Local binary missing. Fetching or building..."
            build_rvs_binary
        fi
        return 0
    elif [[ -e "$rvs_target" ]]; then
        echo ""
        warn "$rvs_target is a static binary, not a symlink."
        echo "  Re-link it to $RVS_BIN so updates apply automatically."
        if [[ "$interactive" == true ]]; then
            local fix_sym="Y"
            prompt_input "  Convert to symlink? [Y/n]: " "Y" fix_sym
            if [[ "$fix_sym" =~ ^[Yy]$ ]]; then
                [[ ! -f "$RVS_BIN" ]] && build_rvs_binary
                mkdir -p "$HOME/.local/bin"
                ln -sfn "$RVS_BIN" "$rvs_target"
                success "Linked: $rvs_target -> $RVS_BIN"
            else
                info "Keeping the existing binary."
            fi
        fi
        return 0
    else
        # Not installed yet: ask for the first time
        echo ""
        log "rvs CLI is not installed."
        if [[ "$interactive" == true ]]; then
            local install_cli="Y"
            prompt_input "Install rvs CLI at ~/.local/bin/rvs? [Y/n]: " "Y" install_cli
            if [[ "$install_cli" =~ ^[Yy]$ ]]; then
                [[ ! -f "$RVS_BIN" ]] && build_rvs_binary
                setup_terminal_shortcut
            else
                info "Skipped CLI setup."
            fi
        fi
        return 0
    fi
}

manage_rvs_cli_menu() {
    while true; do
        echo ""
        echo -e "${C_BOLD}rvs CLI${C_RESET}"
        echo "  Binary : $RVS_BIN ($([[ -f "$RVS_BIN" ]] && echo "${C_GREEN}ready${C_RESET}" || echo "${C_YELLOW}missing${C_RESET}"))"
        local link_info="${C_DIM}not installed${C_RESET}"
        if [[ -L "$HOME/.local/bin/rvs" ]]; then
            link_info="${C_GREEN}-> $(readlink "$HOME/.local/bin/rvs")${C_RESET}"
        elif [[ -e "$HOME/.local/bin/rvs" ]]; then
            link_info="${C_YELLOW}static file${C_RESET}"
        fi
        echo -e "  CLI    : $HOME/.local/bin/rvs ($link_info)"
        echo ""
        echo "  1) Rebuild binary"
        echo "  2) Create/update symlink"
        echo "  3) Show version"
        echo "  0) Back"
        echo ""
        local cli_choice=""
        if ! read -r -p "Select [0-3]: " cli_choice; then
            echo ""
            return 0
        fi

        case "$cli_choice" in
            1)
                build_rvs_binary
                setup_terminal_shortcut
                echo ""
                prompt_input "Press Enter to return..." "" unused
                ;;
            2)
                [[ ! -f "$RVS_BIN" ]] && build_rvs_binary
                setup_terminal_shortcut
                echo ""
                prompt_input "Press Enter to return..." "" unused
                ;;
            3)
                if command -v rvs &>/dev/null; then
                    success "System CLI: $(rvs --version)"
                elif [[ -f "$RVS_BIN" ]]; then
                    success "Local Binary: $("$RVS_BIN" --version)"
                else
                    warn "rvs is not found in PATH or target/release/rvs."
                fi
                echo ""
                prompt_input "Press Enter to return..." "" unused
                ;;
            0|q|Q)
                return 0
                ;;
            *)
                warn "Invalid selection."
                sleep 1
                ;;
        esac
    done
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
        log "Excluding tests..."
        if git sparse-checkout set --no-cone '/*' '!/tests' '!/.agents' 2>/dev/null; then
            success "Tests excluded."
        else
            rm -rf "$REPO_DIR/tests" "$REPO_DIR/.agents"
            info "Removed local test folders."
        fi
    else
        log "Restoring tests..."
        git sparse-checkout disable 2>/dev/null || true
        success "Tests included."
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
    echo -e "${C_BOLD}Manual MCP config${C_RESET} (saved to $MANUAL_CONFIG_FILE)"
    echo -e "${C_DIM}Repo: $REPO_DIR${C_RESET}"
    echo ""
    echo -e "${C_CYAN}$(cat "$MANUAL_CONFIG_FILE")${C_RESET}"
    echo ""
    echo "Add this block to:"
    echo "  Antigravity    : ~/.gemini/config/mcp_config.json"
    echo "  Claude Desktop : ~/.config/Claude/claude_desktop_config.json"
    echo "  Claude Code    : claude mcp add rvs -- python3 \"$HARNESS_PATH\" --mcp"
    echo "  Cursor         : ~/.cursor/mcp.json"
    echo "  OpenCode       : opencode mcp add rvs --global -- python3 \"$HARNESS_PATH\" --mcp"
    echo ""
    echo "Skill: copy or link $SKILL_SRC"
    echo ""
    info "Manual setup does not enable background update checks."
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

export_antigravity_tools() {
    local schemas_dir="$HOME/.gemini/antigravity-cli/mcp/rvs"
    mkdir -p "$schemas_dir"

    local tools_json
    tools_json=$(python3 "$HARNESS_PATH" --export-tools mcp 2>/dev/null) || return 0
    echo "$tools_json" | jq -c '.[] | {name, description, parameters: .inputSchema}' | while read -r tool; do
        local tool_name
        tool_name=$(echo "$tool" | jq -r .name)
        echo "$tool" > "$schemas_dir/${tool_name}.json"
    done
}

configure_antigravity_core() {
    local use_lazy="$1"
    local skill_mode="$2"

    local cmd args_json
    { read -r cmd; read -r args_json; } < <(get_mcp_cmd_and_args "$use_lazy")

    local config_file="$HOME/.gemini/config/mcp_config.json"
    safe_merge_mcp_config "$config_file" "$cmd" "$args_json"
    export_antigravity_tools

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

configure_opencode_core() {
    local use_lazy="$1"
    local skill_mode="$2"
    local mcp_configured=false

    if command -v opencode &>/dev/null; then
        local -a mcp_command
        if [[ "$use_lazy" == true ]]; then
            mcp_command=("$REPO_DIR/install.sh" "--mcp-proxy")
        else
            mcp_command=(python3 "$HARNESS_PATH" "--mcp")
        fi

        if opencode mcp add rvs --global -- "${mcp_command[@]}" >/dev/null; then
            mcp_configured=true
        else
            warn "Failed to configure the OpenCode MCP server."
        fi
    else
        warn "OpenCode CLI not found. Skipping MCP configuration."
    fi

    attach_skill_to_dir "$OPENCODE_CONFIG_DIR/skills/rvs" "OpenCode" "$skill_mode"
    if [[ "$mcp_configured" == true ]]; then
        success "OpenCode configured."
    else
        success "OpenCode skill attached."
    fi
}

# OpenCode V2 has no MCP remove command, so remove the global entry directly.
remove_opencode_mcp_server() {
    local config_file="$1"
    [[ -f "$config_file" ]] || return 0

    local temp_config="${config_file}.tmp.$$"

    # Keep JSONC comments/trailing commas by removing only the multiline rvs block.
    if [[ "$config_file" == *.jsonc ]]; then
        local removing=false
        local removed=false
        local entry_indent=""
        local in_servers=false
        local servers_indent=""
        local line=""
        local servers_pattern='^([[:space:]]*)"servers"[[:space:]]*:[[:space:]]*\{'
        local rvs_pattern='^([[:space:]]*)"rvs"[[:space:]]*:[[:space:]]*\{'
        local close_pattern='^([[:space:]]*)\}[[:space:]]*,?[[:space:]]*(//.*)?$'

        while IFS= read -r line || [[ -n "$line" ]]; do
            if [[ "$in_servers" == false && "$line" =~ $servers_pattern ]]; then
                in_servers=true
                servers_indent="${BASH_REMATCH[1]}"
            elif [[ "$in_servers" == true && "$line" =~ $close_pattern ]]; then
                [[ "${BASH_REMATCH[1]}" == "$servers_indent" ]] && in_servers=false
            fi

            if [[ "$removing" == false && "$in_servers" == true && "$line" =~ $rvs_pattern ]]; then
                removing=true
                removed=true
                entry_indent="${BASH_REMATCH[1]}"
                continue
            fi

            if [[ "$removing" == true ]]; then
                if [[ "$line" =~ $close_pattern ]]; then
                    [[ "${BASH_REMATCH[1]}" == "$entry_indent" ]] && removing=false
                fi
                continue
            fi

            printf '%s\n' "$line"
        done < "$config_file" > "$temp_config"

        if [[ "$removed" == true && "$removing" == false ]]; then
            mv -f "$temp_config" "$config_file"
        else
            rm -f "$temp_config"
        fi
    elif jq 'del(.mcp.servers.rvs)' "$config_file" > "$temp_config" 2>/dev/null; then
        mv -f "$temp_config" "$config_file"
    else
        rm -f "$temp_config"
    fi
}

# =============================================================================
# 7. GitHub Repository Sync & On-Demand Upgrade
# =============================================================================
check_update_silent() {
    check_repo_sync_status
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

    [[ "$silent" == false ]] && log "Checking repository sync with GitHub..."

    check_repo_sync_status

    local current_commit head_tag current_branch
    current_commit=$(git rev-parse HEAD 2>/dev/null || true)
    head_tag=$(git describe --tags --exact-match 2>/dev/null || true)
    current_branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")

    if [[ -f "$PENDING_UPDATE_FILE" ]]; then
        local pending_msg
        pending_msg=$(cat "$PENDING_UPDATE_FILE" 2>/dev/null || true)
        if [[ "$silent" == false ]]; then
            echo -e "  Current : ${head_tag:-${current_branch} @ ${current_commit:0:7}}"
            echo -e "  Status  : ${C_YELLOW}${pending_msg} available on GitHub${C_RESET}"
            local do_up="Y"
            prompt_input "Synchronize / pull updates from GitHub? [Y/n]: " "Y" do_up
            if [[ ! "$do_up" =~ ^[Yy]$ ]]; then
                info "Canceled."
                return 0
            fi
        fi

        [[ "$silent" == false ]] && log "Pulling updates..."
        if [[ "$current_branch" != "HEAD" ]]; then
            git pull origin "$current_branch" -q 2>/dev/null || git fetch --tags origin -q 2>/dev/null || return 0
        else
            git fetch --tags origin -q 2>/dev/null || return 0
        fi

        build_rvs_binary
        [[ -d "$HOME/.gemini/antigravity-cli/mcp/rvs" ]] && export_antigravity_tools

        rm -f "$PENDING_UPDATE_FILE"
        [[ "$silent" == false ]] && success "Updated."
    else
        rm -f "$PENDING_UPDATE_FILE"
        [[ "$silent" == false ]] && success "Up to date (${head_tag:-${current_branch} @ ${current_commit:0:7}})."
    fi
}

# =============================================================================
# 8. Clean Uninstall
# =============================================================================
remove_legacy_mcp_entry() {
    local config_file="$1"
    [[ -f "$config_file" ]] || return 0

    local temp_config="${config_file}.tmp.$$"
    if jq 'del(.mcpServers.rvs)' "$config_file" > "$temp_config" 2>/dev/null; then
        mv -f "$temp_config" "$config_file"
    else
        rm -f "$temp_config"
    fi
}

perform_uninstall() {
    echo ""
    echo -e "${C_YELLOW}Remove rvs MCP entries and skills from all agents?${C_RESET}"
    local confirm="N"
    prompt_input "Proceed? [y/N]: " "N" confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        info "Canceled."
        return 0
    fi

    local gemini_cfg="$HOME/.gemini/config/mcp_config.json"
    remove_legacy_mcp_entry "$gemini_cfg"
    rm -rf "$HOME/.gemini/antigravity-cli/mcp/rvs" "$HOME/.gemini/config/skills/rvs"

    local claude_cfg="$HOME/.config/Claude/claude_desktop_config.json"
    [[ "$(uname -s)" == "Darwin" ]] && claude_cfg="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
    remove_legacy_mcp_entry "$claude_cfg"
    command -v claude &>/dev/null && claude mcp remove rvs -s user &>/dev/null || true
    rm -rf "$HOME/.claude/skills/rvs"

    remove_legacy_mcp_entry "$HOME/.cursor/mcp.json"

    remove_opencode_mcp_server "$OPENCODE_CONFIG_DIR/opencode.json"
    remove_opencode_mcp_server "$OPENCODE_CONFIG_DIR/opencode.jsonc"
    rm -rf "$OPENCODE_CONFIG_DIR/skills/rvs"

    rm -f "$HOME/.local/bin/rvs" "$MANUAL_CONFIG_FILE"
    rm -rf "$CACHE_DIR"

    success "rvs removed."
}

# =============================================================================
# 9. Interactive Setup Wizard (Agent MCP & Skills Configuration)
# =============================================================================
run_installation_wizard() {
    # 1. Automatic rvs CLI verification (silent if symlink exists; warning if static binary; prompt if first time)
    ensure_rvs_cli_setup true

    # Step 1: Target Agents
    echo ""
    echo -e "${C_BOLD}[1/3] Agents${C_RESET}"
    echo "  1) All detected"
    echo "  2) Antigravity"
    echo "  3) Claude"
    echo "  4) Cursor"
    echo "  5) OpenCode"
    echo "  6) Manual config only"
    echo "  7) Skip"
    local agent_choice="1"
    prompt_input "  Select [1-7] (default: 1): " "1" agent_choice

    # Step 2: Skill Linking Method (if not manual or skip)
    local skill_mode="symlink"
    if [[ "$agent_choice" =~ ^[1-5]$ ]]; then
        echo ""
        echo -e "${C_BOLD}[2/3] Skill install${C_RESET}"
        echo "  1) Symlink (recommended)"
        echo "  2) Copy"
        local skill_choice="1"
        prompt_input "  Select [1-2] (default: 1): " "1" skill_choice
        [[ "$skill_choice" == "2" ]] && skill_mode="copy"
    fi

    # Step 3: Background Update Check
    local use_lazy=false
    if [[ "$agent_choice" =~ ^[1-5]$ ]]; then
        echo ""
        echo -e "${C_BOLD}[3/3] Update check${C_RESET}"
        echo "  Check GitHub once per day in the background (notify only)."
        local lazy_choice="Y"
        prompt_input "  Enable? [Y/n]: " "Y" lazy_choice
        [[ "$lazy_choice" =~ ^[Yy]$ ]] && use_lazy=true
    fi

    local agent_label="Unknown"
    case "$agent_choice" in
        1) agent_label="All detected" ;;
        2) agent_label="Antigravity" ;;
        3) agent_label="Claude" ;;
        4) agent_label="Cursor" ;;
        5) agent_label="OpenCode" ;;
        6) agent_label="Manual config" ;;
        7) agent_label="Skip" ;;
    esac

    # Summary
    echo ""
    echo -e "${C_DIM}------------------------------------------------------------${C_RESET}"
    echo "Summary"
    echo "  Agents : $agent_label"
    if [[ "$agent_choice" =~ ^[1-5]$ ]]; then
        echo "  Skill  : $skill_mode"
        echo "  Updates: $([ "$use_lazy" == true ] && echo "on" || echo "off")"
    fi
    echo -e "${C_DIM}------------------------------------------------------------${C_RESET}"

    local confirm_apply="Y"
    prompt_input "Apply changes? [Y/n]: " "Y" confirm_apply
    if [[ ! "$confirm_apply" =~ ^[Yy]$ ]]; then
        info "Aborted."
        return 0
    fi

    echo ""
    detect_agents

    case "$agent_choice" in
        1)
            [[ "$AG_ANTIGRAVITY" == true ]] && configure_antigravity_core "$use_lazy" "$skill_mode"
            [[ "$AG_CLAUDE" == true ]] && configure_claude_core "$use_lazy" "$skill_mode"
            [[ "$AG_CURSOR" == true ]] && configure_cursor_core "$use_lazy"
            [[ "$AG_OPENCODE" == true ]] && configure_opencode_core "$use_lazy" "$skill_mode"
            if [[ "$AG_ANTIGRAVITY" == false && "$AG_CLAUDE" == false && "$AG_CURSOR" == false && "$AG_OPENCODE" == false ]]; then
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
            configure_opencode_core "$use_lazy" "$skill_mode"
            ;;
        6)
            export_manual_mcp_config
            ;;
        7)
            info "Skipped agent configuration."
            ;;
        *)
            warn "Invalid selection."
            ;;
    esac

    echo ""
    success "Setup complete."
    exit 0
}

# =============================================================================
# 10. Main Menu
# =============================================================================
interactive_menu() {
    while true; do
        local update_badge=""
        if [[ -f "$PENDING_UPDATE_FILE" ]]; then
            update_badge=" ${C_YELLOW}(update)${C_RESET}"
        fi

        echo ""
        echo "1) Setup agents"
        echo "2) Manage rvs CLI"
        echo "3) Export manual config"
        echo -e "4) Check for updates${update_badge}"
        echo "5) Test suites"
        echo "6) Diagnostics"
        echo "7) Uninstall"
        echo "0) Exit"
        echo ""
        local main_choice=""
        if ! read -r -p "Select [0-7]: " main_choice; then
            echo ""
            exit 0
        fi

        case "$main_choice" in
            1)
                run_installation_wizard
                exit 0
                ;;
            2)
                manage_rvs_cli_menu
                ;;
            3)
                export_manual_mcp_config
                echo ""
                prompt_input "Press Enter to return..." "" unused
                ;;
            4)
                echo ""
                perform_update false
                echo ""
                prompt_input "Press Enter to return..." "" unused
                ;;
            5)
                echo ""
                echo -e "${C_BOLD}Tests${C_RESET}"
                echo "  1) Exclude (saves disk)"
                echo "  2) Include (restore tests/ and .agents/)"
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
            6)
                echo ""
                run_preflight_diagnostics true
                echo ""
                prompt_input "Press Enter to return..." "" unused
                ;;
            7)
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
