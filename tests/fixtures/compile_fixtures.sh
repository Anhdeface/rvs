#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

compile_target() {
    local src_file="$1"
    local base_name="$2"

    if [ ! -f "${src_file}" ]; then
        echo "Error: ${src_file} not found" >&2
        return 1
    fi

    echo "--- Compiling fixtures from ${src_file} ---"

    # 1. Standard ELF64 (no-pie, no-inline, no-stack-protector)
    if command -v gcc >/dev/null 2>&1; then
        echo "Building ${base_name}_elf64 (non-PIE)..."
        gcc -O0 -fno-inline -fno-stack-protector -no-pie "${src_file}" -o "${SCRIPT_DIR}/${base_name}_elf64"
        chmod +x "${SCRIPT_DIR}/${base_name}_elf64"

        echo "Building ${base_name}_elf64_pie..."
        gcc -O0 -fno-inline -fno-stack-protector "${src_file}" -o "${SCRIPT_DIR}/${base_name}_elf64_pie"
        chmod +x "${SCRIPT_DIR}/${base_name}_elf64_pie"
    fi

    # 2. Clang ELF64 if clang is installed
    if command -v clang >/dev/null 2>&1; then
        echo "Building ${base_name}_clang..."
        clang -O0 -fno-inline -fno-stack-protector "${src_file}" -o "${SCRIPT_DIR}/${base_name}_clang"
        chmod +x "${SCRIPT_DIR}/${base_name}_clang"
    fi
}

compile_target "${SCRIPT_DIR}/test_target.c" "test_target"
compile_target "${SCRIPT_DIR}/auth_gate.c" "auth_gate"
compile_target "${SCRIPT_DIR}/flow_calc.c" "flow_calc"

echo "Compilation complete. Fixtures created in ${SCRIPT_DIR}:"
ls -la "${SCRIPT_DIR}"/*_elf64 "${SCRIPT_DIR}"/*_pie "${SCRIPT_DIR}"/*_clang 2>/dev/null || true
