#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/**
 * Function 1: Returns a static string banner.
 * Analysis goal: Proves function detection, prologue/epilogue, string xrefs.
 * Patching goal: String patch alters output from "LOCKED" to "ACTIVE".
 */
const char *get_system_banner(void) {
    return "STATUS_SYSTEM_LOCKED";
}

/**
 * Function 2: Evaluates an authorization integer code.
 * Analysis goal: Proves basic block branching (cmp, jne) and CFG analysis.
 * Patching goal: Patching instruction or jump bypasses code check.
 */
int check_auth_token(int token) {
    if (token == 1337) {
        return 1;
    }
    return 0;
}

/**
 * Function 3: Validates a license key string.
 * Analysis goal: Proves callgraph dependency (calls strcmp) and string xrefs.
 * Patching goal: Patching string or strcmp return allows custom key acceptance.
 */
int validate_license_key(const char *key) {
    if (strcmp(key, "MASTER-PASS-2026") == 0) {
        return 100;
    }
    return -1;
}

/**
 * Function 4: Compute a cryptographic transform or flag.
 * Analysis goal: Arithmetic instructions, basic block loops.
 * Patching goal: Modifying return register value or branch condition.
 */
int compute_feature_flag(int a, int b) {
    int sum = a + b;
    if (sum > 50) {
        return 1;
    }
    return 0;
}

/**
 * Main Entry:
 * Orchestrates calls and returns:
 * - Exit code 0 if ALL checks pass.
 * - Exit code 10 if Auth Token check fails.
 * - Exit code 20 if License Key check fails.
 * - Exit code 30 if Feature Flag check fails.
 */
int main(int argc, char **argv) {
    printf("Banner: %s\n", get_system_banner());

    // Step 1: Check Auth Token (Default input: 0 -> Fails in unpatched state)
    int auth_status = check_auth_token(0);
    printf("Auth Status: %d\n", auth_status);
    if (auth_status != 1) {
        printf("FAILED: Authentication Failed\n");
        return 10;
    }

    // Step 2: Validate License Key (Default input: "DEFAULT_USER_KEY" -> Fails in unpatched state)
    const char *key_input = (argc > 1) ? argv[1] : "DEFAULT_USER_KEY";
    int lic_status = validate_license_key(key_input);
    printf("License Status: %d\n", lic_status);
    if (lic_status != 100) {
        printf("FAILED: Invalid License\n");
        return 20;
    }

    // Step 3: Feature flag check (Inputs: 10, 20 -> sum 30 <= 50 -> Fails in unpatched state)
    int feat_status = compute_feature_flag(10, 20);
    printf("Feature Status: %d\n", feat_status);
    if (feat_status != 1) {
        printf("FAILED: Feature Disabled\n");
        return 30;
    }

    printf("SUCCESS: All security gates unlocked\n");
    return 0;
}
