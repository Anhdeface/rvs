#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAYLOAD_LEN 49
#define XOR_KEY 0x5A

/*
 * Plaintext: "FLAG{rvs_dynamic_decryptor_buffer_extracted_2026}"
 * XOR-encrypted with key 0x5A
 */
static const unsigned char g_encrypted_payload[PAYLOAD_LEN] = {
    0x1C, 0x16, 0x1B, 0x1D, 0x21, 0x28, 0x2C, 0x29,
    0x05, 0x3E, 0x23, 0x34, 0x3B, 0x37, 0x33, 0x39,
    0x05, 0x3E, 0x3F, 0x39, 0x28, 0x23, 0x2A, 0x2E,
    0x35, 0x28, 0x05, 0x38, 0x2F, 0x3C, 0x3C, 0x3F,
    0x28, 0x05, 0x3F, 0x22, 0x2E, 0x28, 0x3B, 0x39,
    0x2E, 0x3F, 0x3E, 0x05, 0x68, 0x6A, 0x68, 0x6C,
    0x27
};

/* Global buffer to hold the decrypted secret in live memory */
unsigned char g_decrypted_buffer[PAYLOAD_LEN + 1];

__attribute__((noinline))
void on_decryption_complete(const unsigned char *buffer, size_t len) {
    /* Breakpoint hook target: buffer is fully decrypted in memory here */
    printf("[decryptor_target] Decryption complete: %s\n", (const char *)buffer);
}

__attribute__((noinline))
void decrypt_buffer(const unsigned char *src, unsigned char *dst, size_t len, unsigned char key) {
    printf("[decryptor_target] Starting XOR decryption loop (len=%zu, key=0x%02X)...\n", len, key);
    for (size_t i = 0; i < len; i++) {
        dst[i] = src[i] ^ key;
    }
    dst[len] = '\0';
    on_decryption_complete(dst, len);
}

int main(int argc, char **argv) {
    printf("[decryptor_target] Process started. Initializing memory buffers...\n");
    memset(g_decrypted_buffer, 0, sizeof(g_decrypted_buffer));

    decrypt_buffer(g_encrypted_payload, g_decrypted_buffer, PAYLOAD_LEN, XOR_KEY);

    printf("[decryptor_target] Final secret: %s\n", g_decrypted_buffer);
    return 0;
}
