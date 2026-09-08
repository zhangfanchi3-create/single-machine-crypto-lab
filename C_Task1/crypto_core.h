#ifndef CRYPTO_CORE_H
#define CRYPTO_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CRYPTO_TEXT_MAX 1023U

typedef enum {
    CRYPTO_STATUS_OK = 0,
    CRYPTO_STATUS_INVALID_ARGUMENT = 1,
    CRYPTO_STATUS_INVALID_KEY = 2,
    CRYPTO_STATUS_INVALID_INPUT = 3,
    CRYPTO_STATUS_BUFFER_TOO_SMALL = 4,
    CRYPTO_STATUS_INTERNAL_ERROR = 5
} crypto_status;

typedef struct {
    uint64_t p;
    uint64_t q;
    uint64_t n;
    uint64_t phi;
    uint64_t e;
    uint64_t d;
} crypto_rsa_key;

typedef struct {
    uint64_t alice_public;
    uint64_t bob_public;
    uint64_t alice_shared;
    uint64_t bob_shared;
} crypto_dh_result;

const char *crypto_status_message(crypto_status status);

crypto_status crypto_caesar_text(const char *input, int shift, int decrypt,
                                  char *output, size_t output_capacity, size_t *output_length);
crypto_status crypto_vigenere_text(const char *input, const char *key, int decrypt,
                                    char *output, size_t output_capacity, size_t *output_length);
crypto_status crypto_playfair_text(const char *input, const char *key, int decrypt,
                                    char *output, size_t output_capacity, size_t *output_length);
crypto_status crypto_columnar_text(const char *input, const char *key, int decrypt,
                                    char *output, size_t output_capacity, size_t *output_length);

crypto_status crypto_rc4_bytes(const uint8_t *input, size_t input_length,
                               const uint8_t *key, size_t key_length,
                               uint8_t *output, size_t output_capacity, size_t *output_length);
crypto_status crypto_rc4_encrypt_text(const char *input, const char *key,
                                      char *hex_output, size_t output_capacity, size_t *output_length);
crypto_status crypto_rc4_decrypt_text(const char *hex_input, const char *key,
                                      char *output, size_t output_capacity, size_t *output_length);

crypto_status crypto_aes128_encrypt_text(const char *input, const char *key,
                                         char *hex_output, size_t output_capacity, size_t *output_length);
crypto_status crypto_aes128_decrypt_text(const char *hex_input, const char *key,
                                         char *output, size_t output_capacity, size_t *output_length);

crypto_status crypto_rsa_generate_key(crypto_rsa_key *key);
crypto_status crypto_rsa_encrypt_text(const char *input, const crypto_rsa_key *key,
                                      char *output, size_t output_capacity, size_t *output_length);
crypto_status crypto_rsa_decrypt_text(const char *input, const crypto_rsa_key *key,
                                      char *output, size_t output_capacity, size_t *output_length);

crypto_status crypto_md5_hex(const char *input, char *output,
                             size_t output_capacity, size_t *output_length);
crypto_status crypto_dh_calculate(uint64_t prime, uint64_t generator,
                                  uint64_t alice_private, uint64_t bob_private,
                                  crypto_dh_result *result);

#ifdef __cplusplus
}
#endif

#endif
