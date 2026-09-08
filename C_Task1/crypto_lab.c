/*
 * Information Security Engineering Practice 2 - Task 1
 * Standalone encryption/decryption laboratory written in ISO C11.
 *
 * Algorithms: Caesar, Vigenere, Playfair, columnar transposition,
 * RC4, AES-128, RSA, MD5 and Diffie-Hellman.
 *
 * The short RSA keys, ECB mode and small DH parameters are for classroom
 * demonstration only. They must not be used to protect real information.
 */

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto_core.h"

#define MAX_TEXT 1024
#define MAX_HEX (MAX_TEXT * 2 + 64)
#define AES_BLOCK 16
#define AES_ROUND_KEY 176

#ifndef CRYPTO_CORE_ONLY
static void read_line(const char *prompt, char *buffer, size_t size) {
    size_t length;
    printf("%s", prompt);
    fflush(stdout);
    if (!fgets(buffer, (int)size, stdin)) {
        buffer[0] = '\0';
        return;
    }
    length = strlen(buffer);
    while (length > 0 && (buffer[length - 1] == '\n' || buffer[length - 1] == '\r')) {
        buffer[--length] = '\0';
    }
}

static void print_hex(const uint8_t *data, size_t length) {
    size_t i;
    for (i = 0; i < length; ++i) printf("%02X", data[i]);
}
#endif

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char *hex, uint8_t *output, size_t capacity, size_t *out_length) {
    size_t length = strlen(hex), i;
    if ((length & 1U) != 0 || length / 2 > capacity) return 0;
    for (i = 0; i < length; i += 2) {
        int high = hex_nibble(hex[i]);
        int low = hex_nibble(hex[i + 1]);
        if (high < 0 || low < 0) return 0;
        output[i / 2] = (uint8_t)((high << 4) | low);
    }
    *out_length = length / 2;
    return 1;
}

/* ---------- Caesar ---------- */

static void caesar_transform(const char *input, char *output, int shift) {
    size_t i;
    shift %= 26;
    if (shift < 0) shift += 26;
    for (i = 0; input[i] != '\0'; ++i) {
        unsigned char c = (unsigned char)input[i];
        if (c >= 'A' && c <= 'Z') output[i] = (char)('A' + (c - 'A' + shift) % 26);
        else if (c >= 'a' && c <= 'z') output[i] = (char)('a' + (c - 'a' + shift) % 26);
        else output[i] = (char)c;
    }
    output[i] = '\0';
}

/* ---------- Vigenere ---------- */

static int normalize_key(const char *raw, char *key, size_t capacity) {
    size_t i, count = 0;
    for (i = 0; raw[i] != '\0' && count + 1 < capacity; ++i) {
        if (isalpha((unsigned char)raw[i])) key[count++] = (char)toupper((unsigned char)raw[i]);
    }
    key[count] = '\0';
    return count > 0;
}

static int vigenere_transform(const char *input, const char *raw_key, char *output, int direction) {
    char key[128];
    size_t i, key_index = 0, key_length;
    if (!normalize_key(raw_key, key, sizeof(key))) return 0;
    key_length = strlen(key);
    for (i = 0; input[i] != '\0'; ++i) {
        unsigned char c = (unsigned char)input[i];
        if (isalpha(c)) {
            int base = isupper(c) ? 'A' : 'a';
            int delta = key[key_index++ % key_length] - 'A';
            int value = ((int)c - base + direction * delta) % 26;
            if (value < 0) value += 26;
            output[i] = (char)(base + value);
        } else output[i] = (char)c;
    }
    output[i] = '\0';
    return 1;
}

/* ---------- Playfair ---------- */

static size_t letters_only(const char *input, char *output, size_t capacity) {
    size_t i, count = 0;
    for (i = 0; input[i] != '\0' && count + 1 < capacity; ++i) {
        if (isalpha((unsigned char)input[i])) {
            char c = (char)toupper((unsigned char)input[i]);
            output[count++] = c == 'J' ? 'I' : c;
        }
    }
    output[count] = '\0';
    return count;
}

static int playfair_build_grid(const char *raw_key, char grid[25]) {
    char key[128];
    int used[26] = {0};
    size_t i, count = 0;
    letters_only(raw_key, key, sizeof(key));
    if (key[0] == '\0') return 0;
    used['J' - 'A'] = 1;
    for (i = 0; key[i] != '\0'; ++i) {
        int index = key[i] - 'A';
        if (!used[index]) {
            used[index] = 1;
            grid[count++] = key[i];
        }
    }
    for (i = 0; i < 26; ++i) {
        if (!used[i]) grid[count++] = (char)('A' + i);
    }
    return count == 25;
}

static int playfair_position(const char grid[25], char c) {
    int i;
    for (i = 0; i < 25; ++i) if (grid[i] == c) return i;
    return -1;
}

static size_t playfair_prepare_plaintext(const char *input, char *prepared, size_t capacity) {
    char letters[MAX_TEXT];
    size_t length = letters_only(input, letters, sizeof(letters));
    size_t i = 0, out = 0;
    while (i < length && out + 2 < capacity) {
        char first = letters[i++];
        char second;
        if (i >= length || letters[i] == first) second = 'X';
        else second = letters[i++];
        prepared[out++] = first;
        prepared[out++] = second;
    }
    prepared[out] = '\0';
    return out;
}

static int playfair_transform(const char *input, const char *key, char *output, int decrypt) {
    char grid[25], data[MAX_TEXT * 2];
    size_t length, i, out = 0;
    int step = decrypt ? -1 : 1;
    if (!playfair_build_grid(key, grid)) return 0;
    if (decrypt) {
        length = letters_only(input, data, sizeof(data));
        if ((length & 1U) != 0) return 0;
    } else length = playfair_prepare_plaintext(input, data, sizeof(data));
    for (i = 0; i < length; i += 2) {
        int a = playfair_position(grid, data[i]);
        int b = playfair_position(grid, data[i + 1]);
        int ar = a / 5, ac = a % 5, br = b / 5, bc = b % 5;
        if (a < 0 || b < 0) return 0;
        if (ar == br) {
            output[out++] = grid[ar * 5 + (ac + step + 5) % 5];
            output[out++] = grid[br * 5 + (bc + step + 5) % 5];
        } else if (ac == bc) {
            output[out++] = grid[((ar + step + 5) % 5) * 5 + ac];
            output[out++] = grid[((br + step + 5) % 5) * 5 + bc];
        } else {
            output[out++] = grid[ar * 5 + bc];
            output[out++] = grid[br * 5 + ac];
        }
    }
    output[out] = '\0';
    return 1;
}

/* ---------- Columnar transposition ---------- */

static int column_order(const char *key, size_t order[64], size_t *count) {
    size_t i, j, length = strlen(key);
    if (length < 2 || length > 64) return 0;
    for (i = 0; i < length; ++i) order[i] = i;
    for (i = 0; i + 1 < length; ++i) {
        for (j = i + 1; j < length; ++j) {
            unsigned char a = (unsigned char)key[order[i]];
            unsigned char b = (unsigned char)key[order[j]];
            if (a > b || (a == b && order[i] > order[j])) {
                size_t temp = order[i]; order[i] = order[j]; order[j] = temp;
            }
        }
    }
    *count = length;
    return 1;
}

static int columnar_encrypt(const char *input, const char *key, char *output) {
    size_t order[64], columns, rows, length = strlen(input), i, row, out = 0;
    if (!column_order(key, order, &columns)) return 0;
    rows = (length + columns - 1) / columns;
    for (i = 0; i < columns; ++i) {
        size_t column = order[i];
        for (row = 0; row < rows; ++row) {
            size_t position = row * columns + column;
            if (position < length) output[out++] = input[position];
        }
    }
    output[out] = '\0';
    return 1;
}

static int columnar_decrypt(const char *input, const char *key, char *output) {
    size_t order[64], offsets[64], lengths[64], columns, rows;
    size_t length = strlen(input), remainder, i, row, cursor = 0, out = 0;
    if (!column_order(key, order, &columns)) return 0;
    rows = (length + columns - 1) / columns;
    remainder = length % columns;
    for (i = 0; i < columns; ++i) lengths[i] = remainder == 0 ? rows : (i < remainder ? rows : rows - 1);
    for (i = 0; i < columns; ++i) {
        size_t column = order[i];
        offsets[column] = cursor;
        cursor += lengths[column];
    }
    for (row = 0; row < rows; ++row) {
        for (i = 0; i < columns; ++i) {
            if (row < lengths[i]) output[out++] = input[offsets[i] + row];
        }
    }
    output[out] = '\0';
    return 1;
}

/* ---------- RC4 ---------- */

static int rc4_crypt(const uint8_t *input, size_t length, const uint8_t *key,
                     size_t key_length, uint8_t *output) {
    uint8_t state[256];
    unsigned int i, j = 0;
    size_t position;
    if (key_length == 0) return 0;
    for (i = 0; i < 256; ++i) state[i] = (uint8_t)i;
    for (i = 0; i < 256; ++i) {
        uint8_t temp;
        j = (j + state[i] + key[i % key_length]) & 255U;
        temp = state[i]; state[i] = state[j]; state[j] = temp;
    }
    i = 0; j = 0;
    for (position = 0; position < length; ++position) {
        uint8_t temp, stream;
        i = (i + 1) & 255U;
        j = (j + state[i]) & 255U;
        temp = state[i]; state[i] = state[j]; state[j] = temp;
        stream = state[(state[i] + state[j]) & 255U];
        output[position] = input[position] ^ stream;
    }
    return 1;
}

/* ---------- AES-128 (classroom ECB wrapper) ---------- */

typedef uint8_t aes_state[4][4];

static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t rsbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8_t rcon[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ (((x >> 7) & 1U) * 0x1bU)); }

static uint8_t aes_multiply(uint8_t x, uint8_t y) {
    return (uint8_t)(((y & 1U) * x) ^ ((y >> 1 & 1U) * xtime(x)) ^
                     ((y >> 2 & 1U) * xtime(xtime(x))) ^
                     ((y >> 3 & 1U) * xtime(xtime(xtime(x)))) ^
                     ((y >> 4 & 1U) * xtime(xtime(xtime(xtime(x))))));
}

static void aes_key_expansion(uint8_t round_key[AES_ROUND_KEY], const uint8_t key[16]) {
    unsigned int i, j;
    uint8_t temp[4];
    for (i = 0; i < 16; ++i) round_key[i] = key[i];
    for (i = 4; i < 44; ++i) {
        for (j = 0; j < 4; ++j) temp[j] = round_key[(i - 1) * 4 + j];
        if (i % 4 == 0) {
            uint8_t first = temp[0];
            temp[0] = sbox[temp[1]] ^ rcon[i / 4];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[first];
        }
        for (j = 0; j < 4; ++j) round_key[i * 4 + j] = round_key[(i - 4) * 4 + j] ^ temp[j];
    }
}

static void aes_add_round_key(uint8_t round, aes_state *state, const uint8_t *round_key) {
    uint8_t column, row;
    for (column = 0; column < 4; ++column)
        for (row = 0; row < 4; ++row)
            (*state)[column][row] ^= round_key[round * 16 + column * 4 + row];
}

static void aes_sub_bytes(aes_state *state) {
    uint8_t column, row;
    for (column = 0; column < 4; ++column)
        for (row = 0; row < 4; ++row) (*state)[column][row] = sbox[(*state)[column][row]];
}

static void aes_inv_sub_bytes(aes_state *state) {
    uint8_t column, row;
    for (column = 0; column < 4; ++column)
        for (row = 0; row < 4; ++row) (*state)[column][row] = rsbox[(*state)[column][row]];
}

static void aes_shift_rows(aes_state *state) {
    uint8_t temp;
    temp = (*state)[0][1]; (*state)[0][1] = (*state)[1][1]; (*state)[1][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[3][1]; (*state)[3][1] = temp;
    temp = (*state)[0][2]; (*state)[0][2] = (*state)[2][2]; (*state)[2][2] = temp;
    temp = (*state)[1][2]; (*state)[1][2] = (*state)[3][2]; (*state)[3][2] = temp;
    temp = (*state)[3][3]; (*state)[3][3] = (*state)[2][3]; (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = (*state)[0][3]; (*state)[0][3] = temp;
}

static void aes_inv_shift_rows(aes_state *state) {
    uint8_t temp;
    temp = (*state)[3][1]; (*state)[3][1] = (*state)[2][1]; (*state)[2][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[0][1]; (*state)[0][1] = temp;
    temp = (*state)[0][2]; (*state)[0][2] = (*state)[2][2]; (*state)[2][2] = temp;
    temp = (*state)[1][2]; (*state)[1][2] = (*state)[3][2]; (*state)[3][2] = temp;
    temp = (*state)[0][3]; (*state)[0][3] = (*state)[1][3]; (*state)[1][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[3][3]; (*state)[3][3] = temp;
}

static void aes_mix_columns(aes_state *state) {
    uint8_t i;
    for (i = 0; i < 4; ++i) {
        uint8_t t = (*state)[i][0];
        uint8_t all = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
        uint8_t tmp = xtime((*state)[i][0] ^ (*state)[i][1]);
        (*state)[i][0] ^= tmp ^ all;
        tmp = xtime((*state)[i][1] ^ (*state)[i][2]); (*state)[i][1] ^= tmp ^ all;
        tmp = xtime((*state)[i][2] ^ (*state)[i][3]); (*state)[i][2] ^= tmp ^ all;
        tmp = xtime((*state)[i][3] ^ t); (*state)[i][3] ^= tmp ^ all;
    }
}

static void aes_inv_mix_columns(aes_state *state) {
    uint8_t i;
    for (i = 0; i < 4; ++i) {
        uint8_t a = (*state)[i][0], b = (*state)[i][1], c = (*state)[i][2], d = (*state)[i][3];
        (*state)[i][0] = aes_multiply(a,0x0e) ^ aes_multiply(b,0x0b) ^ aes_multiply(c,0x0d) ^ aes_multiply(d,0x09);
        (*state)[i][1] = aes_multiply(a,0x09) ^ aes_multiply(b,0x0e) ^ aes_multiply(c,0x0b) ^ aes_multiply(d,0x0d);
        (*state)[i][2] = aes_multiply(a,0x0d) ^ aes_multiply(b,0x09) ^ aes_multiply(c,0x0e) ^ aes_multiply(d,0x0b);
        (*state)[i][3] = aes_multiply(a,0x0b) ^ aes_multiply(b,0x0d) ^ aes_multiply(c,0x09) ^ aes_multiply(d,0x0e);
    }
}

static void aes_encrypt_block(uint8_t block[16], const uint8_t round_key[AES_ROUND_KEY]) {
    uint8_t round;
    aes_state *state = (aes_state *)block;
    aes_add_round_key(0, state, round_key);
    for (round = 1; round < 10; ++round) {
        aes_sub_bytes(state); aes_shift_rows(state); aes_mix_columns(state); aes_add_round_key(round, state, round_key);
    }
    aes_sub_bytes(state); aes_shift_rows(state); aes_add_round_key(10, state, round_key);
}

static void aes_decrypt_block(uint8_t block[16], const uint8_t round_key[AES_ROUND_KEY]) {
    int round;
    aes_state *state = (aes_state *)block;
    aes_add_round_key(10, state, round_key);
    for (round = 9; round > 0; --round) {
        aes_inv_shift_rows(state); aes_inv_sub_bytes(state); aes_add_round_key((uint8_t)round, state, round_key); aes_inv_mix_columns(state);
    }
    aes_inv_shift_rows(state); aes_inv_sub_bytes(state); aes_add_round_key(0, state, round_key);
}

static void aes_key_from_text(const char *text, uint8_t key[16]) {
    size_t length = strlen(text), i;
    for (i = 0; i < 16; ++i) key[i] = i < length ? (uint8_t)text[i] : 0;
}

static int aes_encrypt_text(const char *text, const char *key_text, char *hex, size_t capacity) {
    uint8_t data[MAX_TEXT + AES_BLOCK], key[16], round_key[AES_ROUND_KEY];
    size_t length = strlen(text), padded, i, out = 0;
    uint8_t padding;
    if (length >= MAX_TEXT || key_text[0] == '\0') return 0;
    padding = (uint8_t)(AES_BLOCK - length % AES_BLOCK);
    padded = length + padding;
    memcpy(data, text, length);
    for (i = length; i < padded; ++i) data[i] = padding;
    aes_key_from_text(key_text, key); aes_key_expansion(round_key, key);
    for (i = 0; i < padded; i += AES_BLOCK) aes_encrypt_block(data + i, round_key);
    if (padded * 2 + 1 > capacity) return 0;
    for (i = 0; i < padded; ++i) out += (size_t)sprintf(hex + out, "%02X", data[i]);
    return 1;
}

static int aes_decrypt_text(const char *hex, const char *key_text, char *text, size_t capacity) {
    uint8_t data[MAX_TEXT + AES_BLOCK], key[16], round_key[AES_ROUND_KEY], padding;
    size_t length, i, plain_length;
    if (key_text[0] == '\0' || !hex_to_bytes(hex, data, sizeof(data), &length) || length == 0 || length % AES_BLOCK != 0) return 0;
    aes_key_from_text(key_text, key); aes_key_expansion(round_key, key);
    for (i = 0; i < length; i += AES_BLOCK) aes_decrypt_block(data + i, round_key);
    padding = data[length - 1];
    if (padding == 0 || padding > AES_BLOCK || padding > length) return 0;
    for (i = length - padding; i < length; ++i) if (data[i] != padding) return 0;
    plain_length = length - padding;
    if (plain_length + 1 > capacity) return 0;
    memcpy(text, data, plain_length); text[plain_length] = '\0';
    return 1;
}

/* ---------- Safe 64-bit modular arithmetic ---------- */

static uint64_t add_mod(uint64_t a, uint64_t b, uint64_t modulus) {
    return a >= modulus - b ? a - (modulus - b) : a + b;
}

static uint64_t mul_mod(uint64_t a, uint64_t b, uint64_t modulus) {
    uint64_t result = 0;
    a %= modulus;
    while (b > 0) {
        if (b & 1U) result = add_mod(result, a, modulus);
        b >>= 1U;
        if (b > 0) a = add_mod(a, a, modulus);
    }
    return result;
}

static uint64_t mod_pow(uint64_t base, uint64_t exponent, uint64_t modulus) {
    uint64_t result = 1 % modulus;
    base %= modulus;
    while (exponent > 0) {
        if (exponent & 1U) result = mul_mod(result, base, modulus);
        exponent >>= 1U;
        if (exponent > 0) base = mul_mod(base, base, modulus);
    }
    return result;
}

static uint64_t gcd_u64(uint64_t a, uint64_t b) {
    while (b != 0) { uint64_t temp = a % b; a = b; b = temp; }
    return a;
}

static uint64_t mod_inverse(uint64_t a, uint64_t modulus) {
    int64_t t = 0, new_t = 1;
    int64_t r = (int64_t)modulus, new_r = (int64_t)a;
    while (new_r != 0) {
        int64_t quotient = r / new_r;
        int64_t temp_t = t - quotient * new_t;
        int64_t temp_r = r - quotient * new_r;
        t = new_t; new_t = temp_t; r = new_r; new_r = temp_r;
    }
    if (r != 1) return 0;
    if (t < 0) t += (int64_t)modulus;
    return (uint64_t)t;
}

/* ---------- RSA ---------- */

typedef crypto_rsa_key rsa_key;

static int is_probable_prime(uint64_t n) {
    static const uint64_t small[] = {2,3,5,7,11,13,17,19,23,29,31,37};
    static const uint64_t bases[] = {2,325,9375,28178,450775,9780504,1795265022};
    uint64_t d, x, a;
    unsigned int s = 0;
    size_t i, r;
    if (n < 2) return 0;
    for (i = 0; i < sizeof(small) / sizeof(small[0]); ++i) {
        if (n == small[i]) return 1;
        if (n % small[i] == 0) return 0;
    }
    d = n - 1;
    while ((d & 1U) == 0) { d >>= 1U; ++s; }
    for (i = 0; i < sizeof(bases) / sizeof(bases[0]); ++i) {
        a = bases[i] % n;
        if (a == 0) continue;
        x = mod_pow(a, d, n);
        if (x == 1 || x == n - 1) continue;
        for (r = 1; r < s; ++r) {
            x = mul_mod(x, x, n);
            if (x == n - 1) break;
        }
        if (r == s) return 0;
    }
    return 1;
}

static uint64_t random_u64(void) {
    uint64_t value = (uint64_t)(unsigned int)rand();
    value = (value << 21) ^ (uint64_t)(unsigned int)rand();
    value = (value << 21) ^ (uint64_t)(unsigned int)rand();
    return value;
}

static uint64_t generate_prime(void) {
    uint64_t candidate;
    do {
        candidate = (1ULL << 29) | (random_u64() & ((1ULL << 29) - 1)) | 1ULL;
    } while (!is_probable_prime(candidate));
    return candidate;
}

static int rsa_generate(rsa_key *key) {
    key->e = 65537;
    do {
        key->p = generate_prime();
        do key->q = generate_prime(); while (key->q == key->p);
        key->n = key->p * key->q;
        key->phi = (key->p - 1) * (key->q - 1);
    } while (gcd_u64(key->e, key->phi) != 1);
    key->d = mod_inverse(key->e, key->phi);
    return key->d != 0;
}

static void rsa_encrypt_bytes(const uint8_t *plain, size_t length, const rsa_key *key, uint64_t *cipher) {
    size_t i;
    for (i = 0; i < length; ++i) cipher[i] = mod_pow(plain[i], key->e, key->n);
}

#ifndef CRYPTO_CORE_ONLY
static void rsa_decrypt_bytes(const uint64_t *cipher, size_t length, const rsa_key *key, uint8_t *plain) {
    size_t i;
    for (i = 0; i < length; ++i) plain[i] = (uint8_t)mod_pow(cipher[i], key->d, key->n);
}
#endif

/* ---------- MD5 ---------- */

typedef struct {
    uint32_t state[4];
    uint64_t bit_length;
    uint8_t data[64];
    size_t data_length;
} md5_context;

static const uint32_t md5_k[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

static const uint32_t md5_s[64] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};

static uint32_t rotate_left(uint32_t value, uint32_t count) {
    return (value << count) | (value >> (32 - count));
}

static void md5_transform(md5_context *ctx, const uint8_t block[64]) {
    uint32_t words[16], a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t f, g, temp;
    size_t i;
    for (i = 0; i < 16; ++i) {
        words[i] = (uint32_t)block[i * 4] | ((uint32_t)block[i * 4 + 1] << 8) |
                   ((uint32_t)block[i * 4 + 2] << 16) | ((uint32_t)block[i * 4 + 3] << 24);
    }
    for (i = 0; i < 64; ++i) {
        if (i < 16) { f = (b & c) | ((~b) & d); g = (uint32_t)i; }
        else if (i < 32) { f = (d & b) | ((~d) & c); g = (uint32_t)((5 * i + 1) % 16); }
        else if (i < 48) { f = b ^ c ^ d; g = (uint32_t)((3 * i + 5) % 16); }
        else { f = c ^ (b | (~d)); g = (uint32_t)((7 * i) % 16); }
        temp = d; d = c; c = b;
        b = b + rotate_left(a + f + md5_k[i] + words[g], md5_s[i]); a = temp;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
}

static void md5_init(md5_context *ctx) {
    ctx->data_length = 0; ctx->bit_length = 0;
    ctx->state[0] = 0x67452301; ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe; ctx->state[3] = 0x10325476;
}

static void md5_update(md5_context *ctx, const uint8_t *data, size_t length) {
    size_t i;
    for (i = 0; i < length; ++i) {
        ctx->data[ctx->data_length++] = data[i];
        if (ctx->data_length == 64) {
            md5_transform(ctx, ctx->data);
            ctx->bit_length += 512;
            ctx->data_length = 0;
        }
    }
}

static void md5_final(md5_context *ctx, uint8_t digest[16]) {
    size_t i = ctx->data_length, j;
    ctx->data[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx->data[i++] = 0;
        md5_transform(ctx, ctx->data); i = 0;
    }
    while (i < 56) ctx->data[i++] = 0;
    ctx->bit_length += (uint64_t)ctx->data_length * 8;
    for (j = 0; j < 8; ++j) ctx->data[56 + j] = (uint8_t)(ctx->bit_length >> (8 * j));
    md5_transform(ctx, ctx->data);
    for (i = 0; i < 4; ++i) {
        digest[i * 4] = (uint8_t)(ctx->state[i]);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i] >> 24);
    }
}

static void md5_string(const char *text, uint8_t digest[16]) {
    md5_context ctx;
    md5_init(&ctx); md5_update(&ctx, (const uint8_t *)text, strlen(text)); md5_final(&ctx, digest);
}

static crypto_status copy_text_output(const char *source, char *output,
                                      size_t output_capacity, size_t *output_length) {
    size_t length = strlen(source);
    if (output_length) *output_length = length;
    if (!output || output_capacity <= length) return CRYPTO_STATUS_BUFFER_TOO_SMALL;
    memcpy(output, source, length + 1);
    return CRYPTO_STATUS_OK;
}

static int text_input_valid(const char *input) {
    return input && strlen(input) <= CRYPTO_TEXT_MAX;
}

const char *crypto_status_message(crypto_status status) {
    switch (status) {
        case CRYPTO_STATUS_OK: return "success";
        case CRYPTO_STATUS_INVALID_ARGUMENT: return "invalid argument";
        case CRYPTO_STATUS_INVALID_KEY: return "invalid key";
        case CRYPTO_STATUS_INVALID_INPUT: return "invalid input or ciphertext";
        case CRYPTO_STATUS_BUFFER_TOO_SMALL: return "output buffer is too small";
        case CRYPTO_STATUS_INTERNAL_ERROR: return "internal calculation failed";
        default: return "unknown error";
    }
}

crypto_status crypto_caesar_text(const char *input, int shift, int decrypt,
                                  char *output, size_t output_capacity, size_t *output_length) {
    char result[MAX_TEXT];
    int effective_shift;
    if (!text_input_valid(input)) return input ? CRYPTO_STATUS_INVALID_INPUT : CRYPTO_STATUS_INVALID_ARGUMENT;
    effective_shift = shift % 26;
    if (decrypt) effective_shift = -effective_shift;
    caesar_transform(input, result, effective_shift);
    return copy_text_output(result, output, output_capacity, output_length);
}

crypto_status crypto_vigenere_text(const char *input, const char *key, int decrypt,
                                    char *output, size_t output_capacity, size_t *output_length) {
    char result[MAX_TEXT];
    if (!input || !key) return CRYPTO_STATUS_INVALID_ARGUMENT;
    if (!text_input_valid(input)) return CRYPTO_STATUS_INVALID_INPUT;
    if (!vigenere_transform(input, key, result, decrypt ? -1 : 1)) return CRYPTO_STATUS_INVALID_KEY;
    return copy_text_output(result, output, output_capacity, output_length);
}

crypto_status crypto_playfair_text(const char *input, const char *key, int decrypt,
                                    char *output, size_t output_capacity, size_t *output_length) {
    char result[MAX_TEXT * 2];
    if (!input || !key) return CRYPTO_STATUS_INVALID_ARGUMENT;
    if (!text_input_valid(input)) return CRYPTO_STATUS_INVALID_INPUT;
    if (!playfair_transform(input, key, result, decrypt != 0)) {
        return key[0] == '\0' ? CRYPTO_STATUS_INVALID_KEY : CRYPTO_STATUS_INVALID_INPUT;
    }
    return copy_text_output(result, output, output_capacity, output_length);
}

crypto_status crypto_columnar_text(const char *input, const char *key, int decrypt,
                                    char *output, size_t output_capacity, size_t *output_length) {
    char result[MAX_TEXT];
    int ok;
    if (!input || !key) return CRYPTO_STATUS_INVALID_ARGUMENT;
    if (!text_input_valid(input)) return CRYPTO_STATUS_INVALID_INPUT;
    ok = decrypt ? columnar_decrypt(input, key, result) : columnar_encrypt(input, key, result);
    if (!ok) return CRYPTO_STATUS_INVALID_KEY;
    return copy_text_output(result, output, output_capacity, output_length);
}

crypto_status crypto_rc4_bytes(const uint8_t *input, size_t input_length,
                               const uint8_t *key, size_t key_length,
                               uint8_t *output, size_t output_capacity, size_t *output_length) {
    if (output_length) *output_length = input_length;
    if ((!input && input_length != 0) || !key) return CRYPTO_STATUS_INVALID_ARGUMENT;
    if (key_length == 0) return CRYPTO_STATUS_INVALID_KEY;
    if (!output || output_capacity < input_length) return CRYPTO_STATUS_BUFFER_TOO_SMALL;
    if (!rc4_crypt(input, input_length, key, key_length, output)) return CRYPTO_STATUS_INTERNAL_ERROR;
    return CRYPTO_STATUS_OK;
}

crypto_status crypto_rc4_encrypt_text(const char *input, const char *key,
                                      char *hex_output, size_t output_capacity, size_t *output_length) {
    uint8_t encrypted[MAX_TEXT];
    char result[MAX_HEX];
    size_t input_length, key_length, i;
    if (!input || !key) return CRYPTO_STATUS_INVALID_ARGUMENT;
    if (!text_input_valid(input)) return CRYPTO_STATUS_INVALID_INPUT;
    input_length = strlen(input);
    key_length = strlen(key);
    if (key_length == 0) return CRYPTO_STATUS_INVALID_KEY;
    if (!rc4_crypt((const uint8_t *)input, input_length, (const uint8_t *)key, key_length, encrypted)) {
        return CRYPTO_STATUS_INTERNAL_ERROR;
    }
    for (i = 0; i < input_length; ++i) sprintf(result + i * 2, "%02X", encrypted[i]);
    result[input_length * 2] = '\0';
    return copy_text_output(result, hex_output, output_capacity, output_length);
}

crypto_status crypto_rc4_decrypt_text(const char *hex_input, const char *key,
                                      char *output, size_t output_capacity, size_t *output_length) {
    uint8_t encrypted[MAX_TEXT], plain[MAX_TEXT];
    size_t encrypted_length, key_length;
    if (!hex_input || !key) return CRYPTO_STATUS_INVALID_ARGUMENT;
    if (strlen(hex_input) > CRYPTO_TEXT_MAX * 2U) return CRYPTO_STATUS_INVALID_INPUT;
    key_length = strlen(key);
    if (key_length == 0) return CRYPTO_STATUS_INVALID_KEY;
    if (!hex_to_bytes(hex_input, encrypted, sizeof(encrypted), &encrypted_length)) return CRYPTO_STATUS_INVALID_INPUT;
    if (output_length) *output_length = encrypted_length;
    if (!output || output_capacity <= encrypted_length) return CRYPTO_STATUS_BUFFER_TOO_SMALL;
    if (!rc4_crypt(encrypted, encrypted_length, (const uint8_t *)key, key_length, plain)) {
        return CRYPTO_STATUS_INTERNAL_ERROR;
    }
    memcpy(output, plain, encrypted_length);
    output[encrypted_length] = '\0';
    return CRYPTO_STATUS_OK;
}

crypto_status crypto_aes128_encrypt_text(const char *input, const char *key,
                                         char *hex_output, size_t output_capacity, size_t *output_length) {
    char result[MAX_HEX];
    if (!input || !key) return CRYPTO_STATUS_INVALID_ARGUMENT;
    if (!text_input_valid(input)) return CRYPTO_STATUS_INVALID_INPUT;
    if (key[0] == '\0') return CRYPTO_STATUS_INVALID_KEY;
    if (!aes_encrypt_text(input, key, result, sizeof(result))) return CRYPTO_STATUS_INTERNAL_ERROR;
    return copy_text_output(result, hex_output, output_capacity, output_length);
}

crypto_status crypto_aes128_decrypt_text(const char *hex_input, const char *key,
                                         char *output, size_t output_capacity, size_t *output_length) {
    char result[MAX_TEXT + AES_BLOCK];
    size_t hex_length;
    if (!hex_input || !key) return CRYPTO_STATUS_INVALID_ARGUMENT;
    if (key[0] == '\0') return CRYPTO_STATUS_INVALID_KEY;
    hex_length = strlen(hex_input);
    if (hex_length == 0 || hex_length > (MAX_TEXT + AES_BLOCK) * 2U || hex_length % (AES_BLOCK * 2U) != 0) {
        return CRYPTO_STATUS_INVALID_INPUT;
    }
    if (!aes_decrypt_text(hex_input, key, result, sizeof(result))) return CRYPTO_STATUS_INVALID_INPUT;
    return copy_text_output(result, output, output_capacity, output_length);
}

crypto_status crypto_rsa_generate_key(crypto_rsa_key *key) {
    static int random_seeded = 0;
    if (!key) return CRYPTO_STATUS_INVALID_ARGUMENT;
    if (!random_seeded) {
        srand((unsigned int)time(NULL));
        random_seeded = 1;
    }
    return rsa_generate(key) ? CRYPTO_STATUS_OK : CRYPTO_STATUS_INTERNAL_ERROR;
}

crypto_status crypto_rsa_encrypt_text(const char *input, const crypto_rsa_key *key,
                                      char *output, size_t output_capacity, size_t *output_length) {
    uint64_t cipher[MAX_TEXT];
    char number[32];
    size_t length, required = 0, position = 0, i;
    int number_length;
    if (!input || !key) return CRYPTO_STATUS_INVALID_ARGUMENT;
    if (!text_input_valid(input)) return CRYPTO_STATUS_INVALID_INPUT;
    if (key->n <= 255 || key->e < 2) return CRYPTO_STATUS_INVALID_KEY;
    length = strlen(input);
    rsa_encrypt_bytes((const uint8_t *)input, length, key, cipher);
    for (i = 0; i < length; ++i) {
        number_length = snprintf(number, sizeof(number), "%llu", (unsigned long long)cipher[i]);
        if (number_length < 0) return CRYPTO_STATUS_INTERNAL_ERROR;
        required += (size_t)number_length + (i == 0 ? 0U : 1U);
    }
    if (output_length) *output_length = required;
    if (!output || output_capacity <= required) return CRYPTO_STATUS_BUFFER_TOO_SMALL;
    for (i = 0; i < length; ++i) {
        if (i != 0) output[position++] = ' ';
        number_length = snprintf(output + position, output_capacity - position, "%llu",
                                 (unsigned long long)cipher[i]);
        if (number_length < 0) return CRYPTO_STATUS_INTERNAL_ERROR;
        position += (size_t)number_length;
    }
    output[position] = '\0';
    return CRYPTO_STATUS_OK;
}

crypto_status crypto_rsa_decrypt_text(const char *input, const crypto_rsa_key *key,
                                      char *output, size_t output_capacity, size_t *output_length) {
    uint64_t cipher[MAX_TEXT];
    char result[MAX_TEXT];
    const char *cursor;
    size_t count = 0, i;
    if (!input || !key) return CRYPTO_STATUS_INVALID_ARGUMENT;
    if (key->n <= 255 || key->d < 2) return CRYPTO_STATUS_INVALID_KEY;
    cursor = input;
    while (*cursor != '\0') {
        uint64_t value = 0;
        unsigned int digit;
        while (isspace((unsigned char)*cursor)) ++cursor;
        if (*cursor == '\0') break;
        if (!isdigit((unsigned char)*cursor) || count >= CRYPTO_TEXT_MAX) return CRYPTO_STATUS_INVALID_INPUT;
        while (isdigit((unsigned char)*cursor)) {
            digit = (unsigned int)(*cursor - '0');
            if (value > (UINT64_MAX - digit) / 10U) return CRYPTO_STATUS_INVALID_INPUT;
            value = value * 10U + digit;
            ++cursor;
        }
        if (*cursor != '\0' && !isspace((unsigned char)*cursor)) return CRYPTO_STATUS_INVALID_INPUT;
        cipher[count++] = value;
    }
    for (i = 0; i < count; ++i) {
        uint64_t value;
        if (cipher[i] >= key->n) return CRYPTO_STATUS_INVALID_INPUT;
        value = mod_pow(cipher[i], key->d, key->n);
        if (value == 0 || value > 255) return CRYPTO_STATUS_INVALID_INPUT;
        result[i] = (char)(uint8_t)value;
    }
    result[count] = '\0';
    return copy_text_output(result, output, output_capacity, output_length);
}

crypto_status crypto_md5_hex(const char *input, char *output,
                             size_t output_capacity, size_t *output_length) {
    uint8_t digest[16];
    char result[33];
    size_t i;
    if (!input) return CRYPTO_STATUS_INVALID_ARGUMENT;
    md5_string(input, digest);
    for (i = 0; i < 16; ++i) sprintf(result + i * 2, "%02x", digest[i]);
    result[32] = '\0';
    return copy_text_output(result, output, output_capacity, output_length);
}

crypto_status crypto_dh_calculate(uint64_t prime, uint64_t generator,
                                  uint64_t alice_private, uint64_t bob_private,
                                  crypto_dh_result *result) {
    if (!result) return CRYPTO_STATUS_INVALID_ARGUMENT;
    if (prime < 5 || !is_probable_prime(prime) || generator < 2 || generator >= prime ||
        alice_private == 0 || alice_private >= prime || bob_private == 0 || bob_private >= prime) {
        return CRYPTO_STATUS_INVALID_INPUT;
    }
    result->alice_public = mod_pow(generator, alice_private, prime);
    result->bob_public = mod_pow(generator, bob_private, prime);
    result->alice_shared = mod_pow(result->bob_public, alice_private, prime);
    result->bob_shared = mod_pow(result->alice_public, bob_private, prime);
    return result->alice_shared == result->bob_shared ? CRYPTO_STATUS_OK : CRYPTO_STATUS_INTERNAL_ERROR;
}

#ifndef CRYPTO_CORE_ONLY
/* ---------- Console operations ---------- */

static void run_caesar(void) {
    char input[MAX_TEXT], encrypted[MAX_TEXT], decrypted[MAX_TEXT], shift_text[32];
    int shift;
    read_line("Plaintext: ", input, sizeof(input)); read_line("Shift (0-25): ", shift_text, sizeof(shift_text));
    shift = atoi(shift_text); caesar_transform(input, encrypted, shift); caesar_transform(encrypted, decrypted, -shift);
    printf("Ciphertext: %s\nRecovered : %s\n", encrypted, decrypted);
}

static void run_vigenere(void) {
    char input[MAX_TEXT], key[128], encrypted[MAX_TEXT], decrypted[MAX_TEXT];
    read_line("Plaintext: ", input, sizeof(input)); read_line("Keyword: ", key, sizeof(key));
    if (!vigenere_transform(input, key, encrypted, 1) || !vigenere_transform(encrypted, key, decrypted, -1)) {
        puts("Error: keyword must contain at least one letter."); return;
    }
    printf("Ciphertext: %s\nRecovered : %s\n", encrypted, decrypted);
}

static void run_playfair(void) {
    char input[MAX_TEXT], key[128], encrypted[MAX_TEXT * 2], decrypted[MAX_TEXT * 2];
    read_line("Plaintext (letters): ", input, sizeof(input)); read_line("Keyword: ", key, sizeof(key));
    if (!playfair_transform(input, key, encrypted, 0) || !playfair_transform(encrypted, key, decrypted, 1)) {
        puts("Error: invalid key or text."); return;
    }
    printf("Ciphertext: %s\nRecovered : %s\nNote: inserted/padded X characters are retained.\n", encrypted, decrypted);
}

static void run_columnar(void) {
    char input[MAX_TEXT], key[65], encrypted[MAX_TEXT], decrypted[MAX_TEXT];
    read_line("Plaintext: ", input, sizeof(input)); read_line("Column keyword (2-64 chars): ", key, sizeof(key));
    if (!columnar_encrypt(input, key, encrypted) || !columnar_decrypt(encrypted, key, decrypted)) {
        puts("Error: invalid column keyword."); return;
    }
    printf("Ciphertext: %s\nRecovered : %s\n", encrypted, decrypted);
}

static void run_rc4(void) {
    char input[MAX_TEXT], key[128];
    uint8_t encrypted[MAX_TEXT], decrypted[MAX_TEXT];
    size_t length;
    read_line("Plaintext: ", input, sizeof(input)); read_line("Key: ", key, sizeof(key)); length = strlen(input);
    if (!rc4_crypt((const uint8_t *)input, length, (const uint8_t *)key, strlen(key), encrypted)) {
        puts("Error: key cannot be empty."); return;
    }
    rc4_crypt(encrypted, length, (const uint8_t *)key, strlen(key), decrypted); decrypted[length] = '\0';
    printf("Ciphertext (hex): "); print_hex(encrypted, length); printf("\nRecovered       : %s\n", decrypted);
}

static void run_aes(void) {
    char input[MAX_TEXT], key[128], encrypted[MAX_HEX], decrypted[MAX_TEXT];
    read_line("Plaintext: ", input, sizeof(input)); read_line("Key text (first 16 bytes used): ", key, sizeof(key));
    if (!aes_encrypt_text(input, key, encrypted, sizeof(encrypted)) || !aes_decrypt_text(encrypted, key, decrypted, sizeof(decrypted))) {
        puts("Error: AES processing failed."); return;
    }
    printf("Ciphertext (hex): %s\nRecovered       : %s\n", encrypted, decrypted);
}

static void run_rsa(void) {
    rsa_key key;
    char input[MAX_TEXT];
    uint64_t cipher[MAX_TEXT];
    uint8_t recovered[MAX_TEXT];
    size_t length, i;
    puts("Generating two classroom primes with Miller-Rabin...");
    if (!rsa_generate(&key)) { puts("Error: RSA key generation failed."); return; }
    printf("p=%llu\nq=%llu\nn=%llu\nphi=%llu\ne=%llu\nd=%llu\n",
           (unsigned long long)key.p, (unsigned long long)key.q, (unsigned long long)key.n,
           (unsigned long long)key.phi, (unsigned long long)key.e, (unsigned long long)key.d);
    read_line("Plaintext: ", input, sizeof(input)); length = strlen(input);
    rsa_encrypt_bytes((const uint8_t *)input, length, &key, cipher);
    printf("Ciphertext integers:\n");
    for (i = 0; i < length; ++i) printf("%llu%s", (unsigned long long)cipher[i], i + 1 == length ? "\n" : " ");
    rsa_decrypt_bytes(cipher, length, &key, recovered); recovered[length] = '\0';
    printf("Recovered: %s\n", recovered);
}

static void run_md5(void) {
    char input[MAX_TEXT]; uint8_t digest[16];
    read_line("Text: ", input, sizeof(input)); md5_string(input, digest);
    printf("MD5: "); print_hex(digest, sizeof(digest)); putchar('\n');
}

static uint64_t read_u64_default(const char *prompt, uint64_t default_value) {
    char text[64]; char *end;
    read_line(prompt, text, sizeof(text));
    if (text[0] == '\0') return default_value;
    return strtoull(text, &end, 10);
}

static void run_dh(void) {
    uint64_t p = read_u64_default("Prime p [23]: ", 23);
    uint64_t g = read_u64_default("Generator g [5]: ", 5);
    uint64_t a = read_u64_default("Alice private a [6]: ", 6);
    uint64_t b = read_u64_default("Bob private b [15]: ", 15);
    uint64_t public_a, public_b, shared_a, shared_b;
    if (p <= 3 || g <= 1 || a == 0 || b == 0) { puts("Error: invalid DH parameters."); return; }
    public_a = mod_pow(g, a, p); public_b = mod_pow(g, b, p);
    shared_a = mod_pow(public_b, a, p); shared_b = mod_pow(public_a, b, p);
    printf("Alice public A = %llu\nBob public B   = %llu\n",
           (unsigned long long)public_a, (unsigned long long)public_b);
    printf("Alice shared K = %llu\nBob shared K   = %llu\nMatch: %s\n",
           (unsigned long long)shared_a, (unsigned long long)shared_b, shared_a == shared_b ? "YES" : "NO");
}

/* ---------- Deterministic self-test ---------- */

static int expect_text(const char *label, const char *actual, const char *expected) {
    int pass = strcmp(actual, expected) == 0;
    printf("[%-5s] %s\n", pass ? "PASS" : "FAIL", label);
    if (!pass) printf("        expected: %s\n        actual  : %s\n", expected, actual);
    return pass;
}

static int self_test(void) {
    int passed = 0, total = 0;
    char buffer[MAX_TEXT * 2], second[MAX_TEXT * 2], hex[MAX_HEX];
    uint8_t bytes[32], round_key[AES_ROUND_KEY], digest[16];
    const uint8_t aes_key[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    const uint8_t aes_plain[16] = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    const uint8_t aes_expected[16] = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
    rsa_key textbook = {61,53,3233,3120,17,2753};
    uint64_t rsa_cipher[8]; uint8_t rsa_plain[8];

    caesar_transform("Attack at dawn!", buffer, 3); ++total; passed += expect_text("Caesar known answer", buffer, "Dwwdfn dw gdzq!");
    vigenere_transform("ATTACKATDAWN", "LEMON", buffer, 1); ++total; passed += expect_text("Vigenere known answer", buffer, "LXFOPVEFRNHR");
    playfair_transform("HIDETHEGOLDINTHETREESTUMP", "PLAYFAIREXAMPLE", buffer, 0); ++total;
    passed += expect_text("Playfair known answer", buffer, "BMODZBXDNABEKUDMUIXMMOUVIF");
    columnar_encrypt("WEAREDISCOVEREDFLEEATONCE", "ZEBRAS", buffer); ++total;
    passed += expect_text("Columnar known answer", buffer, "EVLNACDTESEAROFODEECWIREE");
    columnar_decrypt(buffer, "ZEBRAS", second); ++total;
    passed += expect_text("Columnar round trip", second, "WEAREDISCOVEREDFLEEATONCE");

    rc4_crypt((const uint8_t *)"Plaintext", 9, (const uint8_t *)"Key", 3, bytes);
    { size_t i, offset = 0; for (i = 0; i < 9; ++i) offset += (size_t)sprintf(hex + offset, "%02x", bytes[i]); }
    ++total; passed += expect_text("RC4 known answer", hex, "bbf316e8d940af0ad3");

    memcpy(bytes, aes_plain, 16); aes_key_expansion(round_key, aes_key); aes_encrypt_block(bytes, round_key);
    ++total; printf("[%-5s] AES-128 FIPS-197 vector\n", memcmp(bytes, aes_expected, 16) == 0 ? "PASS" : "FAIL");
    if (memcmp(bytes, aes_expected, 16) == 0) ++passed;
    aes_decrypt_block(bytes, round_key); ++total; printf("[%-5s] AES-128 inverse cipher\n", memcmp(bytes, aes_plain, 16) == 0 ? "PASS" : "FAIL");
    if (memcmp(bytes, aes_plain, 16) == 0) ++passed;

    rsa_encrypt_bytes((const uint8_t *)"Hi", 2, &textbook, rsa_cipher); rsa_decrypt_bytes(rsa_cipher, 2, &textbook, rsa_plain); rsa_plain[2] = '\0';
    ++total; passed += expect_text("RSA textbook round trip", (char *)rsa_plain, "Hi");

    md5_string("abc", digest); { size_t i, offset = 0; for (i = 0; i < 16; ++i) offset += (size_t)sprintf(hex + offset, "%02x", digest[i]); }
    ++total; passed += expect_text("MD5 RFC vector", hex, "900150983cd24fb0d6963f7d28e17f72");

    ++total; printf("[%-5s] DH shared secret (p=23,g=5,a=6,b=15)\n", mod_pow(mod_pow(5,15,23),6,23) == 2 ? "PASS" : "FAIL");
    if (mod_pow(mod_pow(5,15,23),6,23) == 2) ++passed;

    printf("\nSelf-test result: %d/%d checks passed.\n", passed, total);
    return passed == total ? 0 : 1;
}

static void print_menu(void) {
    puts("\n============================================================");
    puts(" Information Security Engineering Practice 2 - Task 1");
    puts(" Standalone Encryption / Decryption Laboratory (C11)");
    puts("============================================================");
    puts(" 1. Caesar cipher               6. AES-128 cipher");
    puts(" 2. Vigenere cipher             7. RSA public-key cipher");
    puts(" 3. Playfair cipher             8. MD5 hash");
    puts(" 4. Columnar transposition      9. Diffie-Hellman exchange");
    puts(" 5. RC4 stream cipher          10. Run self-test");
    puts(" 0. Exit");
}

int main(int argc, char **argv) {
    char choice_text[32]; int choice;
    srand((unsigned int)time(NULL));
    if (argc > 1 && strcmp(argv[1], "--self-test") == 0) return self_test();
    for (;;) {
        print_menu(); read_line("Select: ", choice_text, sizeof(choice_text)); choice = atoi(choice_text);
        switch (choice) {
            case 1: run_caesar(); break;
            case 2: run_vigenere(); break;
            case 3: run_playfair(); break;
            case 4: run_columnar(); break;
            case 5: run_rc4(); break;
            case 6: run_aes(); break;
            case 7: run_rsa(); break;
            case 8: run_md5(); break;
            case 9: run_dh(); break;
            case 10: self_test(); break;
            case 0: puts("Goodbye."); return 0;
            default: puts("Unknown selection.");
        }
    }
}
#endif
