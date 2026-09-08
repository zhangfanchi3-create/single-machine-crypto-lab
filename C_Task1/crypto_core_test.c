#include <stdio.h>
#include <string.h>

#include "crypto_core.h"

static int checks = 0;
static int passed = 0;

static void check_text(const char *name, crypto_status status,
                       const char *actual, const char *expected) {
    int ok = status == CRYPTO_STATUS_OK && strcmp(actual, expected) == 0;
    ++checks;
    if (ok) ++passed;
    printf("[%-4s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) {
        printf("       status=%s expected=%s actual=%s\n",
               crypto_status_message(status), expected, actual);
    }
}

static void check_true(const char *name, int condition) {
    ++checks;
    if (condition) ++passed;
    printf("[%-4s] %s\n", condition ? "PASS" : "FAIL", name);
}

int main(void) {
    char output[32768];
    char recovered[4096];
    size_t output_length = 0;
    crypto_status status;
    crypto_rsa_key textbook_key = {61, 53, 3233, 3120, 17, 2753};
    crypto_dh_result dh_result;

    status = crypto_caesar_text("Attack at dawn!", 3, 0,
                                output, sizeof(output), &output_length);
    check_text("Caesar API", status, output, "Dwwdfn dw gdzq!");

    status = crypto_vigenere_text("ATTACKATDAWN", "LEMON", 0,
                                  output, sizeof(output), &output_length);
    check_text("Vigenere API", status, output, "LXFOPVEFRNHR");

    status = crypto_playfair_text("HIDETHEGOLDINTHETREESTUMP", "PLAYFAIREXAMPLE", 0,
                                  output, sizeof(output), &output_length);
    check_text("Playfair API", status, output, "BMODZBXDNABEKUDMUIXMMOUVIF");

    status = crypto_columnar_text("WEAREDISCOVEREDFLEEATONCE", "ZEBRAS", 0,
                                  output, sizeof(output), &output_length);
    check_text("Columnar API", status, output, "EVLNACDTESEAROFODEECWIREE");
    status = crypto_columnar_text(output, "ZEBRAS", 1,
                                  recovered, sizeof(recovered), &output_length);
    check_text("Columnar inverse", status, recovered, "WEAREDISCOVEREDFLEEATONCE");

    status = crypto_rc4_encrypt_text("Plaintext", "Key",
                                     output, sizeof(output), &output_length);
    check_text("RC4 API", status, output, "BBF316E8D940AF0AD3");
    status = crypto_rc4_decrypt_text(output, "Key",
                                     recovered, sizeof(recovered), &output_length);
    check_text("RC4 inverse", status, recovered, "Plaintext");

    status = crypto_aes128_encrypt_text("hello AES", "classroom-key",
                                        output, sizeof(output), &output_length);
    check_true("AES encrypt", status == CRYPTO_STATUS_OK && output_length > 0);
    status = crypto_aes128_decrypt_text(output, "classroom-key",
                                        recovered, sizeof(recovered), &output_length);
    check_text("AES inverse", status, recovered, "hello AES");

    status = crypto_rsa_encrypt_text("Hi", &textbook_key,
                                     output, sizeof(output), &output_length);
    check_true("RSA encrypt", status == CRYPTO_STATUS_OK && output_length > 0);
    status = crypto_rsa_decrypt_text(output, &textbook_key,
                                     recovered, sizeof(recovered), &output_length);
    check_text("RSA inverse", status, recovered, "Hi");

    status = crypto_md5_hex("abc", output, sizeof(output), &output_length);
    check_text("MD5 API", status, output, "900150983cd24fb0d6963f7d28e17f72");

    status = crypto_dh_calculate(23, 5, 6, 15, &dh_result);
    check_true("DH API", status == CRYPTO_STATUS_OK &&
               dh_result.alice_shared == 2 && dh_result.bob_shared == 2);

    status = crypto_caesar_text("abc", 3, 0, output, 2, &output_length);
    check_true("Buffer check", status == CRYPTO_STATUS_BUFFER_TOO_SMALL && output_length == 3);

    printf("\nGUI core API result: %d/%d checks passed.\n", passed, checks);
    return passed == checks ? 0 : 1;
}
