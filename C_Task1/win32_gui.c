#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "crypto_core.h"
#include "win32_crypto_panel.h"

enum {
    ID_ALGORITHM = 1001,
    ID_MODE,
    ID_INPUT,
    ID_KEY,
    ID_OUTPUT,
    ID_EXECUTE,
    ID_SWAP,
    ID_CLEAR,
    ID_COPY,
    ID_GENERATE_RSA,
    ID_HELP_TEXT,
    ID_WARNING_TEXT,
    ID_STATUS_TEXT
};

enum {
    ALGORITHM_CAESAR = 0,
    ALGORITHM_VIGENERE,
    ALGORITHM_PLAYFAIR,
    ALGORITHM_COLUMNAR,
    ALGORITHM_RC4,
    ALGORITHM_AES,
    ALGORITHM_RSA,
    ALGORITHM_MD5,
    ALGORITHM_DH
};

typedef struct {
    HWND window;
    HWND algorithm_label;
    HWND algorithm_combo;
    HWND mode_label;
    HWND mode_combo;
    HWND help_text;
    HWND warning_text;
    HWND input_label;
    HWND input_edit;
    HWND key_label;
    HWND key_edit;
    HWND execute_button;
    HWND swap_button;
    HWND clear_button;
    HWND copy_button;
    HWND rsa_button;
    HWND output_label;
    HWND output_edit;
    HWND status_text;
    HFONT font;
    crypto_rsa_key rsa_key;
    int rsa_ready;
} application_state;

static application_state application;

static const wchar_t *window_class_name = L"CryptoPracticeWin32Window";

static HWND create_control(const wchar_t *class_name, const wchar_t *text,
                           DWORD style, DWORD extended_style, int control_id) {
    HWND control = CreateWindowExW(
        extended_style, class_name, text, WS_CHILD | WS_VISIBLE | style,
        0, 0, 0, 0, application.window, (HMENU)(INT_PTR)control_id,
        GetModuleHandleW(NULL), NULL);
    if (control && application.font) SendMessageW(control, WM_SETFONT, (WPARAM)application.font, TRUE);
    return control;
}

static void set_status(const wchar_t *text) {
    SetWindowTextW(application.status_text, text);
}

static void show_error(const wchar_t *text) {
    SetWindowTextW(application.output_edit, text);
    set_status(text);
    MessageBoxW(application.window, text, L"输入或计算错误", MB_OK | MB_ICONWARNING);
}

static const wchar_t *status_message_chinese(crypto_status status) {
    switch (status) {
        case CRYPTO_STATUS_INVALID_ARGUMENT: return L"缺少必要参数。";
        case CRYPTO_STATUS_INVALID_KEY: return L"密钥格式或长度无效。";
        case CRYPTO_STATUS_INVALID_INPUT: return L"输入文本或密文格式无效。";
        case CRYPTO_STATUS_BUFFER_TOO_SMALL: return L"输出内容过长，请缩短输入。";
        case CRYPTO_STATUS_INTERNAL_ERROR: return L"算法内部计算失败。";
        default: return L"未知错误。";
    }
}

static int get_control_utf8(HWND control, char *output, size_t output_capacity) {
    int wide_length = GetWindowTextLengthW(control);
    int utf8_length;
    wchar_t *wide_text;
    if (!output || output_capacity == 0) return 0;
    wide_text = (wchar_t *)malloc(((size_t)wide_length + 1U) * sizeof(wchar_t));
    if (!wide_text) return 0;
    GetWindowTextW(control, wide_text, wide_length + 1);
    utf8_length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                     wide_text, -1, NULL, 0, NULL, NULL);
    if (utf8_length <= 0 || (size_t)utf8_length > output_capacity) {
        free(wide_text);
        return 0;
    }
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                        wide_text, -1, output, utf8_length, NULL, NULL);
    free(wide_text);
    return 1;
}

static int set_control_utf8(HWND control, const char *text) {
    int wide_length;
    wchar_t *wide_text;
    if (!text) return 0;
    wide_length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, NULL, 0);
    if (wide_length <= 0) return 0;
    wide_text = (wchar_t *)malloc((size_t)wide_length * sizeof(wchar_t));
    if (!wide_text) return 0;
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, wide_text, wide_length);
    SetWindowTextW(control, wide_text);
    free(wide_text);
    return 1;
}

static void set_default_key(int algorithm) {
    const wchar_t *default_text = L"";
    switch (algorithm) {
        case ALGORITHM_CAESAR: default_text = L"3"; break;
        case ALGORITHM_VIGENERE: default_text = L"LEMON"; break;
        case ALGORITHM_PLAYFAIR: default_text = L"PLAYFAIREXAMPLE"; break;
        case ALGORITHM_COLUMNAR: default_text = L"ZEBRAS"; break;
        case ALGORITHM_RC4: default_text = L"Key"; break;
        case ALGORITHM_AES: default_text = L"classroom-key"; break;
        case ALGORITHM_RSA: default_text = application.rsa_ready ? NULL : L"请先点击生成 RSA 密钥"; break;
        case ALGORITHM_DH: default_text = L"23,5,6,15"; break;
        default: break;
    }
    if (default_text) SetWindowTextW(application.key_edit, default_text);
}

static void show_rsa_key(void) {
    char key_text[1024];
    snprintf(key_text, sizeof(key_text),
             "p=%llu\r\nq=%llu\r\nn=%llu\r\nphi=%llu\r\ne=%llu\r\nd=%llu",
             (unsigned long long)application.rsa_key.p,
             (unsigned long long)application.rsa_key.q,
             (unsigned long long)application.rsa_key.n,
             (unsigned long long)application.rsa_key.phi,
             (unsigned long long)application.rsa_key.e,
             (unsigned long long)application.rsa_key.d);
    set_control_utf8(application.key_edit, key_text);
}

static void update_algorithm_controls(void) {
    int algorithm = (int)SendMessageW(application.algorithm_combo, CB_GETCURSEL, 0, 0);
    const wchar_t *help_text = L"";
    const wchar_t *key_label = L"密钥或参数";
    int single_mode = 0;

    SendMessageW(application.mode_combo, CB_RESETCONTENT, 0, 0);
    switch (algorithm) {
        case ALGORITHM_CAESAR:
            help_text = L"Caesar：输入整数位移量；加密向右移动，解密自动反向移动。";
            key_label = L"位移量";
            break;
        case ALGORITHM_VIGENERE:
            help_text = L"Vigenere：密钥至少包含一个英文字母，非字母字符保持不变。";
            key_label = L"关键词";
            break;
        case ALGORITHM_PLAYFAIR:
            help_text = L"Playfair：仅处理英文字母，I/J 共用一个位置，解密结果可能保留填充 X。";
            key_label = L"关键词";
            break;
        case ALGORITHM_COLUMNAR:
            help_text = L"列置换：关键词长度为 2 到 64 个字符，加解密必须使用相同关键词。";
            key_label = L"排序关键词";
            break;
        case ALGORITHM_RC4:
            help_text = L"RC4：加密结果显示为十六进制；解密时输入十六进制密文。";
            key_label = L"RC4 密钥";
            break;
        case ALGORITHM_AES:
            help_text = L"AES-128：课堂 ECB 演示封装；密钥文本截取或补零为 16 字节。";
            key_label = L"AES 密钥文本";
            break;
        case ALGORITHM_RSA:
            help_text = L"RSA：先生成课堂演示密钥，再选择加密或解密；密文是空格分隔的整数。";
            key_label = L"当前 RSA 密钥";
            break;
        case ALGORITHM_MD5:
            help_text = L"MD5：输出 128 位十六进制摘要，散列函数不可解密。";
            key_label = L"无需密钥";
            single_mode = 1;
            break;
        case ALGORITHM_DH:
            help_text = L"Diffie-Hellman：参数格式为 p,g,a,b，例如 23,5,6,15。";
            key_label = L"p,g,a,b";
            single_mode = 2;
            break;
        default:
            algorithm = ALGORITHM_CAESAR;
            break;
    }

    if (single_mode == 1) {
        SendMessageW(application.mode_combo, CB_ADDSTRING, 0, (LPARAM)L"计算摘要");
    } else if (single_mode == 2) {
        SendMessageW(application.mode_combo, CB_ADDSTRING, 0, (LPARAM)L"计算共享密钥");
    } else {
        SendMessageW(application.mode_combo, CB_ADDSTRING, 0, (LPARAM)L"加密");
        SendMessageW(application.mode_combo, CB_ADDSTRING, 0, (LPARAM)L"解密");
    }
    SendMessageW(application.mode_combo, CB_SETCURSEL, 0, 0);
    SetWindowTextW(application.help_text, help_text);
    SetWindowTextW(application.key_label, key_label);
    EnableWindow(application.rsa_button, algorithm == ALGORITHM_RSA);
    EnableWindow(application.input_edit, algorithm != ALGORITHM_DH);
    SendMessageW(application.key_edit, EM_SETREADONLY,
                 algorithm == ALGORITHM_RSA || algorithm == ALGORITHM_MD5, 0);
    set_default_key(algorithm);
    if (algorithm == ALGORITHM_RSA && application.rsa_ready) show_rsa_key();
    set_status(L"已切换算法，等待输入。 ");
}

static int parse_integer_shift(const char *text, int *shift) {
    char *end;
    long value;
    if (!text || !shift) return 0;
    value = strtol(text, &end, 10);
    if (end == text) return 0;
    while (isspace((unsigned char)*end)) ++end;
    if (*end != '\0' || value < -1000000L || value > 1000000L) return 0;
    *shift = (int)value;
    return 1;
}

static int is_ascii_text(const char *text) {
    const unsigned char *cursor = (const unsigned char *)text;
    while (*cursor != '\0') {
        if (*cursor > 0x7fU) return 0;
        ++cursor;
    }
    return 1;
}

static int parse_dh_parameters(const char *text, uint64_t *prime, uint64_t *generator,
                               uint64_t *alice_private, uint64_t *bob_private) {
    unsigned long long parsed_prime, parsed_generator, parsed_alice, parsed_bob;
    char trailing;
    int count = sscanf(text, " %llu , %llu , %llu , %llu %c",
                       &parsed_prime, &parsed_generator, &parsed_alice, &parsed_bob, &trailing);
    if (count != 4) return 0;
    *prime = (uint64_t)parsed_prime;
    *generator = (uint64_t)parsed_generator;
    *alice_private = (uint64_t)parsed_alice;
    *bob_private = (uint64_t)parsed_bob;
    return 1;
}

static void execute_algorithm(void) {
    char input[4096];
    char key[4096];
    char output[32768];
    size_t output_length = 0;
    crypto_status status = CRYPTO_STATUS_INVALID_ARGUMENT;
    int algorithm = (int)SendMessageW(application.algorithm_combo, CB_GETCURSEL, 0, 0);
    int mode = (int)SendMessageW(application.mode_combo, CB_GETCURSEL, 0, 0);

    input[0] = '\0';
    key[0] = '\0';
    output[0] = '\0';
    if (algorithm != ALGORITHM_DH && !get_control_utf8(application.input_edit, input, sizeof(input))) {
        show_error(L"输入内容过长或无法转换为 UTF-8。单次输入最多 1023 字节。");
        return;
    }
    if (algorithm != ALGORITHM_MD5 && !get_control_utf8(application.key_edit, key, sizeof(key))) {
        show_error(L"密钥或参数内容过长。");
        return;
    }
    if ((algorithm == ALGORITHM_PLAYFAIR || algorithm == ALGORITHM_COLUMNAR) &&
        !is_ascii_text(input)) {
        show_error(L"Playfair 和列置换模式请使用英文、数字及 ASCII 标点，避免破坏 UTF-8 中文字节。");
        return;
    }

    switch (algorithm) {
        case ALGORITHM_CAESAR: {
            int shift;
            if (!parse_integer_shift(key, &shift)) {
                show_error(L"Caesar 位移量必须是整数。");
                return;
            }
            status = crypto_caesar_text(input, shift, mode == 1,
                                        output, sizeof(output), &output_length);
            break;
        }
        case ALGORITHM_VIGENERE:
            status = crypto_vigenere_text(input, key, mode == 1,
                                          output, sizeof(output), &output_length);
            break;
        case ALGORITHM_PLAYFAIR:
            status = crypto_playfair_text(input, key, mode == 1,
                                          output, sizeof(output), &output_length);
            break;
        case ALGORITHM_COLUMNAR:
            status = crypto_columnar_text(input, key, mode == 1,
                                          output, sizeof(output), &output_length);
            break;
        case ALGORITHM_RC4:
            status = mode == 0
                ? crypto_rc4_encrypt_text(input, key, output, sizeof(output), &output_length)
                : crypto_rc4_decrypt_text(input, key, output, sizeof(output), &output_length);
            break;
        case ALGORITHM_AES:
            status = mode == 0
                ? crypto_aes128_encrypt_text(input, key, output, sizeof(output), &output_length)
                : crypto_aes128_decrypt_text(input, key, output, sizeof(output), &output_length);
            break;
        case ALGORITHM_RSA:
            if (!application.rsa_ready) {
                show_error(L"请先点击“生成 RSA 密钥”。");
                return;
            }
            status = mode == 0
                ? crypto_rsa_encrypt_text(input, &application.rsa_key,
                                          output, sizeof(output), &output_length)
                : crypto_rsa_decrypt_text(input, &application.rsa_key,
                                          output, sizeof(output), &output_length);
            break;
        case ALGORITHM_MD5:
            status = crypto_md5_hex(input, output, sizeof(output), &output_length);
            break;
        case ALGORITHM_DH: {
            uint64_t prime, generator, alice_private, bob_private;
            crypto_dh_result result;
            if (!parse_dh_parameters(key, &prime, &generator, &alice_private, &bob_private)) {
                show_error(L"DH 参数格式应为 p,g,a,b，例如 23,5,6,15。");
                return;
            }
            status = crypto_dh_calculate(prime, generator, alice_private, bob_private, &result);
            if (status == CRYPTO_STATUS_OK) {
                snprintf(output, sizeof(output),
                         "Alice 公钥 A = %llu\r\nBob 公钥 B = %llu\r\n"
                         "Alice 共享密钥 K = %llu\r\nBob 共享密钥 K = %llu\r\n匹配结果：YES",
                         (unsigned long long)result.alice_public,
                         (unsigned long long)result.bob_public,
                         (unsigned long long)result.alice_shared,
                         (unsigned long long)result.bob_shared);
                output_length = strlen(output);
            }
            break;
        }
        default:
            show_error(L"请选择一个算法。");
            return;
    }

    if (status != CRYPTO_STATUS_OK) {
        show_error(status_message_chinese(status));
        return;
    }
    if (!set_control_utf8(application.output_edit, output)) {
        show_error(L"计算成功，但结果无法转换为界面文本。");
        return;
    }
    set_status(L"计算完成。结果可以复制，或交换到输入框继续解密。 ");
    (void)output_length;
}

static void generate_rsa_key(void) {
    crypto_status status = crypto_rsa_generate_key(&application.rsa_key);
    if (status != CRYPTO_STATUS_OK) {
        show_error(status_message_chinese(status));
        return;
    }
    application.rsa_ready = 1;
    show_rsa_key();
    set_status(L"RSA 教学密钥已生成。 ");
}

static void swap_input_output(void) {
    wchar_t input[32768];
    wchar_t output[32768];
    GetWindowTextW(application.input_edit, input, (int)(sizeof(input) / sizeof(input[0])));
    GetWindowTextW(application.output_edit, output, (int)(sizeof(output) / sizeof(output[0])));
    SetWindowTextW(application.input_edit, output);
    SetWindowTextW(application.output_edit, input);
    set_status(L"输入与输出已交换。 ");
}

static void clear_fields(void) {
    SetWindowTextW(application.input_edit, L"");
    SetWindowTextW(application.output_edit, L"");
    set_status(L"输入和输出已清空。 ");
}

static void copy_output(void) {
    int length = GetWindowTextLengthW(application.output_edit);
    HGLOBAL memory;
    wchar_t *text;
    if (length == 0) {
        set_status(L"当前没有可复制的结果。 ");
        return;
    }
    memory = GlobalAlloc(GMEM_MOVEABLE, ((size_t)length + 1U) * sizeof(wchar_t));
    if (!memory) {
        show_error(L"无法分配剪贴板内存。");
        return;
    }
    text = (wchar_t *)GlobalLock(memory);
    if (!text) {
        GlobalFree(memory);
        show_error(L"无法访问剪贴板内存。");
        return;
    }
    GetWindowTextW(application.output_edit, text, length + 1);
    GlobalUnlock(memory);
    if (!OpenClipboard(application.window)) {
        GlobalFree(memory);
        show_error(L"无法打开剪贴板。");
        return;
    }
    EmptyClipboard();
    if (!SetClipboardData(CF_UNICODETEXT, memory)) {
        CloseClipboard();
        GlobalFree(memory);
        show_error(L"复制结果失败。");
        return;
    }
    CloseClipboard();
    set_status(L"结果已复制到剪贴板。 ");
}

static void layout_controls(int client_width, int client_height) {
    int margin = 16;
    int top_row = 14;
    int label_width = 58;
    int combo_width = 205;
    int row_height = 28;
    int help_top = 52;
    int input_top = 118;
    int key_top;
    int buttons_top;
    int output_top;
    int status_height = 24;
    int available_height = client_height - input_top - status_height - 176;
    int input_height = available_height / 2;
    int output_height;
    if (input_height < 120) input_height = 120;
    key_top = input_top + input_height + 32;
    buttons_top = key_top + 66;
    output_top = buttons_top + 54;
    output_height = client_height - output_top - status_height - margin;
    if (output_height < 120) output_height = 120;

    MoveWindow(application.algorithm_label, margin, top_row + 5, label_width, 22, TRUE);
    MoveWindow(application.algorithm_combo, margin + label_width + 8, top_row,
               combo_width, 240, TRUE);
    MoveWindow(application.mode_label, margin + label_width + combo_width + 30,
               top_row + 5, 42, 22, TRUE);
    MoveWindow(application.mode_combo, margin + label_width + combo_width + 76,
               top_row, 130, 160, TRUE);
    MoveWindow(application.rsa_button, margin + label_width + combo_width + 220,
               top_row, 140, row_height, TRUE);
    MoveWindow(application.warning_text, client_width - 270, top_row + 4,
               250, 22, TRUE);
    MoveWindow(application.help_text, margin, help_top,
               client_width - margin * 2, 48, TRUE);

    MoveWindow(application.input_label, margin, input_top - 26, 120, 22, TRUE);
    MoveWindow(application.input_edit, margin, input_top,
               client_width - margin * 2, input_height, TRUE);
    MoveWindow(application.key_label, margin, key_top - 26, 180, 22, TRUE);
    MoveWindow(application.key_edit, margin, key_top,
               client_width - margin * 2, 44, TRUE);

    MoveWindow(application.execute_button, margin, buttons_top, 120, 34, TRUE);
    MoveWindow(application.swap_button, margin + 132, buttons_top, 120, 34, TRUE);
    MoveWindow(application.copy_button, margin + 264, buttons_top, 120, 34, TRUE);
    MoveWindow(application.clear_button, margin + 396, buttons_top, 120, 34, TRUE);

    MoveWindow(application.output_label, margin, output_top - 26, 120, 22, TRUE);
    MoveWindow(application.output_edit, margin, output_top,
               client_width - margin * 2, output_height, TRUE);
    MoveWindow(application.status_text, 0, client_height - status_height,
               client_width, status_height, TRUE);
}

static int create_application_controls(void) {
    application.font = CreateFontW(
        -17, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");

    application.algorithm_label = create_control(L"STATIC", L"算法", SS_LEFT, 0, 0);
    application.algorithm_combo = create_control(L"COMBOBOX", L"",
        CBS_DROPDOWNLIST | WS_TABSTOP | WS_VSCROLL, WS_EX_CLIENTEDGE, ID_ALGORITHM);
    application.mode_label = create_control(L"STATIC", L"模式", SS_LEFT, 0, 0);
    application.mode_combo = create_control(L"COMBOBOX", L"",
        CBS_DROPDOWNLIST | WS_TABSTOP, WS_EX_CLIENTEDGE, ID_MODE);
    application.rsa_button = create_control(L"BUTTON", L"生成 RSA 密钥",
        BS_PUSHBUTTON | WS_TABSTOP, 0, ID_GENERATE_RSA);
    application.warning_text = create_control(L"STATIC", L"教学演示，不能保护真实数据",
        SS_RIGHT, 0, ID_WARNING_TEXT);
    application.help_text = create_control(L"STATIC", L"", SS_LEFT, 0, ID_HELP_TEXT);
    application.input_label = create_control(L"STATIC", L"输入文本", SS_LEFT, 0, 0);
    application.input_edit = create_control(L"EDIT", L"",
        ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN |
        WS_VSCROLL | WS_TABSTOP, WS_EX_CLIENTEDGE, ID_INPUT);
    application.key_label = create_control(L"STATIC", L"密钥或参数", SS_LEFT, 0, 0);
    application.key_edit = create_control(L"EDIT", L"",
        ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL | WS_TABSTOP,
        WS_EX_CLIENTEDGE, ID_KEY);
    application.execute_button = create_control(L"BUTTON", L"执行",
        BS_DEFPUSHBUTTON | WS_TABSTOP, 0, ID_EXECUTE);
    application.swap_button = create_control(L"BUTTON", L"交换输入输出",
        BS_PUSHBUTTON | WS_TABSTOP, 0, ID_SWAP);
    application.copy_button = create_control(L"BUTTON", L"复制结果",
        BS_PUSHBUTTON | WS_TABSTOP, 0, ID_COPY);
    application.clear_button = create_control(L"BUTTON", L"清空",
        BS_PUSHBUTTON | WS_TABSTOP, 0, ID_CLEAR);
    application.output_label = create_control(L"STATIC", L"输出结果", SS_LEFT, 0, 0);
    application.output_edit = create_control(L"EDIT", L"",
        ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY |
        WS_VSCROLL | WS_HSCROLL | WS_TABSTOP, WS_EX_CLIENTEDGE, ID_OUTPUT);
    application.status_text = create_control(L"STATIC", L"就绪。 ",
        SS_LEFT | SS_SUNKEN, 0, ID_STATUS_TEXT);

    if (!application.algorithm_combo || !application.mode_combo || !application.input_edit ||
        !application.key_edit || !application.output_edit || !application.execute_button) {
        return 0;
    }

    SendMessageW(application.algorithm_combo, CB_ADDSTRING, 0, (LPARAM)L"Caesar 单表替代");
    SendMessageW(application.algorithm_combo, CB_ADDSTRING, 0, (LPARAM)L"Vigenere 多表替代");
    SendMessageW(application.algorithm_combo, CB_ADDSTRING, 0, (LPARAM)L"Playfair 多图替代");
    SendMessageW(application.algorithm_combo, CB_ADDSTRING, 0, (LPARAM)L"列置换密码");
    SendMessageW(application.algorithm_combo, CB_ADDSTRING, 0, (LPARAM)L"RC4 流密码");
    SendMessageW(application.algorithm_combo, CB_ADDSTRING, 0, (LPARAM)L"AES-128 分块密码");
    SendMessageW(application.algorithm_combo, CB_ADDSTRING, 0, (LPARAM)L"RSA 公钥密码");
    SendMessageW(application.algorithm_combo, CB_ADDSTRING, 0, (LPARAM)L"MD5 单向散列");
    SendMessageW(application.algorithm_combo, CB_ADDSTRING, 0, (LPARAM)L"Diffie-Hellman 密钥交换");
    SendMessageW(application.algorithm_combo, CB_SETCURSEL, 0, 0);
    SendMessageW(application.input_edit, EM_SETLIMITTEXT, CRYPTO_TEXT_MAX, 0);
    SendMessageW(application.key_edit, EM_SETLIMITTEXT, 4095, 0);
    SendMessageW(application.output_edit, EM_SETLIMITTEXT, 32767, 0);
    update_algorithm_controls();
    return 1;
}

static LRESULT CALLBACK window_procedure(HWND window, UINT message,
                                         WPARAM w_param, LPARAM l_param) {
    switch (message) {
        case WM_CREATE:
            application.window = window;
            if (!create_application_controls()) return -1;
            return 0;
        case WM_SIZE:
            layout_controls(LOWORD(l_param), HIWORD(l_param));
            return 0;
        case WM_GETMINMAXINFO: {
            if (!GetParent(window)) {
                MINMAXINFO *information = (MINMAXINFO *)l_param;
                information->ptMinTrackSize.x = 820;
                information->ptMinTrackSize.y = 680;
            }
            return 0;
        }
        case WM_COMMAND:
            if (LOWORD(w_param) == ID_ALGORITHM && HIWORD(w_param) == CBN_SELCHANGE) {
                update_algorithm_controls();
                return 0;
            }
            if (HIWORD(w_param) == BN_CLICKED) {
                switch (LOWORD(w_param)) {
                    case ID_EXECUTE: execute_algorithm(); return 0;
                    case ID_SWAP: swap_input_output(); return 0;
                    case ID_CLEAR: clear_fields(); return 0;
                    case ID_COPY: copy_output(); return 0;
                    case ID_GENERATE_RSA: generate_rsa_key(); return 0;
                    default: break;
                }
            }
            break;
        case WM_CTLCOLORSTATIC:
            if ((HWND)l_param == application.warning_text) {
                SetTextColor((HDC)w_param, RGB(180, 35, 35));
                SetBkMode((HDC)w_param, TRANSPARENT);
                return (LRESULT)GetSysColorBrush(COLOR_WINDOW);
            }
            break;
        case WM_DESTROY:
            if (application.font) DeleteObject(application.font);
            application.font = NULL;
            application.window = NULL;
            if (!GetParent(window)) PostQuitMessage(0);
            return 0;
        default:
            break;
    }
    return DefWindowProcW(window, message, w_param, l_param);
}

int crypto_win32_register_class(HINSTANCE instance) {
    WNDCLASSW window_class;
    ZeroMemory(&window_class, sizeof(window_class));
    window_class.lpfnWndProc = window_procedure;
    window_class.hInstance = instance;
    window_class.lpszClassName = window_class_name;
    window_class.hCursor = LoadCursorW(NULL, IDC_ARROW);
    window_class.hIcon = LoadIconW(NULL, IDI_APPLICATION);
    window_class.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    if (RegisterClassW(&window_class)) return 1;
    return GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
}

HWND crypto_win32_create_panel(HINSTANCE instance, HWND parent,
                               int x, int y, int width, int height, int control_id) {
    DWORD style;
    const wchar_t *title;
    HMENU menu_or_id;
    if (application.window && IsWindow(application.window)) return NULL;
    ZeroMemory(&application, sizeof(application));
    if (!crypto_win32_register_class(instance)) return NULL;
    if (parent) {
        style = WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN;
        title = L"";
        menu_or_id = (HMENU)(INT_PTR)control_id;
    } else {
        style = WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN;
        title = L"信息安全工程实训 2  单机加解密平台";
        menu_or_id = NULL;
    }
    return CreateWindowExW(
        0, window_class_name, title, style,
        x, y, width, height, parent, menu_or_id, instance, NULL);
}

#ifndef CRYPTO_WIN32_EMBEDDED
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous_instance,
                    PWSTR command_line, int show_command) {
    MSG message;
    HWND window;
    int message_result;
    (void)previous_instance;
    (void)command_line;

    SetProcessDPIAware();
    if (!crypto_win32_register_class(instance)) {
        MessageBoxW(NULL, L"窗口类注册失败。", L"启动错误", MB_OK | MB_ICONERROR);
        return 1;
    }

    window = crypto_win32_create_panel(instance, NULL,
                                       CW_USEDEFAULT, CW_USEDEFAULT, 1050, 780, 0);
    if (!window) {
        MessageBoxW(NULL, L"主窗口创建失败。", L"启动错误", MB_OK | MB_ICONERROR);
        return 1;
    }

    ShowWindow(window, show_command);
    UpdateWindow(window);
    while ((message_result = GetMessageW(&message, NULL, 0, 0)) > 0) {
        if (!IsDialogMessageW(window, &message)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    if (message_result < 0) return 1;
    return (int)message.wParam;
}
#endif
