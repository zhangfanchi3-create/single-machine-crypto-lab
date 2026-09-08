# C语言GUI集成说明

## 交付文件

- `crypto_core.h`：GUI可以调用的公共接口与数据结构。
- `crypto_lab.c`：算法实现；定义 `CRYPTO_CORE_ONLY` 后不会编译控制台菜单和 `main()`。
- `crypto_core.o`：使用 MinGW-w64 GCC 生成的可链接目标文件。
- `crypto_core_test.c`：公共接口测试程序。
- `crypto_lab.exe`：原控制台演示程序，便于独立验收。

## 工程结构

最终GUI工程只能保留一个 `main()`。组长的窗口程序负责创建控件、读取输入和显示结果，算法文件只负责计算。

```text
group_project/
├─ gui_main.c
├─ gui_callbacks.c
├─ crypto_core.h
├─ crypto_lab.c
└─ other_modules/
```

## 编译方式

直接把源代码加入GUI工程时，为 `crypto_lab.c` 增加预处理宏 `CRYPTO_CORE_ONLY`：

```powershell
gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -DCRYPTO_CORE_ONLY -c crypto_lab.c -o crypto_core.o
gcc gui_main.c gui_callbacks.c crypto_core.o -o group_gui.exe
```

本项目已经提供原生 Win32 API 界面 `win32_gui.c`：

```powershell
gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -DUNICODE -D_UNICODE -municode -mwindows win32_gui.c crypto_core.o -o crypto_gui.exe -luser32 -lgdi32
```

`-municode` 用于启用 `wWinMain` 入口，`-mwindows` 用于生成无控制台窗口的 GUI 程序。Win32 控件全部使用宽字符 API，进入算法模块前统一转换为 UTF-8。

如果组长已经有主窗口，不能再编译第二个 `wWinMain`。应将本界面编译为子页面对象：

```powershell
gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -DUNICODE -D_UNICODE -DCRYPTO_WIN32_EMBEDDED -c win32_gui.c -o win32_crypto_panel.o
gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -DUNICODE -D_UNICODE -municode -mwindows group_main.c win32_crypto_panel.o crypto_core.o -o group_gui.exe -luser32 -lgdi32
```

组长的 `WM_CREATE` 调用 `crypto_win32_create_panel` 创建页面，`WM_SIZE` 使用 `MoveWindow` 调整大小。完整的父窗口示例位于 `win32_host_example.c`，对外声明位于 `win32_crypto_panel.h`。

如果使用现成的 `crypto_core.o`，GUI工程使用的编译器版本和目标架构必须与该文件一致。跨开发环境时应重新编译 `crypto_lab.c`，不要只复制 `.o` 文件。

## GUI回调调用方式

每个按钮回调执行四步：读取明文、密钥和算法参数；调用 `crypto_core.h` 中的函数；检查返回状态；把输出写入结果文本框。

```c
char result[4096];
size_t result_length = 0;
crypto_status status;

status = crypto_vigenere_text(input_text, key_text, 0,
                               result, sizeof(result), &result_length);
if (status == CRYPTO_STATUS_OK) {
    gui_set_result_text(result);
} else {
    gui_show_error(crypto_status_message(status));
}
```

上例中的 `gui_set_result_text` 和 `gui_show_error` 应替换为实际GUI框架提供的控件函数。

## 接口对应关系

| 功能 | 加密或计算 | 解密或验证 |
|---|---|---|
| Caesar | `crypto_caesar_text(..., 0, ...)` | `crypto_caesar_text(..., 1, ...)` |
| Vigenere | `crypto_vigenere_text(..., 0, ...)` | `crypto_vigenere_text(..., 1, ...)` |
| Playfair | `crypto_playfair_text(..., 0, ...)` | `crypto_playfair_text(..., 1, ...)` |
| 列置换 | `crypto_columnar_text(..., 0, ...)` | `crypto_columnar_text(..., 1, ...)` |
| RC4 | `crypto_rc4_encrypt_text` | `crypto_rc4_decrypt_text` |
| AES-128 | `crypto_aes128_encrypt_text` | `crypto_aes128_decrypt_text` |
| RSA | `crypto_rsa_generate_key`、`crypto_rsa_encrypt_text` | `crypto_rsa_decrypt_text` |
| MD5 | `crypto_md5_hex` | 不可逆 |
| DH | `crypto_dh_calculate` | 比较双方共享密钥 |

RC4和AES的密文使用十六进制字符串显示，RSA密文使用空格分隔的十进制整数，适合直接放入GUI多行文本框。

## 界面建议

- 算法下拉框：选择九种算法。
- 模式单选框：加密、解密或计算摘要。
- 输入框：明文或密文。
- 密钥框：根据算法显示关键词、AES密钥或RSA参数。
- 参数区：Caesar位移、DH参数等。
- 输出框：只读、多行、支持复制。
- 按钮：执行、交换输入输出、清空、运行测试。

当前 `win32_gui.c` 已实现上述控件，并增加复制结果、RSA 密钥生成和状态提示。

## 限制

单次文本输入最多为1023字节。AES-ECB、RC4、MD5、短RSA密钥和小型DH参数仅用于课程演示，界面中应显示“教学用途，不能保护真实数据”。
