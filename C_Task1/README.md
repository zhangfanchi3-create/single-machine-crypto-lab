# Task 1：C 语言单机加解密实验平台

本项目用 C11 编写，实现 Caesar、Vigenère、Playfair、列置换、RC4、AES-128、RSA、MD5 与 Diffie–Hellman。项目既可作为统一控制台程序运行，也可编译为供 C 语言 GUI 工程调用的算法模块。

## 编译与测试

```powershell
gcc -std=c11 -O2 -Wall -Wextra -Wpedantic crypto_lab.c -o crypto_lab.exe
.\crypto_lab.exe --self-test
```

自测模式包含经典已知答案、FIPS-197 AES 测试向量、RFC MD5 测试向量以及加解密往返验证。直接运行 `.\crypto_lab.exe` 可进入交互菜单。

## GUI 集成

GUI 工程包含自己的 `main()`，因此算法文件需要使用 `CRYPTO_CORE_ONLY` 编译：

```powershell
gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -DCRYPTO_CORE_ONLY -c crypto_lab.c -o crypto_core.o
gcc -std=c11 -O2 -Wall -Wextra -Wpedantic crypto_core_test.c crypto_core.o -o crypto_core_test.exe
.\crypto_core_test.exe
```

GUI 源文件包含 `crypto_core.h`，再链接 `crypto_core.o`。完整接口、按钮回调方式和工程目录见 `GUI_INTEGRATION.md`。

## Win32 图形界面

`win32_gui.c` 是纯 C、原生 Win32 API 实现，不依赖第三方界面库：

```powershell
gcc -std=c11 -O2 -Wall -Wextra -Wpedantic -DUNICODE -D_UNICODE -municode -mwindows win32_gui.c crypto_core.o -o crypto_gui.exe -luser32 -lgdi32
.\crypto_gui.exe
```

界面提供算法选择、加密或解密模式、输入框、密钥参数框、结果复制、输入输出交换、RSA 密钥生成和 DH 共享密钥计算。

如果组长已有 Win32 主窗口，请使用 `win32_crypto_panel.h` 和带 `CRYPTO_WIN32_EMBEDDED` 宏生成的 `win32_crypto_panel.o`，不要再加入第二个 `wWinMain`。`win32_host_example.c` 展示了在父窗口的 `WM_CREATE` 和 `WM_SIZE` 中嵌入本页面的方法。

> 程序中的 AES-ECB、短 RSA 密钥、RC4 和小型 DH 参数仅用于课程实验，不能用于真实安全系统。
