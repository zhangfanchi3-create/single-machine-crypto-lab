# 单机加解密实验平台

这是一个用于信息安全课程学习的单机加解密实验项目，包含可直接在浏览器中运行的网页版本，以及使用 C11 编写的控制台与 Win32 GUI 版本。

> 本项目中的古典密码、RC4、AES-ECB、短 RSA 密钥和小型 Diffie–Hellman 参数仅用于教学演示，不能用于真实安全系统。

## 已实现算法

- Caesar cipher
- Vigenère cipher
- Playfair cipher
- Columnar transposition cipher
- RC4
- AES（网页版本使用 AES-256-GCM，C 版本包含 AES-128 教学实现）
- RSA
- MD5
- Diffie–Hellman

## 快速体验

直接打开 `task1_single_machine_crypto.html`。如果浏览器在本地文件模式下限制 Web Crypto API，可在项目根目录启动一个静态服务器：

```powershell
python -m http.server 8000
```

然后访问 <http://localhost:8000/task1_single_machine_crypto.html>。

## C 语言版本

进入 `C_Task1` 目录后编译并运行自测：

```powershell
gcc -std=c11 -O2 -Wall -Wextra -Wpedantic crypto_lab.c -o crypto_lab.exe
.\crypto_lab.exe --self-test
```

项目还提供 Win32 图形界面、可嵌入已有窗口的算法面板，以及独立的核心模块测试。详细说明见 [`C_Task1/README.md`](C_Task1/README.md) 和 [`C_Task1/GUI_INTEGRATION.md`](C_Task1/GUI_INTEGRATION.md)。

## 项目结构

```text
.
├── README.md
├── task1_single_machine_crypto.html
└── C_Task1/
    ├── crypto_lab.c
    ├── crypto_core.h
    ├── crypto_core_test.c
    ├── win32_gui.c
    ├── win32_crypto_panel.h
    ├── win32_host_example.c
    ├── Makefile
    ├── README.md
    └── GUI_INTEGRATION.md
```

## 学习目标

本项目用于理解不同密码算法的基本工作流程、加解密往返验证、已知答案测试，以及 C 语言模块与图形界面的集成方式。
