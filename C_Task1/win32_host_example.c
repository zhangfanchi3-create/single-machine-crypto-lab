#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "win32_crypto_panel.h"

static const wchar_t *host_class_name = L"GroupProjectHostExample";
static HWND crypto_panel;

static LRESULT CALLBACK host_window_procedure(HWND window, UINT message,
                                              WPARAM w_param, LPARAM l_param) {
    switch (message) {
        case WM_CREATE: {
            CREATESTRUCTW *creation = (CREATESTRUCTW *)l_param;
            RECT client;
            GetClientRect(window, &client);
            crypto_panel = crypto_win32_create_panel(
                creation->hInstance, window, 0, 0,
                client.right - client.left, client.bottom - client.top, 2001);
            return crypto_panel ? 0 : -1;
        }
        case WM_SIZE:
            if (crypto_panel) MoveWindow(crypto_panel, 0, 0, LOWORD(l_param), HIWORD(l_param), TRUE);
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        default:
            break;
    }
    return DefWindowProcW(window, message, w_param, l_param);
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous_instance,
                    PWSTR command_line, int show_command) {
    WNDCLASSW window_class;
    HWND window;
    MSG message;
    int message_result;
    (void)previous_instance;
    (void)command_line;

    ZeroMemory(&window_class, sizeof(window_class));
    window_class.lpfnWndProc = host_window_procedure;
    window_class.hInstance = instance;
    window_class.lpszClassName = host_class_name;
    window_class.hCursor = LoadCursorW(NULL, IDC_ARROW);
    window_class.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    if (!RegisterClassW(&window_class)) return 1;

    window = CreateWindowExW(
        0, host_class_name, L"组内软件主窗口示例",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, 1080, 820,
        NULL, NULL, instance, NULL);
    if (!window) return 1;
    ShowWindow(window, show_command);
    UpdateWindow(window);

    while ((message_result = GetMessageW(&message, NULL, 0, 0)) > 0) {
        if (!IsDialogMessageW(window, &message)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    return message_result < 0 ? 1 : (int)message.wParam;
}
