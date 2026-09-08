#ifndef WIN32_CRYPTO_PANEL_H
#define WIN32_CRYPTO_PANEL_H

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

int crypto_win32_register_class(HINSTANCE instance);
HWND crypto_win32_create_panel(HINSTANCE instance, HWND parent,
                               int x, int y, int width, int height, int control_id);

#ifdef __cplusplus
}
#endif

#endif
