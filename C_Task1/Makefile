CC = gcc
CFLAGS = -std=c11 -O2 -Wall -Wextra -Wpedantic

all: crypto_lab.exe crypto_core.o crypto_gui.exe win32_crypto_panel.o

crypto_lab.exe: crypto_lab.c crypto_core.h
	$(CC) $(CFLAGS) crypto_lab.c -o crypto_lab.exe

crypto_core.o: crypto_lab.c crypto_core.h
	$(CC) $(CFLAGS) -DCRYPTO_CORE_ONLY -c crypto_lab.c -o crypto_core.o

crypto_core_test.exe: crypto_core_test.c crypto_core.h crypto_core.o
	$(CC) $(CFLAGS) crypto_core_test.c crypto_core.o -o crypto_core_test.exe

crypto_gui.exe: win32_gui.c crypto_core.h crypto_core.o
	$(CC) $(CFLAGS) -DUNICODE -D_UNICODE -municode -mwindows win32_gui.c crypto_core.o -o crypto_gui.exe -luser32 -lgdi32

win32_crypto_panel.o: win32_gui.c win32_crypto_panel.h crypto_core.h
	$(CC) $(CFLAGS) -DUNICODE -D_UNICODE -DCRYPTO_WIN32_EMBEDDED -c win32_gui.c -o win32_crypto_panel.o

win32_host_example.exe: win32_host_example.c win32_crypto_panel.h win32_crypto_panel.o crypto_core.o
	$(CC) $(CFLAGS) -DUNICODE -D_UNICODE -municode -mwindows win32_host_example.c win32_crypto_panel.o crypto_core.o -o win32_host_example.exe -luser32 -lgdi32

test: crypto_lab.exe crypto_core_test.exe
	./crypto_lab.exe --self-test
	./crypto_core_test.exe

clean:
	del /Q crypto_lab.exe crypto_core.o crypto_core_test.exe crypto_gui.exe win32_crypto_panel.o win32_host_example.exe 2>NUL || exit 0
