SHELL := cmd.exe
.SHELLFLAGS := /C
CC := gcc
CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2 -D_WIN32_WINNT=0x0601
LDLIBS := -lws2_32 -lbcrypt
COMMON := src/common.c src/aes.c
HEADERS := src/common.h src/aes.h

.PHONY: all test
all: bin/kdc.exe bin/alice.exe bin/bob.exe

bin:
	if not exist bin mkdir bin

bin/kdc.exe: src/kdc.c $(COMMON) $(HEADERS) | bin
	$(CC) $(CFLAGS) src/kdc.c $(COMMON) -o $@ $(LDLIBS)

bin/alice.exe: src/alice.c $(COMMON) $(HEADERS) | bin
	$(CC) $(CFLAGS) src/alice.c $(COMMON) -o $@ $(LDLIBS)

bin/bob.exe: src/bob.c $(COMMON) $(HEADERS) | bin
	$(CC) $(CFLAGS) src/bob.c $(COMMON) -o $@ $(LDLIBS)

bin/test_aes.exe: tests/test_aes.c $(COMMON) $(HEADERS) | bin
	$(CC) $(CFLAGS) tests/test_aes.c $(COMMON) -o $@ $(LDLIBS)

test: bin/test_aes.exe
	.\bin\test_aes.exe
