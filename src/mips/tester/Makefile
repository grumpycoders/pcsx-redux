TARGET = tester.psx
TLOAD_ADDR = 0x80100000
SRCS = \
	crt0/crt0.S \
	src/main.c \
	src/flash.c \
	src/syscalls.S

LIBS =

LDSCRIPT = ./psx-exe.ld
CPPFLAGS := -Isrc -Iinclude -I../ps1sdk/include
LDFLAGS :=

include ../common.mk
