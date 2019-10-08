TARGET = tinyload.psx
TLOAD_ADDR = 0x80030000
SRCS = \
	crt0/crt0.S \
	src/main.c \
	src/syscalls.S

LIBS =

LDSCRIPT = ../psx-exe.ld
CPPFLAGS := -I../ps1sdk/include -Isrc -Iinclude
LDFLAGS :=

include ../common.mk
