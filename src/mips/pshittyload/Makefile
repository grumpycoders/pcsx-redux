TARGET = pshittyload.bin
TLOAD_ADDR = 0x80030000
SRCS = \
	crt0/crt0.S \
	src/main.c \
	src/pshittysio.c \
	src/exec.S \
	src/syscalls.S

LIBS =

LDSCRIPT = ../shell/shell.ld
CPPFLAGS := -Isrc -Iinclude -I../ps1sdk/include
LDFLAGS :=

include ../common.mk
