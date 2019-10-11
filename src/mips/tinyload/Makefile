TARGET = tinyload.bin
TLOAD_ADDR = 0x80030000
SRCS = \
	crt0/crt0.S \
	src/main.c \
	src/exec.S \
	src/flushcache.s
	
LIBS =

LDSCRIPT = ../shell/shell.ld
CPPFLAGS := -Isrc -Iinclude
LDFLAGS :=

include ../common.mk
