TARGET = hello.psx
TLOAD_ADDR = 0x80010000
SRCS = \
	../common/hardware/cop0.s \
	crt0/crt0.S \
	src/main.c \

LDSCRIPT = ../psx-exe.ld

CPPFLAGS = -Iinclude -Isrc -I${PS1SDK}/include

include ../common.mk
