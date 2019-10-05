TARGET = serial.psx
TLOAD_ADDR = 0x80010000
SRCS = \
	../common/hardware/cop0.s \
	crt0/crt0.S \
	src/main.c

LIBS = ../ps1sdk/libps1sdk.a

LDSCRIPT = ../psx-exe.ld
CPPFLAGS := -I../ps1sdk/include -Isrc -Iinclude
LDFLAGS := -L../ps1sdk -lps1sdk

include ../common.mk
