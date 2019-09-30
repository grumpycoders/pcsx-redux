TARGET = hello.psx
TLOAD_ADDR = 0x80010000
SRCS = \
	../common/hardware/cop0.s \
	crt0/crt0.S \
	src/main.c \

LDSCRIPT = ../psx-exe.ld

LDFLAGS = -L${PS1SDK}/libs -lsio

## If "TLOAD_ADDR" was specified in the Makefile, pass it to the linker.
ifneq ($(strip $(TLOAD_ADDR)),)
LDFLAGS := -Wl,--defsym,TLOAD_ADDR=$(TLOAD_ADDR)
endif

CPPFLAGS = -Iinclude -Isrc -I${PS1SDK}/include

include ../common.mk
