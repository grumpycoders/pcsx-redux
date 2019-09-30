TARGET = hello.psx
TLOAD_ADDR = 0x80010000
SRCS = \
../common/hardware/cop0.s \
crt0/crt0.s \
main/main.c \

LDSCRIPT = psx-exe.ld

## If "TLOAD_ADDR" was specified in the Makefile, pass it to the linker.
ifneq ($(strip $(TLOAD_ADDR)),)
LDFLAGS := -Wl,--defsym,TLOAD_ADDR=$(TLOAD_ADDR)
else
LDFLAGS =
endif

include ../common.mk
