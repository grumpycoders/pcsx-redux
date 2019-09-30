TARGET = lib/libps1.a

SRCS = \
	src/syscalls.S \

#LDSCRIPT = psx-exe.ld

## If "TLOAD_ADDR" was specified in the Makefile, pass it to the linker.
#~ ifneq ($(strip $(TLOAD_ADDR)),)
#~ LDFLAGS := -Wl,--defsym,TLOAD_ADDR=$(TLOAD_ADDR)
#~ else
LDFLAGS =
#~ endif

CPPFLAGS += -Iinclude -Isrc

include ../common.mk
