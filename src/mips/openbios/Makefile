TARGET = openbios

SRCS = \
../common/hardware/cop0.s \
boot/boot.s \
kernel/flushcache.s \
kernel/handlers.c \
kernel/vectors.s \
main/main.c \

LDSCRIPT = psx-bios.ld

CPPFLAGS = -DNOFLOATINGPOINT

include ../common.mk
