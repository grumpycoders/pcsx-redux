TARGET = openbios

SRCS = \
../common/hardware/cop0.s \
../common/hardware/sio1.c \
boot/boot.s \
kernel/flushcache.s \
kernel/handlers.c \
kernel/vectors.s \
main/main.c \
\
uC-sdk-glue/BoardConsole.c \
uC-sdk-glue/BoardInit.c \
uC-sdk-glue/init.c \
\
../../../third_party/uC-sdk/libc/src/cxx-glue.c \
../../../third_party/uC-sdk/libc/src/errno.c \
../../../third_party/uC-sdk/libc/src/initfini.c \
../../../third_party/uC-sdk/libc/src/malloc.c \
../../../third_party/uC-sdk/libc/src/qsort.c \
../../../third_party/uC-sdk/libc/src/rand.c \
../../../third_party/uC-sdk/libc/src/reent.c \
../../../third_party/uC-sdk/libc/src/stdio.c \
../../../third_party/uC-sdk/libc/src/strto.c \
../../../third_party/uC-sdk/libc/src/unistd.c \
../../../third_party/uC-sdk/libc/src/xprintf.c \
../../../third_party/uC-sdk/libc/src/xscanf.c \
../../../third_party/uC-sdk/libc/src/yscanf.c \
../../../third_party/uC-sdk/os/src/devfs.c \
../../../third_party/uC-sdk/os/src/filesystem.c \
../../../third_party/uC-sdk/os/src/fio.c \
../../../third_party/uC-sdk/os/src/hash-djb2.c \
../../../third_party/uC-sdk/os/src/init.c \
../../../third_party/uC-sdk/os/src/osdebug.c \
../../../third_party/uC-sdk/os/src/romfs.c \
../../../third_party/uC-sdk/os/src/sbrk.c \


LDSCRIPT = psx-bios.ld

CPPFLAGS = -DNOFLOATINGPOINT
CPPFLAGS += -I../../../third_party/uC-sdk/libc/include
CPPFLAGS += -I../../../third_party/uC-sdk/os/include
CPPFLAGS += -IuC-sdk-glue

include ../common.mk
