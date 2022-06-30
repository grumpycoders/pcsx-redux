TARGET = cpu
USE_FUNCTION_SECTIONS = false
TYPE = ps-exe

SRCS = \
../uC-sdk-glue/BoardConsole.c \
../uC-sdk-glue/BoardInit.c \
../uC-sdk-glue/init.c \
\
../../../../third_party/uC-sdk/libc/src/cxx-glue.c \
../../../../third_party/uC-sdk/libc/src/errno.c \
../../../../third_party/uC-sdk/libc/src/initfini.c \
../../../../third_party/uC-sdk/libc/src/malloc.c \
../../../../third_party/uC-sdk/libc/src/qsort.c \
../../../../third_party/uC-sdk/libc/src/rand.c \
../../../../third_party/uC-sdk/libc/src/reent.c \
../../../../third_party/uC-sdk/libc/src/stdio.c \
../../../../third_party/uC-sdk/libc/src/string.c \
../../../../third_party/uC-sdk/libc/src/strto.c \
../../../../third_party/uC-sdk/libc/src/unistd.c \
../../../../third_party/uC-sdk/libc/src/xprintf.c \
../../../../third_party/uC-sdk/libc/src/xscanf.c \
../../../../third_party/uC-sdk/libc/src/yscanf.c \
../../../../third_party/uC-sdk/os/src/devfs.c \
../../../../third_party/uC-sdk/os/src/filesystem.c \
../../../../third_party/uC-sdk/os/src/fio.c \
../../../../third_party/uC-sdk/os/src/hash-djb2.c \
../../../../third_party/uC-sdk/os/src/init.c \
../../../../third_party/uC-sdk/os/src/osdebug.c \
../../../../third_party/uC-sdk/os/src/romfs.c \
../../../../third_party/uC-sdk/os/src/sbrk.c \


CPPFLAGS = -DNOFLOATINGPOINT
CPPFLAGS += -I.
CPPFLAGS += -I../../../../third_party/uC-sdk/libc/include
CPPFLAGS += -I../../../../third_party/uC-sdk/os/include
CPPFLAGS += -I../../../../third_party/libcester/include
CPPFLAGS += -I../../openbios/uC-sdk-glue

ifeq ($(PCSX_TESTS),true)
CPPFLAGS += -DPCSX_TESTS=1
endif

SRCS += \
../../common/syscalls/printf.s \
../../common/crt0/uC-sdk-crt0.s \
../cop0/exceptions.cpp \
branchbranch.s \
cpu.c \
links.s \
lwlr.s \

include ../../common.mk
