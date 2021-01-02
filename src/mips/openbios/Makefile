TARGET = openbios
TYPE = bin

SRCS = \
../common/hardware/sio1.c \
../common/psxlibc/fastmemset.s \
boot/boot.s \
cdrom/cdrom.c \
cdrom/events.c \
cdrom/filesystem.c \
cdrom/helpers.c \
cdrom/statemachine.c \
fileio/misc.c \
fileio/stdio.c \
gpu/gpu.c \
handlers/irq.c \
handlers/setup.c \
handlers/syscall.c \
kernel/events.c \
kernel/flushcache.s \
kernel/handlers.c \
kernel/libcmisc.c \
kernel/misc.c \
kernel/psxexe.c \
kernel/psxexec.s \
kernel/setjmp.s \
kernel/threads.c \
kernel/util.c \
kernel/vectors.s \
main/main.c \
pio/pio.c \
shell/shell.c \
sio0/busyloop.s \
sio0/driver.c \
sio0/pad.c \
tty/tty.c \
\
patches/hash.c \
patches/patches.c \
\
patches/patch_gte.c \
patches/patch_pad.c \
patches/remove_ChgclrPAD.c \
patches/send_pad.c \
\
../shell/shell_data.o \
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
../../../third_party/uC-sdk/libc/src/string.c \
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

ifneq ($(EMBED_PSEXE),)
CPPFLAGS += -DOPENBIOS_USE_EMBEDDED_PSEXE
SRCS += ./psexe_data.o
endif

include ../common.mk

../shell/shell_data.o: shell

./psexe_data.o: $(EMBED_PSEXE)
	cp $(EMBED_PSEXE) psexe.bin
	$(PREFIX)-objcopy -I binary --rename-section .data=.rodata,alloc,load,readonly,data,contents -O elf32-tradlittlemips -B mips psexe.bin psexe_data.o

shell:
	$(MAKE) -C ../shell shell_data.o

deepclean: clean
	$(MAKE) -C ../shell clean

.PHONY: deepclean shell
