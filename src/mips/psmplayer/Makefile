TARGET = psmplayer-demo
TYPE = ps-exe

SRCS = \
../common/crt0/crt0.s \
../common/crt0/memory-c.c \
../common/crt0/memory-s.s \
../common/syscalls/printf.s \
demo.c \
psmplayer.c \
test-vab.o \
test-psm.o \

include ../common.mk

test-vab.o: test.vab
	$(PREFIX)-objcopy -I binary --set-section-alignment .data=4 --rename-section .data=.rodata,alloc,load,readonly,data,contents -O $(FORMAT) -B mips $< $@

test-psm.o: test.psm
	$(PREFIX)-objcopy -I binary --set-section-alignment .data=4 --rename-section .data=.rodata,alloc,load,readonly,data,contents -O $(FORMAT) -B mips $< $@
