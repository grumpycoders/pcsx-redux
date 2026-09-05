TARGET = spdplayer-demo
TYPE = ps-exe

SRCS = \
../common/crt0/crt0.s \
../common/crt0/memory-c.c \
../common/crt0/memory-s.s \
../common/syscalls/printf.s \
demo.c \
spdplayer.c \
test.o \

include ../common.mk

%.o: %.spd
	$(PREFIX)-objcopy -I binary --set-section-alignment .data=4 --rename-section .data=.rodata,alloc,load,readonly,data,contents -O $(FORMAT) -B mips $< $@
