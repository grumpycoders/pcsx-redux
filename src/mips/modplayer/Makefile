TARGET = modplay-demo
TYPE = ps-exe

SRCS = \
../common/crt0/crt0.s \
../common/syscalls/printf.s \
demo.c \
modplayer.c \
timewarped.o \

include ../common.mk

timewarped.o: timewarped.hit
	$(PREFIX)-objcopy -I binary --set-section-alignment .data=4 --rename-section .data=.rodata,alloc,load,readonly,data,contents -O $(FORMAT) -B mips timewarped.hit timewarped.o
