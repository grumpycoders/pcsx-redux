TARGET = shell
TYPE = bin

SRCS = \
../common/crt0/crt0.s \
dcos.c \
gpu.c \
hull.c \
main.c \
math.c \
../modplayer/modplayer.c \

LDSCRIPT = shell.ld

include ../common.mk

shell_data.o: shell.bin
	$(PREFIX)-objcopy -I binary --rename-section .data=.rodata,alloc,load,readonly,data,contents -O $(FORMAT) -B mips shell.bin shell_data.o
