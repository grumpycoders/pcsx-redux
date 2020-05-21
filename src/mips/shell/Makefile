TARGET = shell
TYPE = bin

SRCS = \
../common/crt0/crt0.s \
main/main.c \

LDSCRIPT = shell.ld

include ../common.mk

shell_data.o: shell.bin
	$(PREFIX)-objcopy -I binary --rename-section .data=.rodata,alloc,load,readonly,data,contents -O elf32-tradlittlemips -B mips shell.bin shell_data.o
