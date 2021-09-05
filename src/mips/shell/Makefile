TARGET = shell
TYPE = bin

SRCS = \
../common/crt0/crt0.s \
../common/syscalls/printf.s \
blip.hit \
cdrom.c \
dcos.c \
gpu.c \
hull.c \
main.c \
math.c \
spu.c \
../modplayer/modplayer.c \

LDSCRIPT = shell.ld

include ../common.mk

shell_data.o: shell.bin
	$(PREFIX)-objcopy -I binary --rename-section .data=.rodata,alloc,load,readonly,data,contents -O $(FORMAT) -B mips $< $@

blip.o: blip.hit
	$(PREFIX)-objcopy -I binary --rename-section .data=.rodata,alloc,load,readonly,data,contents -O $(FORMAT) -B mips $< $@
