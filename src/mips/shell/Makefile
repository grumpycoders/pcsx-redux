TARGET = shell
ifeq ($(PACK_SHELL),true)
TYPE = ps-exe

shell.bin: shell.ps-exe
	../../../ps1-packer shell.ps-exe -tload 0x80030000 -raw -o shell.bin
else
TYPE = bin
LDSCRIPT = shell.ld
endif

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

include ../common.mk

shell_data.o: shell.bin
	$(PREFIX)-objcopy -I binary --set-section-alignment .data=4 --rename-section .data=.rodata,alloc,load,readonly,data,contents -O $(FORMAT) -B mips $< $@

blip.o: blip.hit
	$(PREFIX)-objcopy -I binary --set-section-alignment .data=4 --rename-section .data=.rodata,alloc,load,readonly,data,contents -O $(FORMAT) -B mips $< $@
