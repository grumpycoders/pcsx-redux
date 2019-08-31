TARGET = openbios

SRCS = \
boot/boot.s \
main/main.c

PREFIX = mipsel-linux-gnu
CC = clang-9

ARCHFLAGS = -march=mips32r3 -mabi=32 -EL -msoft-float -Wa,-msoft-float
ARCHFLAGS += -target mipsel-none-eabi -ccc-gcc-name $(PREFIX)-gcc
INCLUDES = include
CPPFLAGS = -mno-gpopt -fomit-frame-pointer
CPPFLAGS += -ffunction-sections -fdata-sections
CPPFLAGS += -fno-builtin
CPPFLAGS += $(ARCHFLAGS)

LDFLAGS = -Wl,-Map=$(TARGET).map -nostdlib -Tpsx-bios.ld -static -Wl,--gc-sections
LDFLAGS += $(ARCHFLAGS)

CPPFLAGS += -O3

OBJS += $(addsuffix .o, $(basename $(SRCS)))

all: $(TARGET).bin

clean:
	rm -f $(OBJS) $(TARGET).elf $(TARGET).map $(TARGET).bin

$(TARGET).bin: $(TARGET).elf
	$(PREFIX)-objcopy -O binary $< $@

$(TARGET).elf: $(OBJS)
	$(CC) $(LDFLAGS) -g -o $(TARGET).elf $(OBJS)

%.o: %.s
	$(CC) $(ARCHFLAGS) $(addprefix -I, $(INCLUDES)) -g -c -o $@ $<
