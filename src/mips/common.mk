PREFIX = mipsel-linux-gnu

CC = clang-9

ARCHFLAGS = -march=mips32r3 -mabi=32 -EL -msoft-float -Wa,-msoft-float
ARCHFLAGS += -target mipsel-none-eabi -ccc-gcc-name $(PREFIX)-gcc
CPPFLAGS = -mno-gpopt -fomit-frame-pointer
CPPFLAGS += -ffunction-sections -fdata-sections
CPPFLAGS += -fno-builtin
CPPFLAGS += $(ARCHFLAGS)
CPPFLAGS += -I..

LDFLAGS = -Wl,-Map=$(TARGET).map -nostdlib -T$(LDSCRIPT) -static -Wl,--gc-sections
LDFLAGS += $(ARCHFLAGS)
LDFLAGS += -g

CPPFLAGS += -O3
CPPFLAGS += -g

OBJS += $(addsuffix .o, $(basename $(SRCS)))

all: $(TARGET).bin

clean:
	rm -f $(OBJS) $(TARGET).elf $(TARGET).map $(TARGET).bin

$(TARGET).bin: $(TARGET).elf
	$(PREFIX)-objcopy -O binary $< $@

$(TARGET).elf: $(OBJS)
	$(CC) $(LDFLAGS) -g -o $(TARGET).elf $(OBJS)

%.o: %.s
	$(CC) $(ARCHFLAGS) -I.. -g -c -o $@ $<
