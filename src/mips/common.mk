PREFIX = mipsel-linux-gnu

CC = $(PREFIX)-gcc

ARCHFLAGS = -march=mips1 -mabi=32 -EL -fno-pic -mno-shared -mno-abicalls -mfp32
ARCHFLAGS += -fno-stack-protector -nostdlib -ffreestanding
CPPFLAGS += -mno-gpopt -fomit-frame-pointer -ffunction-sections
CPPFLAGS += -fno-builtin
CPPFLAGS += $(ARCHFLAGS)
CPPFLAGS += -I..

LDFLAGS = -Wl,-Map=$(TARGET).map -nostdlib -T$(LDSCRIPT) -static -Wl,--gc-sections
LDFLAGS += $(ARCHFLAGS)

LDFLAGS += -g -O3 -flto
CPPFLAGS += -g -O3 -flto

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
