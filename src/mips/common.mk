PREFIX = mipsel-linux-gnu

CC = $(PREFIX)-gcc

TYPE ?= cpe
LDSCRIPT ?= ../$(TYPE).ld

ARCHFLAGS = -march=mips1 -mabi=32 -EL -fno-pic -mno-shared -mno-abicalls -mfp32
ARCHFLAGS += -fno-stack-protector -nostdlib -ffreestanding
CPPFLAGS += -mno-gpopt -fomit-frame-pointer -ffunction-sections
CPPFLAGS += -fno-builtin -fno-strict-aliasing
CPPFLAGS += $(ARCHFLAGS)
CPPFLAGS += -I..

LDFLAGS = -Wl,-Map=$(TARGET).map -nostdlib -T$(LDSCRIPT) -static -Wl,--gc-sections
LDFLAGS += $(ARCHFLAGS)

LDFLAGS += -g -Os
CPPFLAGS += -g -Os

OBJS += $(addsuffix .o, $(basename $(SRCS)))

all: $(TARGET).$(TYPE)

clean:
	rm -f $(OBJS) $(TARGET).elf $(TARGET).map $(TARGET).$(TYPE)

$(TARGET).$(TYPE): $(TARGET).elf
	$(PREFIX)-objcopy -O binary $< $@

$(TARGET).elf: $(OBJS)
	$(CC) $(LDFLAGS) -g -o $(TARGET).elf $(OBJS)

%.o: %.s
	$(CC) $(ARCHFLAGS) -I.. -g -c -o $@ $<
