PREFIX = mipsel-linux-gnu

CC = $(PREFIX)-gcc
AR = $(PREFIX)-ar

TARGETBASE = $(basename $(TARGET))

ARCHFLAGS = -march=mips1 -mabi=32 -EL -msoft-float -Wa,-msoft-float -fno-pic -mno-shared -mno-abicalls
ARCHFLAGS += -mno-gpopt -fomit-frame-pointer -nostartfiles -nostdinc -fno-builtin -fno-pic

CPPFLAGS += -fno-builtin
CPPFLAGS += $(ARCHFLAGS)
CPPFLAGS += -I..

LDFLAGS += -Wl,-Map=$(TARGETBASE).map -nostdlib -T$(LDSCRIPT) -static -Wl,--gc-sections
LDFLAGS += $(ARCHFLAGS)

LDFLAGS += -g -O3 -flto
CPPFLAGS += -g -O3 -flto

OBJS += $(addsuffix .o, $(basename $(SRCS)))

all: $(TARGET)

clean:
	rm -f $(OBJS) $(TARGETBASE).psx $(TARGETBASE).elf $(TARGET).map $(TARGETBASE).bin $(TARGET)

$(TARGETBASE).bin: $(TARGETBASE).elf
	$(PREFIX)-objcopy -O binary $< $@

$(TARGETBASE).psx: $(TARGETBASE).elf
	$(PREFIX)-objcopy -O binary $< $@

$(TARGETBASE).a : $(OBJS)
	$(AR) cru $(TARGET) $(OBJS)

$(TARGETBASE).elf: $(OBJS)
	$(CC) $(LDFLAGS) -g -o $(TARGETBASE).elf $(OBJS)

%.o: %.S
	$(CC) $(CPPFLAGS) -I.. -g -c -o $@ $<

%.o: %.s
	$(CC) $(ARCHFLAGS) -I.. -g -c -o $@ $<

