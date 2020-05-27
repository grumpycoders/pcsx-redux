PREFIX = mipsel-linux-gnu

CC = $(PREFIX)-gcc

TYPE ?= cpe
LDSCRIPT ?= ../$(TYPE).ld

ARCHFLAGS = -march=mips1 -mabi=32 -EL -fno-pic -mno-shared -mno-abicalls -mfp32
ARCHFLAGS += -fno-stack-protector -nostdlib -ffreestanding
CPPFLAGS += -mno-gpopt -fomit-frame-pointer -ffunction-sections
CPPFLAGS += -fno-builtin -fno-strict-aliasing -Wno-attributes
CPPFLAGS += $(ARCHFLAGS)
CPPFLAGS += -I..

LDFLAGS = -Wl,-Map=$(TARGET).map -nostdlib -T$(LDSCRIPT) -static -Wl,--gc-sections
LDFLAGS += $(ARCHFLAGS)

LDFLAGS += -g -Os
CPPFLAGS += -g -Os

OBJS += $(addsuffix .o, $(basename $(SRCS)))

all: dep $(TARGET).$(TYPE)

$(TARGET).$(TYPE): $(TARGET).elf
	$(PREFIX)-objcopy -O binary $< $@

$(TARGET).elf: $(OBJS)
	$(CC) $(LDFLAGS) -g -o $(TARGET).elf $(OBJS)

%.o: %.s
	$(CC) $(ARCHFLAGS) -I.. -g -c -o $@ $<

%.dep: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -M -MT $(addsuffix .o, $(basename $@)) -MF $@ $<

%.dep: %.cc
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -M -MT $(addsuffix .o, $(basename $@)) -MF $@ $<

# A bit broken, but that'll do in most cases.
%.dep: %.s
	touch $@

DEPS := $(patsubst %.cc,%.dep,$(filter %.cc,$(SRCS)))
DEPS += $(patsubst %.c,%.dep,$(filter %.c,$(SRCS)))
DEPS += $(patsubst %.s,%.dep,$(filter %.s,$(SRCS)))

dep: $(DEPS)

clean:
	rm -f $(OBJS) $(TARGET).elf $(TARGET).map $(TARGET).$(TYPE) $(DEPS)

ifneq ($(MAKECMDGOALS), clean)
ifneq ($(MAKECMDGOALS), deepclean)
-include $(DEPS)
endif
endif

.PHONY: clean dep all
