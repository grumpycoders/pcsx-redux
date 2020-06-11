PREFIX = mipsel-linux-gnu
BUILD ?= Release

ROOTDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

CC = $(PREFIX)-gcc

TYPE ?= cpe
LDSCRIPT ?= $(ROOTDIR)/$(TYPE).ld

USE_FUNCTION_SECTIONS ?= true

ARCHFLAGS = -march=mips1 -mabi=32 -EL -fno-pic -mno-shared -mno-abicalls -mfp32
ARCHFLAGS += -fno-stack-protector -nostdlib -ffreestanding
ifeq ($(USE_FUNCTION_SECTIONS),true)
CPPFLAGS += -ffunction-sections
endif
CPPFLAGS += -mno-gpopt -fomit-frame-pointer
CPPFLAGS += -fno-builtin -fno-strict-aliasing -Wno-attributes
CPPFLAGS += $(ARCHFLAGS)
CPPFLAGS += -I$(ROOTDIR)

LDFLAGS = -Wl,-Map=$(TARGET).map -nostdlib -T$(LDSCRIPT) -static -Wl,--gc-sections
LDFLAGS += $(ARCHFLAGS)

CPPFLAGS_Release += -Os -flto
LDFLAGS_Release += -Os -flto

CPPFLAGS_Debug += -O0

LDFLAGS += -g
CPPFLAGS += -g

CPPFLAGS += $(CPPFLAGS_$(BUILD))
LDFLAGS += $(LDFLAGS_$(BUILD))

OBJS += $(addsuffix .o, $(basename $(SRCS)))

all: dep $(TARGET).$(TYPE)

$(TARGET).$(TYPE): $(TARGET).elf
	$(PREFIX)-objcopy -O binary $< $@

$(TARGET).elf: $(OBJS)
	$(CC) $(LDFLAGS) -g -o $(TARGET).elf $(OBJS)

%.o: %.s
	$(CC) $(ARCHFLAGS) -I$(ROOTDIR) -g -c -o $@ $<

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
