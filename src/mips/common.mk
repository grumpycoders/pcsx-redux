BUILD ?= Release

ifeq ($(OS),Windows_NT)
HAS_LINUX_MIPS_GCC = false
else
HAS_LINUX_MIPS_GCC = $(shell which mipsel-linux-gnu-gcc > /dev/null 2> /dev/null && echo true || echo false)
endif

ifeq ($(HAS_LINUX_MIPS_GCC),true)
PREFIX ?= mipsel-linux-gnu
FORMAT ?= elf32-tradlittlemips
else
PREFIX ?= mipsel-none-elf
FORMAT ?= elf32-littlemips
endif

ROOTDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

CC  = $(PREFIX)-gcc
CXX = $(PREFIX)-g++
AR  = $(PREFIX)-gcc-ar

TYPE ?= cpe
LDSCRIPT ?= $(ROOTDIR)$(TYPE).ld
ifeq ($(strip $(OVERLAYSCRIPT)),)
OVERLAYSCRIPT := $(ROOTDIR)nooverlay.ld
endif

LDSCRIPTS = $(OVERLAYSCRIPT) $(LDSCRIPT) $(EXTRA_LDSCRIPT)

USE_FUNCTION_SECTIONS ?= true

ARCHFLAGS = -march=mips1 -mabi=32 -EL -fno-pic -mno-shared -mno-abicalls -mfp32 -mno-llsc
ARCHFLAGS += -fno-stack-protector -nostdlib -ffreestanding
ifeq ($(USE_FUNCTION_SECTIONS),true)
CPPFLAGS += -ffunction-sections
endif
CPPFLAGS += -mno-gpopt -fomit-frame-pointer
CPPFLAGS += -fno-builtin -fno-strict-aliasing -Wno-attributes
CPPFLAGS += $(ARCHFLAGS)
CPPFLAGS += -I$(ROOTDIR)
CPPFLAGS += $(foreach f, $(DEFINES), -D$(f))

LDFLAGS += -Wl,-Map=$(BINDIR)$(TARGET).map -nostdlib $(foreach script, $(LDSCRIPTS), -T$(script)) -static -Wl,--gc-sections
LDFLAGS += $(ARCHFLAGS) -Wl,--oformat=$(FORMAT)

CPPFLAGS_Release += -Os
LDFLAGS_Release += -Os

CPPFLAGS_LTO += -Os -flto -ffat-lto-objects
LDFLAGS_LTO += -Os -flto -ffat-lto-objects

CPPFLAGS_Debug += -O0
CPPFLAGS_SmallDebug += -Og
CPPFLAGS_Coverage += -Og

LDFLAGS += -g
CPPFLAGS += -g

CPPFLAGS += $(CPPFLAGS_$(BUILD))
LDFLAGS += $(LDFLAGS_$(BUILD))

CXXFLAGS += -fno-exceptions -fno-rtti

OBJS += $(addsuffix .o, $(basename $(SRCS)))

ifeq ($(TYPE), library)
all: dep $(BINDIR)lib$(TARGET).a
else
all: dep $(LIBRARIES) $(BINDIR)$(TARGET).$(TYPE) $(foreach ovl, $(OVERLAYSECTION), $(BINDIR)Overlay$(ovl))
endif

$(BINDIR)Overlay%: $(BINDIR)$(TARGET).elf
	$(PREFIX)-objcopy -j $(@:$(BINDIR)Overlay%=%) -O binary $< $(BINDIR)Overlay$(@:$(BINDIR)Overlay%=%)

$(BINDIR)$(TARGET).$(TYPE): $(BINDIR)$(TARGET).elf
	$(PREFIX)-objcopy $(addprefix -R , $(OVERLAYSECTION)) -O binary $< $@

$(BINDIR)$(TARGET).elf: $(OBJS) $(LIBRARIES) $(EXTRA_DEPS)
ifneq ($(strip $(BINDIR)),)
	mkdir -p $(BINDIR)
endif
	$(CC) -g -o $(BINDIR)$(TARGET).elf $(OBJS) $(LDFLAGS) $(LIBRARIES)

$(BINDIR)lib$(TARGET).a: $(OBJS) $(EXTRA_DEPS)
	$(AR) rcs $(BINDIR)lib$(TARGET).a $(OBJS)

%.o: %.s
	$(CC) $(ARCHFLAGS) -I$(ROOTDIR) -g -c -o $@ $<

%.dep: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -M -MT $(addsuffix .o, $(basename $@)) -MF $@ $<

%.dep: %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -M -MT $(addsuffix .o, $(basename $@)) -MF $@ $<

%.dep: %.cc
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -M -MT $(addsuffix .o, $(basename $@)) -MF $@ $<

# A bit broken, but that'll do in most cases.
%.dep: %.s
	touch $@

DEPS := $(patsubst %.cpp, %.dep,$(filter %.cpp,$(SRCS)))
DEPS += $(patsubst %.cc,  %.dep,$(filter %.cc,$(SRCS)))
DEPS +=	$(patsubst %.c,   %.dep,$(filter %.c,$(SRCS)))
DEPS += $(patsubst %.s,   %.dep,$(filter %.s,$(SRCS)))

dep: $(DEPS)

clean: $(EXTRA_CLEAN)
	rm -f $(OBJS) $(BINDIR)*.a $(BINDIR)Overlay.* $(BINDIR)*.elf $(BINDIR)*.ps-exe $(BINDIR)*.map $(DEPS)

ifneq ($(MAKECMDGOALS), clean)
ifneq ($(MAKECMDGOALS), deepclean)
-include $(DEPS)
endif
endif

.PHONY: clean dep all
