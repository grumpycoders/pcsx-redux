TARGET = revstream
TYPE = ps-exe

ifeq ($(PN),true)
CPPFLAGS += -DREVSTREAM_PN
endif

ifeq ($(PROBE),true)
CPPFLAGS += -DREVSTREAM_PROBE
endif

ifeq ($(HALL),true)
CPPFLAGS += -DREVSTREAM_HALL
endif

ifeq ($(DRY),true)
CPPFLAGS += -DREVSTREAM_DRY
endif

ifeq ($(BURST),true)
CPPFLAGS += -DREVSTREAM_BURST
endif

SRCS = \
../../common/syscalls/printf.s \
../../common/crt0/crt0.s \
revstream.c \

include ../../common.mk
