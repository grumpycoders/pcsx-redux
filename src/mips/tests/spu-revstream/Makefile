TARGET = revstream
TYPE = ps-exe

ifeq ($(PN),true)
CPPFLAGS += -DREVSTREAM_PN
endif

ifeq ($(PROBE),true)
CPPFLAGS += -DREVSTREAM_PROBE
endif

ifeq ($(PROBEDIFF),true)
CPPFLAGS += -DREVSTREAM_PROBE_DIFF
endif

ifeq ($(PROBEIIR),true)
CPPFLAGS += -DREVSTREAM_PROBE_IIR
endif

ifeq ($(ROOMNOAPF),true)
CPPFLAGS += -DREVSTREAM_ROOM_NOAPF
endif

ifeq ($(ROOMAPF1),true)
CPPFLAGS += -DREVSTREAM_ROOM_APF1
endif

ifeq ($(ROOMAPF2),true)
CPPFLAGS += -DREVSTREAM_ROOM_APF2
endif

ifeq ($(PROBEAPF1),true)
CPPFLAGS += -DREVSTREAM_PROBE_APF1
endif

ifeq ($(PANNED),true)
CPPFLAGS += -DREVSTREAM_PANNED
endif

ifeq ($(NEGOUT),true)
CPPFLAGS += -DREVSTREAM_NEGOUT
endif

ifeq ($(PITCH),true)
CPPFLAGS += -DREVSTREAM_PITCH
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
