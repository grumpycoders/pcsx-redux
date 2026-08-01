TARGET = revstream
TYPE = ps-exe

ifeq ($(DRY),true)
CPPFLAGS += -DREVSTREAM_DRY
endif

SRCS = \
../../common/syscalls/printf.s \
../../common/crt0/crt0.s \
revstream.c \

include ../../common.mk
