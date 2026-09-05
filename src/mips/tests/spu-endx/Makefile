TARGET = spu-endx
TYPE = ps-exe

ifeq ($(ONESHOT),true)
CPPFLAGS += -DENDX_ONESHOT
endif

SRCS = \
../../common/syscalls/printf.s \
../../common/crt0/crt0.s \
spu-endx.c \

include ../../common.mk
