PSYQODIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

TARGET = psyqo
TYPE = library

SRCS = \
$(wildcard ../../../third_party/EASTL/source/*.cpp) \
../common/crt0/crt0cxx.s \
../common/crt0/cxxglue.c \
../common/crt0/memory-c.c \
../common/crt0/memory-s.s \
../common/hardware/flushcache.s \
../common/psxlibc/ucontext.s \
../common/syscalls/printf.s \
$(wildcard src/hardware/*.cpp) \
$(wildcard src/*.cpp) \
$(wildcard src/*.c) \
$(wildcard src/*.s) \

CPPFLAGS = -I../../../third_party/EASTL/include -I../../../third_party/EABase/include/Common
CXXFLAGS = -std=c++20

ifeq ($(TEST),true)
CPPFLAGS += -Werror
endif

EXTRA_DEPS += $(PSYQODIR)Makefile

include ../common.mk
