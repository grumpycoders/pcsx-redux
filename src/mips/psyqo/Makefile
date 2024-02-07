PSYQODIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

TARGET = psyqo
TYPE = library

SRCS = \
../../../third_party/EASTL/source/fixed_pool.cpp \
../common/crt0/crt0cxx.s \
../common/crt0/cxxglue.c \
../common/crt0/memory-c.c \
../common/crt0/memory-s.s \
../common/syscalls/printf.s \
$(wildcard src/hardware/*.cpp) \
$(wildcard src/*.cpp) \
$(wildcard src/*.c) \

CPPFLAGS = -I../../../third_party/EASTL/include -I../../../third_party/EABase/include/Common
CXXFLAGS = -std=c++20

ifeq ($(TEST),true)
CPPFLAGS += -Werror
endif

EXTRA_DEPS += $(PSYQODIR)Makefile

include ../common.mk
