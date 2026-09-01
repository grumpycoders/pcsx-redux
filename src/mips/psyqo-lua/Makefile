PSYQOLUADIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

TARGET = psyqo-lua
TYPE = library

SRCS = \
src/lua.cpp \

CPPFLAGS += -I$(PSYQOLUADIR)../../../third_party/psxlua/src
CPPFLAGS += -DLUA_TARGET_PSX

EXTRA_DEPS += $(PSYQOLUADIR)Makefile

include ../psyqo/psyqo.mk
