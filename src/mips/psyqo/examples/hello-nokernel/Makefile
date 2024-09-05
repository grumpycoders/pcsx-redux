TARGET = hello
TYPE = ps-exe

SRCS = \
hello.cpp \

LDFLAGS += -Xlinker --defsym=TLOAD_ADDR=0x80001000

ifeq ($(TEST),true)
CPPFLAGS = -Werror
endif
CXXFLAGS = -std=c++20

include ../../psyqo.mk
