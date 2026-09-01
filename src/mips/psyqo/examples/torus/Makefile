TARGET = torus
TYPE = ps-exe

SRCS = \
torus.cpp \

ifeq ($(TEST),true)
CPPFLAGS = -Werror
endif
CXXFLAGS = -std=c++20

LDFLAGS += -Wl,-wrap,memcpy -Wl,-wrap,memset

include ../../psyqo.mk
