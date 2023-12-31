TARGET = coroutine-demo
TYPE = ps-exe

SRCS = \
coroutine-demo.cpp \

ifeq ($(TEST),true)
CPPFLAGS = -Werror
endif
CXXFLAGS = -std=c++20 -fcoroutines

include ../../psyqo.mk
