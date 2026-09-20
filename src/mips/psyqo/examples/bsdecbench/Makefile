TARGET = bsdecbench
TYPE = ps-exe

SRCS = \
bsdecbench.cpp \
../../../common/crt0/clz.c \

CPPFLAGS += -I../../..
CXXFLAGS = -std=c++20
# The whole tree is -Os. Time the AC loop's pieces at the level the decoder is
# actually built at, which is -O3 on that one object.
CPPFLAGS += -O3

include ../../psyqo.mk
