PSYQOPATHSDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

TARGET = psyqo-paths
TYPE = library

SRCS = \
src/cdrom-loader.cpp \

EXTRA_DEPS += $(PSYQOPATHSDIR)Makefile

include ../psyqo/psyqo.mk
