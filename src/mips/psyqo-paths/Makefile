PSYQOPATHSDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

TARGET = psyqo-paths
TYPE = library

SRCS = \
src/cdrom-loader.cpp \
src/archive-manager.cpp \
../ucl-demo/n2e-d.S \

EXTRA_DEPS += $(PSYQOPATHSDIR)Makefile

include ../psyqo/psyqo.mk
