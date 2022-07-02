TARGET = hello
TYPE = ps-exe

SRCS = \
../../../common/crt0/crt0cxx.s \
../../../common/crt0/cxxglue.c \
../../../common/syscalls/printf.s \
../../src/application.cpp \
../../src/font.cpp \
../../src/kernel.cpp \
../../src/gpu.cpp \
../../src/scene.cpp \
hello.cpp \

CPPFLAGS = -Werror -I../../../../../third_party/EASTL/include -I../../../../../third_party/EABase/include/Common
CXXFLAGS = -std=c++20

# DEFINES = EASTL_USER_DEFINED_ALLOCATOR

include ../../../common.mk
