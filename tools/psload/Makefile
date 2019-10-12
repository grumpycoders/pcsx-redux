MKDIR=mkdir
CP=cp
RM=rm
RMF=rm -f
CC=gcc
CPP=cpp

TARGET=psload

SRCS = \
	src/main.c \
	src/utils.c \
	src/pcsio.c

LIBS =
# -lusb-1.0

CFLAGS=-I/usr/include
CFLAGS+=-Wall -g
CFLAGS+=-Iinclude -Isrc
OBJS=
LDFLAGS=

OBJS += $(addsuffix .o, $(basename $(SRCS)))

all: $(TARGET)

clean:
	$(RMF) $(OBJS) $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LIBS)
