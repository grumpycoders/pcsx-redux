PATCHES = \
patch_gte.c \
patch_gte2.c \
patch_pad.c \
patch_pad2.c \
remove_ChgclrPAD.c \
remove_ChgclrPAD2.c \
send_pad.c \
send_pad2.c \


CC ?= cc

all:
	$(CC) -g -o generate generate.c hash.c -I../.. -DGENERATE_HASHES $(PATCHES)
