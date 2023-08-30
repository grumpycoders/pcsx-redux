PATCHES = \
clear_card_1.c \
custom_handler_1.c \
initgun_1.c \
patch_card_info_1.c \
patch_card_1.c \
patch_card_2.c \
patch_card2_1.c \
patch_card2_2.c \
patch_gte_1.c \
patch_gte_2.c \
patch_gte_3.c \
patch_pad_1.c \
patch_pad_2.c \
patch_pad_3.c \
remove_ChgclrPAD_1.c \
remove_ChgclrPAD_2.c \
send_pad_1.c \
send_pad_2.c \


CC ?= cc

all:
	$(CC) -g -o generate generate.c hash.c -I../.. -DGENERATE_HASHES $(PATCHES)
