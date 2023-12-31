TARGET = tetris
TYPE = ps-exe

SRCS = \
../../../modplayer/modplayer.c \
\
musix-oh-amiga-with-effects.o \
\
credits.cpp \
game.cpp \
gameover.cpp \
mainmenu.cpp \
options.cpp \
pause.cpp \
pieces.cpp \
rand.cpp \
sound.cpp \
splash.cpp \
tetris.cpp \

ifeq ($(TEST),true)
CPPFLAGS = -Werror
endif
CXXFLAGS = -std=c++20

include ../../psyqo.mk

%.o: %.hit
	$(PREFIX)-objcopy -I binary --set-section-alignment .data=4 --rename-section .data=.rodata,alloc,load,readonly,data,contents -O $(FORMAT) -B mips $< $@
