rwildcard=$(wildcard $1$2) $(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2))
TARGET := pcsx-redux

PACKAGES := libavcodec libavformat libavutil libswresample sdl2 zlib glfw3

LOCALES := fr
UNAME_S := $(shell uname -s)

CXXFLAGS := -std=c++2a
CPPFLAGS := `pkg-config --cflags $(PACKAGES)`
CPPFLAGS += -Isrc
CPPFLAGS += -Ithird_party
CPPFLAGS += -Ithird_party/imgui
CPPFLAGS += -Ithird_party/imgui/examples/libs/gl3w
CPPFLAGS += -Ithird_party/imgui/examples
CPPFLAGS += -Ithird_party/imgui_club
CPPFLAGS += -O3
CPPFLAGS += -g

ifeq ($(UNAME_S),Darwin)
	CPPFLAGS += -mmacosx-version-min=10.15
	CPPFLAGS += -stdlib=libc++
endif

LDFLAGS := `pkg-config --libs $(PACKAGES)`

ifeq ($(UNAME_S),Darwin)
	LDFLAGS += -L/usr/local/Cellar/llvm/HEAD-e374798_1/lib
	LDFLAGS += -lc++ -framework GLUT -framework OpenGL -framework CoreFoundation 
	LDFLAGS += -mmacosx-version-min=10.15
else
	LDFLAGS += -lstdc++fs
	LDFLAGS += -lGL
endif

LDFLAGS += -ldl
LDFLAGS += -g

LD := $(CXX)

SRC_CC := $(call rwildcard,src/,*.cc)
SRC_CPP := $(wildcard third_party/imgui/*.cpp)
SRC_CPP += third_party/imgui/examples/imgui_impl_opengl3.cpp
SRC_CPP += third_party/imgui/examples/imgui_impl_glfw.cpp
SRC_CPP += third_party/imgui/misc/cpp/imgui_stdlib.cpp
SRC_CPP += third_party/ImGuiColorTextEdit/TextEditor.cpp
SRC_C := third_party/imgui/examples/libs/gl3w/GL/gl3w.c
OBJECTS := $(patsubst %.cc,%.o,$(SRC_CC))
OBJECTS += $(patsubst %.cpp,%.o,$(SRC_CPP))
OBJECTS += $(patsubst %.c,%.o,$(SRC_C))

all: dep $(TARGET)

$(TARGET): $(OBJECTS)
	$(LD) -o $@ $(OBJECTS) $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CPPFLAGS) $(CFLAGS)

%.o: %.cc
	$(CXX) -c -o $@ $< $(CPPFLAGS) $(CXXFLAGS)

%.o: %.cpp
	$(CXX) -c -o $@ $< $(CPPFLAGS) $(CXXFLAGS)

%.dep: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -M -MT $(addsuffix .o, $(basename $@)) -MF $@ $<

%.dep: %.cc
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -M -MT $(addsuffix .o, $(basename $@)) -MF $@ $<

%.dep: %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -M -MT $(addsuffix .o, $(basename $@)) -MF $@ $<

clean:
	rm -f $(OBJECTS) $(TARGET) $(DEPS)

gitclean:
	git clean -f -d -x
	git submodule foreach --recursive git clean -f -d -x

define msgmerge
msgmerge --update i18n/$(1).po i18n/pcsx-redux.pot
endef

regen-i18n:
	find src -name *.cc -or -name *.c -or -name *.h > pcsx-src-list.txt
	xgettext --keyword=_ --language=C++ --add-comments --sort-output -o i18n/pcsx-redux.pot --omit-header -f pcsx-src-list.txt
	rm pcsx-src-list.txt
	$(foreach l,$(LOCALES),$(call msgmerge,$(l)))

.PHONY: all clean gitclean regen-i18n

DEPS := $(patsubst %.cc,%.dep,$(SRC_CC))
DEPS += $(patsubst %.cpp,%.dep,$(SRC_CPP))
DEPS += $(patsubst %.c,%.dep,$(SRC_C))

dep: $(DEPS)

ifneq ($(MAKECMDGOALS), regen-i18n)
ifneq ($(MAKECMDGOALS), clean)
ifneq ($(MAKECMDGOALS), gitclean)
-include $(DEPS)
endif
endif
endif
