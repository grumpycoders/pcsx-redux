rwildcard=$(wildcard $1$2) $(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2))
TARGET := pcsx-redux

PACKAGES := libavcodec libavformat libavutil libswresample sdl2 zlib

CXXFLAGS := -std=c++2a
CPPFLAGS := `pkg-config --cflags $(PACKAGES)`
CPPFLAGS += -Isrc
CPPFLAGS += -Ithird_party
CPPFLAGS += -Ithird_party/imgui
CPPFLAGS += -Ithird_party/imgui/examples/libs/gl3w
CPPFLAGS += -Ithird_party/imgui/examples
CPPFLAGS += -Ithird_party/imgui_club
CPPFLAGS += -O3

LDFLAGS := `pkg-config --libs $(PACKAGES)`
LDFLAGS += -lstdc++fs
LDFLAGS += -ldl
LDFLAGS += -lGL

LD := $(CXX)

SRC_CC := $(call rwildcard,src/,*.cc)
SRC_CPP := $(wildcard third_party/imgui/*.cpp)
SRC_CPP += third_party/imgui/examples/imgui_impl_opengl3.cpp
SRC_CPP += third_party/imgui/examples/imgui_impl_sdl.cpp
SRC_CPP += third_party/imgui/misc/cpp/imgui_stdlib.cpp
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

DEPS := $(patsubst %.cc,%.dep,$(SRC_CC))
DEPS += $(patsubst %.cpp,%.dep,$(SRC_CPP))
DEPS += $(patsubst %.c,%.dep,$(SRC_C))

dep: $(DEPS)

ifneq ($(MAKECMDGOALS), clean)
ifneq ($(MAKECMDGOALS), gitclean)
-include $(DEPS)
endif
endif
