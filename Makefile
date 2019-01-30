rwildcard=$(wildcard $1$2) $(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2))

PACKAGES := libavcodec libavformat libavutil libswresample sdl2 zlib

CXXFLAGS := -std=c++2a
CPPFLAGS := `pkg-config --cflags $(PACKAGES)` -Isrc -Ithird_party -Ithird_party/imgui -Ithird_party/imgui/examples/libs/gl3w -Ithird_party/imgui/examples -Ithird_party/imgui_club

LDFLAGS := `pkg-config --libs $(PACKAGES)` -lstdc++fs -ldl -lGL
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

all: pcsx-redux

pcsx-redux: $(OBJECTS)
	@echo $(SRC_C)
	$(LD) -o $@ $? $(LDFLAGS)

%.o: %.c
	$(CC) -c -o $@ $? $(CPPFLAGS) $(CFLAGS)

%.o: %.cc
	$(CXX) -c -o $@ $? $(CPPFLAGS) $(CXXFLAGS)

%.o: %.cpp
	$(CXX) -c -o $@ $? $(CPPFLAGS) $(CXXFLAGS)
