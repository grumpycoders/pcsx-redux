rwildcard=$(wildcard $1$2) $(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2))
TARGET := pcsx-redux
BUILD ?= Release

PACKAGES := glfw3 libavcodec libavformat libavutil libswresample libuv sdl2 zlib

LOCALES := fr
UNAME_S := $(shell uname -s)

CXXFLAGS := -std=c++2a
CPPFLAGS := `pkg-config --cflags $(PACKAGES)`
CPPFLAGS += -Isrc
CPPFLAGS += -Ithird_party
CPPFLAGS += -Ithird_party/fmt/include/
CPPFLAGS += -Ithird_party/googletest/googletest/include
CPPFLAGS += -Ithird_party/imgui
CPPFLAGS += -Ithird_party/imgui/examples/libs/gl3w
CPPFLAGS += -Ithird_party/imgui/examples
CPPFLAGS += -Ithird_party/imgui/misc/cpp
CPPFLAGS += -Ithird_party/imgui_club
CPPFLAGS += -Ithird_party/libelfin
CPPFLAGS += -Ithird_party/zstr/src
CPPFLAGS += -g
CPPFLAGS += -DIMGUI_IMPL_OPENGL_LOADER_GL3W

CPPFLAGS_Release += -O3

CPPFLAGS_Debug += -O0

CPPFLAGS_Coverage += -O0
CPPFLAGS_Coverage += -fprofile-instr-generate -fcoverage-mapping

ifeq ($(UNAME_S),Darwin)
	CPPFLAGS += -mmacosx-version-min=10.15
	CPPFLAGS += -stdlib=libc++
endif

LDFLAGS := `pkg-config --libs $(PACKAGES)`

ifeq ($(UNAME_S),Darwin)
	LDFLAGS += -lc++ -framework GLUT -framework OpenGL -framework CoreFoundation 
	LDFLAGS += -mmacosx-version-min=10.15
else
	LDFLAGS += -lstdc++fs
	LDFLAGS += -lGL
endif

LDFLAGS += -ldl
LDFLAGS += -g

LDFLAGS_Coverage += -fprofile-instr-generate -fcoverage-mapping

CPPFLAGS += $(CPPFLAGS_$(BUILD))
LDFLAGS += $(LDFLAGS_$(BUILD))

LD := $(CXX)

SRCS := $(call rwildcard,src/,*.cc)
SRCS += $(wildcard third_party/fmt/src/*.cc)
SRCS += $(wildcard third_party/libelfin/*.cc)
SRCS += $(wildcard third_party/imgui/*.cpp)
SRCS += third_party/imgui/examples/imgui_impl_opengl3.cpp
SRCS += third_party/imgui/examples/imgui_impl_glfw.cpp
SRCS += third_party/imgui/misc/cpp/imgui_stdlib.cpp
SRCS += third_party/ImGuiColorTextEdit/TextEditor.cpp
SRCS += third_party/imgui/examples/libs/gl3w/GL/gl3w.c
OBJECTS := $(patsubst %.c,%.o,$(filter %.c,$(SRCS)))
OBJECTS += $(patsubst %.cc,%.o,$(filter %.cc,$(SRCS)))
OBJECTS += $(patsubst %.cpp,%.o,$(filter %.cpp,$(SRCS)))

NONMAIN_OBJECTS := $(filter-out src/main/main.o,$(OBJECTS))

TESTS_SRC := $(call rwildcard,tests/,*.cc)
TESTS := $(patsubst %.cc,%,$(TESTS_SRC))

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
	rm -f $(OBJECTS) $(TARGET) $(DEPS) gtest-all.o

gtest-all.o: $(wildcard third_party/googletest/googletest/src/*.cc)
	$(CXX) -O3 -g $(CXXFLAGS) -Ithird_party/googletest/googletest -Ithird_party/googletest/googletest/include -c third_party/googletest/googletest/src/gtest-all.cc

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

pcsx-redux-tests: $(foreach t,$(TESTS),$(t).o) $(NONMAIN_OBJECTS) gtest-all.o
	$(LD) -o pcsx-redux-tests $(NONMAIN_OBJECTS) gtest-all.o $(foreach t,$(TESTS),$(t).o) -Ithird_party/googletest/googletest/include third_party/googletest/googletest/src/gtest_main.cc $(LDFLAGS)

runtests: pcsx-redux-tests
	./pcsx-redux-tests

.PHONY: all dep clean gitclean regen-i18n runtests

DEPS += $(patsubst %.c,%.dep,$(filter %.c,$(SRCS)))
DEPS := $(patsubst %.cc,%.dep,$(filter %.cc,$(SRCS)))
DEPS += $(patsubst %.cpp,%.dep,$(filter %.cpp,$(SRCS)))

dep: $(DEPS)

ifneq ($(MAKECMDGOALS), regen-i18n)
ifneq ($(MAKECMDGOALS), clean)
ifneq ($(MAKECMDGOALS), gitclean)
-include $(DEPS)
endif
endif
endif
