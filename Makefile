TARGET := pcsx-redux
BUILD ?= Release
DESTDIR ?= /usr/local
CROSS ?= none

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
rwildcard = $(wildcard $1$2) $(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2))
CC_IS_CLANG := $(shell $(CC) --version | grep -q clang && echo true || echo false)

PACKAGES := capstone freetype2 glfw3 libavcodec libavformat libavutil libswresample libcurl libuv zlib
OPTIONAL_PACKAGES := md4c fmt libllhttp libluv liburiparser
OPTIONAL_LIBRARIES := multipart ucl

LOCALES := el es_ES fr ja pt_BR uk zh_CN

ifeq ($(wildcard third_party/imgui/imgui.h),)
HAS_SUBMODULES = false
else
HAS_SUBMODULES = true
endif

CXXFLAGS += -std=c++2b
CPPFLAGS += -I.
CPPFLAGS += -Isrc
CPPFLAGS += -Ithird_party
CPPFLAGS += -Ithird_party/ELFIO
CPPFLAGS_pkg_fmt += -Ithird_party/fmt/include/
CPPFLAGS += -Ithird_party/gl3w
CPPFLAGS += -Ithird_party/googletest/googletest/include
CPPFLAGS += -Ithird_party/imgui
CPPFLAGS += -Ithird_party/imgui/backends
CPPFLAGS += -Ithird_party/imgui/examples
CPPFLAGS += -Ithird_party/imgui/misc/cpp
CPPFLAGS += -Ithird_party/libelfin
CPPFLAGS_pkg_libllhttp += -Ithird_party/llhttp
CPPFLAGS += -Ithird_party/luajit/src
CPPFLAGS_pkg_libluv += -Ithird_party/luv/src
CPPFLAGS_pkg_libluv += -Ithird_party/luv/deps/lua-compat-5.3/c-api
CPPFLAGS += -Ithird_party/magic_enum/include/magic_enum
CPPFLAGS_pkg_md4c += -Ithird_party/md4c/src
CPPFLAGS_lib_multipart += -Ithird_party/multipart-parser-c
CPPFLAGS += -Ithird_party/tracy/public
CPPFLAGS_lib_ucl += -Ithird_party/ucl -Ithird_party/ucl/include
CPPFLAGS_pkg_liburiparser += -Ithird_party/uriparser/include
CPPFLAGS += -Ithird_party/zep/extensions
CPPFLAGS += -Ithird_party/zep/include
CPPFLAGS += -Ithird_party/xbyak/xbyak
CPPFLAGS += -g
CPPFLAGS += -DIMGUI_IMPL_OPENGL_LOADER_GL3W -DIMGUI_ENABLE_FREETYPE
CPPFLAGS += -DZEP_FEATURE_CPP_FILE_SYSTEM
CPPFLAGS += -DNVG_NO_STB
CPPFLAGS += -DPB_STATIC_API
IMGUI_CPPFLAGS += -include src/forced-includes/imgui.h

CPPFLAGS_Release += -O3
CPPFLAGS_Debug += -O0
CPPFLAGS_Coverage += -O0
ifeq ($(CC_IS_CLANG),true)
    CPPFLAGS_Coverage += -fprofile-instr-generate -fcoverage-mapping
else
    CPPFLAGS_Coverage += -fprofile-arcs -ftest-coverage
endif
CPPFLAGS_asan += -O1 -fsanitize=address -fno-omit-frame-pointer
CPPFLAGS_ubsan += -O1 -fsanitize=undefined -fno-omit-frame-pointer
CPPFLAGS_lto += -O3 -flto=auto -fno-fat-lto-objects -flto-partition=one
CPPFLAGS_ReleaseWithTracy += -O3 -DTRACY_ENABLE

ifeq ($(CC_IS_CLANG),true)
    LUAJIT_CFLAGS = -fno-stack-check
endif

ifeq ($(UNAME_S),Darwin)
    CPPFLAGS += -mmacosx-version-min=10.15
    CPPFLAGS += -stdlib=libc++
endif

LUAJIT_LDFLAGS := $(LDFLAGS)

ifeq ($(UNAME_S),Darwin)
    LDFLAGS += -lc++ -framework GLUT -framework OpenGL -framework CoreFoundation -framework Cocoa
    LDFLAGS += -mmacosx-version-min=10.15
else
    LDFLAGS += -lstdc++fs
    LDFLAGS += -lGL -lX11 -lxcb
endif

LDFLAGS += third_party/luajit/src/libluajit.a
LDFLAGS += -ldl
LDFLAGS += -g

ifeq ($(CC_IS_CLANG),true)
    LDFLAGS_Coverage += -fprofile-instr-generate -fcoverage-mapping
else
    LDFLAGS_Coverage += -fprofile-arcs -ftest-coverage
endif
LDFLAGS_asan += -fsanitize=address
LDFLAGS_ubsan += -fsanitize=undefined
LDFLAGS_lto += -O3 -flto=auto -flto-partition=one

CPPFLAGS += $(CPPFLAGS_$(BUILD)) -pthread
LDFLAGS += $(LDFLAGS_$(BUILD)) -pthread

ifeq ($(CROSS),arm64)
    CPPFLAGS += -fPIC -Wl,-rpath-link,/opt/cross/sysroot/usr/lib/aarch64-linux-gnu -L/opt/cross/sysroot/usr/lib/aarch64-linux-gnu
    LDFLAGS += -fPIC -Wl,-rpath-link,/opt/cross/sysroot/usr/lib/aarch64-linux-gnu -L/opt/cross/sysroot/usr/lib/aarch64-linux-gnu
endif

LD := $(CXX)

SRCS += $(call rwildcard,src/,*.cc)
SRCS_pkg_fmt += third_party/fmt/src/os.cc third_party/fmt/src/format.cc
IMGUI_SRCS += $(wildcard third_party/imgui/*.cpp)
VIXL_SRCS := $(call rwildcard, third_party/vixl/src,*.cc)
SRCS += $(IMGUI_SRCS)
SRCS += $(wildcard third_party/libelfin/*.cc)
SRCS += third_party/cq/reclaimer.cc
SRCS += third_party/clip/clip.cpp
SRCS += third_party/clip/image.cpp
SRCS += $(wildcard third_party/cueparser/*.c)
SRCS += third_party/gl3w/GL/gl3w.c
SRCS += third_party/gl3w/GL/gl3w-throwers.cc
SRCS += $(wildcard third_party/iec-60908b/*.c)
SRCS += third_party/ImFileDialog/ImFileDialog.cpp
SRCS += third_party/imgui/backends/imgui_impl_opengl3.cpp
SRCS += third_party/imgui/backends/imgui_impl_glfw.cpp
SRCS += third_party/imgui/misc/cpp/imgui_stdlib.cpp
SRCS += third_party/imgui/misc/freetype/imgui_freetype.cpp
SRCS += third_party/imgui_lua_bindings/imgui_lua_bindings.cpp
SRCS += third_party/imgui_md/imgui_md.cpp
SRCS += third_party/imgui_memory_editor/imgui_memory_editor.cpp
SRCS_pkg_libllhttp += $(wildcard third_party/llhttp/*.c)
SRCS += $(wildcard third_party/lpeg/*.c)
SRCS += third_party/lua-protobuf/pb.c
SRCS += third_party/luafilesystem/src/lfs.c
SRCS_pkg_libluv += third_party/luv/src/luv.c
SRCS_pkg_md4c += third_party/md4c/src/md4c.c
SRCS_lib_multipart += third_party/multipart-parser-c/multipart_parser.c
SRCS += third_party/nanovg/src/nanovg.c
SRCS_ReleaseWithTracy += third_party/tracy/public/TracyClient.cpp
SRCS_lib_ucl += third_party/ucl/src/n2e_99.c third_party/ucl/src/alloc.c
SRCS += $(wildcard third_party/uriparser/src/*.c)
SRCS += third_party/zep/extensions/repl/mode_repl.cpp
SRCS += $(wildcard third_party/zep/src/*.cpp)
SRCS += third_party/zep/src/mcommon/animation/timer.cpp
SRCS += third_party/zep/src/mcommon/file/path.cpp
SRCS += third_party/zep/src/mcommon/string/stringutils.cpp
ifeq ($(UNAME_S),Darwin)
    SRCS += src/main/complain.mm third_party/clip/clip_osx.mm
else
    SRCS += third_party/clip/clip_x11.cpp
endif
ifeq ($(UNAME_M),aarch64)
        SRCS += $(VIXL_SRCS)
        CPPFLAGS += -DVIXL_INCLUDE_TARGET_AARCH64 -DVIXL_CODE_BUFFER_MMAP
        CPPFLAGS += -Ithird_party/vixl/src -Ithird_party/vixl/src/aarch64
endif
ifeq ($(UNAME_M),arm64)
        SRCS += $(VIXL_SRCS)
        CPPFLAGS += -DVIXL_INCLUDE_TARGET_AARCH64 -DVIXL_CODE_BUFFER_MMAP
        CPPFLAGS += -Ithird_party/vixl/src -Ithird_party/vixl/src/aarch64
endif
ifeq ($(CROSS),arm64)
        SRCS += $(VIXL_SRCS)
        CPPFLAGS += -DVIXL_INCLUDE_TARGET_AARCH64 -DVIXL_CODE_BUFFER_MMAP
        CPPFLAGS += -Ithird_party/vixl/src -Ithird_party/vixl/src/aarch64
endif
SUPPORT_SRCS := src/support/container-file.cc src/support/file.cc src/support/mem4g.cc src/support/zfile.cc
SUPPORT_SRCS += src/supportpsx/adpcm.cc src/supportpsx/binloader.cc src/supportpsx/iec-60908b.cc src/supportpsx/iso9660-builder.cc src/supportpsx/ps1-packer.cc
SUPPORT_SRCS += third_party/fmt/src/os.cc third_party/fmt/src/format.cc
SUPPORT_SRCS += third_party/ucl/src/n2e_99.c third_party/ucl/src/alloc.c
SUPPORT_SRCS += $(wildcard third_party/iec-60908b/*.c)
LIBS := third_party/luajit/src/libluajit.a

TOOLS = authoring exe2elf exe2iso modconv ps1-packer psyq-obj-parser

##############################################################################

SRCS += $(SRCS_$(BUILD))

define CHECK_PKG
ifeq ($(shell pkg-config --exists $(1) && echo true || echo false),true)
PACKAGES += $(1)
else
CPPFLAGS += $(CPPFLAGS_pkg_$(1))
LDFLAGS += $(LDFLAGS_pkg_$(1))
SRCS += $(SRCS_pkg_$(1))
endif
endef

define CHECK_LIB
ifeq ($(shell echo "int main(){}" | gcc -x c - -l$(1) -Wl,--no-as-needed -Wl,--unresolved-symbols=ignore-all -Wl,--no-undefined -o /dev/null 1> /dev/null 2> /dev/null && echo true || echo false),true)
LDFLAGS += -l$(1)
else
CPPFLAGS += $(CPPFLAGS_lib_$(1))
LDFLAGS += $(LDFLAGS_lib_$(1))
SRCS += $(SRCS_lib_$(1))
endif
endef

$(foreach pkg,$(OPTIONAL_PACKAGES),$(eval $(call CHECK_PKG,$(pkg))))
$(foreach lib,$(OPTIONAL_LIBRARIES),$(eval $(call CHECK_LIB,$(lib))))

CPPFLAGS_PKGCONFIG := $(shell pkg-config --cflags $(PACKAGES))
LDFLAGS_PKGCONFIG := $(shell pkg-config --libs $(PACKAGES))

CPPFLAGS += $(CPPFLAGS_PKGCONFIG)
LDFLAGS += $(LDFLAGS_PKGCONFIG)

OBJECTS += $(addprefix objs/$(BUILD)/,$(patsubst %.c,%.o,$(filter %.c,$(SRCS))))
OBJECTS += $(addprefix objs/$(BUILD)/,$(patsubst %.cc,%.o,$(filter %.cc,$(SRCS))))
OBJECTS += $(addprefix objs/$(BUILD)/,$(patsubst %.cpp,%.o,$(filter %.cpp,$(SRCS))))
OBJECTS += $(addprefix objs/$(BUILD)/,$(patsubst %.mm,%.o,$(filter %.mm,$(SRCS))))
SUPPORT_OBJECTS := $(addprefix objs/$(BUILD)/,$(patsubst %.c,%.o,$(filter %.c,$(SUPPORT_SRCS))))
SUPPORT_OBJECTS += $(addprefix objs/$(BUILD)/,$(patsubst %.cc,%.o,$(filter %.cc,$(SUPPORT_SRCS))))
NONMAIN_OBJECTS := $(filter-out objs/$(BUILD)/src/main/mainthunk.o,$(OBJECTS))
IMGUI_OBJECTS := $(addprefix objs/$(BUILD)/,$(patsubst %.cpp,%.o,$(filter %.cpp,$(IMGUI_SRCS))))
VIXL_OBJECTS := $(addprefix objs/$(BUILD)/,$(patsubst %.cc,%.o,$(filter %.cc,$(VIXL_SRCS))))
$(IMGUI_OBJECTS): EXTRA_CPPFLAGS := $(IMGUI_CPPFLAGS)

TESTS_SRC := $(call rwildcard,tests/,*.cc)
TESTS := $(patsubst %.cc,%,$(TESTS_SRC))

DEPS += $(addprefix deps/$(BUILD)/,$(patsubst %.c,%.dep,$(filter %.c,$(SRCS))))
DEPS += $(addprefix deps/$(BUILD)/,$(patsubst %.cc,%.dep,$(filter %.cc,$(SRCS))))
DEPS += $(addprefix deps/$(BUILD)/,$(patsubst %.cpp,%.dep,$(filter %.cpp,$(SRCS))))

CP ?= cp
MKDIRP ?= mkdir -p

all: check_submodules dep $(TARGET)

ifeq ($(HAS_SUBMODULES),true)
check_submodules:
	@true

else
check_submodules:
	@echo "You need to clone this repository recursively, in order to get its submodules."
	@false
endif

strip: all
	strip $(TARGET)

openbios:
	$(MAKE) $(MAKEOPTS) -C src/mips/openbios

install: all strip
	$(MKDIRP) $(DESTDIR)/bin
	$(MKDIRP) $(DESTDIR)/share/applications
	$(MKDIRP) $(DESTDIR)/share/icons/hicolor/256x256/apps
	$(MKDIRP) $(DESTDIR)/share/pcsx-redux/fonts
	$(MKDIRP) $(DESTDIR)/share/pcsx-redux/i18n
	$(MKDIRP) $(DESTDIR)/share/pcsx-redux/resources
	$(CP) $(TARGET) $(DESTDIR)/bin
	$(CP) resources/pcsx-redux.desktop $(DESTDIR)/share/applications
	convert resources/pcsx-redux.ico[0] -alpha on -background none $(DESTDIR)/share/icons/hicolor/256x256/apps/pcsx-redux.png
	$(CP) third_party/noto/* $(DESTDIR)/share/pcsx-redux/fonts
	$(CP) i18n/*.po $(DESTDIR)/share/pcsx-redux/i18n
	$(CP) resources/*.ico $(DESTDIR)/share/pcsx-redux/resources
	$(CP) third_party/SDL_GameControllerDB/LICENSE $(DESTDIR)/share/pcsx-redux/resources
	$(CP) third_party/SDL_GameControllerDB/gamecontrollerdb.txt $(DESTDIR)/share/pcsx-redux/resources

install-openbios: openbios
	$(MKDIRP) $(DESTDIR)/share/pcsx-redux/resources
	$(CP) src/mips/openbios/openbios.bin $(DESTDIR)/share/pcsx-redux/resources
	zip -j src/mips/openbios/openbios.zip src/mips/openbios/openbios.elf

appimage:
	rm -rf AppDir
	DESTDIR=AppDir/usr $(MAKE) $(MAKEOPTS) install
	sed -i s:/usr/bin/:: AppDir/usr/share/applications/pcsx-redux.desktop
	linuxdeploy -v 3 --appdir=AppDir -e AppDir/usr/bin/pcsx-redux -d AppDir/usr/share/applications/pcsx-redux.desktop -i AppDir/usr/share/icons/hicolor/256x256/apps/pcsx-redux.png -o appimage
	mv PCSX-Redux-x86_64.AppImage PCSX-Redux-HEAD-x86_64.AppImage

ifeq ($(CROSS),arm64)
third_party/luajit/src/libluajit.a:
	$(MAKE) $(MAKEOPTS) -C third_party/luajit/src amalg HOST_CC=cc CROSS=aarch64-linux-gnu- TARGET_CFLAGS=--sysroot=/opt/cross/sysroot BUILDMODE=static CFLAGS=$(LUAJIT_CFLAGS) LDFLAGS=$(LUAJIT_LDFLAGS) XCFLAGS="-DLUAJIT_ENABLE_GC64 -DLUAJIT_ENABLE_LUA52COMPAT" MACOSX_DEPLOYMENT_TARGET=10.15
else
third_party/luajit/src/libluajit.a:
	$(MAKE) $(MAKEOPTS) -C third_party/luajit/src amalg CC=$(CC) BUILDMODE=static CFLAGS=$(LUAJIT_CFLAGS) LDFLAGS=$(LUAJIT_LDFLAGS) XCFLAGS="-DLUAJIT_ENABLE_GC64 -DLUAJIT_ENABLE_LUA52COMPAT" MACOSX_DEPLOYMENT_TARGET=10.15
endif

bins/$(BUILD)/$(TARGET): $(OBJECTS) $(LIBS)
	@$(MKDIRP) $(dir $@)
	$(LD) -o $@ $(OBJECTS) $(LIBS) $(LDFLAGS)

$(TARGET): bins/$(BUILD)/$(TARGET)
	$(CP) $< $@

objs/$(BUILD)/%.o: %.c
	@$(MKDIRP) $(dir $@)
	$(CC) -c -o $@ $< $(CPPFLAGS) $(EXTRA_CPPFLAGS) $(CFLAGS)

objs/$(BUILD)/%.o: %.cc
	@$(MKDIRP) $(dir $@)
	$(CXX) -c -o $@ $< $(CPPFLAGS) $(EXTRA_CPPFLAGS) $(CXXFLAGS)

objs/$(BUILD)/%.o: %.cpp
	@$(MKDIRP) $(dir $@)
	$(CXX) -c -o $@ $< $(CPPFLAGS) $(EXTRA_CPPFLAGS) $(CXXFLAGS)

objs/$(BUILD)/%.o: %.mm
	@$(MKDIRP) $(dir $@)
	$(CC) -c -o $@ $< $(CPPFLAGS) $(EXTRA_CPPFLAGS) $(CFLAGS)

deps/$(BUILD)/%.dep: third_party/luajit/src/luajit.h %.c
	@$(MKDIRP) $(dir $@)
	$(CC) $(CPPFLAGS) $(EXTRA_CPPFLAGS) $(CFLAGS) -M -MT $(addprefix objs/$(BUILD)/,$(addsuffix .o,$(basename $@))) -MF $@ $<

deps/$(BUILD)/%.dep: third_party/luajit/src/luajit.h %.cc
	@$(MKDIRP) $(dir $@)
	$(CXX) $(CPPFLAGS) $(EXTRA_CPPFLAGS) $(CXXFLAGS) -M -MT $(addprefix objs/$(BUILD)/,$(addsuffix .o,$(basename $@))) -MF $@ $<

deps/$(BUILD)/%.dep: third_party/luajit/src/luajit.h %.cpp
	@$(MKDIRP) $(dir $@)
	$(CXX) $(CPPFLAGS) $(EXTRA_CPPFLAGS) $(CXXFLAGS) -M -MT $(addprefix objs/$(BUILD)/,$(addsuffix .o,$(basename $@))) -MF $@ $<

objs/$(BUILD)/gtest-all.o: $(wildcard third_party/googletest/googletest/src/*.cc)
	@$(MKDIRP) $(dir $@)
	$(CXX) -O3 -g $(CXXFLAGS) -Ithird_party/googletest/googletest -Ithird_party/googletest/googletest/include -c third_party/googletest/googletest/src/gtest-all.cc -o objs/$(BUILD)/gtest-all.o

objs/$(BUILD)/gtest_main.o: third_party/googletest/googletest/src/gtest_main.cc
	@$(MKDIRP) $(dir $@)
	$(CXX) -O3 -g $(CXXFLAGS) -Ithird_party/googletest/googletest -Ithird_party/googletest/googletest/include -c third_party/googletest/googletest/src/gtest_main.cc -o objs/$(BUILD)/gtest_main.o

clean:
	rm -f $(OBJECTS) $(TOOLS) $(TARGET) bins/$(BUILD)/$(TARGET) $(addprefix bins/$(BUILD)/,$(TOOLS)) $(DEPS) objs/$(BUILD)/gtest-all.o objs/$(BUILD)/gtest_main.o
	$(MAKE) -C third_party/luajit clean MACOSX_DEPLOYMENT_TARGET=10.15

cleanall:
	rm -rf bins objs deps $(TOOLS) $(TARGET)
	$(MAKE) -C third_party/luajit clean MACOSX_DEPLOYMENT_TARGET=10.15

gitclean:
	git clean -f -d -x
	git submodule foreach --recursive git clean -f -d -x

define msgmerge
-msgmerge --update i18n/$(1).po i18n/pcsx-redux.pot

endef

regen-i18n:
	find src -name *.cc -or -name *.c -or -name *.h | sort -u > pcsx-src-list.txt
	xgettext --from-code=utf-8 --keyword=_ --keyword=f_ --keyword=l_ --language=C++ --add-comments --sort-by-file -o i18n/pcsx-redux.pot -f pcsx-src-list.txt
	find src -name *.lua | sort -u > pcsx-src-list.txt
	xgettext --from-code=utf-8 --keyword=t_ --language=Lua --join-existing --sort-by-file -o i18n/pcsx-redux.pot -f pcsx-src-list.txt
	sed '/POT-Creation-Date/d' -i i18n/pcsx-redux.pot
	rm pcsx-src-list.txt
	$(foreach l,$(LOCALES),$(call msgmerge,$(l)))

bins/$(BUILD)/pcsx-redux-tests: $(foreach t,$(TESTS),$(t).o) $(NONMAIN_OBJECTS) $(LIBS) objs/$(BUILD)/gtest-all.o objs/$(BUILD)/gtest_main.o
	@$(MKDIRP) $(dir $@)
	$(LD) -o bins/$(BUILD)/pcsx-redux-tests $(NONMAIN_OBJECTS) $(LIBS) objs/$(BUILD)/gtest-all.o objs/$(BUILD)/gtest_main.o $(foreach t,$(TESTS),$(t).o) -Ithird_party/googletest/googletest/include $(LDFLAGS)

pcsx-redux-tests: check_submodules bins/$(BUILD)/pcsx-redux-tests
	$(CP) bins/$(BUILD)/pcsx-redux-tests pcsx-redux-tests

runtests: pcsx-redux-tests
	./pcsx-redux-tests

define TOOLDEF
bins/$(BUILD)/$(1): $(SUPPORT_OBJECTS) objs/$(BUILD)/tools/$(1)/$(1).o
	@$(MKDIRP) $(dir bins/$(BUILD)/$(1))
	$(LD) -o bins/$(BUILD)/$(1) $(CPPFLAGS) $(CXXFLAGS) $(SUPPORT_OBJECTS) objs/$(BUILD)/tools/$(1)/$(1).o -static -lz

$(1): check_submodules bins/$(BUILD)/$(1)
	$(CP) bins/$(BUILD)/$(1) $(1)

endef

$(foreach tool,$(TOOLS),$(eval $(call TOOLDEF,$(tool))))

tools: check_submodules dep $(TOOLS)

dep: check_submodules $(DEPS)

.PHONY: all dep clean gitclean regen-i18n runtests openbios install strip appimage tools $(TOOLS) $(TARGET)

ifneq ($(MAKECMDGOALS), regen-i18n)
ifneq ($(MAKECMDGOALS), clean)
ifneq ($(MAKECMDGOALS), cleanall)
ifneq ($(MAKECMDGOALS), gitclean)
ifeq ($(HAS_SUBMODULES), true)
-include $(DEPS)
endif
endif
endif
endif
endif

third_party/luajit/src/lua.hpp: third_party/luajit/src/luajit.h

third_party/luajit/src/luajit.h: third_party/luajit/src/libluajit.a
