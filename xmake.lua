includes("third_party/luajit")

add_rules("mode.debug", "mode.release")

add_requires("capstone", "ffmpeg", "fmt", "freetype", "glfw", "libcurl", "libuv", "zlib")
set_languages("c++26")

target("pcsx-redux", function()
    add_includedirs(
        ".",
        "src",
        "third_party",
        "third_party/ELFIO",
        "third_party/gl3w",
        "third_party/imgui",
        "third_party/imgui/backends",
        "third_party/imgui/misc/cpp",
        "third_party/llhttp",
        "third_party/luajit/src",
        "third_party/luv/src",
        "third_party/luv/deps/lua-compat-5.3/c-api",
        "third_party/magic_enum/include",
        "third_party/md4c/src",
        "third_party/multipart-parser-c",
        "third_party/PEGTL/include",
        "third_party/tracy/public",
        "third_party/ucl",
        "third_party/ucl/include",
        "third_party/uriparser/include",
        "third_party/xbyak/xbyak",
        "third_party/zep/extensions",
        "third_party/zep/include",
        nil
    )

    add_files("third_party/imgui/*.cpp", { cxxflags = "-include src/forced-includes/imgui.h" })

    add_deps("luajit")
    add_packages("capstone", "ffmpeg", "fmt", "freetype", "glfw", "libcurl", "libuv", "zlib")
    add_files(
        "src/**/*.cc",
        "third_party/cq/reclaimer.cc",
        "third_party/clip/clip.cpp",
        "third_party/clip/image.cpp",
        "third_party/cueparser/*.c",
        "third_party/gl3w/GL/gl3w.c",
        "third_party/gl3w/GL/gl3w-throwers.cc",
        "third_party/iec-60908b/*.c",
        "third_party/ImFileDialog/ImFileDialog.cpp",
        "third_party/imgui/backends/imgui_impl_opengl3.cpp",
        "third_party/imgui/backends/imgui_impl_glfw.cpp",
        "third_party/imgui/misc/cpp/imgui_stdlib.cpp",
        "third_party/imgui/misc/freetype/imgui_freetype.cpp",
        "third_party/imgui_lua_bindings/imgui_lua_bindings.cpp",
        "third_party/imgui_md/imgui_md.cpp",
        "third_party/imgui_memory_editor/imgui_memory_editor.cpp",
        "third_party/llhttp/*.c",
        "third_party/lpeg/*.c",
        "third_party/lua-protobuf/pb.c",
        "third_party/luafilesystem/src/lfs.c",
        "third_party/luv/src/luv.c",
        "third_party/md4c/src/md4c.c",
        "third_party/multipart-parser-c/multipart_parser.c",
        "third_party/nanovg/src/nanovg.c",
        "third_party/ucl/src/n2e_99.c",
        "third_party/ucl/src/n2e_ds.c",
        "third_party/ucl/src/alloc.c",
        "third_party/uriparser/src/*.c",
        "third_party/zep/extensions/repl/mode_repl.cpp",
        "third_party/zep/src/*.cpp",
        "third_party/zep/src/mcommon/animation/timer.cpp",
        "third_party/zep/src/mcommon/file/path.cpp",
        "third_party/zep/src/mcommon/string/stringutils.cpp",
        nil
    )

    add_defines(
        "IMGUI_IMPL_OPENGL_LOADER_GL3W",
        "IMGUI_ENABLE_FREETYPE",
        "NVG_NO_STB",
        "PB_STATIC_API",
        "ZEP_FEATURE_CPP_FILE_SYSTEM",
        nil
    )

    if is_plat("macosx") then
        add_files("src/main/complain.mm", "third_party/clip/clip_osx.mm")
        add_frameworks("GLUT", "OpenGL", "CoreFoundation", "Cocoa")
    else
        add_files("third_party/clip/clip_x11.cpp")
        add_ldflags("-lstdc++fs", "-lGL", "-lX11", "-lxcb")
    end

end)
