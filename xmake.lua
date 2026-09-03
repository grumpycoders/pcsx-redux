-- LuaJIT's build is host-arch-gated (its minilua/buildvm targets are guarded on
-- x64/arm64/mips64) and its VM is per-arch assembly, so there is nothing for it
-- to do on wasm. The wasm arm uses PUC-Lua 5.4 through third_party/puc-lua-compat
-- instead - a SECOND Lua backend, not a migration off LuaJIT.
if not is_plat("wasm") then
    includes("third_party/luajit")
end

add_rules("mode.debug", "mode.release")

-- WASM PROBE (local, uncommitted): libuv is the ONLY package xmake reports as
-- unsupported on wasm/wasm32, and libav is pkgconfig-on-the-host. Both are
-- already scoped OUT of v1. Dropped here purely to let configure proceed far
-- enough to enumerate the NEXT layer of blockers.
if is_plat("wasm") then
    -- The packages have to be built with the SAME threading model as the target.
    -- -pthread implies -matomics -mbulk-memory, and wasm-ld refuses to mix:
    -- "--shared-memory is disallowed by sfnt.c.o because it was not compiled
    -- with 'atomics' or 'bulk-memory' features." freetype and SDL3 come from
    -- xmake packages built in a separate compilation that does not see the
    -- target's flags, so they must be told separately. Same shape as the
    -- exception-model constraint above: the packages pin the ABI, not us.
    add_requireconfs("*", {configs = {cxflags = "-pthread", cflags = "-pthread",
                                      ldflags = "-pthread"}})
    add_requires("capstone", "fmt", "freetype", "libsdl3", "zlib")
else
    add_requires("capstone", "fmt", "freetype", "libcurl", "libsdl3", "libuv", "zlib")
end

-- Only four of ffmpeg's libraries are used, and asking for "ffmpeg" wholesale
-- never resolves to the system copy: that package requires all eight pkg-config
-- modules, and libpostproc is GPL-only and so isn't packaged on Ubuntu at all.
-- The result is ffmpeg getting built from source on every clean checkout. These
-- are the same four names the Makefile's PACKAGES already asks for.
if not is_plat("wasm") then
add_requires("pkgconfig::libavcodec", "pkgconfig::libavformat",
             "pkgconfig::libavutil", "pkgconfig::libswresample")
end

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
        -- WASM PROBE (local): PUC-Lua headers + a luajit.h shim must come FIRST
        -- so "lua.hpp" resolves to the compat one rather than LuaJIT's.
        (is_plat("wasm") and "third_party/puc-lua-compat" or "third_party/luajit/src"),
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

    -- NOT folded into the list above: a nil in the middle of a vararg call
    -- truncates it, so `(cond and dir or nil)` inline would silently drop every
    -- includedir after it on the non-wasm arm.
    if is_plat("wasm") then
        -- uv-wasm-stub declares exactly uv_loop_t / uv_run / uv_loop_init /
        -- uv_loop_close and #errors outside __EMSCRIPTEN__. That is the whole of
        -- the core's libuv surface once the three servers and uvfile are dropped.
        -- Anything wanting a real handle, timer, poll or async MUST fail to
        -- compile against it rather than get a silent no-op: a no-op in an async
        -- layer is a runtime-only failure on a build with no debugger.
        add_includedirs("third_party/uv-wasm-stub")
    end

    add_files("third_party/imgui/*.cpp", { cxxflags = "-include src/forced-includes/imgui.h" })

    if is_plat("wasm") then
        add_packages("capstone", "fmt", "freetype", "libsdl3", "zlib")

        -- ===== THE SECOND LUA BACKEND =====
        -- PUC-Lua 5.4.7 + luaffifb + libffi, replacing LuaJIT on wasm only.
        -- Redux's own Lua corpus and its C++ host layer are unchanged; this is a
        -- build-time backend choice, not a migration off LuaJIT.
        --
        -- Four PUC-Lua sources are overridden rather than compiled from the
        -- submodule: linit.c auto-opens ffi so `require 'ffi'` works, llex.c
        -- ignores LL/ULL suffixes, and lobject.c + lvm.c make (void*)NULL == nil
        -- compare true. onelua/luac/ltests are drivers we do not want, and lua.c
        -- would give us a second main().
        local LUA_SKIP = {["linit.c"] = true, ["llex.c"] = true, ["lobject.c"] = true,
                          ["lvm.c"] = true, ["onelua.c"] = true, ["luac.c"] = true,
                          ["ltests.c"] = true, ["lua.c"] = true}
        for _, f in ipairs(os.files("third_party/lua/*.c")) do
            if not LUA_SKIP[path.filename(f)] then add_files(f) end
        end
        add_files("third_party/lua-wasm-patch/*.c")

        add_files("third_party/luaffifb/call.c", "third_party/luaffifb/ctype.c",
                  "third_party/luaffifb/ffi.c", "third_party/luaffifb/ffi_complex.c",
                  "third_party/luaffifb/lua.c", "third_party/luaffifb/parser.c")

        -- libffi's configured output is not relocatable, which is why lua-ffi-wasm
        -- compiles these eight directly rather than linking a built library. There
        -- is no wasm arm in xmake-repo's libffi package either (checked: aui, botan
        -- and chipmunk2d do carry wasm arms, so that absence is real).
        for _, f in ipairs({"prep_cif", "types", "raw_api", "java_raw_api",
                            "closures", "tramp", "debug", "wasm/ffi"}) do
            add_files("third_party/libffi/src/" .. f .. ".c")
        end

        add_includedirs(
            "third_party/lua",                  -- pristine PUC-Lua 5.4.7 headers
            "third_party/luaffifb",             -- so "luaffifb/ffi.h" resolves
            "third_party/libffi-wasm-config",   -- fficonfig.h, configure-generated
                                                -- and absent upstream; MUST precede
                                                -- the submodule's own include dir
            "third_party/libffi/src/wasm",      -- the wasm ffitarget.h, which is
                                                -- pristine - the x86 one is the
                                                -- wrongly-autodetected header, so
                                                -- ORDER is the whole correction
            "third_party/libffi/include",
            "third_party/libffi/src")
        -- CALL_WITH_LIBFFI swaps luaffifb's DynASM call path, which cannot target
        -- wasm, for libffi's signature-keyed dispatch.
        add_defines("CALL_WITH_LIBFFI", "LUA_COMPAT_5_3", "PCSX_GL3W_TRACE_MISSING")
        -- The link had NO memory settings at all, so it took emscripten's
        -- defaults: a 16 MB heap with growth OFF. Redux is past that before it
        -- draws a frame - imgui plus freetype's atlas plus the 2 MB PSX RAM, the
        -- 8 MB expansion and the read/write LUTs - so it aborted at startup.
        -- MSAN's 1.5 GB is NOT part of this: it is lazily calloc'd in msanInit
        -- and never touched unless the user turns it on.
        --
        -- INITIAL_MEMORY is deliberately generous rather than minimal: with
        -- growth enabled every expansion copies the whole heap, and there is no
        -- reason to pay that repeatedly during startup.
        -- C++ EXCEPTIONS ARE REQUIRED, and this is NOT what v1 scoped out.
        -- The v1 note says "drop C++ exception support", but that was about
        -- Support.extra.safeFFI - the pcall net catching C++ exceptions crossing
        -- the LUA barrier. Redux's own C++ throws internally regardless;
        -- gl3w-throwers.cc exists to do exactly that. Without this the first
        -- throw aborts with "Exception thrown, but exception catching is not
        -- enabled", which is what the browser did.
        --
        -- THE JS-BASED MODEL, NOT -fwasm-exceptions, AND THE PACKAGES DECIDE
        -- THAT. Native wasm EH is the faster one and was the first thing tried.
        -- It forces SUPPORT_LONGJMP=wasm, emcc rejects
        -- "SUPPORT_LONGJMP=emscripten is not compatible with -fwasm-exceptions"
        -- outright, and freetype's ftbase.c/sfnt.c come from an xmake PACKAGE
        -- built in a separate compilation that never sees these flags - so they
        -- carry JS-lowered setjmp and the link dies on an undefined
        -- emscripten_longjmp. The EH model is therefore not a free choice: it is
        -- pinned by whatever the packages were built with. Moving to wasm EH
        -- means rebuilding freetype (and anything else using setjmp) to match.
        -- THREADS. Pixel, 2026-09-02: "The SPU can't run on the main loop,
        -- especially with all of the pending changes I have." So std::thread has
        -- to work rather than be scoped out: spu.cc:914 starts MainThread and
        -- sdlaudio.cc:292 starts nullThread, and without -pthread both fail at
        -- construction with "thread constructor failed: Not supported".
        --
        -- This needs SharedArrayBuffer, so the page must be served
        -- cross-origin-isolated (COOP: same-origin + COEP: require-corp) or the
        -- module will not even instantiate. That is a SERVING requirement, not a
        -- build one, and it is easy to miss because a non-isolated page fails
        -- late and unhelpfully.
        add_cxflags("-fexceptions", "-pthread", {force = true})
        add_ldflags("-fexceptions", "-sNO_DISABLE_EXCEPTION_CATCHING",
                    "-pthread", "-sPTHREAD_POOL_SIZE=8",
                    -- The browser main thread cannot block, and Redux's main
                    -- thread joins workers. PROXY_TO_PTHREAD moves main() itself
                    -- onto a worker so blocking there is legal.
                    "-sPROXY_TO_PTHREAD=1", {force = true})
        add_ldflags("-sALLOW_MEMORY_GROWTH=1", "-sINITIAL_MEMORY=512MB",
                    "-sMAXIMUM_MEMORY=4GB",
                    -- 64 kB by default in current emscripten, which nothing in a
                    -- C++ UI with recursive parsers survives.
                    "-sSTACK_SIZE=8MB",
                    -- ASSERTIONS is what turned the first abort from "OOM, build
                    -- with -sASSERTIONS" into something readable. Keep it until
                    -- the thing renders; it is a debug build either way.
                    "-sASSERTIONS=1",
                    -- -g2 keeps the wasm name section, so a RuntimeError stack
                    -- shows function names instead of wasm-function[6585]. No
                    -- source maps, no codegen change; drop it once this renders.
                    "-g",
                    "-sEXIT_RUNTIME=0",
                    -- gl3w and imgui's GL3 backend both want real ES3/WebGL2.
                    "-sMIN_WEBGL_VERSION=2", "-sMAX_WEBGL_VERSION=2", "-sFULL_ES3=1",
                    "-Wl,--error-limit=0", {force = true})
    else
    add_deps("luajit")
    add_packages("capstone", "fmt", "freetype", "libcurl", "libsdl3", "libuv", "zlib",
                 "pkgconfig::libavcodec", "pkgconfig::libavformat",
                 "pkgconfig::libavutil", "pkgconfig::libswresample")
    end
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
        "third_party/imgui/backends/imgui_impl_sdl3.cpp",
        "third_party/imgui/misc/cpp/imgui_stdlib.cpp",
        "third_party/imgui/misc/freetype/imgui_freetype.cpp",
        "third_party/imgui_lua_bindings/imgui_lua_bindings.cpp",
        "third_party/imgui_md/imgui_md.cpp",
        "third_party/imgui_memory_editor/imgui_memory_editor.cpp",
        "third_party/llhttp/*.c",
        "third_party/lpeg/*.c",
        "third_party/lua-protobuf/pb.c",
        "third_party/luafilesystem/src/lfs.c",
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
    -- src/mips is the nugget submodule, built by its own toolchain.
    remove_files("src/mips/**")

    -- luv is the Lua libuv binding and v1 wasm has no libuv. It is the ONE
    -- exception to putting the guard in the source: luvit/luv is an upstream
    -- submodule we do not control, so a whole-file #ifdef there would mean
    -- forking a third repository.
    --
    -- ITS OWN BLOCK, NOT AN INLINE CONDITIONAL IN THE LIST ABOVE. I put
    -- `(not is_plat("wasm")) and "..." or nil` in that list and it evaluated to a
    -- bare nil on wasm, which TRUNCATES a vararg call - silently dropping zep,
    -- nanovg, ucl, uriparser and everything else after it. 159 undefined symbols
    -- and 3661 errors, from a footgun documented in a comment forty lines up in
    -- this same file.
    if not is_plat("wasm") then
        add_files("third_party/luv/src/luv.c")
    end

    -- v1 wasm scope is expressed in the SOURCES, not here. Every file below that
    -- belongs to a dropped feature wraps its whole body in one #ifdef, the way
    -- sharedmem-unix.cc / sharedmem-windows.cc and version-linux.cc already do,
    -- and the specialised wasm implementations sit beside them: binpath-wasm.cc,
    -- version-wasm.cc, DynaRec_none/recompiler.cc, third_party/clip/clip_wasm.cpp.
    -- So src/**/*.cc stays a full glob on every platform and nothing is removed.

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
    elseif is_plat("wasm") then
        -- A browser has no X11 and no synchronous host clipboard, so clip_wasm
        -- is a process-local board: copy and paste work inside the app, nothing
        -- crosses to the host. GL comes from emscripten's WebGL2 shim at link.
        add_files("third_party/clip/clip_wasm.cpp")
    else
        add_files("third_party/clip/clip_x11.cpp")
        add_ldflags("-lstdc++fs", "-lGL", "-lX11", "-lxcb")
    end

end)
