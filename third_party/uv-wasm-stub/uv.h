/* Minimal libuv stand-in for the wasm build. WASM PROBE, local, NOT a libuv port.
 *
 * WHY A STUB AND NOT A PORT: libuv has no wasm target and the reason is
 * architectural, not build plumbing. Its loop is backed by epoll / kqueue /
 * IOCP / event ports, none of which exist in a browser sandbox, and the browser
 * already owns an event loop that libuv wants to own. That is the same class of
 * blocker as LuaJIT's per-arch DynASM VM.
 *
 * WHY A STUB IS ENOUGH FOR v1: measured across the whole tree, Redux's CORE
 * touches libuv in exactly four places once the three server features are set
 * aside - `uv_run` in ui.cc and main.cc, `uv_loop_init`/`uv_loop_close` in
 * system.cc, and `uv_loop_t` as a parameter type in version.cc. Everything else
 * lives in uvfile.cc (40 distinct uv symbols), gdb-server.cc (9),
 * web-server.cc (14) and sio1-server.cc (3), all of which v1 drops.
 *
 * So this covers the core's entire libuv surface and nothing more. It is
 * deliberately NOT a general shim: anything that needs a real handle, timer,
 * poll or async should FAIL TO COMPILE against this header rather than silently
 * get a no-op, because a silent no-op in an async layer is the failure mode you
 * only find at runtime.
 */
#ifndef PCSX_UV_WASM_STUB_H
#define PCSX_UV_WASM_STUB_H

#ifndef __EMSCRIPTEN__
#error "uv-wasm-stub/uv.h is for the wasm build only; use the real libuv elsewhere."
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* An empty loop object. There is nothing to poll: v1 has no async I/O, no
 * sockets and no download path. */
typedef struct uv_loop_s {
    void* data;
} uv_loop_t;

typedef enum { UV_RUN_DEFAULT = 0, UV_RUN_ONCE, UV_RUN_NOWAIT } uv_run_mode;

static inline int uv_loop_init(uv_loop_t* loop) {
    if (loop) loop->data = 0;
    return 0;
}
static inline int uv_loop_close(uv_loop_t* loop) {
    (void)loop;
    return 0;
}
/* Returns 0 = "no active handles remain", which is true by construction here. */
static inline int uv_run(uv_loop_t* loop, uv_run_mode mode) {
    (void)loop;
    (void)mode;
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* PCSX_UV_WASM_STUB_H */
