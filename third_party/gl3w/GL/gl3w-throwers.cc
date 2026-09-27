#include <stdexcept>

#include "gl3w.h"

namespace {

// ⛔ THESE USED TO BE `void no##x() { throw ...; }` - ZERO ARGUMENTS, stored into
// a typed slot in GL3WProcs and then called with the real GL arity.
//
// On x86-64 that is harmless: the callee ignores the argument registers and
// throws immediately, so it behaves as intended. WebAssembly type-checks every
// indirect call against the table entry's signature, so the same code TRAPS with
// "RuntimeError: function signature mismatch" - uncatchable, no C++ exception,
// and with a stack that names only the enclosing function. Any GL entry point
// that WebGL2 lacks and Redux still calls hits it, which is what killed
// PCSX::GUI::init.
//
// The signature is recoverable without a table of prototypes: each slot is
// already declared as its own PFNGL...PROC, so decltype on the union member
// gives the exact type and this template produces a thrower that matches it.
template <typename T>
struct Thrower;

template <typename R, typename... A>
struct Thrower<R (*)(A...)> {
    static R call(A...) { throw std::runtime_error("gl function not loaded"); }
};

#if defined(_WIN32) && (defined(_M_IX86) || defined(__i386__))
// APIENTRY is __stdcall on Windows, which is a distinct type from the one above
// only on 32-bit x86. Everywhere else the calling convention is ignored and a
// second specialization would redefine the first.
template <typename R, typename... A>
struct Thrower<R(APIENTRY *)(A...)> {
    static R APIENTRY call(A...) { throw std::runtime_error("gl function not loaded"); }
};
#endif

template <typename T>
constexpr T thrower_for(T) {
    return &Thrower<T>::call;
}

}  // namespace

extern "C" GL3W_API void gl3wFillCppThrowers() {
// By NAME rather than by index: the old version walked gl3wProcs.ptr[i] with a
// counter that had to stay in step with gl3w-list.h by hand, and the typed
// thrower needs the named member anyway.
#define GL3W_SYMBOL(x) \
    if (!gl3wProcs.gl.x) gl3wProcs.gl.x = thrower_for(gl3wProcs.gl.x);

#include "gl3w-list.h"

#undef GL3W_SYMBOL
}

extern "C" GL3W_API int gl3wIsCppThrower(GL3WglProc proc) {
#define GL3W_SYMBOL(x) \
    if (proc == reinterpret_cast<GL3WglProc>(thrower_for(gl3wProcs.gl.x))) return 1;

#include "gl3w-list.h"

#undef GL3W_SYMBOL

    return 0;
}
