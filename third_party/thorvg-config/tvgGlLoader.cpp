// thorvg's GL loader on Linux only tries to dlopen "libGL.so", "libGL.so.4"
// and "libGL.so.3". The unversioned name is only provided by the GL
// development packages, and the runtime library is "libGL.so.1", so the
// GL engine fails to initialize on most end user systems. This wrapper
// builds the loader with a dlopen that also tries the versioned name.

#if defined(__linux__)
#include <dlfcn.h>
#include <string.h>

static void* tvgReduxDlopen(const char* name, int flags) {
    void* handle = dlopen(name, flags);
    if (!handle && (strcmp(name, "libGL.so") == 0)) handle = dlopen("libGL.so.1", flags);
    return handle;
}

#define dlopen tvgReduxDlopen
#endif

#include "../thorvg/src/renderer/gpu_engine/gl/tvgGl.cpp"
