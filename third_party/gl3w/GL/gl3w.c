/*
 * This file was generated with gl3w_gen.py, part of gl3w
 * (hosted at https://github.com/skaslev/gl3w)
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */
#include <GL/gl3w.h>
#include <stdlib.h>
#define ARRAY_SIZE(x)  (sizeof(x) / sizeof((x)[0]))
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#include <windows.h>
static HMODULE libgl;
typedef PROC(__stdcall* GL3WglGetProcAddr)(LPCSTR);
static GL3WglGetProcAddr wgl_get_proc_address;
static int open_libgl(void)
{
	libgl = LoadLibraryA("opengl32.dll");
	if (!libgl)
		return GL3W_ERROR_LIBRARY_OPEN;
	wgl_get_proc_address = (GL3WglGetProcAddr)GetProcAddress(libgl, "wglGetProcAddress");
	return GL3W_OK;
}
static void close_libgl(void)
{
	FreeLibrary(libgl);
}
static GL3WglProc get_proc(const char *proc)
{
	GL3WglProc res;
	res = (GL3WglProc)wgl_get_proc_address(proc);
	if (!res)
		res = (GL3WglProc)GetProcAddress(libgl, proc);
	return res;
}
#elif defined(__APPLE__)
#include <dlfcn.h>
static void *libgl;
static int open_libgl(void)
{
	libgl = dlopen("/System/Library/Frameworks/OpenGL.framework/OpenGL", RTLD_LAZY | RTLD_LOCAL);
	if (!libgl)
		return GL3W_ERROR_LIBRARY_OPEN;
	return GL3W_OK;
}
static void close_libgl(void)
{
	dlclose(libgl);
}
static GL3WglProc get_proc(const char *proc)
{
	GL3WglProc res;
	*(void **)(&res) = dlsym(libgl, proc);
	return res;
}
#else
#include <dlfcn.h>
static void *libgl;  /* OpenGL library */
static void *libglx;  /* GLX library */
static void *libegl;  /* EGL library */
static GL3WGetProcAddressProc gl_get_proc_address;
static void close_libgl(void)
{
	if (libgl) {
		dlclose(libgl);
		libgl = NULL;
	}
	if (libegl) {
		dlclose(libegl);
		libegl = NULL;
	}
	if (libglx) {
		dlclose(libglx);
		libglx = NULL;
	}
}
static int is_library_loaded(const char *name, void **lib)
{
	*lib = dlopen(name, RTLD_LAZY | RTLD_LOCAL | RTLD_NOLOAD);
	return *lib != NULL;
}
static int open_libs(void)
{
	/* On Linux we have two APIs to get process addresses: EGL and GLX.
	 * EGL is supported under both X11 and Wayland, whereas GLX is X11-specific.
	 * First check what's already loaded, the windowing library might have
	 * already loaded either EGL or GLX and we want to use the same one.
	 */
	if (is_library_loaded("libEGL.so.1", &libegl) ||
			is_library_loaded("libGLX.so.0", &libglx)) {
		libgl = dlopen("libOpenGL.so.0", RTLD_LAZY | RTLD_LOCAL);
		if (libgl)
			return GL3W_OK;
		else
			close_libgl();
	}
	if (is_library_loaded("libGL.so.1", &libgl))
		return GL3W_OK;
	/* Neither is already loaded, so we have to load one. Try EGL first
	 * because it is supported under both X11 and Wayland.
	 */
	/* Load OpenGL + EGL */
	libgl = dlopen("libOpenGL.so.0", RTLD_LAZY | RTLD_LOCAL);
	libegl = dlopen("libEGL.so.1", RTLD_LAZY | RTLD_LOCAL);
	if (libgl && libegl)
		return GL3W_OK;
	/* Fall back to legacy libGL, which includes GLX */
	close_libgl();
	libgl = dlopen("libGL.so.1", RTLD_LAZY | RTLD_LOCAL);
	if (libgl)
		return GL3W_OK;
	return GL3W_ERROR_LIBRARY_OPEN;
}
static int open_libgl(void)
{
	int res = open_libs();
	if (res)
		return res;
	if (libegl)
		*(void **)(&gl_get_proc_address) = dlsym(libegl, "eglGetProcAddress");
	else if (libglx)
		*(void **)(&gl_get_proc_address) = dlsym(libglx, "glXGetProcAddressARB");
	else
		*(void **)(&gl_get_proc_address) = dlsym(libgl, "glXGetProcAddressARB");
	if (!gl_get_proc_address) {
		close_libgl();
		return GL3W_ERROR_LIBRARY_OPEN;
	}
	return GL3W_OK;
}
static GL3WglProc get_proc(const char *proc)
{
	GL3WglProc res = NULL;
	/* Before EGL version 1.5, eglGetProcAddress doesn't support querying core
	 * functions and may return a dummy function if we try, so try to load the
	 * function from the GL library directly first.
	 */
	if (libegl)
		*(void **)(&res) = dlsym(libgl, proc);
	if (!res)
		res = gl_get_proc_address(proc);
	if (!libegl && !res)
		*(void **)(&res) = dlsym(libgl, proc);
	return res;
}
#endif
static struct {
	int major, minor;
} version;
static int parse_version(void)
{
	if (!glGetIntegerv)
		return GL3W_ERROR_INIT;
	glGetIntegerv(GL_MAJOR_VERSION, &version.major);
	glGetIntegerv(GL_MINOR_VERSION, &version.minor);
	if (version.major < 3)
		return GL3W_ERROR_OPENGL_VERSION;
	return GL3W_OK;
}
static void load_procs(GL3WGetProcAddressProc proc);
int gl3wInit(void)
{
	int res;
	res = open_libgl();
	if (res)
		return res;
	atexit(close_libgl);
	return gl3wInit2(get_proc);
}
int gl3wInit2(GL3WGetProcAddressProc proc)
{
	load_procs(proc);
	return parse_version();
}
int gl3wIsSupported(int major, int minor)
{
	if (major < 3)
		return 0;
	if (version.major == major)
		return version.minor >= minor;
	return version.major >= major;
}
GL3WglProc gl3wGetProcAddress(const char *proc)
{
	return get_proc(proc);
}
#define GL3W_SYMBOL(x) "gl"#x,
static const char *proc_names[] = {
#include "gl3w-list.h"
};
GL3W_API union GL3WProcs gl3wProcs;
static void load_procs(GL3WGetProcAddressProc proc)
{
	size_t i;
	for (i = 0; i < ARRAY_SIZE(proc_names); i++)
		gl3wProcs.ptr[i] = proc(proc_names[i]);
}
