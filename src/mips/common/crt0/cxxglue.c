/*

MIT License

Copyright (c) 2021 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

/* Properly using C++ on the PSX requires a form of the libstdc++ that's
typically called "freestanding", which isn't really buildable at the moment.
See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=100057 for details.
This means however that using a full linux compiler such as the Ubuntu
mipsel compiler package will bring in a libstdc++ that utilizes all of
the existing libc. Properly filling in portions of the required ABI, while
avoiding the bits that won't work can be tricky, but is doable. Using a
freestanding compiler won't have the libstdc++, and this wouldn't work. */

#include <stddef.h>

#include "common/hardware/pcsxhw.h"

typedef void (*fptr)();

extern fptr __preinit_array_start[] __attribute__((weak));
extern fptr __preinit_array_end[] __attribute__((weak));
extern fptr __init_array_start[] __attribute__((weak));
extern fptr __init_array_end[] __attribute__((weak));

void main();

void cxxmain() {
    size_t count, i;

    count = __preinit_array_end - __preinit_array_start;
    for (i = 0; i < count; i++) {
        fptr f = __preinit_array_start[i];
        if (f) {
            f();
        }
    }

    count = __init_array_end - __init_array_start;
    for (i = 0; i < count; i++) {
        fptr f = __init_array_start[i];
        if (f) {
            f();
        }
    }

    main();
}

__attribute__((weak)) void abort() {
    pcsx_debugbreak();
    // TODO: make this better
    while (1)
        ;
}

// This will be called if a pure virtual function is called, usually mistakenly calling
// a method after its object got deleted, because that's the only way this happens.
__attribute__((weak)) void __cxa_pure_virtual() { abort(); }

// All of these (and probably more) will be called one way or another through
// the normal C++ ABI. These are declared weak here so they can be overriden
// by an actual proper implementation that'd do what they should do.
__attribute__((weak)) void* __builtin_new(size_t size) { abort(); }
__attribute__((weak)) void __builtin_delete(void* ptr) { abort(); }
// void * operator new(unsigned int);
__attribute__((weak)) void* _Znwj(unsigned int size) { abort(); }
// void * operator new[](unsigned int);
__attribute__((weak)) void* _Znaj(unsigned int size) { abort(); }
// void operator delete(void*);
__attribute__((weak)) void _ZdlPv(void* ptr) { abort(); }
// void operator delete[](void*);
__attribute__((weak)) void _ZdaPv(void* ptr) { abort(); }
// void operator delete(void*, unsigned int);
__attribute__((weak)) void _ZdlPvj(void* ptr, unsigned int size) { abort(); }
// void operator delete[](void*, unsigned int);
__attribute__((weak)) void _ZdaPvj(void* ptr, unsigned int size) { abort(); }

/*

  In order to use new / delete, the following must be defined somewhere, but due
  to the fact there's no good memory allocation story for the PS1 at start time,
  it's pretty difficult to define something that'd be one size fits all. It's
  best to drop these in your own project with your own memory allocation functions.

void * __builtin_new(size_t size) { return malloc(size); }
void __builtin_delete(void * ptr) { free(ptr); }
void * _Znwj(unsigned int size) { return malloc(size); }
void * _Znaj(unsigned int size) { return malloc(size); }
void _ZdlPv(void * ptr) { free(ptr); }
void _ZdaPv(void * ptr) { free(ptr); }
void _ZdlPvj(void * ptr, unsigned int size) { free(ptr); }
void _ZdaPvj(void * ptr, unsigned int size) { free(ptr); }

  One way to make this all work would be to have the following snippet to
  initialize the heap through the bios or any other mean before the memory
  allocation functions can be safely used:

static uint8_t global_heap[HEAPSIZE];
static void init_heap_wrapper() {
    InitHeap(global_heap, HEAPSIZE);
}

__attribute__((section(".preinit_array"))) static fptr pi_heap[] = {
    init_heap_wrapper
};

*/

// we're not going to care about exit cleanup
__attribute__((weak)) void __cxa_atexit(void (*func)(void*), void* arg, void* dso_handle) {}

// no, we're not going to have shared libraries
__attribute__((weak)) void* __dso_handle = NULL;

__attribute__((weak)) void* memcpy(void* s1_, const void* s2_, size_t n) {
    uint8_t* s1 = (uint8_t*)s1_;
    const uint8_t* s2 = (uint8_t*)s2_;
    size_t i;

    for (i = 0; i < n; i++) *s1++ = *s2++;

    return s1_;
}

__attribute__((weak)) void* memmove(void* s1_, const void* s2_, size_t n) {
    uint8_t* s1 = (uint8_t*)s1_;
    const uint8_t* s2 = (uint8_t*)s2_;
    size_t i;

    if (s1 < s2) {
        for (i = 0; i < n; i++) *s1++ = *s2++;
    } else if (s1 > s2) {
        s1 += n;
        s2 += n;
        for (i = 0; i < n; i++) *--s1 = *--s2;
    }

    return s1_;
}

__attribute__((weak)) int memcmp(const void* s1_, const void* s2_, size_t n) {
    uint8_t* s1 = (uint8_t*)s1_;
    const uint8_t* s2 = (uint8_t*)s2_;
    size_t i;

    for (i = 0; i < n; i++, s1++, s2++) {
        if (*s1 < *s2) {
            return -1;
        } else if (*s1 > *s2) {
            return 1;
        }
    }

    return 0;
}

__attribute__((weak)) void* memset(void* s_, int c, size_t n) {
    uint8_t* s = (uint8_t*)s_;
    size_t i;

    for (i = 0; i < n; i++) *s++ = (uint8_t)c;

    return s_;
}
