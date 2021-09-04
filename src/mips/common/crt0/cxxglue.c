#include <stddef.h>

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

void abort() {
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
