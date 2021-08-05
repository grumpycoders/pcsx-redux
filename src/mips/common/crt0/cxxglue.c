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

__attribute__((weak)) void __cxa_pure_virtual() { abort(); }

/*

  In order to use new / delete, the following must be defined somewhere, but due
  to the fact there's no good memory allocation story for the PS1 at start time,
  it's pretty difficult to define something that'd be one size fits all. It's
  best to drop these in your own project with your own memory allocation functions.

__attribute__((weak)) void * __builtin_new(size_t size) { return malloc(size); }
__attribute__((weak)) void __builtin_delete(void * ptr) { free(ptr); }
__attribute__((weak)) void * _Znwj(unsigned int size) { return malloc(size); }
__attribute__((weak)) void * _Znaj(unsigned int size) { return malloc(size); }
__attribute__((weak)) void _ZdlPv(void * ptr) { free(ptr); }
__attribute__((weak)) void _ZdaPv(void * ptr) { free(ptr); }

*/
