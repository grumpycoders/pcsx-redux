# Limited C runtime

This directory contains some limited C runtime features. It will take care of booting the binary, setting up some minimal environment and then call the main function. It also contains some basic implementations of standard C functions which are required by the compiler when doing self-hosted compilation.

## Using very bare C runtime
The file `crt0.s` is the entry point of the C runtime. It will set up the stack, and call the `main` function. It will not perform any other initialization beyond clearing the BSS section.

## Using C++ runtime
The file `crt0cxx.s` is the entry point of the C++ runtime. It will set up the stack, and then go to the `cxxglue.c` file for further initialization, which will then call the `main` function. The `cxxglue.c` file also contains the minimal implementation of the C++ runtime that is required by the C++ compiler.

## Memory C runtime functions
The files `memory-c.c` and `memory-s.s` contain the 4 basic memory functions that are required by the self-hosted C and C++ compilers. These are `memcpy`, `memset`, `memcmp`, and `memmove`. These are implemented in a very basic way, being very small, and are not optimized for speed. They also contain optimized versions of `memcpy` and `memset` for the MIPS architecture, available using the LDFLAGS `-Wl,-wrap,memcpy` and `-Wl,-wrap,memset` toggles. They are somewhat bigger, but much faster. Note that these 4 functions are available directly when writing C or C++ code using the `__builtin_memcpy`, `__builtin_memset`, `__builtin_memcmp` and `__builtin_memmove` functions, with no need to include any header file.
