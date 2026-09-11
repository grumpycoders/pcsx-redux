/*

MIT License

Copyright (c) 2025 PCSX-Redux authors

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

#pragma once

// This file provides an ersatz for the ucontext.h API, which is otherwise not available on PSX.
// It defines the necessary structures and function prototypes to allow for context switching,
// similar to what ucontext.h provides in POSIX systems. It's not strictly compliant with the POSIX standard,
// but it provides a minimal implementation suitable for coroutine management in a PSX environment.

#include <stdint.h>

struct stack_t {
    void *ss_sp;
    unsigned ss_size;
};

struct mcontext_t {
    uint32_t reserved[16];
};

struct ucontext_t {
    struct mcontext_t uc_mcontext;
    struct ucontext_t *uc_link;
    struct stack_t uc_stack;
};

#ifdef __cplusplus
extern "C" {
#endif

int getcontext(struct ucontext_t *ucp);
int setcontext(const struct ucontext_t *ucp);
int makecontext(struct ucontext_t *ucp, void (*func)(void *), void *arg);
int swapcontext(struct ucontext_t *oucp, const struct ucontext_t *ucp);

#ifdef __cplusplus
}
#endif
