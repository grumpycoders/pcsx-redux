/*

MIT License

Copyright (c) 2024 PCSX-Redux authors

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

// This example demonstrates how to run a heavy compute function in a separate stack,
// using a trampoline function and setjmp/longjmp. This is useful if you have a very
// hot function which makes the compiler thrash a lot of registers in and out of the
// stack. The main ram of the PS1 is fairly slow, so this can be a significant performance
// improvement. This is a very advanced technique, and should only be used if you
// have profiled your code and know that this is a bottleneck. Also, note that using
// setjmp/longjmp is not free, so the function you want to run in a separate stack
// should be doing a lot of work in a loop to make up for the overhead of setjmp/longjmp.
// Last but not least, using setjmp/longjmp is the only safe way to switch stacks on
// the fly while avoiding compiler optimizations that would break around the stack switch.
#include <stdint.h>

#include "common/psxlibc/setjmp.h"
#include "common/syscalls/syscalls.h"

// This function would be a heavy compute function that we want to run in a separate stack.
// This is the part of the example that you would replace with your own code.
static uint32_t someHeavyComputeFunction(uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4, uint32_t arg5) {
    syscall_puts("Starting heavy compute function\n");
    // Do some heavy computation here
    uint32_t ret = arg1 + arg2 + arg3 + arg4 + arg5;
    syscall_puts("Heavy compute function done\n");
    return ret;
}

// These prototypes are for the mechanism to run the heavy compute function in a separate stack.
// Their implementation later is a detail which is a bit complex to understand, and not relevant to the
// point of just using the mechanism. Of course, read the implementation to understand how it works.
static void setupHeavyComputeFunctionTrampoline();
static uint32_t someHeavyComputeFunctionStub(uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4, uint32_t arg5);

// How to actually use this mechanism - here from main, but it could be from anywhere.
int main() {
    // Setup the trampoline once somewhere at the start of the program.
    setupHeavyComputeFunctionTrampoline();
    // Then we can call the heavy compute function as if it was a normal function,
    // as many times as we want.
    for (int i = 0; i < 10; i++) {
        syscall_puts("Calling heavy compute function\n");
        uint32_t ret = someHeavyComputeFunctionStub(1, 2, 3, 4, i);
        ramsyscall_printf("Heavy compute function returned: %d\n", ret);
    }
}

// The rest here is the boilerplate code to set up a trampoline to run the heavy compute function
// in a separate stack.

// First we need some scratch space to store the arguments and return value of the heavy compute function.
static __attribute__((section(".scratchpad"))) uint32_t s_computeArgsAndRet[6];

// Then we need a separate stack to run the heavy compute function on. Our total stack size is 1000 bytes.
// The scratchpad is 1024 bytes, and 24 of those bytes are used for the arguments and return value above.
// It probably would be better to use a struct for both and assert that the struct size is equal to 1024.
static __attribute__((section(".scratchpad"))) uint32_t s_scratchStack[250];

// We need to store the context of the heavy compute function and the caller function.
static struct JmpBuf s_jmpbufToCompute;
static struct JmpBuf s_jmpbufToReturn;

// Technically, this function sets up a trampoline to run the heavy compute function in a separate stack.
// But as a side effect, it is also responsible for running the heavy compute function.
static void setupHeavyComputeFunctionTrampoline() {
    // The first time this function returns is when the context buffer has been set up.
    if (syscall_setjmp(&s_jmpbufToCompute) == 0) {
        // So we mangle the stack pointer to point to the scratch stack.
        s_jmpbufToCompute.sp = ((uintptr_t)(s_scratchStack)) + sizeof(s_scratchStack);
        // and return to the caller function which can then go on as normal.
        // The caller function will never know that this will return multiple times,
        // and this return statement is the only time this function will actually return.
        return;
    }
    // The second time this function returns is when the stub function called longjmp on the context buffer.
    // At this point, we're in the new stack, so we can pop the arguments and call the heavy compute function.
    s_computeArgsAndRet[5] =
        someHeavyComputeFunction(s_computeArgsAndRet[0], s_computeArgsAndRet[1], s_computeArgsAndRet[2],
                                 s_computeArgsAndRet[3], s_computeArgsAndRet[4]);
    // Then we longjmp back to the caller function.
    syscall_longjmp(&s_jmpbufToReturn, 1);
    // This function will never return again, and this location of code will never be reached.
    __builtin_unreachable();
}

// This is the stub function that the caller function will actually call. It will first
// set a context buffer so the heavy compute function can return to it, then it will set
// the arguments and longjmp to the heavy compute function buffer.
static uint32_t someHeavyComputeFunctionStub(uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4,
                                             uint32_t arg5) {
    // The second time this function returns is when the heavy compute function has finished, so
    // we can return the return value to the caller function.
    if (syscall_setjmp(&s_jmpbufToReturn) == 1) return s_computeArgsAndRet[5];
    // And the first time this function returns is when the context buffer has been set up,
    // so we can set the arguments and longjmp to the heavy compute function context buffer,
    // which is inside the trampoline function above.
    s_computeArgsAndRet[0] = arg1;
    s_computeArgsAndRet[1] = arg2;
    s_computeArgsAndRet[2] = arg3;
    s_computeArgsAndRet[3] = arg4;
    s_computeArgsAndRet[4] = arg5;
    syscall_longjmp(&s_jmpbufToCompute, 1);
    __builtin_unreachable();
}
