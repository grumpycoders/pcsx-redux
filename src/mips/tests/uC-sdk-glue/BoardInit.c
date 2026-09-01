/*

MIT License

Copyright (c) 2019 PCSX-Redux authors

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

#include "common/hardware/pcsxhw.h"
#include "common/syscalls/syscalls.h"

void BoardEarlyInit() {}

void BoardInit() {}

void BoardLateInit() {}

// Trap into the resident debugger with the exit code in $a0 via break
// category 4. Categories 0/6/7/14 are taken (pcdrv / compiler overflow /
// compiler divide-by-zero / psyqo), so 4 is free. On hardware this halts
// the program (Unirom reports HLTD) and leaves the exit code readable in
// $a0, giving the host a deterministic end-of-binary signal instead of a
// printed sentinel string. On the emulator pcsx_exit() has already exited,
// so this is never reached there.
static inline void exitBreak(int code) {
    register int a0 asm("$4") = code;
    __asm__ volatile("break 4, 0\n" : : "r"(a0) : "memory");
}

void BoardShutdown() {
    pcsx_exit(0);
    exitBreak(0);
    syscall__exit(0);
}

void BoardExceptionHandler(int code) {
    pcsx_exit(code);
    exitBreak(code);
    syscall__exit(code);
}
