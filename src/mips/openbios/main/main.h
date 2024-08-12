/*

MIT License

Copyright (c) 2020 PCSX-Redux authors

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

#include "common/hardware/hwregs.h"
#include "common/psxlibc/setjmp.h"

// The original 700B01 kernel clears the watchdog using inline code in some
// places and a subroutine call in others. As there is no point in replicating
// this inconsistency, we are going to always use an inline function for this
// purpose. This additionally lets us easily stub out all watchdog calls for
// non-573 builds in a single place.
static inline void clearWatchdog() {
#ifdef OPENBIOS_BOARD_SYS573
    SYS573_WATCHDOG = 0;
#endif
}

void setConfiguration(int eventsCount, int taskCount, void* stackBase);
void getConfiguration(int* eventsCount, int* taskCount, void** stackBase);

extern struct JmpBuf g_ioAbortJmpBuf;
