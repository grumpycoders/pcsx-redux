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

#include "common/kernel/events.h"
#include "common/syscalls/syscalls.h"
#include "openbios/sio0/card.h"

int g_overallMCsuccess;
int g_mcErrors[4];

void mcResetStatus() {
    g_overallMCsuccess = 0;
    g_mcErrors[0] = 0;
    g_mcErrors[1] = 0;
    g_mcErrors[2] = 0;
    g_mcErrors[3] = 0;

    syscall_undeliverEvent(EVENT_VBLANK, 0x0004);
    syscall_undeliverEvent(EVENT_VBLANK, 0x8000);
    syscall_undeliverEvent(EVENT_VBLANK, 0x2000);
    syscall_undeliverEvent(EVENT_VBLANK, 0x0100);
}

int mcWaitForStatus() {
    while (1) {
        if (g_overallMCsuccess) {
            mcResetStatus();
            return 1;
        }
        for (unsigned i = 0; i < 4; i++) {
            if (g_mcErrors[i]) {
                mcResetStatus();
                return 0;
            }
        }
    }
}

int mcWaitForStatusAndReturnIndex() {
    while (1) {
        if (g_overallMCsuccess) {
            mcResetStatus();
            return 0;
        }
        for (unsigned i = 0; i < 4; i++) {
            if (g_mcErrors[i]) {
                mcResetStatus();
                return i + 1;
            }
        }
    }
}
