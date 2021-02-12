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

#include "common/hardware/hwregs.h"
#include "common/hardware/irq.h"
#include "common/syscalls/syscalls.h"
#include "modplayer/modplayer.h"

extern const uint8_t _binary_timewarped_hit_start[];

#define printf ramsyscall_printf

void waitVSync() {
    int wasLocked = enterCriticalSection();
    uint32_t imask = IMASK;

    IMASK = imask | IRQ_VBLANK;

    while ((IREG & IRQ_VBLANK) == 0)
        ;
    IREG &= ~IRQ_VBLANK;
    IMASK = imask;
    if (!wasLocked) leaveCriticalSection();
}

// Don't do this: it's not going to be able to pickup tempo
// changes properly, and it will be too fast on PAL.
//#define POLL_ON_VSYNC

void main() {
    printf("Loading MOD:\'%s\'\n", _binary_timewarped_hit_start);
    // The right way is to use timer1 to call MOD_Poll periodically,
    // at the right frequency, independently of the current video
    // mode, and will also properly tolerate the tempo changes.
#ifndef POLL_ON_VSYNC
    int wasInCS = enterCriticalSection();
    syscall_setDefaultExceptionJmpBuf();
#endif
    MOD_Load((struct MODFileFormat*)_binary_timewarped_hit_start);
#ifndef POLL_ON_VSYNC
    syscall_enableTimerIRQ(1);
    uint32_t event = syscall_openEvent(0xf2000001, 2, 0x1000, MOD_Poll);
    syscall_enableEvent(event);
    if (!wasInCS) leaveCriticalSection();
#endif
    printf("%02d Channels, %02d Orders\n", MOD_Channels, MOD_SongLength);
    unsigned row = 0xffffffff;
    unsigned order = 0xffffffff;
    unsigned pattern = 0xffffffff;
    while (1) {
        if (row != MOD_CurrentRow || order != MOD_CurrentOrder || pattern != MOD_CurrentPattern) {
            row = MOD_CurrentRow;
            order = MOD_CurrentOrder;
            pattern = MOD_CurrentPattern;
            printf("Row: %02d, Order: %02d, Pattern: %02d\n", row, order, pattern);
        }
        waitVSync();
        // If we really want to synchronize the music to vblank, we can
        // just do that instead of using the event callback stuff, but it
        // will play at different speed depending on video mode, and it
        // won't handle any tempo change from the track.
#ifdef POLL_ON_VSYNC
        MOD_Poll();
#endif
    }
}
