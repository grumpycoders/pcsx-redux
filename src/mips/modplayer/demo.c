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

static uint16_t s_nextCounter = 0;

// Function to call periodically if we can't use interrupts for some reason.
// If the code is running slower than the normal vsync speed, then you should
// call this during your frame computation code, in order to make sure you're
// not missing any tick.
static void checkMusic() {
    if (((int16_t)(s_nextCounter - COUNTERS[1].value)) <= 0) {
        MOD_Poll();
        s_nextCounter += MOD_hblanks;
    }
}

static void waitVSync() {
    int wasLocked = enterCriticalSection();
    uint32_t imask = IMASK;

    IMASK = imask | IRQ_VBLANK;

    while ((IREG & IRQ_VBLANK) == 0) {
        // Since our vsync is a kludge, we can't use the root counter IRQ
        // mechanism to call MOD_Poll, and so we have to poll here, during
        // vsync, for when our timer has passed the target value manually.

        // We *could* set up the timer properly using the target value system,
        // but this might make a few emulators sad. Beside, this is a perfectly
        // valid and common solution.
        checkMusic();
    }
    IREG &= ~IRQ_VBLANK;
    IMASK = imask;
    if (!wasLocked) leaveCriticalSection();
}

void main() {
    printf("Loading MOD:\'%s\'\n", _binary_timewarped_hit_start);
    // We are going to use timer1 and its hblank counter to tell us when
    // we need to call MOD_Poll again. For this, we need timer1 to be
    // counting hblanks instead of the system clock.
    COUNTERS[1].mode = 0x0100;
    MOD_Load((struct MODFileFormat*)_binary_timewarped_hit_start);
    printf("%02d Channels, %02d Orders\n", MOD_Channels, MOD_SongLength);
    unsigned row = 0xffffffff;
    unsigned order = 0xffffffff;
    unsigned pattern = 0xffffffff;
    // Giving our initial counter a proper value.
    s_nextCounter = COUNTERS[1].value + MOD_hblanks;
    while (1) {
        if (row != MOD_CurrentRow || order != MOD_CurrentOrder || pattern != MOD_CurrentPattern) {
            row = MOD_CurrentRow;
            order = MOD_CurrentOrder;
            pattern = MOD_CurrentPattern;
            printf("Row: %02d, Order: %02d, Pattern: %02d\n", row, order, pattern);
        }
        waitVSync();
    }
}
