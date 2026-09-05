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

#include "common/hardware/hwregs.h"
#include "common/hardware/irq.h"
#include "common/syscalls/syscalls.h"
#include "spdplayer/spdplayer.h"

extern const uint8_t _binary_test_spd_start[];
extern const uint8_t _binary_test_spd_end[];

#define printf ramsyscall_printf

static uint16_t s_nextCounter = 0;

// Poll the music player when the hblank counter says it's time.
// Same approach as the modplayer demo.
static void checkMusic() {
    if (((int16_t)(s_nextCounter - COUNTERS[1].value)) <= 0) {
        SPD_Poll();
        s_nextCounter += SPD_hblanks;
    }
}

static void waitVSync() {
    int wasLocked = enterCriticalSection();
    uint32_t imask = IMASK;

    IMASK = imask | IRQ_VBLANK;

    while ((IREG & IRQ_VBLANK) == 0) {
        checkMusic();
    }
    IREG &= ~IRQ_VBLANK;
    IMASK = imask;
    if (!wasLocked) leaveCriticalSection();
}

void main() {
    uint32_t size = _binary_test_spd_end - _binary_test_spd_start;
    printf("Loading SPUDUMP (%lu bytes)\n", size);

    // Timer1 in hblank counting mode, same as modplayer demo.
    COUNTERS[1].mode = 0x0100;

    unsigned voices = SPD_Load(_binary_test_spd_start, size);
    if (voices == 0) {
        printf("Invalid SPUDUMP file.\n");
        return;
    }
    printf("%02d Voices, %02d Orders, %02d Patterns, %02d Samples\n",
           SPD_VoiceCount, SPD_OrderCount, SPD_PatternCount, SPD_SampleCount);

    unsigned order = 0xffffffff;
    // Give our initial counter a proper value.
    s_nextCounter = COUNTERS[1].value + SPD_hblanks;
    while (1) {
        if (order != SPD_CurrentOrder) {
            order = SPD_CurrentOrder;
            printf("Order: %02d\n", order);
        }
        waitVSync();
    }
}
