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
#include "psmplayer/psmplayer.h"

extern const uint8_t _binary_test_vab_start[];
extern const uint8_t _binary_test_vab_end[];
extern const uint8_t _binary_test_psm_start[];
extern const uint8_t _binary_test_psm_end[];

#define printf ramsyscall_printf

static uint16_t s_nextCounter = 0;

static void checkMusic() {
    if (((int16_t)(s_nextCounter - COUNTERS[1].value)) <= 0) {
        PSM_Poll();
        s_nextCounter += PSM_hblanks;
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
    uint32_t vabSize = _binary_test_vab_end - _binary_test_vab_start;
    uint32_t psmSize = _binary_test_psm_end - _binary_test_psm_start;
    printf("PSM Player Demo\n");
    printf("VAB: %lu bytes, PSM: %lu bytes\n", vabSize, psmSize);

    // Timer1 in hblank counting mode
    COUNTERS[1].mode = 0x0100;

    // Load instrument bank (DMA samples to SPU RAM)
    unsigned programs = PSM_LoadBank(_binary_test_vab_start, vabSize);
    if (programs == 0) {
        printf("Invalid VAB file.\n");
        return;
    }
    printf("Loaded VAB: %u programs\n", programs);

    // Load song
    uint32_t events = PSM_LoadSong(_binary_test_psm_start, psmSize);
    if (events == 0) {
        printf("Invalid PSM file.\n");
        return;
    }
    printf("Loaded PSM: %lu events, hblanks=%lu\n", events, PSM_hblanks);

    // Start playback
    uint32_t lastEvent = 0xffffffff;
    s_nextCounter = COUNTERS[1].value + PSM_hblanks;
    while (1) {
        if (PSM_currentEvent != lastEvent) {
            lastEvent = PSM_currentEvent;
            if ((lastEvent & 0xFF) == 0) {
                printf("Event: %lu / %lu\n", lastEvent, PSM_eventCount);
            }
        }
        if (!PSM_playing) {
            printf("Playback finished.\n");
            break;
        }
        waitVSync();
    }
}
