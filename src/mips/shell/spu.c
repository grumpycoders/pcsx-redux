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

#include <stdint.h>

#include "common/hardware/hwregs.h"
#include "common/syscalls/syscalls.h"
#include "modplayer/modplayer.h"

#define printf ramsyscall_printf

extern struct MODFileFormat _binary_blip_hit_start;

static uint16_t s_nextCounter = 0;
static uint16_t s_oldMode = 0;
static int s_idle = 1;

int spuIsIntro() { return MOD_CurrentPattern == 0; }

void initSPU() {
    s_oldMode = COUNTERS[1].mode;
    COUNTERS[1].mode = 0x0100;
    MOD_Load(&_binary_blip_hit_start);
    printf("(TS) SPU: Loaded %02d Channels, %02d Orders\n", MOD_Channels, MOD_SongLength);
    s_nextCounter = COUNTERS[1].value + MOD_hblanks;
}

void checkSPU() {
    if (((int16_t)(s_nextCounter - COUNTERS[1].value)) <= 0) {
        MOD_Poll();
        s_nextCounter += MOD_hblanks;

        if (MOD_CurrentOrder != 0) {
            if (MOD_CurrentRow == 60) {
                MOD_CurrentRow = 59;
            }
        }
        static unsigned row = 0xffffffff;
        static unsigned order = 0xffffffff;
        static unsigned pattern = 0xffffffff;
        if (row != MOD_CurrentRow || order != MOD_CurrentOrder || pattern != MOD_CurrentPattern) {
            row = MOD_CurrentRow;
            order = MOD_CurrentOrder;
            pattern = MOD_CurrentPattern;
            printf("(TS) SPU: Row: %02d, Order: %02d, Pattern: %02d\n", row, order, pattern);
        }
    }
}

void uninitSPU() {
    COUNTERS[1].mode = s_oldMode;
    MOD_Silence();
}

void spuSchedulePing() {
    printf("(TS) SPU: scheduling ping\n");
    if (!s_idle) return;
    if (MOD_CurrentOrder < 1) return;
    if ((MOD_CurrentOrder == 1) && (MOD_CurrentRow < 31)) return;

    MOD_ChangeOrderNextTick = 1;
    MOD_NextOrder = 2;
}

void spuScheduleIdle() {
    printf("(TS) SPU: scheduling idle\n");
    if (s_idle) return;
    s_idle = 1;
    MOD_ChangeOrderNextTick = 1;
    MOD_NextOrder = 2;
}

void spuScheduleOutro() {
    printf("(TS) SPU: scheduling outro\n");
    s_idle = 0;
    if (MOD_CurrentOrder < 1) return;
    if ((MOD_CurrentOrder == 1) && (MOD_CurrentRow < 31)) return;
    MOD_ChangeOrderNextTick = 1;
    MOD_NextOrder = 3;
}

void spuScheduleError() {
    printf("(TS) SPU: scheduling error\n");
    s_idle = 0;
    MOD_ChangeOrderNextTick = 1;
    MOD_NextOrder = 4;
}
