/***************************************************************************
 *   Copyright (C) 2010 by Blade_Arma                                      *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

/*
 * Internal PSX counters.
 */

#include "psxcounters.h"

/******************************************************************************/

typedef struct Rcnt {
    u16 mode, target;
    u32 rate, irq, counterState, irqState;
    u32 cycle, cycleStart;
} Rcnt;

enum {
    Rc0Gate = 0x0001,            // 0    not implemented
    Rc1Gate = 0x0001,            // 0    not implemented
    Rc2Disable = 0x0001,         // 0    partially implemented
    RcUnknown1 = 0x0002,         // 1    ?
    RcUnknown2 = 0x0004,         // 2    ?
    RcCountToTarget = 0x0008,    // 3
    RcIrqOnTarget = 0x0010,      // 4
    RcIrqOnOverflow = 0x0020,    // 5
    RcIrqRegenerate = 0x0040,    // 6
    RcUnknown7 = 0x0080,         // 7    ?
    Rc0PixelClock = 0x0100,      // 8    fake implementation
    Rc1HSyncClock = 0x0100,      // 8
    Rc2Unknown8 = 0x0100,        // 8    ?
    Rc0Unknown9 = 0x0200,        // 9    ?
    Rc1Unknown9 = 0x0200,        // 9    ?
    Rc2OneEighthClock = 0x0200,  // 9
    RcIrqRequest = 0x0400,       // 10   Interrupt request flag (0 disabled or during int, 1 request)
    RcCountEqTarget = 0x0800,    // 11
    RcOverflow = 0x1000,         // 12
    RcUnknown13 = 0x2000,        // 13   ? (always zero)
    RcUnknown14 = 0x4000,        // 14   ? (always zero)
    RcUnknown15 = 0x8000         // 15   ? (always zero)
};

#define CounterQuantity (4)
// static const u32 CounterQuantity  = 4;

static const u32 CountToOverflow = 0;
static const u32 CountToTarget = 1;

static const u32 FrameRate[] = {60, 50};
static const u32 VBlankStart[] = {243, 256};
static const u32 SpuUpdInterval[] = {23, 22};

#if defined(PSXHW_LOG)
#if defined(PSXMEM_LOG) && defined(PSXDMA_LOG)  // automatic guess if we want trace level logging
static const s32 VerboseLevel = 4;
#else
static const s32 VerboseLevel = 0;
#endif
#endif
static const u16 JITTER_FLAGS = (Rc2OneEighthClock | RcIrqRegenerate | RcCountToTarget);

/******************************************************************************/

static Rcnt rcnts[CounterQuantity];

static u32 hSyncCount = 0;
static u32 spuSyncCount = 0;

u32 HSyncTotal[PSX_TYPE_PAL + 1];  // 2
u32 psxNextCounter = 0, psxNextsCounter = 0;

/******************************************************************************/

static inline void setIrq(u32 irq) { psxHu32ref(0x1070) |= SWAPu32(irq); }

static void verboseLog(s32 level, const char *str, ...) {
#ifdef PSXHW_LOG
    if (level <= VerboseLevel) {
        va_list va;
        char buf[4096];

        va_start(va, str);
        vsnprintf(buf, sizeof(buf), str, va);
        va_end(va);

        PSXHW_LOG("%s", buf);
    }
#endif
}

/******************************************************************************/

static inline void _psxRcntWcount(u32 index, u32 value) {
    if (value > 0xffff) {
        verboseLog(1, "[RCNT %i] wcount > 0xffff: %x\n", index, value);
        value &= 0xffff;
    }

    rcnts[index].cycleStart = g_psxRegs.cycle;
    rcnts[index].cycleStart -= value * rcnts[index].rate;

    // TODO: <=.
    if (value < rcnts[index].target) {
        rcnts[index].cycle = rcnts[index].target * rcnts[index].rate;
        rcnts[index].counterState = CountToTarget;
    } else {
        rcnts[index].cycle = 0xffff * rcnts[index].rate;
        rcnts[index].counterState = CountToOverflow;
    }
    verboseLog(5, "[RCNT %i] scount: %x\n", index, value);
}

static inline u32 _psxRcntRcount(u32 index) {
    u32 count;

    count = g_psxRegs.cycle;
    count -= rcnts[index].cycleStart;
    count /= rcnts[index].rate;

    if (count > 0xffff) {
        verboseLog(1, "[RCNT %i] rcount > 0xffff: %x\n", index, count);
        count &= 0xffff;
    }

    return count;
}

/******************************************************************************/

static void psxRcntSet() {
    s32 countToUpdate;
    u32 i;

    psxNextsCounter = g_psxRegs.cycle;
    psxNextCounter = 0x7fffffff;

    for (i = 0; i < CounterQuantity; ++i) {
        countToUpdate = rcnts[i].cycle - (psxNextsCounter - rcnts[i].cycleStart);

        if (countToUpdate < 0) {
            psxNextCounter = 0;
            break;
        }

        if (countToUpdate < (s32)psxNextCounter) {
            psxNextCounter = countToUpdate;
        }
    }
}

/******************************************************************************/

static void psxRcntReset(u32 index) {
    u32 count;

    if (rcnts[index].counterState == CountToTarget) {
        if (rcnts[index].mode & RcCountToTarget) {
            count = g_psxRegs.cycle;
            count -= rcnts[index].cycleStart;
            count /= rcnts[index].rate;
            count -= rcnts[index].target;
        } else {
            count = _psxRcntRcount(index);
        }

        _psxRcntWcount(index, count);

        if (rcnts[index].mode & RcIrqOnTarget) {
            if ((rcnts[index].mode & RcIrqRegenerate) || (!rcnts[index].irqState)) {
                verboseLog(3, "[RCNT %i] irq: %x\n", index, count);
                setIrq(rcnts[index].irq);
                rcnts[index].irqState = TRUE;
            }
        }

        rcnts[index].mode |= RcCountEqTarget;
    } else if (rcnts[index].counterState == CountToOverflow) {
        count = g_psxRegs.cycle;
        count -= rcnts[index].cycleStart;
        count /= rcnts[index].rate;
        count -= 0xffff;

        _psxRcntWcount(index, count);

        if (rcnts[index].mode & RcIrqOnOverflow) {
            if ((rcnts[index].mode & RcIrqRegenerate) || (!rcnts[index].irqState)) {
                verboseLog(3, "[RCNT %i] irq: %x\n", index, count);
                setIrq(rcnts[index].irq);
                rcnts[index].irqState = TRUE;
            }
        }

        rcnts[index].mode |= RcOverflow;
    }

    rcnts[index].mode |= RcIrqRequest;

    psxRcntSet();
}

void psxRcntUpdate() {
    u32 cycle;

    cycle = g_psxRegs.cycle;

    // rcnt 0.
    if (cycle - rcnts[0].cycleStart >= rcnts[0].cycle) {
        psxRcntReset(0);
    }

    // rcnt 1.
    if (cycle - rcnts[1].cycleStart >= rcnts[1].cycle) {
        psxRcntReset(1);
    }

    // rcnt 2.
    if (cycle - rcnts[2].cycleStart >= rcnts[2].cycle) {
        psxRcntReset(2);
    }

    // rcnt base.
    if (cycle - rcnts[3].cycleStart >= rcnts[3].cycle) {
        psxRcntReset(3);

        GPU_hSync(hSyncCount);

        spuSyncCount++;
        hSyncCount++;

        // Update spu.
        if (spuSyncCount >= SpuUpdInterval[g_config.PsxType]) {
            spuSyncCount = 0;

            if (SPU_async) {
                SPU_async(SpuUpdInterval[g_config.PsxType] * rcnts[3].target);
            }
        }

#ifdef ENABLE_SIO1API
        if (SIO1_update) {
            SIO1_update(0);
        }
#endif

        // VSync irq.
        if (hSyncCount == VBlankStart[g_config.PsxType]) {
            GPU_vBlank(1);

            // For the best times. :D
            // setIrq( 0x01 );
        }

        // Update lace. (calculated at psxHsyncCalculate() on init/defreeze)
        if (hSyncCount >= HSyncTotal[g_config.PsxType]) {
            hSyncCount = 0;

            GPU_vBlank(0);
            setIrq(0x01);

            GPU_updateLace();
            EmuUpdate();
        }
    }

    DebugVSync();
}

/******************************************************************************/

void psxRcntWcount(u32 index, u32 value) {
    verboseLog(2, "[RCNT %i] wcount: %x\n", index, value);

    psxRcntUpdate();

    _psxRcntWcount(index, value);
    psxRcntSet();
}

void psxRcntWmode(u32 index, u32 value) {
    verboseLog(1, "[RCNT %i] wmode: %x\n", index, value);

    psxRcntUpdate();

    rcnts[index].mode = value;
    rcnts[index].irqState = FALSE;

    switch (index) {
        case 0:
            if (value & Rc0PixelClock) {
                rcnts[index].rate = 5;
            } else {
                rcnts[index].rate = 1;
            }
            break;
        case 1:
            if (value & Rc1HSyncClock) {
                rcnts[index].rate = (PSXCLK / (FrameRate[g_config.PsxType] * HSyncTotal[g_config.PsxType]));
            } else {
                rcnts[index].rate = 1;
            }
            break;
        case 2:
            if (value & Rc2OneEighthClock) {
                rcnts[index].rate = 8;
            } else {
                rcnts[index].rate = 1;
            }

            // TODO: wcount must work.
            if (value & Rc2Disable) {
                rcnts[index].rate = 0xffffffff;
            }
            break;
    }

    _psxRcntWcount(index, 0);
    psxRcntSet();
}

void psxRcntWtarget(u32 index, u32 value) {
    verboseLog(1, "[RCNT %i] wtarget: %x\n", index, value);

    psxRcntUpdate();

    rcnts[index].target = value;  // TODO: only upper 16bit used

    _psxRcntWcount(index, _psxRcntRcount(index));
    psxRcntSet();
}

/******************************************************************************/

u32 psxRcntRcount(u32 index) {
    u32 count;

    psxRcntUpdate();

    count = _psxRcntRcount(index);

    // Parasite Eve 2 fix - artificial clock jitter based on BIAS
    // TODO: any other games depend on getting excepted value from RCNT?
    if (g_config.HackFix && index == 2 && rcnts[index].counterState == CountToTarget &&
        (g_config.RCntFix || ((rcnts[index].mode & 0x2FF) == JITTER_FLAGS))) {
        /*
         *The problem is that...
         *
         *We generate too many cycles during PSX HW hardware operations.
         *
         *OR
         *
         *We simply count too many cycles here for RCNTs.
         *
         *OR
         *
         *RCNT implementation here is only 99% compatible. Assumed this since easities to fix (only PE2 known to be
         *affected).
         */
        static u32 clast = 0xffff;
        static u32 cylast = 0;
        u32 count1 = count;
        count /= BIAS;
        verboseLog(4, "[RCNT %i] rcountpe2: %x %x %x (%u)\n", index, count, count1, clast, (g_psxRegs.cycle - cylast));
        cylast = g_psxRegs.cycle;
        clast = count;
    }

    verboseLog(2, "[RCNT %i] rcount: %x\n", index, count);

    return count;
}

u32 psxRcntRmode(u32 index) {
    u16 mode;

    psxRcntUpdate();

    mode = rcnts[index].mode;
    rcnts[index].mode &= 0xe7ff;

    verboseLog(2, "[RCNT %i] rmode: %x\n", index, mode);

    return mode;
}

u32 psxRcntRtarget(u32 index) {
    verboseLog(2, "[RCNT %i] rtarget: %x\n", index, rcnts[index].target);

    return rcnts[index].target;
}

/******************************************************************************/

void psxHsyncCalculate() {
    HSyncTotal[PSX_TYPE_NTSC] = 263;
    HSyncTotal[PSX_TYPE_PAL] = 313;
    if (g_config.VSyncWA) {
        HSyncTotal[g_config.PsxType] = HSyncTotal[g_config.PsxType] / BIAS;
    } else if (g_config.HackFix) {
        HSyncTotal[g_config.PsxType] = HSyncTotal[g_config.PsxType] + 1;
    }
}

void psxRcntInit() {
    s32 i;

    psxHsyncCalculate();

    // rcnt 0.
    rcnts[0].rate = 1;
    rcnts[0].irq = 0x10;

    // rcnt 1.
    rcnts[1].rate = 1;
    rcnts[1].irq = 0x20;

    // rcnt 2.
    rcnts[2].rate = 1;
    rcnts[2].irq = 0x40;

    // rcnt base.
    rcnts[3].rate = 1;
    rcnts[3].mode = RcCountToTarget;
    rcnts[3].target = (PSXCLK / (FrameRate[g_config.PsxType] * HSyncTotal[g_config.PsxType]));

    for (i = 0; i < CounterQuantity; ++i) {
        _psxRcntWcount(i, 0);
    }

    hSyncCount = 0;
    spuSyncCount = 0;

    psxRcntSet();
}

/******************************************************************************/

s32 psxRcntFreeze(gzFile f, s32 Mode) {
    gzfreeze(&rcnts, sizeof(rcnts));
    gzfreeze(&hSyncCount, sizeof(hSyncCount));
    gzfreeze(&spuSyncCount, sizeof(spuSyncCount));
    gzfreeze(&psxNextCounter, sizeof(psxNextCounter));
    gzfreeze(&psxNextsCounter, sizeof(psxNextsCounter));

    if (Mode == 0) {
        psxHsyncCalculate();
        // iCB: recalculate target count in case overclock is changed
        rcnts[3].target = (PSXCLK / (FrameRate[g_config.PsxType] * HSyncTotal[g_config.PsxType]));
        if (rcnts[1].rate != 1) rcnts[1].rate = (PSXCLK / (FrameRate[g_config.PsxType] * HSyncTotal[g_config.PsxType]));
    }

    return 0;
}

/******************************************************************************/
