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

#include "core/psxcounters.h"

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

static const u32 s_countToOverflow = 0;
static const u32 s_countToTarget = 1;

static const u32 s_frameRate[] = {60, 50};
static const u32 s_VBlankStart[] = {243, 256};
static const u32 s_spuUpdInterval[] = {23, 22};

#if defined(PSXHW_LOG)
#if defined(PSXMEM_LOG) && defined(PSXDMA_LOG)  // automatic guess if we want trace level logging
static const s32 VerboseLevel = 4;
#else
static const s32 VerboseLevel = 0;
#endif
#endif
static const u16 JITTER_FLAGS = (Rc2OneEighthClock | RcIrqRegenerate | RcCountToTarget);

/******************************************************************************/

static Rcnt s_rcnts[CounterQuantity];

static u32 s_hSyncCount = 0;
static u32 s_spuSyncCount = 0;

static u32 s_HSyncTotal[PSX_TYPE_PAL + 1];  // 2
u32 g_psxNextCounter = 0, g_psxNextsCounter = 0;

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

    s_rcnts[index].cycleStart = g_psxRegs.cycle;
    s_rcnts[index].cycleStart -= value * s_rcnts[index].rate;

    // TODO: <=.
    if (value < s_rcnts[index].target) {
        s_rcnts[index].cycle = s_rcnts[index].target * s_rcnts[index].rate;
        s_rcnts[index].counterState = s_countToTarget;
    } else {
        s_rcnts[index].cycle = 0xffff * s_rcnts[index].rate;
        s_rcnts[index].counterState = s_countToOverflow;
    }
    verboseLog(5, "[RCNT %i] scount: %x\n", index, value);
}

static inline u32 _psxRcntRcount(u32 index) {
    u32 count;

    count = g_psxRegs.cycle;
    count -= s_rcnts[index].cycleStart;
    count /= s_rcnts[index].rate;

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

    g_psxNextsCounter = g_psxRegs.cycle;
    g_psxNextCounter = 0x7fffffff;

    for (i = 0; i < CounterQuantity; ++i) {
        countToUpdate = s_rcnts[i].cycle - (g_psxNextsCounter - s_rcnts[i].cycleStart);

        if (countToUpdate < 0) {
            g_psxNextCounter = 0;
            break;
        }

        if (countToUpdate < (s32)g_psxNextCounter) {
            g_psxNextCounter = countToUpdate;
        }
    }
}

/******************************************************************************/

static void psxRcntReset(u32 index) {
    u32 count;

    if (s_rcnts[index].counterState == s_countToTarget) {
        if (s_rcnts[index].mode & RcCountToTarget) {
            count = g_psxRegs.cycle;
            count -= s_rcnts[index].cycleStart;
            count /= s_rcnts[index].rate;
            count -= s_rcnts[index].target;
        } else {
            count = _psxRcntRcount(index);
        }

        _psxRcntWcount(index, count);

        if (s_rcnts[index].mode & RcIrqOnTarget) {
            if ((s_rcnts[index].mode & RcIrqRegenerate) || (!s_rcnts[index].irqState)) {
                verboseLog(3, "[RCNT %i] irq: %x\n", index, count);
                setIrq(s_rcnts[index].irq);
                s_rcnts[index].irqState = TRUE;
            }
        }

        s_rcnts[index].mode |= RcCountEqTarget;
    } else if (s_rcnts[index].counterState == s_countToOverflow) {
        count = g_psxRegs.cycle;
        count -= s_rcnts[index].cycleStart;
        count /= s_rcnts[index].rate;
        count -= 0xffff;

        _psxRcntWcount(index, count);

        if (s_rcnts[index].mode & RcIrqOnOverflow) {
            if ((s_rcnts[index].mode & RcIrqRegenerate) || (!s_rcnts[index].irqState)) {
                verboseLog(3, "[RCNT %i] irq: %x\n", index, count);
                setIrq(s_rcnts[index].irq);
                s_rcnts[index].irqState = TRUE;
            }
        }

        s_rcnts[index].mode |= RcOverflow;
    }

    s_rcnts[index].mode |= RcIrqRequest;

    psxRcntSet();
}

void psxRcntUpdate() {
    u32 cycle;

    cycle = g_psxRegs.cycle;

    // rcnt 0.
    if (cycle - s_rcnts[0].cycleStart >= s_rcnts[0].cycle) {
        psxRcntReset(0);
    }

    // rcnt 1.
    if (cycle - s_rcnts[1].cycleStart >= s_rcnts[1].cycle) {
        psxRcntReset(1);
    }

    // rcnt 2.
    if (cycle - s_rcnts[2].cycleStart >= s_rcnts[2].cycle) {
        psxRcntReset(2);
    }

    // rcnt base.
    if (cycle - s_rcnts[3].cycleStart >= s_rcnts[3].cycle) {
        psxRcntReset(3);

        GPU_hSync(s_hSyncCount);

        s_spuSyncCount++;
        s_hSyncCount++;

        // Update spu.
        if (s_spuSyncCount >= s_spuUpdInterval[g_config.PsxType]) {
            s_spuSyncCount = 0;

            if (SPU_async) {
                SPU_async(s_spuUpdInterval[g_config.PsxType] * s_rcnts[3].target);
            }
        }

#ifdef ENABLE_SIO1API
        if (SIO1_update) {
            SIO1_update(0);
        }
#endif

        // VSync irq.
        if (s_hSyncCount == s_VBlankStart[g_config.PsxType]) {
            GPU_vBlank(1);

            // For the best times. :D
            // setIrq( 0x01 );
        }

        // Update lace. (calculated at psxHsyncCalculate() on init/defreeze)
        if (s_hSyncCount >= s_HSyncTotal[g_config.PsxType]) {
            s_hSyncCount = 0;

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

    s_rcnts[index].mode = value;
    s_rcnts[index].irqState = FALSE;

    switch (index) {
        case 0:
            if (value & Rc0PixelClock) {
                s_rcnts[index].rate = 5;
            } else {
                s_rcnts[index].rate = 1;
            }
            break;
        case 1:
            if (value & Rc1HSyncClock) {
                s_rcnts[index].rate = (PSXCLK / (s_frameRate[g_config.PsxType] * s_HSyncTotal[g_config.PsxType]));
            } else {
                s_rcnts[index].rate = 1;
            }
            break;
        case 2:
            if (value & Rc2OneEighthClock) {
                s_rcnts[index].rate = 8;
            } else {
                s_rcnts[index].rate = 1;
            }

            // TODO: wcount must work.
            if (value & Rc2Disable) {
                s_rcnts[index].rate = 0xffffffff;
            }
            break;
    }

    _psxRcntWcount(index, 0);
    psxRcntSet();
}

void psxRcntWtarget(u32 index, u32 value) {
    verboseLog(1, "[RCNT %i] wtarget: %x\n", index, value);

    psxRcntUpdate();

    s_rcnts[index].target = value;  // TODO: only upper 16bit used

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
    if (g_config.HackFix && index == 2 && s_rcnts[index].counterState == s_countToTarget &&
        (g_config.RCntFix || ((s_rcnts[index].mode & 0x2FF) == JITTER_FLAGS))) {
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

    mode = s_rcnts[index].mode;
    s_rcnts[index].mode &= 0xe7ff;

    verboseLog(2, "[RCNT %i] rmode: %x\n", index, mode);

    return mode;
}

u32 psxRcntRtarget(u32 index) {
    verboseLog(2, "[RCNT %i] rtarget: %x\n", index, s_rcnts[index].target);

    return s_rcnts[index].target;
}

/******************************************************************************/

void psxHsyncCalculate() {
    s_HSyncTotal[PSX_TYPE_NTSC] = 263;
    s_HSyncTotal[PSX_TYPE_PAL] = 313;
    if (g_config.VSyncWA) {
        s_HSyncTotal[g_config.PsxType] = s_HSyncTotal[g_config.PsxType] / BIAS;
    } else if (g_config.HackFix) {
        s_HSyncTotal[g_config.PsxType] = s_HSyncTotal[g_config.PsxType] + 1;
    }
}

void psxRcntInit() {
    s32 i;

    psxHsyncCalculate();

    // rcnt 0.
    s_rcnts[0].rate = 1;
    s_rcnts[0].irq = 0x10;

    // rcnt 1.
    s_rcnts[1].rate = 1;
    s_rcnts[1].irq = 0x20;

    // rcnt 2.
    s_rcnts[2].rate = 1;
    s_rcnts[2].irq = 0x40;

    // rcnt base.
    s_rcnts[3].rate = 1;
    s_rcnts[3].mode = RcCountToTarget;
    s_rcnts[3].target = (PSXCLK / (s_frameRate[g_config.PsxType] * s_HSyncTotal[g_config.PsxType]));

    for (i = 0; i < CounterQuantity; ++i) {
        _psxRcntWcount(i, 0);
    }

    s_hSyncCount = 0;
    s_spuSyncCount = 0;

    psxRcntSet();
}

/******************************************************************************/

s32 psxRcntFreeze(gzFile f, s32 Mode) {
    gzfreeze(&s_rcnts, sizeof(s_rcnts));
    gzfreeze(&s_hSyncCount, sizeof(s_hSyncCount));
    gzfreeze(&s_spuSyncCount, sizeof(s_spuSyncCount));
    gzfreeze(&g_psxNextCounter, sizeof(g_psxNextCounter));
    gzfreeze(&g_psxNextsCounter, sizeof(g_psxNextsCounter));

    if (Mode == 0) {
        psxHsyncCalculate();
        // iCB: recalculate target count in case overclock is changed
        s_rcnts[3].target = (PSXCLK / (s_frameRate[g_config.PsxType] * s_HSyncTotal[g_config.PsxType]));
        if (s_rcnts[1].rate != 1) s_rcnts[1].rate = (PSXCLK / (s_frameRate[g_config.PsxType] * s_HSyncTotal[g_config.PsxType]));
    }

    return 0;
}

/******************************************************************************/
