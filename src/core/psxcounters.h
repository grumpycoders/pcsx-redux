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

#pragma once

#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"

namespace PCSX {

struct SaveStateWrapper;

class Counters {
  private:
    static inline void setIrq(uint32_t irq) { g_emulator->m_mem->setIRQ(irq); }
    uint32_t readCounterInternal(uint32_t index);
    void writeCounterInternal(uint32_t index, uint32_t value);

    void set();
    void reset(uint32_t index);
    void calculateHsync();

    struct Rcnt {
        uint16_t mode, target;
        uint32_t rate, irq, counterState, irqState;
        uint64_t cycle, cycleStart;
    };

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

    static const uint32_t CounterQuantity = 4;
    static const uint32_t CountToOverflow = 0;
    static const uint32_t CountToTarget = 1;

    static inline const uint32_t FrameRate[] = {60, 50};
    static inline const uint32_t VBlankStart[] = {243, 256};
    static inline const uint32_t SpuUpdInterval[] = {23, 22};

    static const uint16_t JITTER_FLAGS = (Rc2OneEighthClock | RcIrqRegenerate | RcCountToTarget);

    Rcnt m_rcnts[CounterQuantity];

    uint32_t m_hSyncCount = 0;
    uint32_t m_audioFrames = 0;
    int32_t m_spuSyncCountdown = 0;

    uint32_t m_HSyncTotal[PCSX::Emulator::PSX_TYPE_PAL + 1];  // 2
  public:
    uint64_t m_psxNextCounter;
    bool m_pollSIO1 = false;
    void init();
    void update();

    void writeCounter(uint32_t index, uint32_t value);
    void writeMode(uint32_t index, uint32_t value);
    void writeTarget(uint32_t index, uint32_t value);

    uint32_t readCounter(uint32_t index);
    uint32_t readMode(uint32_t index);
    uint32_t readTarget(uint32_t index);

    void serialize(SaveStateWrapper *);
    void deserialize(const SaveStateWrapper *);
};

}  // namespace PCSX
