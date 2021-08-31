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

#include "core/debug.h"
#include "core/gpu.h"
#include "fmt/printf.h"
#include "spu/interface.h"

/******************************************************************************/

template <typename... Args>
void verboseLog(int32_t level, const char *str, const Args &...args) {
    PSXHW_LOG(str, args...);
}

inline void PCSX::Counters::psxRcntWcountInternal(uint32_t index, uint32_t value) {
    if (value > 0xffff) {
        verboseLog(1, "[RCNT %i] wcount > 0xffff: %x\n", index, value);
        value &= 0xffff;
    }

    m_rcnts[index].cycleStart = PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle;
    m_rcnts[index].cycleStart -= value * m_rcnts[index].rate;

    // TODO: <=.
    if (value < m_rcnts[index].target) {
        m_rcnts[index].cycle = m_rcnts[index].target * m_rcnts[index].rate;
        m_rcnts[index].counterState = CountToTarget;
    } else {
        m_rcnts[index].cycle = 0xffff * m_rcnts[index].rate;
        m_rcnts[index].counterState = CountToOverflow;
    }
    verboseLog(5, "[RCNT %i] scount: %x\n", index, value);
}

inline uint32_t PCSX::Counters::psxRcntRcountInternal(uint32_t index) {
    uint32_t count;

    count = PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle;
    count -= m_rcnts[index].cycleStart;
    count /= m_rcnts[index].rate;

    if (count > 0xffff) {
        verboseLog(1, "[RCNT %i] rcount > 0xffff: %x\n", index, count);
        count &= 0xffff;
    }

    return count;
}

void PCSX::Counters::psxRcntSet() {
    int32_t countToUpdate;
    uint32_t i;

    m_psxNextsCounter = PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle;
    m_psxNextCounter = 0x7fffffff;

    for (i = 0; i < CounterQuantity; ++i) {
        countToUpdate = m_rcnts[i].cycle - (m_psxNextsCounter - m_rcnts[i].cycleStart);

        if (countToUpdate < 0) {
            m_psxNextCounter = 0;
            break;
        }

        if (countToUpdate < (int32_t)m_psxNextCounter) {
            m_psxNextCounter = countToUpdate;
        }
    }
}

/******************************************************************************/

void PCSX::Counters::psxRcntReset(uint32_t index) {
    uint32_t count;

    if (m_rcnts[index].counterState == CountToTarget) {
        if (m_rcnts[index].mode & RcCountToTarget) {
            count = PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle;
            count -= m_rcnts[index].cycleStart;
            count /= m_rcnts[index].rate;
            count -= m_rcnts[index].target;
        } else {
            count = psxRcntRcountInternal(index);
        }

        psxRcntWcountInternal(index, count);

        if (m_rcnts[index].mode & RcIrqOnTarget) {
            if ((m_rcnts[index].mode & RcIrqRegenerate) || (!m_rcnts[index].irqState)) {
                verboseLog(3, "[RCNT %i] irq: %x\n", index, count);
                setIrq(m_rcnts[index].irq);
                m_rcnts[index].irqState = true;
            }
        }

        m_rcnts[index].mode |= RcCountEqTarget;
    } else if (m_rcnts[index].counterState == CountToOverflow) {
        count = PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle;
        count -= m_rcnts[index].cycleStart;
        count /= m_rcnts[index].rate;
        count -= 0xffff;

        psxRcntWcountInternal(index, count);

        if (m_rcnts[index].mode & RcIrqOnOverflow) {
            if ((m_rcnts[index].mode & RcIrqRegenerate) || (!m_rcnts[index].irqState)) {
                verboseLog(3, "[RCNT %i] irq: %x\n", index, count);
                setIrq(m_rcnts[index].irq);
                m_rcnts[index].irqState = true;
            }
        }

        m_rcnts[index].mode |= RcOverflow;
    }

    m_rcnts[index].mode |= RcIrqRequest;

    psxRcntSet();
}

void PCSX::Counters::psxRcntUpdate() {
    const uint32_t cycle = PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle;

    {
        uint32_t prev = g_emulator->m_psxCpu->m_psxRegs.previousCycles;
        uint64_t diff;
        if (cycle > prev) {
            diff = cycle - prev;
        } else {
            diff = std::numeric_limits<uint32_t>::max();
            diff += cycle + 1;
            diff -= prev;
        }
        diff *= 4410000;
        diff /= g_emulator->settings.get<Emulator::SettingScaler>();
        diff /= g_emulator->m_psxClockSpeed;
        uint32_t target = m_audioFrames + diff;
        uint32_t newFrames = g_emulator->m_spu->getCurrentFrames();
        int32_t framesDiff = target - newFrames;
        if (framesDiff > 0) {
            g_emulator->m_psxCpu->m_psxRegs.previousCycles = cycle;
            g_emulator->m_spu->waitForGoal(target);
            m_audioFrames = target;
        } else if (framesDiff < -100000) {
            m_audioFrames = newFrames;
        }
    }

    // rcnt 0.
    if (cycle - m_rcnts[0].cycleStart >= m_rcnts[0].cycle) {
        psxRcntReset(0);
    }

    // rcnt 1.
    if (cycle - m_rcnts[1].cycleStart >= m_rcnts[1].cycle) {
        psxRcntReset(1);
    }

    // rcnt 2.
    if (cycle - m_rcnts[2].cycleStart >= m_rcnts[2].cycle) {
        psxRcntReset(2);
    }
    // rcnt base.
    if (cycle - m_rcnts[3].cycleStart >= m_rcnts[3].cycle) {
        psxRcntReset(3);

        PCSX::g_emulator->m_gpu->hSync(m_hSyncCount);

        m_spuSyncCount++;
        m_hSyncCount++;

        // Update spu.
        if (m_spuSyncCount >= SpuUpdInterval[PCSX::g_emulator->settings.get<PCSX::Emulator::SettingVideo>()]) {
            m_spuSyncCount = 0;

            PCSX::g_emulator->m_spu->async(
                SpuUpdInterval[PCSX::g_emulator->settings.get<PCSX::Emulator::SettingVideo>()] * m_rcnts[3].target);
        }

#ifdef ENABLE_SIO1API
        if (SIO1_update) {
            SIO1_update(0);
        }
#endif

        // VSync irq.
        if (m_hSyncCount == VBlankStart[PCSX::g_emulator->settings.get<PCSX::Emulator::SettingVideo>()]) {
            PCSX::g_emulator->m_gpu->vBlank(1);

            // For the best times. :D
            // setIrq( 0x01 );
        }

        // Update lace. (calculated at psxHsyncCalculate() on init/defreeze)
        if (m_hSyncCount >= m_HSyncTotal[PCSX::g_emulator->settings.get<PCSX::Emulator::SettingVideo>()]) {
            m_hSyncCount = 0;

            PCSX::g_emulator->m_gpu->vBlank(0);
            setIrq(0x01);

            PCSX::g_emulator->m_gpu->updateLace();
            PCSX::g_emulator->vsync();
        }
    }
}

/******************************************************************************/

void PCSX::Counters::psxRcntWcount(uint32_t index, uint32_t value) {
    verboseLog(2, "[RCNT %i] wcount: %x\n", index, value);

    psxRcntUpdate();

    psxRcntWcountInternal(index, value);
    psxRcntSet();
}

void PCSX::Counters::psxRcntWmode(uint32_t index, uint32_t value) {
    verboseLog(1, "[RCNT %i] wmode: %x\n", index, value);

    psxRcntUpdate();

    m_rcnts[index].mode = value;
    m_rcnts[index].irqState = false;

    switch (index) {
        case 0:
            if (value & Rc0PixelClock) {
                m_rcnts[index].rate = 5;
            } else {
                m_rcnts[index].rate = 1;
            }
            break;
        case 1:
            if (value & Rc1HSyncClock) {
                m_rcnts[index].rate = (PCSX::g_emulator->m_psxClockSpeed /
                                       (FrameRate[PCSX::g_emulator->settings.get<PCSX::Emulator::SettingVideo>()] *
                                        m_HSyncTotal[PCSX::g_emulator->settings.get<PCSX::Emulator::SettingVideo>()]));
            } else {
                m_rcnts[index].rate = 1;
            }
            break;
        case 2:
            if (value & Rc2OneEighthClock) {
                m_rcnts[index].rate = 8;
            } else {
                m_rcnts[index].rate = 1;
            }

            // TODO: wcount must work.
            if (value & Rc2Disable) {
                m_rcnts[index].rate = 0xffffffff;
            }
            break;
    }

    psxRcntWcountInternal(index, 0);
    psxRcntSet();
}

void PCSX::Counters::psxRcntWtarget(uint32_t index, uint32_t value) {
    verboseLog(1, "[RCNT %i] wtarget: %x\n", index, value);

    psxRcntUpdate();

    m_rcnts[index].target =
        value;  // The target is only 16 bits. To make sure of this, the 32-bit write handlers mask it with 0xFFFF

    psxRcntWcountInternal(index, psxRcntRcountInternal(index));
    psxRcntSet();
}

/******************************************************************************/

uint32_t PCSX::Counters::psxRcntRcount(uint32_t index) {
    uint32_t count;

    psxRcntUpdate();

    count = psxRcntRcountInternal(index);

    // Parasite Eve 2 fix - artificial clock jitter based on PCSX::Emulator::BIAS
    // TODO: any other games depend on getting excepted value from RCNT?
    if (PCSX::g_emulator->config().HackFix && index == 2 && m_rcnts[index].counterState == CountToTarget &&
        (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingRCntFix>() ||
         ((m_rcnts[index].mode & 0x2FF) == JITTER_FLAGS))) {
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
        static uint32_t clast = 0xffff;
        static uint32_t cylast = 0;
        uint32_t count1 = count;
        count /= PCSX::Emulator::BIAS;
        verboseLog(4, "[RCNT %i] rcountpe2: %x %x %x (%u)\n", index, count, count1, clast,
                   (PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle - cylast));
        cylast = PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle;
        clast = count;
    }

    verboseLog(2, "[RCNT %i] rcount: %x\n", index, count);

    return count;
}

uint32_t PCSX::Counters::psxRcntRmode(uint32_t index) {
    uint16_t mode;

    psxRcntUpdate();

    mode = m_rcnts[index].mode;
    m_rcnts[index].mode &= 0xe7ff;

    verboseLog(2, "[RCNT %i] rmode: %x\n", index, mode);

    return mode;
}

uint32_t PCSX::Counters::psxRcntRtarget(uint32_t index) {
    verboseLog(2, "[RCNT %i] rtarget: %x\n", index, m_rcnts[index].target);

    return m_rcnts[index].target;
}

/******************************************************************************/

void PCSX::Counters::psxHsyncCalculate() {
    m_HSyncTotal[PCSX::Emulator::PSX_TYPE_NTSC] = 263;
    m_HSyncTotal[PCSX::Emulator::PSX_TYPE_PAL] = 313;
    if (PCSX::g_emulator->config().VSyncWA) {
        m_HSyncTotal[PCSX::g_emulator->settings.get<PCSX::Emulator::SettingVideo>()] =
            m_HSyncTotal[PCSX::g_emulator->settings.get<PCSX::Emulator::SettingVideo>()] / PCSX::Emulator::BIAS;
    } else if (PCSX::g_emulator->config().HackFix) {
        m_HSyncTotal[PCSX::g_emulator->settings.get<PCSX::Emulator::SettingVideo>()] =
            m_HSyncTotal[PCSX::g_emulator->settings.get<PCSX::Emulator::SettingVideo>()] + 1;
    }
}

void PCSX::Counters::psxRcntInit() {
    int32_t i;

    psxHsyncCalculate();

    // rcnt 0.
    m_rcnts[0].rate = 1;
    m_rcnts[0].irq = 0x10;

    // rcnt 1.
    m_rcnts[1].rate = 1;
    m_rcnts[1].irq = 0x20;

    // rcnt 2.
    m_rcnts[2].rate = 1;
    m_rcnts[2].irq = 0x40;

    // rcnt base.
    m_rcnts[3].rate = 1;
    m_rcnts[3].mode = RcCountToTarget;
    m_rcnts[3].target = (PCSX::g_emulator->m_psxClockSpeed /
                         (FrameRate[PCSX::g_emulator->settings.get<PCSX::Emulator::SettingVideo>()] *
                          m_HSyncTotal[PCSX::g_emulator->settings.get<PCSX::Emulator::SettingVideo>()]));

    for (i = 0; i < CounterQuantity; ++i) {
        psxRcntWcountInternal(i, 0);
    }

    m_hSyncCount = 0;
    m_spuSyncCount = 0;

    m_audioFrames = PCSX::g_emulator->m_spu->getCurrentFrames();

    psxRcntSet();
}

/******************************************************************************/

void PCSX::Counters::save(PCSX::SaveStates::Counters &counters) {
    for (unsigned i = 0; i < CounterQuantity; i++) {
        counters.get<SaveStates::Rcnts>().value[i].get<SaveStates::RcntMode>().value = m_rcnts[i].mode;
        counters.get<SaveStates::Rcnts>().value[i].get<SaveStates::RcntTarget>().value = m_rcnts[i].target;
        counters.get<SaveStates::Rcnts>().value[i].get<SaveStates::RcntRate>().value = m_rcnts[i].rate;
        counters.get<SaveStates::Rcnts>().value[i].get<SaveStates::RcntIRQ>().value = m_rcnts[i].irq;
        counters.get<SaveStates::Rcnts>().value[i].get<SaveStates::RcntCounterState>().value = m_rcnts[i].counterState;
        counters.get<SaveStates::Rcnts>().value[i].get<SaveStates::RcntIRQState>().value = m_rcnts[i].irqState;
        counters.get<SaveStates::Rcnts>().value[i].get<SaveStates::RcntCycle>().value = m_rcnts[i].cycle;
        counters.get<SaveStates::Rcnts>().value[i].get<SaveStates::RcntCycleStart>().value = m_rcnts[i].cycleStart;
    }
    counters.get<SaveStates::HSyncCount>().value = m_hSyncCount;
    counters.get<SaveStates::SPUSyncCount>().value = m_spuSyncCount;
    counters.get<SaveStates::PSXNextCounter>().value = m_psxNextCounter;
    counters.get<SaveStates::PSXNextsCounter>().value = m_psxNextsCounter;
}

void PCSX::Counters::load(const PCSX::SaveStates::Counters &counters) {
    for (unsigned i = 0; i < CounterQuantity; i++) {
        m_rcnts[i].mode = counters.get<SaveStates::Rcnts>().value[i].get<SaveStates::RcntMode>().value;
        m_rcnts[i].target = counters.get<SaveStates::Rcnts>().value[i].get<SaveStates::RcntTarget>().value;
        m_rcnts[i].rate = counters.get<SaveStates::Rcnts>().value[i].get<SaveStates::RcntRate>().value;
        m_rcnts[i].irq = counters.get<SaveStates::Rcnts>().value[i].get<SaveStates::RcntIRQ>().value;
        m_rcnts[i].counterState = counters.get<SaveStates::Rcnts>().value[i].get<SaveStates::RcntCounterState>().value;
        m_rcnts[i].irqState = counters.get<SaveStates::Rcnts>().value[i].get<SaveStates::RcntIRQState>().value;
        m_rcnts[i].cycle = counters.get<SaveStates::Rcnts>().value[i].get<SaveStates::RcntCycle>().value;
        m_rcnts[i].cycleStart = counters.get<SaveStates::Rcnts>().value[i].get<SaveStates::RcntCycleStart>().value;
    }
    m_hSyncCount = counters.get<SaveStates::HSyncCount>().value;
    m_spuSyncCount = counters.get<SaveStates::SPUSyncCount>().value;
    m_psxNextCounter = counters.get<SaveStates::PSXNextCounter>().value;
    m_psxNextsCounter = counters.get<SaveStates::PSXNextsCounter>().value;

    psxHsyncCalculate();
    // iCB: recalculate target count in case overclock is changed
    m_rcnts[3].target = (PCSX::g_emulator->m_psxClockSpeed /
                         (FrameRate[PCSX::g_emulator->settings.get<PCSX::Emulator::SettingVideo>()] *
                          m_HSyncTotal[PCSX::g_emulator->settings.get<PCSX::Emulator::SettingVideo>()]));
    if (m_rcnts[1].rate != 1)
        m_rcnts[1].rate = (PCSX::g_emulator->m_psxClockSpeed /
                           (FrameRate[PCSX::g_emulator->settings.get<PCSX::Emulator::SettingVideo>()] *
                            m_HSyncTotal[PCSX::g_emulator->settings.get<PCSX::Emulator::SettingVideo>()]));

    m_audioFrames = g_emulator->m_spu->getCurrentFrames();
}
