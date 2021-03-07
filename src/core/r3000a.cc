/***************************************************************************
 *   Copyright (C) 2007 Ryan Schultz, PCSX-df Team, PCSX team              *
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
 * R3000A CPU functions.
 */

#include "core/r3000a.h"

#include "core/cdrom.h"
#include "core/debug.h"
#include "core/gpu.h"
#include "core/gte.h"
#include "core/mdec.h"
#include "core/pgxp_mem.h"
#include "core/spu.h"

int PCSX::R3000Acpu::psxInit() {
    g_system->printf(_("PCSX-Redux booting\n"));
    g_system->printf(_("Copyright (C) 2019-2021 PCSX-Redux authors\n"));

    if (g_emulator->settings.get<Emulator::SettingDynarec>()) g_emulator->m_psxCpu = Cpus::DynaRec();
    if (!g_emulator->m_psxCpu) g_emulator->m_psxCpu = Cpus::Interpreted();

    PGXP_Init();

    return g_emulator->m_psxCpu->Init();
}

void PCSX::R3000Acpu::psxReset() {
    Reset();

    memset(&m_psxRegs, 0, sizeof(m_psxRegs));
    m_shellStarted = false;

    m_psxRegs.pc = 0xbfc00000;  // Start in bootstrap

    m_psxRegs.CP0.r[12] = 0x10900000;  // COP0 enabled | BEV = 1 | TS = 1
    m_psxRegs.CP0.r[15] = 0x00000002;  // PRevID = Revision ID, same as R3000A

    PCSX::g_emulator->m_hw->psxHwReset();

    EMU_LOG("*BIOS END*\n");
}

void PCSX::R3000Acpu::psxShutdown() { Shutdown(); }

void PCSX::R3000Acpu::psxException(uint32_t code, bool bd) {
    // Set the Cause
    m_psxRegs.CP0.n.Cause = code;

    // Set the EPC & PC
    if (bd) {
        PSXCPU_LOG("bd set!!!\n");
        g_system->printf("bd set!!!\n");
        m_psxRegs.CP0.n.Cause |= 0x80000000;
        m_psxRegs.CP0.n.EPC = (m_psxRegs.pc - 4);
    } else
        m_psxRegs.CP0.n.EPC = (m_psxRegs.pc);

    if (m_psxRegs.CP0.n.Status & 0x400000)
        m_psxRegs.pc = 0xbfc00180;
    else
        m_psxRegs.pc = 0x80000080;

    // Set the Status
    m_psxRegs.CP0.n.Status = (m_psxRegs.CP0.n.Status & ~0x3f) | ((m_psxRegs.CP0.n.Status & 0xf) << 2);
}

void PCSX::R3000Acpu::psxBranchTest() {
#if 0
    if( SPU_async )
    {
        static int init;
        int elapsed;

        if( init == 0 ) {
            // 10 apu cycles
            // - Final Fantasy Tactics (distorted - dropped sound effects)
            m_psxRegs.intCycle[PSXINT_SPUASYNC].cycle = g_emulator->m_psxClockSpeed / 44100 * 10;

            init = 1;
        }

        elapsed = m_psxRegs.cycle - m_psxRegs.intCycle[PSXINT_SPUASYNC].sCycle;
        if (elapsed >= m_psxRegs.intCycle[PSXINT_SPUASYNC].cycle) {
            SPU_async( elapsed );

            m_psxRegs.intCycle[PSXINT_SPUASYNC].sCycle = m_psxRegs.cycle;
        }
    }
#endif

    const uint32_t cycle = m_psxRegs.cycle;

    if ((cycle - PCSX::g_emulator->m_psxCounters->m_psxNextsCounter) >=
        PCSX::g_emulator->m_psxCounters->m_psxNextCounter)
        PCSX::g_emulator->m_psxCounters->psxRcntUpdate();

    if (m_psxRegs.spuInterrupt.exchange(false)) PCSX::g_emulator->m_spu->interrupt();

    const uint32_t interrupts = m_psxRegs.interrupt;

    int32_t lowestDistance = std::numeric_limits<int32_t>::max();
    uint32_t lowestTarget = cycle;
    uint32_t * targets = m_psxRegs.intTargets;

    if ((interrupts != 0) && (((int32_t)(m_psxRegs.lowestTarget - cycle)) <= 0)) {
        auto checkAndUpdate = [&lowestDistance, &lowestTarget, interrupts, cycle, targets, this](unsigned interrupt, std::function<void()> act) {
            uint32_t mask = 1 << interrupt;
            if ((interrupts & mask) == 0) return;
            uint32_t target = targets[interrupt];
            int32_t dist = target - cycle;
            if (dist > 0) {
                if (lowestDistance > dist) {
                    lowestDistance = dist;
                    lowestTarget = target;
                }
            } else {
                m_psxRegs.interrupt &= ~mask;
                PSXCPU_LOG("inttrig %08x\n", PSXINT_CDRLID);
                act();
            }
        };

        checkAndUpdate(PSXINT_SIO, []() { g_emulator->m_sio->interrupt(); });
        checkAndUpdate(PSXINT_CDR, []() { g_emulator->m_cdrom->interrupt(); });
        checkAndUpdate(PSXINT_CDREAD, []() { g_emulator->m_cdrom->readInterrupt(); });
        checkAndUpdate(PSXINT_GPUDMA, []() { GPU::gpuInterrupt(); });
        checkAndUpdate(PSXINT_MDECOUTDMA, []() { g_emulator->m_mdec->mdec1Interrupt(); });
        checkAndUpdate(PSXINT_SPUDMA, []() { spuInterrupt(); });
        checkAndUpdate(PSXINT_MDECINDMA, []() { g_emulator->m_mdec->mdec0Interrupt(); });
        checkAndUpdate(PSXINT_GPUOTCDMA, []() { gpuotcInterrupt(); });
        checkAndUpdate(PSXINT_CDRDMA, []() { g_emulator->m_cdrom->dmaInterrupt(); });
        checkAndUpdate(PSXINT_CDRPLAY, []() { g_emulator->m_cdrom->playInterrupt(); });
        checkAndUpdate(PSXINT_CDRDBUF, []() { g_emulator->m_cdrom->decodedBufferInterrupt(); });
        checkAndUpdate(PSXINT_CDRLID, []() { g_emulator->m_cdrom->lidSeekInterrupt(); });
        m_psxRegs.lowestTarget = lowestTarget;
    }
    if ((psxHu32(0x1070) & psxHu32(0x1074)) && ((m_psxRegs.CP0.n.Status & 0x401) == 0x401)) {
        PSXCPU_LOG("Interrupt: %x %x\n", psxHu32(0x1070), psxHu32(0x1074));
        psxException(0x400, 0);
    }
}

void PCSX::R3000Acpu::psxSetPGXPMode(uint32_t pgxpMode) {
    SetPGXPMode(pgxpMode);
    // g_emulator->m_psxCpu->Reset();
}

std::unique_ptr<PCSX::R3000Acpu> PCSX::Cpus::Interpreted() {
    std::unique_ptr<PCSX::R3000Acpu> cpu = getInterpreted();
    if (cpu->Implemented()) return cpu;
    return nullptr;
}

std::unique_ptr<PCSX::R3000Acpu> PCSX::Cpus::DynaRec() {
    std::unique_ptr<PCSX::R3000Acpu> cpu = getX86DynaRec();
    if (cpu->Implemented()) return cpu;
    return nullptr;
}
