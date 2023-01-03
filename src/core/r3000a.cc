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
#include "core/sio.h"
#include "core/sio1.h"
#include "core/spu.h"
#include "fmt/format.h"
#include "magic_enum/include/magic_enum.hpp"

int PCSX::R3000Acpu::psxInit() {
    g_system->printf(_("PCSX-Redux booting\n"));
    g_system->printf(_("Copyright (C) 2019-2023 PCSX-Redux authors\n"));
    const auto& args = g_system->getArgs();

    if (args.get<bool>("interpreter"))
        g_emulator->m_cpu = Cpus::Interpreted();
    else if (args.get<bool>("dynarec"))
        g_emulator->m_cpu = Cpus::DynaRec();
    else if (g_emulator->settings.get<Emulator::SettingDynarec>())
        g_emulator->m_cpu = Cpus::DynaRec();

    if (!g_emulator->m_cpu) g_emulator->m_cpu = Cpus::Interpreted();

    PGXP_Init();

    return g_emulator->m_cpu->Init();
}

void PCSX::R3000Acpu::psxReset() {
    Reset();

    memset(&m_regs, 0, sizeof(m_regs));
    m_shellStarted = false;

    m_regs.pc = 0xbfc00000;  // Start in bootstrap

    g_emulator->m_debug->updatedPC(0xbfc00000);

    m_regs.CP0.r[12] = 0x10900000;  // COP0 enabled | BEV = 1 | TS = 1
    m_regs.CP0.r[15] = 0x00000002;  // PRevID = Revision ID, same as R3000A

    PCSX::g_emulator->m_hw->reset();
}

void PCSX::R3000Acpu::psxShutdown() { Shutdown(); }

void PCSX::R3000Acpu::exception(uint32_t code, bool bd, bool cop0) {
    auto& emuSettings = g_emulator->settings;
    auto& debugSettings = emuSettings.get<Emulator::SettingDebugSettings>();
    unsigned ec = (code >> 2) & 0x1f;
    auto e = magic_enum::enum_cast<Exception>(ec);
    if (e.has_value()) {
        if (!cop0 && debugSettings.get<Emulator::DebugSettings::PCdrv>() && (e.value() == Exception::Break)) {
            uint32_t code = (PSXMu32(m_regs.pc) >> 6) & 0xfffff;
            auto& regs = m_regs.GPR.n;
            switch (code) {
                case 0x101: {  // PCinit
                    closeAllPCdevFiles();
                    regs.v0 = 0;
                    regs.v1 = 0;
                    m_regs.pc += 4;
                    return;
                }
                case 0x102: {  // PCcreat
                    if (m_pcdrvFiles.size() > std::numeric_limits<decltype(m_pcdrvIndex)>::max()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        m_regs.pc += 4;
                        return;
                    }
                    std::filesystem::path basepath = debugSettings.get<Emulator::DebugSettings::PCdrvBase>();
                    const char* filename = PSXS(m_regs.GPR.n.a0);
                    PCdrvFiles::iterator file;
                    do {
                        file = m_pcdrvFiles.find(++m_pcdrvIndex);
                    } while (file != m_pcdrvFiles.end());
                    file = m_pcdrvFiles.insert(m_pcdrvIndex, new PCdrvFile(basepath / filename, FileOps::TRUNCATE));
                    file->m_relativeFilename = filename;
                    if (file->failed()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        file->close();
                        delete &*file;
                    } else {
                        regs.v0 = 0;
                        regs.v1 = file->getKey();
                    }
                    m_regs.pc += 4;
                    return;
                }
                case 0x103: {  // PCopen
                    if (m_pcdrvFiles.size() > std::numeric_limits<decltype(m_pcdrvIndex)>::max()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        m_regs.pc += 4;
                        return;
                    }
                    std::filesystem::path basepath = debugSettings.get<Emulator::DebugSettings::PCdrvBase>();
                    const char* filename = PSXS(m_regs.GPR.n.a0);
                    PCdrvFiles::iterator file;
                    do {
                        file = m_pcdrvFiles.find(++m_pcdrvIndex);
                    } while (file != m_pcdrvFiles.end());
                    file = m_pcdrvFiles.insert(m_pcdrvIndex, new PCdrvFile(basepath / filename));
                    file->m_relativeFilename = filename;
                    if (file->failed()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        file->close();
                        delete &*file;
                    } else {
                        regs.v0 = 0;
                        regs.v1 = file->getKey();
                    }
                    m_regs.pc += 4;
                    return;
                }
                case 0x104: {  // PCclose
                    auto file = m_pcdrvFiles.find(m_regs.GPR.n.a0);
                    if (file == m_pcdrvFiles.end()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                    } else {
                        regs.v0 = 0;
                        regs.v1 = 0;
                        file->close();
                        delete &*file;
                    }
                    m_regs.pc += 4;
                    return;
                }
                case 0x105: {  // PCread
                    auto file = m_pcdrvFiles.find(m_regs.GPR.n.a1);
                    if (file == m_pcdrvFiles.end()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        m_regs.pc += 4;
                        return;
                    }
                    if ((regs.v1 = file->read(PSXM(regs.a3), regs.a2)) < 0) {
                        regs.v0 = -1;
                    } else {
                        regs.v0 = 0;
                    }
                    m_regs.pc += 4;
                    return;
                }
                case 0x106: {  // PCwrite
                    auto file = m_pcdrvFiles.find(m_regs.GPR.n.a1);
                    if (file == m_pcdrvFiles.end()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        m_regs.pc += 4;
                        return;
                    }
                    if ((regs.v1 = file->write(PSXM(regs.a3), regs.a2)) < 0) {
                        regs.v0 = -1;
                    } else {
                        regs.v0 = 0;
                    }
                    m_regs.pc += 4;
                    return;
                }
                case 0x107: {  // PClseek
                    auto file = m_pcdrvFiles.find(m_regs.GPR.n.a0);
                    if (file == m_pcdrvFiles.end()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        m_regs.pc += 4;
                        return;
                    }
                    int wheel;
                    switch (regs.a3) {
                        case 0:
                            wheel = SEEK_SET;
                            break;
                        case 1:
                            wheel = SEEK_CUR;
                            break;
                        case 2:
                            wheel = SEEK_END;
                            break;
                        default:
                            regs.v0 = -1;
                            regs.v1 = -1;
                            m_regs.pc += 4;
                            return;
                    }
                    auto ret = file->writable() ? file->wSeek(regs.a2, wheel) : file->rSeek(regs.a2, wheel);
                    if (ret == 0) {
                        regs.v0 = 0;
                        regs.v1 = file->writable() ? file->wTell() : file->rTell();
                    } else {
                        regs.v0 = -1;
                        regs.v1 = ret;
                    }
                    m_regs.pc += 4;
                    return;
                }
                default:
                    break;
            }
        }
        ec = 1 << ec;
        if (!g_system->testmode() && ((debugSettings.get<Emulator::DebugSettings::FirstChanceException>() & ec) != 0)) {
            auto name = magic_enum::enum_name(e.value());
            g_system->printf(fmt::format("First chance exception: {} from 0x{:08x}\n", name, m_regs.pc).c_str());
            g_system->pause(true);
        }
    }

    m_inISR = true;

    // Set the EPC & PC
    if (bd) {
        code |= 0x80000000;
        m_regs.CP0.n.EPC = (m_regs.pc - 4);
    } else {
        m_regs.CP0.n.EPC = (m_regs.pc);
    }

    if (m_regs.CP0.n.Status & 0x400000) {
        m_regs.pc = 0xbfc00180;
    } else {
        m_regs.pc = 0x80000080;
    }

    if (cop0) m_regs.pc -= 0x40;

    // Set the Cause
    m_regs.CP0.n.Cause = code;
    // Set the Status
    m_regs.CP0.n.Status = (m_regs.CP0.n.Status & ~0x3f) | ((m_regs.CP0.n.Status & 0xf) << 2);
}

void PCSX::R3000Acpu::restorePCdrvFile(const std::filesystem::path& filename, uint16_t fd) {
    auto& emuSettings = g_emulator->settings;
    auto& debugSettings = emuSettings.get<Emulator::SettingDebugSettings>();
    std::filesystem::path basepath = debugSettings.get<Emulator::DebugSettings::PCdrvBase>();
    m_pcdrvFiles.insert(fd, new PCdrvFile(basepath / filename));
}

void PCSX::R3000Acpu::restorePCdrvFile(const std::filesystem::path& filename, uint16_t fd, FileOps::Create) {
    auto& emuSettings = g_emulator->settings;
    auto& debugSettings = emuSettings.get<Emulator::SettingDebugSettings>();
    std::filesystem::path basepath = debugSettings.get<Emulator::DebugSettings::PCdrvBase>();
    auto f = new PCdrvFile(basepath / filename, FileOps::CREATE);
    f->wSeek(0, SEEK_END);
    m_pcdrvFiles.insert(fd, f);
}

void PCSX::R3000Acpu::branchTest() {
#if 0
    if( SPU_async )
    {
        static int init;
        int elapsed;

        if( init == 0 ) {
            // 10 apu cycles
            // - Final Fantasy Tactics (distorted - dropped sound effects)
            m_regs.intCycle[PSXINT_SPUASYNC].cycle = g_emulator->m_psxClockSpeed / 44100 * 10;

            init = 1;
        }

        elapsed = m_regs.cycle - m_regs.intCycle[PSXINT_SPUASYNC].sCycle;
        if (elapsed >= m_regs.intCycle[PSXINT_SPUASYNC].cycle) {
            SPU_async( elapsed );

            m_regs.intCycle[PSXINT_SPUASYNC].sCycle = m_regs.cycle;
        }
    }
#endif

    const uint32_t cycle = m_regs.cycle;

    if (cycle >= PCSX::g_emulator->m_counters->m_psxNextCounter) PCSX::g_emulator->m_counters->update();

    if (m_regs.spuInterrupt.exchange(false)) PCSX::g_emulator->m_spu->interrupt();

    const uint32_t interrupts = m_regs.interrupt;

    int32_t lowestDistance = std::numeric_limits<int32_t>::max();
    uint32_t lowestTarget = cycle;
    uint32_t* targets = m_regs.intTargets;

    if ((interrupts != 0) && (((int32_t)(m_regs.lowestTarget - cycle)) <= 0)) {
#define checkAndUpdate(irq, act)                                \
    {                                                           \
        constexpr uint32_t mask = 1 << irq;                     \
        if ((interrupts & mask) != 0) {                         \
            uint32_t target = targets[irq];                     \
            int32_t dist = target - cycle;                      \
            if (dist > 0) {                                     \
                if (lowestDistance > dist) {                    \
                    lowestDistance = dist;                      \
                    lowestTarget = target;                      \
                }                                               \
            } else {                                            \
                m_regs.interrupt &= ~mask;                      \
                PSXIRQ_LOG("Triggering interrupt %08x\n", irq); \
                act();                                          \
            }                                                   \
        }                                                       \
    }
        checkAndUpdate(PSXINT_SIO, g_emulator->m_sio->interrupt);
        checkAndUpdate(PSXINT_SIO1, g_emulator->m_sio1->interrupt);
        checkAndUpdate(PSXINT_CDR, g_emulator->m_cdrom->interrupt);
        checkAndUpdate(PSXINT_CDREAD, g_emulator->m_cdrom->readInterrupt);
        checkAndUpdate(PSXINT_GPUDMA, GPU::gpuInterrupt);
        checkAndUpdate(PSXINT_MDECOUTDMA, g_emulator->m_mdec->mdec1Interrupt);
        checkAndUpdate(PSXINT_SPUDMA, spuInterrupt);
        checkAndUpdate(PSXINT_MDECINDMA, g_emulator->m_mdec->mdec0Interrupt);
        checkAndUpdate(PSXINT_GPUOTCDMA, gpuotcInterrupt);
        checkAndUpdate(PSXINT_CDRDMA, g_emulator->m_cdrom->dmaInterrupt);
        checkAndUpdate(PSXINT_CDRPLAY, g_emulator->m_cdrom->playInterrupt);
        checkAndUpdate(PSXINT_CDRDBUF, g_emulator->m_cdrom->decodedBufferInterrupt);
        checkAndUpdate(PSXINT_CDRLID, g_emulator->m_cdrom->lidSeekInterrupt);
        m_regs.lowestTarget = lowestTarget;
    }
    if ((psxHu32(0x1070) & psxHu32(0x1074)) && ((m_regs.CP0.n.Status & 0x401) == 0x401)) {
        // If the next instruction is a GTE instruction sans LWC2/SWC2, there's a hardware bug where the instruction
        // gets executed
        // But EPC still ends up pointing to the GTE instruction. In this case, the BIOS will add 4 to EPC to skip the
        // GTE instruction. To deal with this, we do not fire IRQs if the next instruction is a GTE instruction
        // https://psx-spx.consoledev.net/cpuspecifications/#interrupts-vs-gte-commands
        const auto pointer = (uint32_t*)PSXM(m_regs.pc);
        if (pointer != nullptr) {
            const auto next = *pointer;           // Fetch next instruction
            if (((next >> 24) & 0xfe) == 0x4a) {  // Return if it's a GTE instruction
                return;
            }
        }

        PSXIRQ_LOG("Interrupt: %x %x\n", psxHu32(0x1070), psxHu32(0x1074));
        exception(0x400, 0);
    }
}

void PCSX::R3000Acpu::psxSetPGXPMode(uint32_t pgxpMode) {
    SetPGXPMode(pgxpMode);
    // g_emulator->m_cpu->Reset();
}

std::unique_ptr<PCSX::R3000Acpu> PCSX::Cpus::Interpreted() {
    std::unique_ptr<PCSX::R3000Acpu> cpu = getInterpreted();
    if (cpu->Implemented()) return cpu;
    return nullptr;
}

std::unique_ptr<PCSX::R3000Acpu> PCSX::Cpus::DynaRec() {
    std::unique_ptr<PCSX::R3000Acpu> cpu = getDynaRec();
    if (cpu->Implemented()) return cpu;
    return nullptr;
}
