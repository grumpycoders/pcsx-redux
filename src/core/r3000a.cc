/***************************************************************************
 *   Copyright (C) 2023 PCSX-Redux authors                                 *
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

#include <magic_enum_all.hpp>

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

int PCSX::R3000Acpu::psxInit() {
    g_system->printf(_("PCSX-Redux booting\n"));
    g_system->printf(_("Copyright (C) 2019-%i PCSX-Redux authors\n"), 2025);
    const auto& args = g_system->getArgs();

    if (g_emulator->settings.get<Emulator::SettingDynarec>()) {
        g_emulator->m_cpu = Cpus::DynaRec();
    }

    if (!g_emulator->m_cpu) g_emulator->m_cpu = Cpus::Interpreted();

    PGXP_Init();
    g_system->printf(_("CPU type: %s\n"), g_emulator->m_cpu->getName().c_str());

    return g_emulator->m_cpu->Init();
}

void PCSX::R3000Acpu::psxReset() {
    Reset();

    memset(&m_regs, 0, sizeof(m_regs));
    m_shellStarted = false;
    m_inISR = false;
    m_nextIsDelaySlot = false;
    m_inDelaySlot = false;
    m_delayedLoadInfo[0].active = false;
    m_delayedLoadInfo[0].pcActive = false;
    m_delayedLoadInfo[1].active = false;
    m_delayedLoadInfo[1].pcActive = false;
    m_currentDelayedLoad = false;
    closeAllPCdrvFiles();

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
            IO<File> memFile = g_emulator->m_mem->getMemoryAsFile();
            uint32_t code = (memFile->readAt<uint32_t>(m_regs.pc) >> 6) & 0xfffff;
            auto& regs = m_regs.GPR.n;
            uint16_t fd = 0;
            m_currentDelayedLoad ^= 1;
            flushCurrentDelayedLoad();
            m_currentDelayedLoad ^= 1;
            flushCurrentDelayedLoad();
            switch (code) {
                case 0x101: {  // PCinit
                    closeAllPCdrvFiles();
                    regs.v0 = 0;
                    regs.v1 = 0;
                    m_regs.pc += 4;
                    return;
                }
                case 0x102: {  // PCcreat
                    if (m_availableFDs.empty()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        m_regs.pc += 4;
                        return;
                    }
                    std::filesystem::path basepath = debugSettings.get<Emulator::DebugSettings::PCdrvBase>();
                    memFile->rSeek(m_regs.GPR.n.a0);
                    auto filename = memFile->gets<false>();
                    fd = m_availableFDs.front();
                    auto file = m_pcdrvFiles.insert(fd, new PCdrvFile(basepath / filename, FileOps::TRUNCATE));
                    file->m_relativeFilename = filename;
                    if ((*file)->failed()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        delete &*file;
                    } else {
                        m_availableFDs.pop_front();
                        regs.v0 = 0;
                        regs.v1 = fd;
                    }
                    m_regs.pc += 4;
                    return;
                }
                case 0x103: {  // PCopen
                    if (m_availableFDs.empty()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        m_regs.pc += 4;
                        return;
                    }
                    std::filesystem::path basepath = debugSettings.get<Emulator::DebugSettings::PCdrvBase>();
                    memFile->rSeek(m_regs.GPR.n.a0);
                    auto filename = memFile->gets<false>();
                    PCdrvFiles::iterator file;
                    auto path = basepath / filename;
                    fd = m_availableFDs.front();
                    if (regs.a2 == 0) {
                        file = m_pcdrvFiles.insert(fd, new PCdrvFile(path));
                    } else {
                        file = m_pcdrvFiles.insert(fd, new PCdrvFile(path, FileOps::READWRITE));
                    }
                    file->m_relativeFilename = filename;
                    if ((*file)->failed()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        delete &*file;
                    } else {
                        m_availableFDs.pop_front();
                        regs.v0 = 0;
                        regs.v1 = fd;
                    }
                    m_regs.pc += 4;
                    return;
                }
                case 0x104: {  // PCclose
                    fd = m_regs.GPR.n.a0;
                    auto file = m_pcdrvFiles.find(fd);
                    if (file == m_pcdrvFiles.end()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                    } else {
                        (*file)->close();
                        regs.v0 = 0;
                        regs.v1 = 0;
                        delete &*file;
                        m_availableFDs.push_back(fd);
                    }
                    m_regs.pc += 4;
                    return;
                }
                case 0x105: {  // PCread
                    auto filei = m_pcdrvFiles.find(m_regs.GPR.n.a1);
                    if (filei == m_pcdrvFiles.end()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        m_regs.pc += 4;
                        return;
                    }
                    IO<File> file = *filei;
                    if (file->failed() || file->eof()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        m_regs.pc += 4;
                        return;
                    }
                    auto slice = file->read(regs.a2);
                    regs.v0 = 0;
                    regs.v1 = slice.size();
                    memFile->writeAt(std::move(slice), regs.a3);
                    m_regs.pc += 4;
                    return;
                }
                case 0x106: {  // PCwrite
                    auto filei = m_pcdrvFiles.find(m_regs.GPR.n.a1);
                    if (filei == m_pcdrvFiles.end()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        m_regs.pc += 4;
                        return;
                    }
                    IO<File> file = *filei;
                    auto slice = memFile->readAt(regs.a2, regs.a3);
                    if ((regs.v1 = file->write(slice.data(), slice.size())) < 0) {
                        regs.v0 = -1;
                    } else {
                        regs.v0 = 0;
                    }
                    m_regs.pc += 4;
                    return;
                }
                case 0x107: {  // PClseek
                    auto filei = m_pcdrvFiles.find(m_regs.GPR.n.a0);
                    if (filei == m_pcdrvFiles.end()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        m_regs.pc += 4;
                        return;
                    }
                    IO<File> file = *filei;
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
                    ssize_t ret = file->rSeek(regs.a2, wheel);
                    if (ret < 0) {
                        regs.v0 = -1;
                        regs.v1 = ret;
                        m_regs.pc += 4;
                        return;
                    }
                    if (file->writable()) {
                        file->wSeek(regs.a2, wheel);
                    }

                    if (ret >= 0) {
                        regs.v0 = 0;
                        regs.v1 = file->rTell();
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
        if (!g_system->getArgs().isTestModeEnabled() &&
            ((debugSettings.get<Emulator::DebugSettings::FirstChanceException>() & ec) != 0)) {
            auto name = magic_enum::enum_name(e.value());
            g_system->printf(fmt::format("First chance exception: {} from 0x{:08x}\n", name, m_regs.pc).c_str());
            g_system->pause(true);
        }
    }

    m_inISR = true;

    // Set the EPC & PC
    if (bd) {
        code |= 0x80000000;
        m_regs.CP0.n.EPC = m_regs.pc - 4;
    } else {
        m_regs.CP0.n.EPC = m_regs.pc;
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
    for (auto f = m_availableFDs.begin(); f != m_availableFDs.end(); f++) {
        if (*f == fd) {
            m_availableFDs.erase(f);
            break;
        }
    }
}

void PCSX::R3000Acpu::restorePCdrvFile(const std::filesystem::path& filename, uint16_t fd, FileOps::Create) {
    auto& emuSettings = g_emulator->settings;
    auto& debugSettings = emuSettings.get<Emulator::SettingDebugSettings>();
    std::filesystem::path basepath = debugSettings.get<Emulator::DebugSettings::PCdrvBase>();
    auto f = new PCdrvFile(basepath / filename, FileOps::CREATE);
    (*f)->wSeek(0, SEEK_END);
    m_pcdrvFiles.insert(fd, f);
    for (auto f = m_availableFDs.begin(); f != m_availableFDs.end(); f++) {
        if (*f == fd) {
            m_availableFDs.erase(f);
            break;
        }
    }
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

    const uint64_t cycle = m_regs.cycle;

    if (cycle >= g_emulator->m_counters->m_psxNextCounter) g_emulator->m_counters->update();

    if (m_regs.spuInterrupt.exchange(false)) g_emulator->m_spu->interrupt();

    const uint32_t interrupts = m_regs.interrupt;

    int32_t lowestDistance = std::numeric_limits<int64_t>::max();
    uint64_t lowestTarget = cycle;
    uint64_t* targets = m_regs.intTargets;

    if ((interrupts != 0) && (m_regs.lowestTarget < cycle)) {
#define checkAndUpdate(irq, act)                                                          \
    {                                                                                     \
        constexpr uint32_t mask = 1 << irq;                                               \
        if ((interrupts & mask) != 0) {                                                   \
            uint64_t target = targets[irq];                                               \
            int64_t dist = target - cycle;                                                \
            if (dist > 0) {                                                               \
                if (lowestDistance > dist) {                                              \
                    lowestDistance = dist;                                                \
                    lowestTarget = target;                                                \
                }                                                                         \
            } else {                                                                      \
                m_regs.interrupt &= ~mask;                                                \
                PSXIRQ_LOG("Triggering interrupt %08x\n", magic_enum::enum_integer(irq)); \
                act();                                                                    \
            }                                                                             \
        }                                                                                 \
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
    auto& mem = g_emulator->m_mem;
    auto istat = mem->readHardwareRegister<Memory::ISTAT>();
    auto imask = mem->readHardwareRegister<Memory::IMASK>();
    if ((istat & imask) && ((m_regs.CP0.n.Status & 0x401) == 0x401)) {
        // If the next instruction is a GTE instruction sans LWC2/SWC2, there's a hardware bug where the instruction
        // gets executed
        // But EPC still ends up pointing to the GTE instruction. In this case, the BIOS will add 4 to EPC to skip
        // the GTE instruction. To deal with this, we do not fire IRQs if the next instruction is a GTE instruction
        // https://psx-spx.consoledev.net/cpuspecifications/#interrupts-vs-gte-commands
        uint32_t next = mem->read32(m_regs.pc, Memory::ReadType::Instr);
        if (((next >> 24) & 0xfe) == 0x4a) {  // Return if it's a GTE instruction
            return;
        }

        PSXIRQ_LOG("Interrupt: %x %x\n", istat, imask);
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

void PCSX::R3000Acpu::processA0KernelCall(uint32_t call) {
    auto& r = m_regs.GPR.n;

    switch (call) {
        case 0x03: {  // write
            if (r.a0 != 1) break;
            IO<File> memFile = g_emulator->m_mem->getMemoryAsFile();
            uint32_t size = r.a2;
            r.v0 = size;
            memFile->rSeek(r.a1);
            while (size--) {
                g_system->biosPutc(memFile->getc());
            }
            break;
        }
        case 0x09: {  // putc
            g_system->biosPutc(r.a0);
            break;
        }
        case 0x3c: {  // putchar
            g_system->biosPutc(r.a0);
            break;
        }
        case 0x3e: {  // puts
            IO<File> memFile = g_emulator->m_mem->getMemoryAsFile();
            memFile->rSeek(r.a0);
            auto str = memFile->gets<false>();
            for (auto c : str) {
                g_system->biosPutc(c);
            }
            break;
        }
    }
}

void PCSX::R3000Acpu::processB0KernelCall(uint32_t call) {
    auto& r = m_regs.GPR.n;

    switch (call) {
        case 0x35: {  // write
            if (r.a0 != 1) break;
            IO<File> memFile = g_emulator->m_mem->getMemoryAsFile();
            uint32_t size = r.a2;
            r.v0 = size;
            memFile->rSeek(r.a1);
            while (size--) {
                g_system->biosPutc(memFile->getc());
            }
            break;
        }
        case 0x3b: {  // putc
            g_system->biosPutc(r.a0);
            break;
        }
        case 0x3d: {  // putchar
            g_system->biosPutc(r.a0);
            break;
        }
        case 0x3f: {  // puts
            IO<File> memFile = g_emulator->m_mem->getMemoryAsFile();
            memFile->rSeek(r.a0);
            auto str = memFile->gets<false>();
            for (auto c : str) {
                g_system->biosPutc(c);
            }
            break;
        }
    }
}
