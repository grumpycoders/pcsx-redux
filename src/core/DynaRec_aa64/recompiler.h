/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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
#include "core/r3000a.h"

#if defined(DYNAREC_AA64)
#include <array>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>

#include "emitter.h"
#include "fmt/format.h"
#include "spu/interface.h"
#include "tracy/Tracy.hpp"

#define HOST_REG_CACHE_OFFSET(x) ((uintptr_t)&m_hostRegisterCache[(x)] - (uintptr_t)this)
#define GPR_OFFSET(x) ((uintptr_t)&m_psxRegs.GPR.r[(x)] - (uintptr_t)this)
#define COP0_OFFSET(x) ((uintptr_t)&m_psxRegs.CP0.r[(x)] - (uintptr_t)this)
#define PC_OFFSET ((uintptr_t)&m_psxRegs.pc - (uintptr_t)this)
#define LO_OFFSET ((uintptr_t)&m_psxRegs.GPR.n.lo - (uintptr_t)this)
#define HI_OFFSET ((uintptr_t)&m_psxRegs.GPR.n.hi - (uintptr_t)this)
#define CYCLE_OFFSET ((uintptr_t)&m_psxRegs.cycle - (uintptr_t)this)

static uint8_t psxMemRead8Wrapper(uint32_t address) { return PCSX::g_emulator->m_psxMem->psxMemRead8(address); }
static uint16_t psxMemRead16Wrapper(uint32_t address) { return PCSX::g_emulator->m_psxMem->psxMemRead16(address); }
static uint32_t psxMemRead32Wrapper(uint32_t address) { return PCSX::g_emulator->m_psxMem->psxMemRead32(address); }

static void SPU_writeRegisterWrapper(uint32_t addr, uint16_t value) {
    PCSX::g_emulator->m_spu->writeRegister(addr, value);
}

static void psxMemWrite8Wrapper(uint32_t address, uint8_t value) {
    PCSX::g_emulator->m_psxMem->psxMemWrite8(address, value);
}
static void psxMemWrite16Wrapper(uint32_t address, uint16_t value) {
    PCSX::g_emulator->m_psxMem->psxMemWrite16(address, value);
}
static void psxMemWrite32Wrapper(uint32_t address, uint32_t value) {
    PCSX::g_emulator->m_psxMem->psxMemWrite32(address, value);
}

using DynarecCallback = void (*)();  // A function pointer to JIT-emitted code

class DynaRecCPU final : public PCSX::R3000Acpu {
    using recompilationFunc = void (DynaRecCPU::*)();  // A function pointer to a dynarec member function

  private:
    uint64_t m_hostRegisterCache[16];  // An array to backup non-volatile regs temporarily

    DynarecCallback** m_recompilerLUT;
    DynarecCallback* m_ramBlocks;   // Pointers to compiled RAM blocks (If nullptr then this block needs to be compiled)
    DynarecCallback* m_biosBlocks;  // Pointers to compiled BIOS blocks
    DynarecCallback* m_dummyBlocks;  // This is where invalid pages will point

    // Functions written in raw assembly
    DynarecCallback m_dispatcher;       // Pointer to our assembly dispatcher
    DynarecCallback m_returnFromBlock;  // Pointer to the code that will be executed when returning from a block
    DynarecCallback m_uncompiledBlock;  // Pointer to the code that will be executed when jumping to an uncompiled block
    DynarecCallback m_invalidBlock;     // Pointer to the code that will be executed the PC is invalid

    uint32_t m_pc;
    Emitter gen;

    bool m_stopCompiling;  // Should we stop compiling code?
    bool m_pcWrittenBack;  // Has the PC been written back already by a jump?
    uint32_t m_ramSize;    // RAM is 2MB on retail units, 8MB on some DTL units (Can be toggled in GUI)
    const int MAX_BLOCK_SIZE = 50;

    enum class RegState { Unknown, Constant };

    // Check if we're executing from valid memory
    inline bool isPcValid(uint32_t addr) { return m_recompilerLUT[addr >> 16] != m_dummyBlocks; }

    DynarecCallback* getBlockPointer(uint32_t pc);
    DynarecCallback recompile(DynarecCallback* callback, uint32_t pc);
    void error();
    void flushCache();
    void handleLinking();
    void handleFastboot();
    void uncompileAll();

  public:
    DynaRecCPU() : R3000Acpu("AA64 DynaRec") {}
    virtual bool Implemented() final { return true; }
    virtual bool Init() final { return false; }
    virtual void Reset() final;
    virtual void Execute() final { abort(); }
    virtual void Clear(uint32_t Addr, uint32_t Size) final { abort(); }
    virtual void Shutdown() final { abort(); }
    virtual bool isDynarec() final { return true; }

    virtual void SetPGXPMode(uint32_t pgxpMode) final {
        if (pgxpMode != 0) {
            throw std::runtime_error("PGXP not supported in x64 JIT");
        }
    }
};

#endif  // DYNAREC_AA64