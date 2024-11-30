/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
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
#include "regAllocation.h"
#include "spu/interface.h"
#include "tracy/public/tracy/Tracy.hpp"

#define HOST_REG_CACHE_OFFSET(x) ((uintptr_t) & m_hostRegisterCache[(x)] - (uintptr_t)this)
#define GPR_OFFSET(x) ((uintptr_t) & m_regs.GPR.r[(x)] - (uintptr_t)this)
#define COP0_OFFSET(x) ((uintptr_t) & m_regs.CP0.r[(x)] - (uintptr_t)this)
#define PC_OFFSET ((uintptr_t) & m_regs.pc - (uintptr_t)this)
#define LO_OFFSET ((uintptr_t) & m_regs.GPR.n.lo - (uintptr_t)this)
#define HI_OFFSET ((uintptr_t) & m_regs.GPR.n.hi - (uintptr_t)this)
#define CYCLE_OFFSET ((uintptr_t) & m_regs.cycle - (uintptr_t)this)

#undef _PC_
#undef _Op_
#undef _Funct_
#undef _Rd_
#undef _Rt_
#undef _Rs_
#undef _Sa_
#undef _Im_
#undef _Target_
#undef _Imm_
#undef _Target_
#undef _ImmU_
#undef _ImmLU_
#undef _rRs_
#undef _rRt_
#undef _rRd_
#undef _c2dRs_
#undef _c2dRt_
#undef _c2dRd_
#undef _rHi_
#undef _rLo_
#undef _JumpTarget_
#undef _BranchTarget_

#define _PC_ m_regs.pc  // The next PC to be executed

#define _Op_ _fOp_(code)
#define _Funct_ _fFunct_(code)
#define _Rd_ _fRd_(code)
#define _Rt_ _fRt_(code)
#define _Rs_ _fRs_(code)
#define _Sa_ _fSa_(code)
#define _Im_ _fIm_(code)
#define _Target_ _fTarget_(code)

#define _Imm_ _fImm_(code)
#define _ImmU_ _fImmU_(code)
#define _ImmLU_ _fImmLU_(code)

static uint8_t read8Wrapper(uint32_t address) { return PCSX::g_emulator->m_mem->read8(address); }
static uint16_t read16Wrapper(uint32_t address) { return PCSX::g_emulator->m_mem->read16(address); }
static uint32_t read32Wrapper(uint32_t address) { return PCSX::g_emulator->m_mem->read32(address); }

static void SPU_writeRegisterWrapper(uint32_t addr, uint16_t value) {
    PCSX::g_emulator->m_spu->writeRegister(addr, value);
}

static void write8Wrapper(uint32_t address, uint32_t value) { PCSX::g_emulator->m_mem->write8(address, value); }
static void write16Wrapper(uint32_t address, uint32_t value) { PCSX::g_emulator->m_mem->write16(address, value); }
static void write32Wrapper(uint32_t address, uint32_t value) { PCSX::g_emulator->m_mem->write32(address, value); }

using DynarecCallback = void (*)();  // A function pointer to JIT-emitted code

class DynaRecCPU final : public PCSX::R3000Acpu {
    using recompilationFunc = void (DynaRecCPU::*)(uint32_t code);  // A function pointer to a dynarec member function

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
    enum class LoadingMode { DoNotLoad, Load };
    // Renamed temporarily to Reg since it collides with Register in vixl::aarch64 namespace
    struct Reg {
        uint32_t val = 0;                    // The register's cached value used for constant propagation
        RegState state = RegState::Unknown;  // Is this register's value a constant, or an unknown value?

        bool allocated = false;  // Has this guest register been allocated to a host reg?
        bool writeback = false;  // Does this register need to be written back to memory at the end of the block?
        Register allocatedReg;   // If a host reg has been allocated to this register, which reg is it?
        int allocatedRegIndex = 0;

        inline bool isConst() { return state == RegState::Constant; }
        inline bool isAllocated() { return allocated; }
        inline void markConst(uint32_t value) {
            val = value;
            state = RegState::Constant;
            writeback = false;  // Disable writeback in case the reg was previously allocated with writeback
            allocated = false;  // Unallocate register
        }

        // Note: It's important that markUnknown does not modify the val field as that would mess up codegen
        inline void markUnknown() { state = RegState::Unknown; }

        inline void setWriteback(bool wb) { writeback = wb; }
    };

    inline void markConst(int index, uint32_t value) {
        m_gprs[index].markConst(value);
        if (m_hostRegs[m_gprs[index].allocatedRegIndex].mappedReg == index) {
            m_hostRegs[m_gprs[index].allocatedRegIndex].mappedReg =
                std::nullopt;  // Unmap the register on the host reg side too
        }
    }

    struct HostRegister {
        std::optional<int> mappedReg = std::nullopt;  // The register this is allocated to, if any
    };

    Reg m_gprs[32];
    std::array<HostRegister, ALLOCATEABLE_REG_COUNT> m_hostRegs;
    std::optional<uint32_t> m_linkedPC = std::nullopt;

    template <LoadingMode mode = LoadingMode::Load>
    void reserveReg(int index);
    void allocateReg(int reg);
    void allocateRegWithoutLoad(int reg);

    template <int T, int U>
    void allocateRegisters(std::array<int, T> regsWithoutWb, std::array<int, U> regsWithWb);
    void alloc_rt_rs(uint32_t code);
    void alloc_rt_wb_rd(uint32_t code);
    void alloc_rs_wb_rd(uint32_t code);
    void alloc_rs_wb_rt(uint32_t code);
    void alloc_rt_rs_wb_rd(uint32_t code);

    void flushRegs();
    void spillRegisterCache();
    void prepareForCall();
    unsigned int m_allocatedRegisters = 0;  // how many registers have been allocated in this block?

    // Check if we're executing from valid memory
    inline bool isPcValid(uint32_t addr) { return m_recompilerLUT[addr >> 16] != m_dummyBlocks; }

    DynarecCallback* getBlockPointer(uint32_t pc);
    DynarecCallback recompile(DynarecCallback* callback, uint32_t pc, bool align = true);
    void error();
    void flushCache();
    void handleLinking();
    void handleShellReached();
    void handleKernelCall();
    void emitDispatcher();
    void emitBlockLookup();
    void uncompileAll();

    // Class Wrapper Functions
    static void exceptionWrapper(DynaRecCPU* that, int32_t e, int32_t bd) { that->exception(e, bd); }
    static void recClearWrapper(DynaRecCPU* that, uint32_t address) { that->Clear(address, 1); }
    static void recBranchTestWrapper(DynaRecCPU* that) { that->branchTest(); }
    static void recErrorWrapper(DynaRecCPU* that) { that->error(); }

    static void signalShellReached(DynaRecCPU* that);
    static DynarecCallback recRecompileWrapper(DynaRecCPU* that, DynarecCallback* callback) {
        return that->recompile(callback, that->m_regs.pc);
    }

    template <uint32_t pc>
    static void interceptKernelCallWrapper(DynaRecCPU* that) {
        that->InterceptBIOS<false>(pc);
    }

    // TODO: This is currently un-unsed in x64 DynaRec. Check this.
    void inlineClear(uint32_t address) {
        if (isPcValid(address & ~3)) {
            loadThisPointer(arg1.X());
            gen.Mov(arg2, address & ~3);
            call(recClearWrapper);
        }
    }

  public:
    DynaRecCPU() : R3000Acpu("Dynarec (arm64)") {}
    virtual bool Implemented() final { return true; }
    virtual bool Init() final;
    virtual void Reset() final;
    virtual void Execute() final {
        ZoneScoped;         // Tell the Tracy profiler to do its thing
        (*m_dispatcher)();  // Jump to assembly dispatcher
    }
    virtual void Clear(uint32_t Addr, uint32_t Size) final {
        auto pointer = getBlockPointer(Addr);
        for (auto i = 0; i < Size; i++) {
            *pointer++ = m_uncompiledBlock;
        }
    }
    virtual void Shutdown() final;
    virtual bool isDynarec() final { return true; }

    virtual void SetPGXPMode(uint32_t pgxpMode) final {
        if (pgxpMode != 0) {
            throw std::runtime_error("PGXP not supported in x64 JIT");
        }
    }

    // For the GUI dynarec disassembly widget
    virtual const uint8_t* getBufferPtr() final { return gen.getCode<const uint8_t*>(); }
    virtual const size_t getBufferSize() final { return gen.getSize(); }

  private:
    // Calculate the number of instructions between the current PC and the branch target
    // Returns a negative number for backwards jumps
    int64_t getPCOffset(const void* current, const void* target) {
        return (int64_t)((ptrdiff_t)target - (ptrdiff_t)current) >> 2;
    }

    // Load a pointer to the JIT object in "reg" using lea with the context pointer
    void loadThisPointer(Register reg) { gen.Mov(reg, contextPointer); }

    // Loads a value into dest from the given pointer.
    template <int size, bool signExtend>
    void load(Register dest, const void* pointer) {
        //        const auto distance = (intptr_t)pointer - (intptr_t)this;
        gen.Mov(x4, (uintptr_t)pointer);
        switch (size) {
            case 8:
                signExtend ? gen.Ldrsb(dest, MemOperand(x4)) : gen.Ldrb(dest, MemOperand(x4));
                break;
            case 16:
                signExtend ? gen.Ldrsh(dest, MemOperand(x4)) : gen.Ldrh(dest, MemOperand(x4));
                break;
            case 32:
                gen.Ldr(dest, MemOperand(x4));
                break;
        }
    }

    // Stores a value of "size" bits from "source" to the given pointer
    template <int size, typename T>
    void store(T source, const void* pointer) {
        gen.Mov(x4, (uintptr_t)pointer);
        gen.Mov(w5, source);
        switch (size) {
            case 8:
                gen.Strb(w5, MemOperand(x4));
                break;
            case 16:
                gen.Strh(w5, MemOperand(x4));
                break;
            case 32:
                gen.Str(w5, MemOperand(x4));
                break;
        }
    }

    // Prepare for a call to a C++ function and then actually emit it
    template <typename T>
    void call(T& func) {
        prepareForCall();
        const auto ptr = reinterpret_cast<const void*>(func);
        const int64_t disp = getPCOffset(gen.getCurr<const void*>(), ptr);

        // If the displacement can fit in a 26-bit int, that means we can emit a direct call to the address
        // Otherwise, load the address into a register and emit a blr
        const bool canDoDirectCall = vixl::IsInt26(disp);

        if (canDoDirectCall) {
            gen.bl(disp);
        } else {
            gen.Mov(x4, (uintptr_t)ptr);
            gen.Blr(x4);
        }
    }

    // jmp function using same method as call to attempt direct jump
    void jmp(void* pointer) {
        const int64_t disp = getPCOffset(gen.getCurr<const void*>(), pointer);

        // If the displacement can fit in a 26-bit int, that means we can emit a direct call to the address
        // Otherwise, load the address into a register and emit a br
        const bool canDoDirectJump = vixl::IsInt26(disp);

        if (canDoDirectJump) {
            gen.b(disp);
        } else {
            gen.Mov(x4, (uintptr_t)pointer);
            gen.Br(x4);
        }
    }

    void maybeCancelDelayedLoad(uint32_t index) {
        const unsigned other = m_currentDelayedLoad ^ 1;
        if (m_delayedLoadInfo[other].index == index) {
            m_delayedLoadInfo[other].active = false;
        }
    }

    // Instruction definitions
    void recUnknown(uint32_t code);
    void recSpecial(uint32_t code);

    void recADD(uint32_t code);
    void recADDIU(uint32_t code);
    void recADDU(uint32_t code);
    void recAND(uint32_t code);
    void recANDI(uint32_t code);
    void recBEQ(uint32_t code);
    void recBGTZ(uint32_t code);
    void recBLEZ(uint32_t code);
    void recBNE(uint32_t code);
    void recBREAK(uint32_t code);
    void recCFC2(uint32_t code);
    void recCOP0(uint32_t code);
    void recCOP2(uint32_t code);
    void recCTC2(uint32_t code);
    void recDIV(uint32_t code);
    void recDIVU(uint32_t code);
    void recJ(uint32_t code);
    void recJAL(uint32_t code);
    void recJALR(uint32_t code);
    void recJR(uint32_t code);
    void recLB(uint32_t code);
    void recLBU(uint32_t code);
    void recLH(uint32_t code);
    void recLHU(uint32_t code);
    void recLUI(uint32_t code);
    void recLW(uint32_t code);
    void recLWC2(uint32_t code);
    void recLWL(uint32_t code);
    void recLWR(uint32_t code);
    void recMFC0(uint32_t code);
    void recMFC2(uint32_t code);
    void recMFHI(uint32_t code);
    void recMFLO(uint32_t code);
    void recMTC0(uint32_t code);
    void recMTC2(uint32_t code);
    void recMTHI(uint32_t code);
    void recMTLO(uint32_t code);
    void recMULT(uint32_t code);
    void recMULTU(uint32_t code);
    void recNOR(uint32_t code);
    void recOR(uint32_t code);
    void recORI(uint32_t code);
    void recREGIMM(uint32_t code);
    void recRFE(uint32_t code);
    void recSB(uint32_t code);
    void recSH(uint32_t code);
    void recSLL(uint32_t code);
    void recSLLV(uint32_t code);
    void recSLT(uint32_t code);
    void recSLTI(uint32_t code);
    void recSLTIU(uint32_t code);
    void recSLTU(uint32_t code);
    void recSRA(uint32_t code);
    void recSRAV(uint32_t code);
    void recSRL(uint32_t code);
    void recSRLV(uint32_t code);
    void recSUB(uint32_t code);
    void recSUBU(uint32_t code);
    void recSW(uint32_t code);
    void recSWC2(uint32_t code);
    void recSWL(uint32_t code);
    void recSWR(uint32_t code);
    void recSYSCALL(uint32_t code);
    void recXOR(uint32_t code);
    void recXORI(uint32_t code);
    void recException(Exception e);

    // GTE instructions
    void recGTEMove(uint32_t code);
    void recAVSZ3(uint32_t code);
    void recAVSZ4(uint32_t code);
    void recCC(uint32_t code);
    void recCDP(uint32_t code);
    void recDCPL(uint32_t code);
    void recDPCS(uint32_t code);
    void recDPCT(uint32_t code);
    void recGPF(uint32_t code);
    void recGPL(uint32_t code);
    void recINTPL(uint32_t code);
    void recMVMVA(uint32_t code);
    void recNCCS(uint32_t code);
    void recNCCT(uint32_t code);
    void recNCDS(uint32_t code);
    void recNCDT(uint32_t code);
    void recNCLIP(uint32_t code);
    void recNCS(uint32_t code);
    void recNCT(uint32_t code);
    void recOP(uint32_t code);
    void recRTPS(uint32_t code);
    void recRTPT(uint32_t code);
    void recSQR(uint32_t code);

    template <bool isAVSZ4>
    void recAVSZ(uint32_t code);

    template <bool loadSR>
    void testSoftwareInterrupt();

    template <int size, bool signExtend>
    void recompileLoad(uint32_t code);

    const recompilationFunc m_recBSC[64] = {
        &DynaRecCPU::recSpecial, &DynaRecCPU::recREGIMM,  &DynaRecCPU::recJ,       &DynaRecCPU::recJAL,      // 00
        &DynaRecCPU::recBEQ,     &DynaRecCPU::recBNE,     &DynaRecCPU::recBLEZ,    &DynaRecCPU::recBGTZ,     // 04
        &DynaRecCPU::recADDIU,   &DynaRecCPU::recADDIU,   &DynaRecCPU::recSLTI,    &DynaRecCPU::recSLTIU,    // 08
        &DynaRecCPU::recANDI,    &DynaRecCPU::recORI,     &DynaRecCPU::recXORI,    &DynaRecCPU::recLUI,      // 0c
        &DynaRecCPU::recCOP0,    &DynaRecCPU::recUnknown, &DynaRecCPU::recCOP2,    &DynaRecCPU::recUnknown,  // 10
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 14
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 18
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 1c
        &DynaRecCPU::recLB,      &DynaRecCPU::recLH,      &DynaRecCPU::recLWL,     &DynaRecCPU::recLW,       // 20
        &DynaRecCPU::recLBU,     &DynaRecCPU::recLHU,     &DynaRecCPU::recLWR,     &DynaRecCPU::recUnknown,  // 24
        &DynaRecCPU::recSB,      &DynaRecCPU::recSH,      &DynaRecCPU::recSWL,     &DynaRecCPU::recSW,       // 28
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recSWR,     &DynaRecCPU::recUnknown,  // 2c
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recLWC2,    &DynaRecCPU::recUnknown,  // 30
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 34
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recSWC2,    &DynaRecCPU::recUnknown,  // 38
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 3c
    };

    const recompilationFunc m_recSPC[64] = {
        &DynaRecCPU::recSLL,     &DynaRecCPU::recUnknown, &DynaRecCPU::recSRL,     &DynaRecCPU::recSRA,      // 00
        &DynaRecCPU::recSLLV,    &DynaRecCPU::recUnknown, &DynaRecCPU::recSRLV,    &DynaRecCPU::recSRAV,     // 04
        &DynaRecCPU::recJR,      &DynaRecCPU::recJALR,    &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 08
        &DynaRecCPU::recSYSCALL, &DynaRecCPU::recBREAK,   &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 0c
        &DynaRecCPU::recMFHI,    &DynaRecCPU::recMTHI,    &DynaRecCPU::recMFLO,    &DynaRecCPU::recMTLO,     // 10
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 14
        &DynaRecCPU::recMULT,    &DynaRecCPU::recMULTU,   &DynaRecCPU::recDIV,     &DynaRecCPU::recDIVU,     // 18
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 1c
        &DynaRecCPU::recADD,     &DynaRecCPU::recADDU,    &DynaRecCPU::recSUB,     &DynaRecCPU::recSUBU,     // 20
        &DynaRecCPU::recAND,     &DynaRecCPU::recOR,      &DynaRecCPU::recXOR,     &DynaRecCPU::recNOR,      // 24
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recSLT,     &DynaRecCPU::recSLTU,     // 28
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 2c
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 30
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 34
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 38
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 3c
    };

    const recompilationFunc m_recGTE[64] = {
        &DynaRecCPU::recGTEMove, &DynaRecCPU::recRTPS,    &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 00
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recNCLIP,   &DynaRecCPU::recUnknown,  // 04
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 08
        &DynaRecCPU::recOP,      &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 0c
        &DynaRecCPU::recDPCS,    &DynaRecCPU::recINTPL,   &DynaRecCPU::recMVMVA,   &DynaRecCPU::recNCDS,     // 10
        &DynaRecCPU::recCDP,     &DynaRecCPU::recUnknown, &DynaRecCPU::recNCDT,    &DynaRecCPU::recUnknown,  // 14
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recNCCS,     // 18
        &DynaRecCPU::recCC,      &DynaRecCPU::recUnknown, &DynaRecCPU::recNCS,     &DynaRecCPU::recUnknown,  // 1c
        &DynaRecCPU::recNCT,     &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 20
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 24
        &DynaRecCPU::recSQR,     &DynaRecCPU::recDCPL,    &DynaRecCPU::recDPCT,    &DynaRecCPU::recUnknown,  // 28
        &DynaRecCPU::recUnknown, &DynaRecCPU::recAVSZ3,   &DynaRecCPU::recAVSZ4,   &DynaRecCPU::recUnknown,  // 2c
        &DynaRecCPU::recRTPT,    &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 30
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 34
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 38
        &DynaRecCPU::recUnknown, &DynaRecCPU::recGPF,     &DynaRecCPU::recGPL,     &DynaRecCPU::recNCCT,     // 3c
    };

    static constexpr bool ENABLE_BLOCK_LINKING = false;
};

#endif  // DYNAREC_AA64
