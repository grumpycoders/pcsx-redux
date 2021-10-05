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
 * i386 assembly functions for R3000A core.
 */

#include "core/debug.h"
#include "core/disr3000a.h"
#include "core/gpu.h"
#include "core/gte.h"
#include "core/pgxp_cpu.h"
#include "core/pgxp_debug.h"
#include "core/pgxp_gte.h"
#include "core/psxemulator.h"
#include "core/r3000a.h"
#include "core/system.h"
#include "spu/interface.h"
#include "tracy/Tracy.hpp"
#include "xbyak.h"
using namespace Xbyak;
using namespace Xbyak::util;

namespace {

#if defined(__i386__) || defined(_M_IX86)

class X86DynaRecCPU;

typedef void (X86DynaRecCPU::*func_t)();
typedef const func_t cfunc_t;
using DynarecCallback = uint32_t (*)();

uint8_t psxMemRead8Wrapper(uint32_t mem) { return PCSX::g_emulator->m_psxMem->psxMemRead8(mem); }
uint16_t psxMemRead16Wrapper(uint32_t mem) { return PCSX::g_emulator->m_psxMem->psxMemRead16(mem); }
uint32_t psxMemRead32Wrapper(uint32_t mem) { return PCSX::g_emulator->m_psxMem->psxMemRead32(mem); }
void psxMemWrite8Wrapper(uint32_t mem, uint8_t value) { PCSX::g_emulator->m_psxMem->psxMemWrite8(mem, value); }
void psxMemWrite16Wrapper(uint32_t mem, uint16_t value) { PCSX::g_emulator->m_psxMem->psxMemWrite16(mem, value); }
void psxMemWrite32Wrapper(uint32_t mem, uint32_t value) { PCSX::g_emulator->m_psxMem->psxMemWrite32(mem, value); }
uint32_t psxRcntRcountWrapper(uint32_t index) { return PCSX::g_emulator->m_psxCounters->psxRcntRcount(index); }
uint32_t psxRcntRmodeWrapper(uint32_t index) { return PCSX::g_emulator->m_psxCounters->psxRcntRmode(index); }
uint32_t psxRcntRtargetWrapper(uint32_t index) { return PCSX::g_emulator->m_psxCounters->psxRcntRtarget(index); }

unsigned long GPU_readDataWrapper() { return PCSX::g_emulator->m_gpu->readData(); }
unsigned long GPU_readStatusWrapper() { return PCSX::g_emulator->m_gpu->readStatus(); }
void GPU_writeDataWrapper(uint32_t gdata) { PCSX::g_emulator->m_gpu->writeData(gdata); }
void GPU_writeStatusWrapper(unsigned long gdata) { PCSX::g_emulator->m_gpu->writeStatus(gdata); }

unsigned short SPUreadRegisterWrapper(unsigned long addr) { return PCSX::g_emulator->m_spu->readRegister(addr); }
void SPUwriteRegisterWrapper(unsigned long addr, unsigned short value) {
    PCSX::g_emulator->m_spu->writeRegister(addr, value);
}

class X86DynaRecCPU final : public PCSX::R3000Acpu {
    inline uintptr_t PC_REC(uint32_t addr) {
        uintptr_t base = m_psxRecLUT[addr >> 16];
        uint32_t offset = addr & 0xffff;
        return base + offset;
    }
    inline bool IsPcValid(uint32_t addr) { return m_psxRecLUT[addr >> 16]; }
    inline bool IsConst(unsigned reg) { return m_iRegs[reg].state == ST_CONST; }
    inline bool Implemented() final { return true; }

  public:
    X86DynaRecCPU() : R3000Acpu("x86 DynaRec"), gen(ALLOC_SIZE) {}

  private:
    virtual bool Init() final;
    virtual void Reset() final;
    virtual void Execute() final;
    virtual void Clear(uint32_t Addr, uint32_t Size) final;
    virtual void Shutdown() final;
    virtual void SetPGXPMode(uint32_t pgxpMode) final;
    virtual bool isDynarec() final { return true; }

    static void recClearWrapper(X86DynaRecCPU *that, uint32_t a, uint32_t s) { that->Clear(a, s); }
    static uint32_t psxExceptionWrapper(X86DynaRecCPU *that, int e, int32_t bd) {
        that->psxException(e, bd);
        return that->m_psxRegs.pc;
    }

    template <uint32_t pc>
    static void interceptKernelCallWrapper(X86DynaRecCPU *that) {
        that->InterceptBIOS<false>(pc);
    }

    void handleKernelCall() {
        const uint32_t pc = m_psxRegs.pc & 0x1fffff;
        const uint32_t base = (m_psxRegs.pc >> 20) & 0xffc;
        if ((base != 0x000) && (base != 0x800) && (base != 0xa00))
            return;  // Mask out the segment, return if not a kernel call vector

        switch (pc) {  // Handle the A0/B0/C0 vectors
            case 0xA0:
                m_needsStackFrame = true;
                gen.push(dword, reinterpret_cast<uintptr_t>(this));  // Push pointer to this object
                gen.call(interceptKernelCallWrapper<0xA0>);          // Call wrapper
                gen.add(esp, 4);                                     // Fix up stack
                break;

            case 0xB0:
                m_needsStackFrame = true;
                gen.push(dword, reinterpret_cast<uintptr_t>(this));
                gen.call(interceptKernelCallWrapper<0xB0>);
                gen.add(esp, 4);
                break;

            case 0xC0:
                m_needsStackFrame = true;
                gen.push(dword, reinterpret_cast<uintptr_t>(this));
                gen.call(interceptKernelCallWrapper<0xC0>);
                gen.add(esp, 4);
                break;
        }
    }

    void maybeCancelDelayedLoad(uint32_t index) {
        unsigned other = m_currentDelayedLoad ^ 1;
        if (m_delayedLoadInfo[other].index == index) m_delayedLoadInfo[other].active = false;
    }

    uintptr_t *m_psxRecLUT;
    static constexpr size_t RECMEM_SIZE = 16 * 1024 * 1024;
    CodeGenerator gen;

    uint8_t *m_recRAM;  // Pointers to compiled RAM blocks here
    uint8_t *m_recROM;  // Pointers to compiled BIOS blocks here

    uint32_t m_pc;  // recompiler pc

    bool m_needsStackFrame;
    bool m_pcInEBP;
    bool m_stopRecompile;
    uint32_t m_ramSize;

    enum iRegState { ST_UNK = 0, ST_CONST = 1 };

    typedef struct {
        uint32_t k;
        iRegState state;
    } iRegisters;

    iRegisters m_iRegs[32];

    cfunc_t *m_pRecBSC = nullptr;
    cfunc_t *m_pRecSPC = nullptr;
    cfunc_t *m_pRecREG = nullptr;
    cfunc_t *m_pRecCP0 = nullptr;
    cfunc_t *m_pRecCP2 = nullptr;
    cfunc_t *m_pRecCP2BSC = nullptr;

    static const func_t m_recBSC[64];
    static const func_t m_recSPC[64];
    static const func_t m_recREG[32];
    static const func_t m_recCP0[32];
    static const func_t m_recCP2[64];
    static const func_t m_recCP2BSC[32];

    static const func_t m_pgxpRecBSC[64];
    static const func_t m_pgxpRecSPC[64];
    static const func_t m_pgxpRecCP0[32];
    static const func_t m_pgxpRecCP2BSC[32];
    static const func_t m_pgxpRecBSCMem[64];

    static const unsigned DYNAREC_BLOCK = 50;
    static const size_t ALLOC_SIZE = RECMEM_SIZE + 0x1000;

    void MapConst(unsigned reg, uint32_t _const);
    void iFlushReg(unsigned reg);
    void iFlushRegs();
    void iPushReg(unsigned reg);
    void flushCache();  // Flush Dynarec cache when it overflows

    void recError();
    void execute();

    void recNULL();
    void recSPECIAL();
    void recREGIMM();

    void recCOP0();
    void recCOP2();

    void recBASIC();

    void recADDIU();
    void recADDI();

    void recSLTI();
    void recSLTIU();

    void recANDI();
    void recORI();
    void recXORI();

    void recLUI();

    void recADDU();
    void recADD();
    void recSUBU();
    void recSUB();

    void recAND();
    void recOR();
    void recXOR();
    void recNOR();

    void recSLT();
    void recSLTU();
    void recMULT();
    void recMULTU();
    void recDIV();
    void recDIVU();

    void iPushOfB();

    void recLB();
    void recLBU();
    void recLH();
    void recLHU();
    void recLW();

    void recLWL();
    void recLWR();

    void recSB();
    void recSH();
    void recSW();

    void iSWLk(uint32_t shift);
    void recSWL();

    void iSWRk(uint32_t shift);
    void recSWR();

    void recSLL();
    void recSRL();
    void recSRA();
    void recSLLV();
    void recSRLV();
    void recSRAV();

    void recSYSCALL();
    void recBREAK();

    void recMFHI();
    void recMTHI();
    void recMFLO();
    void recMTLO();

    void recBLTZ();
    void recBGTZ();
    void recBLTZAL();
    void recBGEZAL();
    void recJ();
    void recJAL();
    void recJR();
    void recJALR();
    void recBEQ();
    void recBNE();
    void recBLEZ();
    void recBGEZ();

    void recMFC0();
    void recCFC0();
    void recMTC0();
    void recCTC0();

    void recRFE();
    void recException(Exception e);
    void testSWInt();

    void recRecompile();

    static uint32_t gteMFC2Wrapper() { return PCSX::g_emulator->m_gte->MFC2(); }
    static uint32_t gteCFC2Wrapper() { return PCSX::g_emulator->m_gte->CFC2(); }
    void recMFC2() {
        gen.mov(dword[&m_psxRegs.code], (uint32_t)m_psxRegs.code);
        gen.call(gteMFC2Wrapper);
        gen.mov(edi, eax);
        m_needsStackFrame = true;
        auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
        delayedLoad.active = true;
        delayedLoad.index = _Rt_;
    }
    void recCFC2() {
        gen.mov(dword[&m_psxRegs.code], (uint32_t)m_psxRegs.code);
        gen.call(gteCFC2Wrapper);
        gen.mov(edi, eax);
        m_needsStackFrame = true;
        auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
        delayedLoad.active = true;
        delayedLoad.index = _Rt_;
    }

#define CP2_FUNC(f)                                                                                           \
    static void gte##f##Wrapper() { PCSX::g_emulator->m_gte->f(PCSX::g_emulator->m_psxCpu->m_psxRegs.code); } \
    void rec##f() {                                                                                           \
        iFlushRegs();                                                                                         \
        gen.mov(dword[&m_psxRegs.code], (uint32_t)m_psxRegs.code);                                            \
        gen.call(gte##f##Wrapper);                                                                            \
    }

    CP2_FUNC(MTC2);
    CP2_FUNC(CTC2);
    CP2_FUNC(LWC2);
    CP2_FUNC(SWC2);
    CP2_FUNC(RTPS);
    CP2_FUNC(OP);
    CP2_FUNC(NCLIP);
    CP2_FUNC(DPCS);
    CP2_FUNC(INTPL);
    CP2_FUNC(MVMVA);
    CP2_FUNC(NCDS);
    CP2_FUNC(NCDT);
    CP2_FUNC(CDP);
    CP2_FUNC(NCCS);
    CP2_FUNC(CC);
    CP2_FUNC(NCS);
    CP2_FUNC(NCT);
    CP2_FUNC(SQR);
    CP2_FUNC(DCPL);
    CP2_FUNC(DPCT);
    CP2_FUNC(AVSZ3);
    CP2_FUNC(AVSZ4);
    CP2_FUNC(RTPT);
    CP2_FUNC(GPF);
    CP2_FUNC(GPL);
    CP2_FUNC(NCCT);

    /////////////////////////////////////////////
    // PGXP wrapper functions
    /////////////////////////////////////////////

    uint32_t m_tempAddr = 0;
    uint32_t m_tempReg1 = 0;
    uint32_t m_tempReg2 = 0;

// Choose between debug and direct function
#ifdef PGXP_CPU_DEBUG
#define PGXP_REC_FUNC_OP(pu, op, nReg) PGXP_psxTraceOp##nReg
#define PGXP_DBG_OP_E(op)        \
    gen.push(dword, DBG_E_##op); \
    gen.add(esp, 4);
#else
#define PGXP_REC_FUNC_OP(pu, op, nReg) PGXP_##pu##_##op
#define PGXP_DBG_OP_E(op)
#endif

#define PGXP_REC_FUNC_PASS(pu, op) \
    void pgxpRec##op() { rec##op(); }

#define PGXP_REC_FUNC(pu, op)                 \
    void pgxpRec##op() {                      \
        gen.push(dword, m_psxRegs.code);      \
        PGXP_DBG_OP_E(op)                     \
        gen.call(PGXP_REC_FUNC_OP(pu, op, )); \
        gen.add(esp, 4);                      \
        rec##op();                            \
    }

#define PGXP_REC_FUNC_1(pu, op, reg1)          \
    void pgxpRec##op() {                       \
        reg1;                                  \
        gen.push(dword, m_psxRegs.code);       \
        PGXP_DBG_OP_E(op)                      \
        gen.call(PGXP_REC_FUNC_OP(pu, op, 1)); \
        gen.add(esp, 8);                       \
        rec##op();                             \
    }

#define PGXP_REC_FUNC_2_2(pu, op, test, nReg, reg1, reg2, reg3, reg4) \
    void pgxpRec##op() {                                              \
        if (test) {                                                   \
            rec##op();                                                \
            return;                                                   \
        }                                                             \
        reg1;                                                         \
        reg2;                                                         \
        rec##op();                                                    \
        reg3;                                                         \
        reg4;                                                         \
        gen.push(dword, m_psxRegs.code);                              \
        PGXP_DBG_OP_E(op)                                             \
        gen.call(PGXP_REC_FUNC_OP(pu, op, nReg));                     \
        gen.add(esp, (4 * nReg) + 4);                                 \
    }

#define PGXP_REC_FUNC_2(pu, op, reg1, reg2)    \
    void pgxpRec##op() {                       \
        reg1;                                  \
        reg2;                                  \
        gen.push(dword, m_psxRegs.code);       \
        PGXP_DBG_OP_E(op)                      \
        gen.call(PGXP_REC_FUNC_OP(pu, op, 2)); \
        gen.add(esp, 12);                      \
        rec##op();                             \
    }

#define PGXP_REC_FUNC_ADDR_1(pu, op, reg1)               \
    void pgxpRec##op() {                                 \
        if (IsConst(_Rs_)) {                             \
            gen.mov(eax, m_iRegs[_Rs_].k + _Imm_);       \
        } else {                                         \
            gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]); \
            if (_Imm_) {                                 \
                gen.add(eax, _Imm_);                     \
            }                                            \
        }                                                \
        gen.mov(dword[&m_tempAddr], eax);                \
        rec##op();                                       \
        gen.push(dword[&m_tempAddr]);                    \
        reg1;                                            \
        gen.push(dword, m_psxRegs.code);                 \
        PGXP_DBG_OP_E(op)                                \
        gen.call(PGXP_REC_FUNC_OP(pu, op, 2));           \
        gen.add(esp, 12);                                \
    }

#define CPU_REG_NC(idx) gen.mov(eax, dword[&m_psxRegs.GPR.r[idx]])

#define CPU_REG(idx)                  \
    if (IsConst(idx))                 \
        gen.mov(eax, m_iRegs[idx].k); \
    else                              \
        gen.mov(eax, dword[&m_psxRegs.GPR.r[idx]]);

#define CP0_REG(idx) gen.mov(eax, dword[&m_psxRegs.CP0.r[idx]])
#define GTE_DATA_REG(idx) gen.mov(eax, dword[&m_psxRegs.CP2D.r[idx]])
#define GTE_CTRL_REG(idx) gen.mov(eax, dword[&m_psxRegs.CP2C.r[idx]])

#define PGXP_REC_FUNC_R1_1(pu, op, test, reg1, reg2) \
    void pgxpRec##op() {                             \
        if (test) {                                  \
            rec##op();                               \
            return;                                  \
        }                                            \
        reg1;                                        \
        gen.mov(dword[&m_tempReg1], eax);            \
        rec##op();                                   \
        gen.push(dword[&m_tempReg1]);                \
        reg2;                                        \
        gen.push(dword, m_psxRegs.code);             \
        PGXP_DBG_OP_E(op)                            \
        gen.call(PGXP_REC_FUNC_OP(pu, op, 2));       \
        gen.add(esp, 12);                            \
    }

#define PGXP_REC_FUNC_R2_1(pu, op, test, reg1, reg2, reg3) \
    void pgxpRec##op() {                                   \
        if (test) {                                        \
            rec##op();                                     \
            return;                                        \
        }                                                  \
        reg1;                                              \
        gen.mov(dword[&m_tempReg1], eax);                  \
        reg2;                                              \
        gen.mov(dword[&m_tempReg2], eax);                  \
        rec##op();                                         \
        gen.push(dword[&m_tempReg1]);                      \
        gen.push(dword[&m_tempReg2]);                      \
        reg3;                                              \
        gen.push(dword, m_psxRegs.code);                   \
        PGXP_DBG_OP_E(op)                                  \
        gen.call(PGXP_REC_FUNC_OP(pu, op, 3));             \
        gen.add(esp, 16);                                  \
    }

#define PGXP_REC_FUNC_R2_2(pu, op, test, reg1, reg2, reg3, reg4) \
    void pgxpRec##op() {                                         \
        if (test) {                                              \
            rec##op();                                           \
            return;                                              \
        }                                                        \
        reg1;                                                    \
        gen.mov(dword[&m_tempReg1], eax);                        \
        reg2;                                                    \
        gen.mov(dword[&m_tempReg2], eax);                        \
        rec##op();                                               \
        gen.push(dword[&m_tempReg1]);                            \
        gen.push(dword[&m_tempReg2]);                            \
        reg3;                                                    \
        reg4;                                                    \
        gen.push(dword, m_psxRegs.code);                         \
        PGXP_DBG_OP_E(op)                                        \
        gen.call(PGXP_REC_FUNC_OP(pu, op, 4));                   \
        gen.add(esp, 20);                                        \
    }

    //#define PGXP_REC_FUNC_R1i_1(pu, op, test, reg1, reg2) \
// void pgxpRec##op()   \
//{ \
//  if(test) { rec##op(); return; }\
//  if (IsConst(reg1))  \
//      gen.mov(eax, m_iRegs[reg1].k);    \
//  else\
//      gen.MOV32MtoR(eax, (uint32_t)&m_psxRegs.GPR.r[reg1]);\
//  gen.MOV32RtoM((uint32_t)&gTempReg, eax);\
//  rec##op();\
//  gen.PUSH32M((uint32_t)&gTempReg);\
//  reg2;\
//  gen.push(dword, m_psxRegs.code);    \
//  gen.call(PGXP_REC_FUNC_OP(pu, op, 2)); \
//  m_resp += 12; \
//}

    // Rt = Rs op imm
    PGXP_REC_FUNC_R1_1(CPU, ADDI, !_Rt_, CPU_REG(_Rs_), iPushReg(_Rt_))
    PGXP_REC_FUNC_R1_1(CPU, ADDIU, !_Rt_, CPU_REG(_Rs_), iPushReg(_Rt_))
    PGXP_REC_FUNC_R1_1(CPU, ANDI, !_Rt_, CPU_REG(_Rs_), iPushReg(_Rt_))
    PGXP_REC_FUNC_R1_1(CPU, ORI, !_Rt_, CPU_REG(_Rs_), iPushReg(_Rt_))
    PGXP_REC_FUNC_R1_1(CPU, XORI, !_Rt_, CPU_REG(_Rs_), iPushReg(_Rt_))
    PGXP_REC_FUNC_R1_1(CPU, SLTI, !_Rt_, CPU_REG(_Rs_), iPushReg(_Rt_))
    PGXP_REC_FUNC_R1_1(CPU, SLTIU, !_Rt_, CPU_REG(_Rs_), iPushReg(_Rt_))

    // Rt = imm
    PGXP_REC_FUNC_2_2(CPU, LUI, !_Rt_, 1, , , iPushReg(_Rt_), )

    // Rd = Rs op Rt
    PGXP_REC_FUNC_R2_1(CPU, ADD, !_Rd_, CPU_REG(_Rt_), CPU_REG(_Rs_), iPushReg(_Rd_))
    PGXP_REC_FUNC_R2_1(CPU, ADDU, !_Rd_, CPU_REG(_Rt_), CPU_REG(_Rs_), iPushReg(_Rd_))
    PGXP_REC_FUNC_R2_1(CPU, SUB, !_Rd_, CPU_REG(_Rt_), CPU_REG(_Rs_), iPushReg(_Rd_))
    PGXP_REC_FUNC_R2_1(CPU, SUBU, !_Rd_, CPU_REG(_Rt_), CPU_REG(_Rs_), iPushReg(_Rd_))
    PGXP_REC_FUNC_R2_1(CPU, AND, !_Rd_, CPU_REG(_Rt_), CPU_REG(_Rs_), iPushReg(_Rd_))
    PGXP_REC_FUNC_R2_1(CPU, OR, !_Rd_, CPU_REG(_Rt_), CPU_REG(_Rs_), iPushReg(_Rd_))
    PGXP_REC_FUNC_R2_1(CPU, XOR, !_Rd_, CPU_REG(_Rt_), CPU_REG(_Rs_), iPushReg(_Rd_))
    PGXP_REC_FUNC_R2_1(CPU, NOR, !_Rd_, CPU_REG(_Rt_), CPU_REG(_Rs_), iPushReg(_Rd_))
    PGXP_REC_FUNC_R2_1(CPU, SLT, !_Rd_, CPU_REG(_Rt_), CPU_REG(_Rs_), iPushReg(_Rd_))
    PGXP_REC_FUNC_R2_1(CPU, SLTU, !_Rd_, CPU_REG(_Rt_), CPU_REG(_Rs_), iPushReg(_Rd_))

    // Hi/Lo = Rs op Rt
    PGXP_REC_FUNC_R2_2(CPU, MULT, 0, CPU_REG(_Rt_), CPU_REG(_Rs_), gen.push(dword[&m_psxRegs.GPR.n.lo]),
                       gen.push(dword[&m_psxRegs.GPR.n.hi]))
    PGXP_REC_FUNC_R2_2(CPU, MULTU, 0, CPU_REG(_Rt_), CPU_REG(_Rs_), gen.push(dword[&m_psxRegs.GPR.n.lo]),
                       gen.push(dword[&m_psxRegs.GPR.n.hi]))
    PGXP_REC_FUNC_R2_2(CPU, DIV, 0, CPU_REG(_Rt_), CPU_REG(_Rs_), gen.push(dword[&m_psxRegs.GPR.n.lo]),
                       gen.push(dword[&m_psxRegs.GPR.n.hi]))
    PGXP_REC_FUNC_R2_2(CPU, DIVU, 0, CPU_REG(_Rt_), CPU_REG(_Rs_), gen.push(dword[&m_psxRegs.GPR.n.lo]),
                       gen.push(dword[&m_psxRegs.GPR.n.hi]))

    PGXP_REC_FUNC_ADDR_1(CPU, SB, iPushReg(_Rt_))
    PGXP_REC_FUNC_ADDR_1(CPU, SH, iPushReg(_Rt_))
    PGXP_REC_FUNC_ADDR_1(CPU, SW, iPushReg(_Rt_))
    PGXP_REC_FUNC_ADDR_1(CPU, SWL, iPushReg(_Rt_))
    PGXP_REC_FUNC_ADDR_1(CPU, SWR, iPushReg(_Rt_))

    PGXP_REC_FUNC_ADDR_1(CPU, LWL, iPushReg(_Rt_))
    PGXP_REC_FUNC_ADDR_1(CPU, LW, iPushReg(_Rt_))
    PGXP_REC_FUNC_ADDR_1(CPU, LWR, iPushReg(_Rt_))
    PGXP_REC_FUNC_ADDR_1(CPU, LH, iPushReg(_Rt_))
    PGXP_REC_FUNC_ADDR_1(CPU, LHU, iPushReg(_Rt_))
    PGXP_REC_FUNC_ADDR_1(CPU, LB, iPushReg(_Rt_))
    PGXP_REC_FUNC_ADDR_1(CPU, LBU, iPushReg(_Rt_))

    // Rd = Rt op Sa
    PGXP_REC_FUNC_R1_1(CPU, SLL, !_Rd_, CPU_REG(_Rt_), iPushReg(_Rd_))
    PGXP_REC_FUNC_R1_1(CPU, SRL, !_Rd_, CPU_REG(_Rt_), iPushReg(_Rd_))
    PGXP_REC_FUNC_R1_1(CPU, SRA, !_Rd_, CPU_REG(_Rt_), iPushReg(_Rd_))

    // Rd = Rt op Rs
    PGXP_REC_FUNC_R2_1(CPU, SLLV, !_Rd_, CPU_REG(_Rs_), CPU_REG(_Rt_), iPushReg(_Rd_))
    PGXP_REC_FUNC_R2_1(CPU, SRLV, !_Rd_, CPU_REG(_Rs_), CPU_REG(_Rt_), iPushReg(_Rd_))
    PGXP_REC_FUNC_R2_1(CPU, SRAV, !_Rd_, CPU_REG(_Rs_), CPU_REG(_Rt_), iPushReg(_Rd_))

    PGXP_REC_FUNC_R1_1(CPU, MFHI, !_Rd_, CPU_REG_NC(33), iPushReg(_Rd_))
    PGXP_REC_FUNC_R1_1(CPU, MTHI, 0, CPU_REG(_Rd_), gen.push(dword[&m_psxRegs.GPR.n.hi]))
    PGXP_REC_FUNC_R1_1(CPU, MFLO, !_Rd_, CPU_REG_NC(32), iPushReg(_Rd_))
    PGXP_REC_FUNC_R1_1(CPU, MTLO, 0, CPU_REG(_Rd_), gen.push(dword[&m_psxRegs.GPR.n.lo]))

    // COP2 (GTE)
    PGXP_REC_FUNC_R1_1(GTE, MFC2, !_Rt_, GTE_DATA_REG(_Rd_), iPushReg(_Rt_))
    PGXP_REC_FUNC_R1_1(GTE, CFC2, !_Rt_, GTE_CTRL_REG(_Rd_), iPushReg(_Rt_))
    PGXP_REC_FUNC_R1_1(GTE, MTC2, 0, CPU_REG(_Rt_), gen.push(dword[&m_psxRegs.CP2D.r[_Rd_]]))
    PGXP_REC_FUNC_R1_1(GTE, CTC2, 0, CPU_REG(_Rt_), gen.push(dword[&m_psxRegs.CP2C.r[_Rd_]]))

    PGXP_REC_FUNC_ADDR_1(GTE, LWC2, gen.push(dword[&m_psxRegs.CP2D.r[_Rt_]]))
    PGXP_REC_FUNC_ADDR_1(GTE, SWC2, gen.push(dword[&m_psxRegs.CP2D.r[_Rt_]]))

    // COP0
    PGXP_REC_FUNC_R1_1(CP0, MFC0, !_Rd_, CP0_REG(_Rd_), iPushReg(_Rt_))
    PGXP_REC_FUNC_R1_1(CP0, CFC0, !_Rd_, CP0_REG(_Rd_), iPushReg(_Rt_))
    PGXP_REC_FUNC_R1_1(CP0, MTC0, !_Rt_, CPU_REG(_Rt_), gen.push(dword[&m_psxRegs.CP0.r[_Rd_]]))
    PGXP_REC_FUNC_R1_1(CP0, CTC0, !_Rt_, CPU_REG(_Rt_), gen.push(dword[&m_psxRegs.CP0.r[_Rd_]]))
    PGXP_REC_FUNC(CP0, RFE)

    // End of PGXP wrappers
};

///

void X86DynaRecCPU::MapConst(unsigned reg, uint32_t value) {
    m_iRegs[reg].k = value;
    m_iRegs[reg].state = ST_CONST;
}

void X86DynaRecCPU::iFlushReg(unsigned reg) {
    if (IsConst(reg)) {
        gen.mov(dword[&m_psxRegs.GPR.r[reg]], m_iRegs[reg].k);
        m_iRegs[reg].state = ST_UNK;
    }
}

void X86DynaRecCPU::iFlushRegs() {
    for (unsigned i = 1; i < 32; i++) iFlushReg(i);
}

void X86DynaRecCPU::iPushReg(unsigned reg) {
    if (IsConst(reg)) {
        gen.push(dword, m_iRegs[reg].k);
    } else {
        gen.push(dword[&m_psxRegs.GPR.r[reg]]);
    }
}

#define REC_FUNC(f)                                                \
    void psx##f();                                                 \
    void rec##f() {                                                \
        iFlushRegs();                                              \
        gen.mov(dword[&m_psxRegs.code], (uint32_t)m_psxRegs.code); \
        gen.mov(dword[&m_psxRegs.pc], (uint32_t)m_pc);             \
        gen.call(psx##f);                                          \
        /*  branch = 2; */                                         \
    }

#define REC_SYS(f)                                                 \
    void psx##f();                                                 \
    void rec##f() {                                                \
        iFlushRegs();                                              \
        gen.mov(dword[&m_psxRegs.code], (uint32_t)m_psxRegs.code); \
        gen.mov(dword[&m_psxRegs.pc], (uint32_t)m_pc);             \
        gen.call(psx##f);                                          \
        branch = 2;                                                \
        iRet();                                                    \
    }

#define REC_BRANCH(f)                                              \
    void psx##f();                                                 \
    void rec##f() {                                                \
        iFlushRegs();                                              \
        gen.mov(dword[&m_psxRegs.code], (uint32_t)m_psxRegs.code); \
        gen.mov(dword[&m_psxRegs.pc], (uint32_t)m_pc);             \
        gen.call(psx##f);                                          \
        branch = 2;                                                \
        iRet();                                                    \
    }

bool X86DynaRecCPU::Init() {
    // Initialize recompiler memory
    // Check for 8MB RAM expansion
    const bool ramExpansion = PCSX::g_emulator->settings.get<PCSX::Emulator::Setting8MB>();
    m_ramSize = ramExpansion ? 0x800000 : 0x200000;
    const auto ramPages = m_ramSize >> 16;  // The amount of 64KB RAM pages. 0x80 with the ram expansion, 0x20 otherwise

    m_psxRecLUT = new uintptr_t[0x010000]();
    m_recROM = new uint8_t[0x080000]();
    m_recRAM = new uint8_t[m_ramSize]();

    if (m_recRAM == nullptr || m_recROM == nullptr || gen.getCode() == nullptr || m_psxRecLUT == nullptr) {
        PCSX::g_system->message("Error allocating memory");
        return false;
    }

    for (auto i = 0; i < ramPages; i++)
        m_psxRecLUT[i] =
            (uintptr_t)&m_recRAM[(i & 0x1f)
                                 << 16];  // map KUSEG/KSEG0/KSEG1 WRAM respectively to the recompiler block LUT
    std::memcpy(m_psxRecLUT + 0x8000, m_psxRecLUT, ramPages * sizeof(uintptr_t));
    std::memcpy(m_psxRecLUT + 0xa000, m_psxRecLUT, ramPages * sizeof(uintptr_t));
    for (auto i = 0; i < 8; i++)
        m_psxRecLUT[i + 0x1fc0] =
            (uintptr_t)&m_recROM[i << 16];  // map KUSEG/KSEG0/KSEG1 BIOS respectively to the recompiler block LUT
    std::memcpy(m_psxRecLUT + 0x9fc0, &m_psxRecLUT[0x1fc0], 8 * sizeof(uintptr_t));
    std::memcpy(m_psxRecLUT + 0xbfc0, &m_psxRecLUT[0x1fc0], 8 * sizeof(uintptr_t));

    // Mark registers as non-constant, except for $zero
    std::memset(m_iRegs, 0, sizeof(m_iRegs));
    m_iRegs[0].state = ST_CONST;
    m_iRegs[0].k = 0;

    // Reset code generator
    gen.reset();

    return true;
}

void X86DynaRecCPU::Reset() {
    R3000Acpu::Reset();  // Reset CPU registers
    Shutdown();          // Deinit and re-init dynarec
    Init();
}

void X86DynaRecCPU::Shutdown() {
    if (gen.getCode() == nullptr) return;  // This should be true, it's only here as a safety measure.
    delete[] m_psxRecLUT;
    delete[] m_recRAM;
    delete[] m_recROM;
}

void X86DynaRecCPU::recError() {
    PCSX::g_system->hardReset();
    PCSX::g_system->stop();
    PCSX::g_system->message("Unrecoverable error while running recompiler\nProgram counter: %08X\n", m_pc);
}

// Flush dynarec cache when it overflows
void X86DynaRecCPU::flushCache() {
    gen.reset();                          // Reset the emitter's code pointer and code size variables
    gen.align(32);                        // Align next block
    std::memset(m_recROM, 0, 0x080000);   // Delete all BIOS blocks
    std::memset(m_recRAM, 0, m_ramSize);  // Delete all RAM blocks
}

void X86DynaRecCPU::execute() {
    const uint32_t pc = m_psxRegs.pc;
    const auto recFunc = (DynarecCallback *)PC_REC(pc);

    if (!IsPcValid(pc)) {
        recError();
        return;
    }

    const bool &debug = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                            .get<PCSX::Emulator::DebugSettings::Debug>();

    if (*recFunc == nullptr) recRecompile();
    m_psxRegs.pc = (*recFunc)();
    psxBranchTest();

    if (debug) PCSX::g_emulator->m_debug->process(pc, m_psxRegs.pc, m_psxRegs.code, PSXMu32(m_psxRegs.pc), false);
}

void X86DynaRecCPU::Execute() {
    ZoneScoped;
    while (hasToRun()) execute();
}

void X86DynaRecCPU::Clear(uint32_t Addr, uint32_t Size) {
    uint32_t bank, offset;

    bank = Addr >> 24;
    offset = Addr & 0xffffff;

    // Pitfall 3D - clear dynarec slots that contain 'stale' ram data
    // - fixes stage 1 loading crash
    if (bank == 0x80 || bank == 0xa0 || bank == 0x00) {
        offset &= 0x1fffff;

        if (offset >= DYNAREC_BLOCK * 4)
            memset((void *)PC_REC(Addr - DYNAREC_BLOCK * 4), 0, DYNAREC_BLOCK * 4);
        else
            memset((void *)PC_REC(Addr - offset), 0, offset);
    }

    memset((void *)PC_REC(Addr), 0, Size * 4);
}

void X86DynaRecCPU::recNULL() {
    PCSX::g_system->message("Unknown instruction for dynarec - address %08x, instruction %08x\n", m_pc, m_psxRegs.code);
    recException(Exception::ReservedInstruction);
}

/*********************************************************
 * goes to opcodes tables...                              *
 * Format:  table[something....]                          *
 *********************************************************/

// REC_SYS(SPECIAL);
void X86DynaRecCPU::recSPECIAL() {
    func_t func = m_pRecSPC[_Funct_];
    (*this.*func)();
}

void X86DynaRecCPU::recREGIMM() {
    func_t func = m_pRecREG[_Rt_];
    (*this.*func)();
}

void X86DynaRecCPU::recCOP0() {
    func_t func = m_pRecCP0[_Rs_];
    (*this.*func)();
}

// REC_SYS(COP2);
void X86DynaRecCPU::recCOP2() {
    Label label;
    gen.mov(eax, dword[&m_psxRegs.CP0.n.Status]);
    gen.and_(eax, 0x40000000);
    gen.jz(label);

    func_t func = m_pRecCP2[_Funct_];
    (*this.*func)();

    gen.L(label);
}

void X86DynaRecCPU::recBASIC() {
    func_t func = m_pRecCP2BSC[_Rs_];
    (*this.*func)();
}

// end of Tables opcodes...

/*********************************************************
 * Arithmetic with immediate operand                      *
 * Format:  OP rt, rs, immediate                          *
 *********************************************************/

void X86DynaRecCPU::recADDIU() {
    // Rt = Rs + Im
    if (!_Rt_) return;
    maybeCancelDelayedLoad(_Rt_);

    if (_Rs_ == _Rt_) {
        if (IsConst(_Rt_)) {
            m_iRegs[_Rt_].k += _Imm_;
        } else {
            if (_Imm_ == 1) {
                gen.inc(dword[&m_psxRegs.GPR.r[_Rt_]]);
            } else if (_Imm_ == -1) {
                gen.dec(dword[&m_psxRegs.GPR.r[_Rt_]]);
            } else if (_Imm_) {
                gen.add(dword[&m_psxRegs.GPR.r[_Rt_]], _Imm_);
            }
        }
    } else {
        if (IsConst(_Rs_)) {
            MapConst(_Rt_, m_iRegs[_Rs_].k + _Imm_);
        } else {
            m_iRegs[_Rt_].state = ST_UNK;

            gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
            if (_Imm_ == 1) {
                gen.inc(eax);
            } else if (_Imm_ == -1) {
                gen.dec(eax);
            } else if (_Imm_) {
                gen.add(eax, _Imm_);
            }
            gen.mov(dword[&m_psxRegs.GPR.r[_Rt_]], eax);
        }
    }
}

void X86DynaRecCPU::recADDI() {
    // Rt = Rs + Im
    if (!_Rt_) return;
    maybeCancelDelayedLoad(_Rt_);

    if (_Rs_ == _Rt_) {
        if (IsConst(_Rt_)) {
            m_iRegs[_Rt_].k += _Imm_;
        } else {
            if (_Imm_ == 1) {
                gen.inc(dword[&m_psxRegs.GPR.r[_Rt_]]);
            } else if (_Imm_ == -1) {
                gen.dec(dword[&m_psxRegs.GPR.r[_Rt_]]);
            } else if (_Imm_) {
                gen.add(dword[&m_psxRegs.GPR.r[_Rt_]], _Imm_);
            }
        }
    } else {
        if (IsConst(_Rs_)) {
            MapConst(_Rt_, m_iRegs[_Rs_].k + _Imm_);
        } else {
            m_iRegs[_Rt_].state = ST_UNK;

            gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
            if (_Imm_ == 1) {
                gen.inc(eax);
            } else if (_Imm_ == -1) {
                gen.dec(eax);
            } else if (_Imm_) {
                gen.add(eax, _Imm_);
            }
            gen.mov(dword[&m_psxRegs.GPR.r[_Rt_]], eax);
        }
    }
}

void X86DynaRecCPU::recSLTI() {
    // Rt = Rs < Im (signed)
    if (!_Rt_) return;
    maybeCancelDelayedLoad(_Rt_);

    if (IsConst(_Rs_)) {
        MapConst(_Rt_, (int32_t)m_iRegs[_Rs_].k < _Imm_);
    } else {
        m_iRegs[_Rt_].state = ST_UNK;

        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        gen.cmp(eax, _Imm_);
        gen.setl(al);        // Set AL depending on whether Rs < imm
        gen.movzx(eax, al);  // Zero extend AL into EAX
        gen.mov(dword[&m_psxRegs.GPR.r[_Rt_]], eax);
    }
}

void X86DynaRecCPU::recSLTIU() {
    // Rt = Rs < Im (unsigned)
    if (!_Rt_) return;
    maybeCancelDelayedLoad(_Rt_);

    if (IsConst(_Rs_)) {
        MapConst(_Rt_, m_iRegs[_Rs_].k < (uint32_t)_Imm_);
    } else {
        m_iRegs[_Rt_].state = ST_UNK;

        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        gen.cmp(eax, _Imm_);
        gen.setb(al);        // Set AL depending on whether Rs < Imm (unsigned)
        gen.movzx(eax, al);  // Zero extend AL into EAX
        gen.mov(dword[&m_psxRegs.GPR.r[_Rt_]], eax);
    }
}

void X86DynaRecCPU::recANDI() {
    // Rt = Rs And Im
    if (!_Rt_) return;
    maybeCancelDelayedLoad(_Rt_);

    if (_Rs_ == _Rt_) {
        if (IsConst(_Rt_)) {
            m_iRegs[_Rt_].k &= _ImmU_;
        } else {
            gen.and_(dword[&m_psxRegs.GPR.r[_Rt_]], _ImmU_);
        }
    } else {
        if (IsConst(_Rs_)) {
            MapConst(_Rt_, m_iRegs[_Rs_].k & _ImmU_);
        } else {
            m_iRegs[_Rt_].state = ST_UNK;

            gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
            gen.and_(eax, _ImmU_);
            gen.mov(dword[&m_psxRegs.GPR.r[_Rt_]], eax);
        }
    }
}

void X86DynaRecCPU::recORI() {
    // Rt = Rs Or Im
    if (!_Rt_) return;
    maybeCancelDelayedLoad(_Rt_);

    if (_Rs_ == _Rt_) {
        if (IsConst(_Rt_)) {
            m_iRegs[_Rt_].k |= _ImmU_;
        } else {
            gen.or_(dword[&m_psxRegs.GPR.r[_Rt_]], _ImmU_);
        }
    } else {
        if (IsConst(_Rs_)) {
            MapConst(_Rt_, m_iRegs[_Rs_].k | _ImmU_);
        } else {
            m_iRegs[_Rt_].state = ST_UNK;

            gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
            if (_ImmU_) gen.or_(eax, _ImmU_);
            gen.mov(dword[&m_psxRegs.GPR.r[_Rt_]], eax);
        }
    }
}

void X86DynaRecCPU::recXORI() {
    // Rt = Rs Xor Im
    if (!_Rt_) return;
    maybeCancelDelayedLoad(_Rt_);

    if (_Rs_ == _Rt_) {
        if (IsConst(_Rt_)) {
            m_iRegs[_Rt_].k ^= _ImmU_;
        } else {
            gen.xor_(dword[&m_psxRegs.GPR.r[_Rt_]], _ImmU_);
        }
    } else {
        if (IsConst(_Rs_)) {
            MapConst(_Rt_, m_iRegs[_Rs_].k ^ _ImmU_);
        } else {
            m_iRegs[_Rt_].state = ST_UNK;

            gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
            gen.xor_(eax, _ImmU_);
            gen.mov(dword[&m_psxRegs.GPR.r[_Rt_]], eax);
        }
    }
}
// end of * Arithmetic with immediate operand

/*********************************************************
 * Load higher 16 bits of the first word in GPR with imm  *
 * Format:  OP rt, immediate                              *
 *********************************************************/
// REC_FUNC(LUI);
void X86DynaRecCPU::recLUI() {
    // Rt = Imm << 16
    if (!_Rt_) return;
    maybeCancelDelayedLoad(_Rt_);

    MapConst(_Rt_, m_psxRegs.code << 16);
}
// End of Load Higher .....

/*********************************************************
 * Register arithmetic                                    *
 * Format:  OP rd, rs, rt                                 *
 *********************************************************/

void X86DynaRecCPU::recADDU() {
    // Rd = Rs + Rt
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, m_iRegs[_Rs_].k + m_iRegs[_Rt_].k);
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        if (_Rt_ == _Rd_) {
            if (m_iRegs[_Rs_].k == 1) {
                gen.inc(dword[&m_psxRegs.GPR.r[_Rd_]]);
            } else if (m_iRegs[_Rs_].k == -1) {
                gen.dec(dword[&m_psxRegs.GPR.r[_Rd_]]);
            } else if (m_iRegs[_Rs_].k) {
                gen.add(dword[&m_psxRegs.GPR.r[_Rd_]], m_iRegs[_Rs_].k);
            }
        } else {
            gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
            if (m_iRegs[_Rs_].k == 1) {
                gen.inc(eax);
            } else if (m_iRegs[_Rs_].k == 0xffffffff) {
                gen.dec(eax);
            } else if (m_iRegs[_Rs_].k) {
                gen.add(eax, m_iRegs[_Rs_].k);
            }
            gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
        }
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        if (_Rs_ == _Rd_) {
            if (m_iRegs[_Rt_].k == 1) {
                gen.inc(dword[&m_psxRegs.GPR.r[_Rd_]]);
            } else if (m_iRegs[_Rt_].k == -1) {
                gen.dec(dword[&m_psxRegs.GPR.r[_Rd_]]);
            } else if (m_iRegs[_Rt_].k) {
                gen.add(dword[&m_psxRegs.GPR.r[_Rd_]], m_iRegs[_Rt_].k);
            }
        } else {
            gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
            if (m_iRegs[_Rt_].k == 1) {
                gen.inc(eax);
            } else if (m_iRegs[_Rt_].k == 0xffffffff) {
                gen.dec(eax);
            } else if (m_iRegs[_Rt_].k) {
                gen.add(eax, m_iRegs[_Rt_].k);
            }
            gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
        }
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        if (_Rs_ == _Rd_) {  // Rd+= Rt
            gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
            gen.add(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
        } else if (_Rt_ == _Rd_) {  // Rd+= Rs
            gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
            gen.add(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
        } else {  // Rd = Rs + Rt
            gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
            gen.add(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
            gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
        }
    }
}

void X86DynaRecCPU::recADD() {
    // Rd = Rs + Rt
    recADDU();
}

void X86DynaRecCPU::recSUBU() {
    // Rd = Rs - Rt
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, m_iRegs[_Rs_].k - m_iRegs[_Rt_].k);
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, m_iRegs[_Rs_].k);
        gen.sub(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        gen.sub(eax, m_iRegs[_Rt_].k);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        gen.sub(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    }
}

void X86DynaRecCPU::recSUB() {
    // Rd = Rs - Rt
    recSUBU();
}

void X86DynaRecCPU::recAND() {
    // Rd = Rs And Rt
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, m_iRegs[_Rs_].k & m_iRegs[_Rt_].k);
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        if (_Rd_ == _Rt_) {  // Rd&= Rs
            gen.and_(dword[&m_psxRegs.GPR.r[_Rd_]], m_iRegs[_Rs_].k);
        } else {
            gen.mov(eax, m_iRegs[_Rs_].k);
            gen.and_(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
            gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
        }
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        if (_Rd_ == _Rs_) {  // Rd&= kRt
            gen.and_(dword[&m_psxRegs.GPR.r[_Rd_]], m_iRegs[_Rt_].k);
        } else {  // Rd = Rs & kRt
            gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
            gen.and_(eax, m_iRegs[_Rt_].k);
            gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
        }
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        if (_Rs_ == _Rd_) {  // Rd&= Rt
            gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
            gen.and_(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
        } else if (_Rt_ == _Rd_) {  // Rd&= Rs
            gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
            gen.and_(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
        } else {  // Rd = Rs & Rt
            gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
            gen.and_(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
            gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
        }
    }
}

void X86DynaRecCPU::recOR() {
    // Rd = Rs Or Rt
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, m_iRegs[_Rs_].k | m_iRegs[_Rt_].k);
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, m_iRegs[_Rs_].k);
        gen.or_(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        gen.or_(eax, m_iRegs[_Rt_].k);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        gen.or_(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    }
}

void X86DynaRecCPU::recXOR() {
    // Rd = Rs Xor Rt
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, m_iRegs[_Rs_].k ^ m_iRegs[_Rt_].k);
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, m_iRegs[_Rs_].k);
        gen.xor_(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        gen.xor_(eax, m_iRegs[_Rt_].k);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        gen.xor_(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    }
}

void X86DynaRecCPU::recNOR() {
    // Rd = Rs Nor Rt
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, ~(m_iRegs[_Rs_].k | m_iRegs[_Rt_].k));
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, m_iRegs[_Rs_].k);
        gen.or_(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
        gen.not_(eax);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        gen.or_(eax, m_iRegs[_Rt_].k);
        gen.not_(eax);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        gen.or_(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
        gen.not_(eax);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    }
}

void X86DynaRecCPU::recSLT() {
    // Rd = Rs < Rt (signed)
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, (int32_t)m_iRegs[_Rs_].k < (int32_t)m_iRegs[_Rt_].k);
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, m_iRegs[_Rs_].k);
        gen.cmp(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
        gen.setl(al);        // set AL to 0 or 1 depending on if Rs < Rt
        gen.movzx(eax, al);  // Zero extend AL into EAX
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        gen.cmp(eax, m_iRegs[_Rt_].k);
        gen.setl(al);        // set AL to 0 or 1 depending on if Rs < Rt
        gen.movzx(eax, al);  // Zero extend AL into EAX
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        gen.cmp(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
        gen.setl(al);        // set AL to 0 or 1 depending on if Rs < Rt
        gen.movzx(eax, al);  // Zero extend AL into EAX
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    }
}

void X86DynaRecCPU::recSLTU() {
    // Rd = Rs < Rt (unsigned)
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, m_iRegs[_Rs_].k < m_iRegs[_Rt_].k);
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, m_iRegs[_Rs_].k);
        gen.cmp(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
        gen.sbb(eax, eax);
        gen.neg(eax);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        gen.cmp(eax, m_iRegs[_Rt_].k);
        gen.sbb(eax, eax);
        gen.neg(eax);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        gen.cmp(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
        gen.sbb(eax, eax);
        gen.neg(eax);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    }
}
// End of * Register arithmetic

/*********************************************************
 * Register mult/div & Register trap logic                *
 * Format:  OP rs, rt                                     *
 *********************************************************/

// REC_FUNC(MULT);
// REC_FUNC(MULTU);
// REC_FUNC(DIV);
// REC_FUNC(DIVU);
void X86DynaRecCPU::recMULT() {
    // Lo/Hi = Rs * Rt (signed)

    if ((IsConst(_Rs_) && m_iRegs[_Rs_].k == 0) || (IsConst(_Rt_) && m_iRegs[_Rt_].k == 0)) {
        gen.xor_(eax, eax);
        gen.mov(dword[&m_psxRegs.GPR.n.lo], eax);
        gen.mov(dword[&m_psxRegs.GPR.n.hi], eax);
        return;
    }

    if (IsConst(_Rs_)) {
        gen.mov(eax, m_iRegs[_Rs_].k);
    } else {
        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
    }
    if (IsConst(_Rt_)) {
        gen.mov(edx, m_iRegs[_Rt_].k);
        gen.imul(edx);
    } else {
        gen.imul(dword[&m_psxRegs.GPR.r[_Rt_]]);
    }
    gen.mov(dword[&m_psxRegs.GPR.n.lo], eax);
    gen.mov(dword[&m_psxRegs.GPR.n.hi], edx);
}

void X86DynaRecCPU::recMULTU() {
    // Lo/Hi = Rs * Rt (unsigned)

    if ((IsConst(_Rs_) && m_iRegs[_Rs_].k == 0) || (IsConst(_Rt_) && m_iRegs[_Rt_].k == 0)) {
        gen.xor_(eax, eax);
        gen.mov(dword[&m_psxRegs.GPR.n.lo], eax);
        gen.mov(dword[&m_psxRegs.GPR.n.hi], eax);
        return;
    }

    if (IsConst(_Rs_)) {
        gen.mov(eax, m_iRegs[_Rs_].k);
    } else {
        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
    }
    if (IsConst(_Rt_)) {
        gen.mov(edx, m_iRegs[_Rt_].k);
        gen.mul(edx);
    } else {
        gen.mul(dword[&m_psxRegs.GPR.r[_Rt_]]);
    }
    gen.mov(dword[&m_psxRegs.GPR.n.lo], eax);
    gen.mov(dword[&m_psxRegs.GPR.n.hi], edx);
}

void X86DynaRecCPU::recDIV() {
    // Lo/Hi = Rs / Rt (signed)
    Label label1;

    if (IsConst(_Rt_)) {
        if (m_iRegs[_Rt_].k == 0) {
            gen.mov(dword[&m_psxRegs.GPR.n.lo], 0xffffffff);
            if (IsConst(_Rs_)) {
                gen.mov(dword[&m_psxRegs.GPR.n.hi], m_iRegs[_Rs_].k);
            } else {
                gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
                gen.mov(dword[&m_psxRegs.GPR.n.hi], eax);
            }
            return;
        }
        gen.mov(ecx, m_iRegs[_Rt_].k);
    } else {
        gen.mov(ecx, dword[&m_psxRegs.GPR.r[_Rt_]]);
        gen.test(ecx, ecx);  // check if ECX == 0
        gen.je(label1, CodeGenerator::LabelType::T_NEAR);
    }
    if (IsConst(_Rs_)) {
        gen.mov(eax, m_iRegs[_Rs_].k);
    } else {
        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
    }
    gen.cdq();
    gen.idiv(ecx);
    gen.mov(dword[&m_psxRegs.GPR.n.lo], eax);
    gen.mov(dword[&m_psxRegs.GPR.n.hi], edx);

    if (!IsConst(_Rt_)) {
        Label label2;
        gen.jmp(label2, CodeGenerator::LabelType::T_NEAR);
        gen.L(label1);

        gen.mov(dword[&m_psxRegs.GPR.n.lo], 0xffffffff);
        if (IsConst(_Rs_)) {
            gen.mov(dword[&m_psxRegs.GPR.n.hi], m_iRegs[_Rs_].k);
        } else {
            gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
            gen.mov(dword[&m_psxRegs.GPR.n.hi], eax);
        }

        gen.L(label2);
    }
}

void X86DynaRecCPU::recDIVU() {
    // Lo/Hi = Rs / Rt (unsigned)
    Label label1;

    if (IsConst(_Rt_)) {
        if (m_iRegs[_Rt_].k == 0) {
            gen.mov(dword[&m_psxRegs.GPR.n.lo], 0xffffffff);
            if (IsConst(_Rs_)) {
                gen.mov(dword[&m_psxRegs.GPR.n.hi], m_iRegs[_Rs_].k);
            } else {
                gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
                gen.mov(dword[&m_psxRegs.GPR.n.hi], eax);
            }
            return;
        }
        gen.mov(ecx, m_iRegs[_Rt_].k);
    } else {
        gen.mov(ecx, dword[&m_psxRegs.GPR.r[_Rt_]]);
        gen.test(ecx, ecx);
        gen.je(label1, CodeGenerator::LabelType::T_NEAR);
    }
    if (IsConst(_Rs_)) {
        gen.mov(eax, m_iRegs[_Rs_].k);
    } else {
        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
    }
    gen.xor_(edx, edx);
    gen.div(ecx);
    gen.mov(dword[&m_psxRegs.GPR.n.lo], eax);
    gen.mov(dword[&m_psxRegs.GPR.n.hi], edx);

    if (!IsConst(_Rt_)) {
        Label label2;

        gen.jmp(label2, CodeGenerator::LabelType::T_NEAR);
        gen.L(label1);

        gen.mov(dword[&m_psxRegs.GPR.n.lo], 0xffffffff);
        if (IsConst(_Rs_)) {
            gen.mov(dword[&m_psxRegs.GPR.n.hi], m_iRegs[_Rs_].k);
        } else {
            gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
            gen.mov(dword[&m_psxRegs.GPR.n.hi], eax);
        }

        gen.L(label2);
    }
}
// End of * Register mult/div & Register trap logic

/* Push OfB for Stores/Loads */
void X86DynaRecCPU::iPushOfB() {
    if (IsConst(_Rs_)) {
        gen.push(dword, m_iRegs[_Rs_].k + _Imm_);
    } else {
        if (_Imm_) {
            gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
            gen.add(eax, _Imm_);
            gen.push(eax);
        } else {
            gen.push(dword[&m_psxRegs.GPR.r[_Rs_]]);
        }
    }
}

void X86DynaRecCPU::recLB() {
    // Rt = mem[Rs + Im] (signed)

    if (_Rt_) {
        m_needsStackFrame = true;
        auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
        delayedLoad.active = true;
        delayedLoad.index = _Rt_;
    }
    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0xfff0) == 0xbfc0) {
            if (!_Rt_) return;
            // since bios is readonly it won't change
            gen.mov(edi, psxRs8(addr));
            return;
        }
        if ((t & 0x1fe0) == 0) {
            if (!_Rt_) return;
            gen.movsx(edi, Xbyak::util::byte[&PCSX::g_emulator->m_psxMem->g_psxM[addr & 0x1fffff]]);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            if (!_Rt_) return;
            gen.movsx(edi, Xbyak::util::byte[&PCSX::g_emulator->m_psxMem->g_psxH[addr & 0xfff]]);
            return;
        }
    }

    iPushOfB();
    gen.call(psxMemRead8Wrapper);
    if (_Rt_) gen.movsx(edi, al);
    gen.add(esp, 4);
}

void X86DynaRecCPU::recLBU() {
    // Rt = mem[Rs + Im] (unsigned)

    if (_Rt_) {
        m_needsStackFrame = true;
        auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
        delayedLoad.active = true;
        delayedLoad.index = _Rt_;
    }
    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0xfff0) == 0xbfc0) {
            if (!_Rt_) return;
            // since bios is readonly it won't change
            gen.mov(edi, psxRu8(addr));
            return;
        }
        if ((t & 0x1fe0) == 0) {
            if (!_Rt_) return;
            gen.movzx(edi, Xbyak::util::byte[&PCSX::g_emulator->m_psxMem->g_psxM[addr & 0x1fffff]]);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            if (!_Rt_) return;
            gen.movzx(edi, Xbyak::util::byte[&PCSX::g_emulator->m_psxMem->g_psxH[addr & 0xfff]]);
            return;
        }
    }

    iPushOfB();
    gen.call(psxMemRead8Wrapper);
    if (_Rt_) gen.movzx(edi, al);
    gen.add(esp, 4);
}

void X86DynaRecCPU::recLH() {
    // Rt = mem[Rs + Im] (signed)

    if (_Rt_) {
        m_needsStackFrame = true;
        auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
        delayedLoad.active = true;
        delayedLoad.index = _Rt_;
    }
    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0xfff0) == 0xbfc0) {
            if (!_Rt_) return;
            // since bios is readonly it won't change
            gen.mov(edi, psxRs16(addr));
            return;
        }
        if ((t & 0x1fe0) == 0) {
            if (!_Rt_) return;
            gen.movsx(edi, word[&PCSX::g_emulator->m_psxMem->g_psxM[addr & 0x1fffff]]);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            if (!_Rt_) return;
            gen.movsx(edi, word[&PCSX::g_emulator->m_psxMem->g_psxH[addr & 0xfff]]);
            return;
        }
    }

    iPushOfB();
    gen.call(psxMemRead16Wrapper);
    if (_Rt_) gen.movsx(edi, ax);
    gen.add(esp, 4);
}

void X86DynaRecCPU::recLHU() {
    // Rt = mem[Rs + Im] (unsigned)

    if (_Rt_) {
        m_needsStackFrame = true;
        auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
        delayedLoad.active = true;
        delayedLoad.index = _Rt_;
    }
    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0xfff0) == 0xbfc0) {
            if (!_Rt_) return;
            // since bios is readonly it won't change
            gen.mov(edi, psxRu16(addr));
            return;
        }
        if ((t & 0x1fe0) == 0) {
            if (!_Rt_) return;
            gen.movzx(edi, word[&PCSX::g_emulator->m_psxMem->g_psxM[addr & 0x1fffff]]);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            if (!_Rt_) return;
            gen.movzx(edi, word[&PCSX::g_emulator->m_psxMem->g_psxH[addr & 0xfff]]);
            return;
        }
        if (t == 0x1f80) {
            if (addr >= 0x1f801c00 && addr < 0x1f801e00) {
                if (!_Rt_) return;
                gen.push(dword, addr);
                gen.call(SPUreadRegisterWrapper);
                gen.movzx(edi, ax);
                gen.add(esp, 4);
                return;
            }
            switch (addr) {
                case 0x1f801100:
                case 0x1f801110:
                case 0x1f801120:
                    if (!_Rt_) return;
                    gen.push(dword, (addr >> 4) & 0x3);
                    gen.call(psxRcntRcountWrapper);
                    gen.movzx(edi, ax);
                    gen.add(esp, 4);
                    return;

                case 0x1f801104:
                case 0x1f801114:
                case 0x1f801124:
                    if (!_Rt_) return;
                    gen.push(dword, (addr >> 4) & 0x3);
                    gen.call(psxRcntRmodeWrapper);
                    gen.movzx(edi, ax);
                    gen.add(esp, 4);
                    return;

                case 0x1f801108:
                case 0x1f801118:
                case 0x1f801128:
                    if (!_Rt_) return;
                    gen.push(dword, (addr >> 4) & 0x3);
                    gen.call(psxRcntRtargetWrapper);
                    gen.movzx(edi, ax);
                    gen.add(esp, 4);
                    return;
            }
        }
    }

    iPushOfB();
    gen.call(psxMemRead16Wrapper);
    if (_Rt_) gen.movzx(edi, ax);
    gen.add(esp, 4);
}

void X86DynaRecCPU::recLW() {
    // Rt = mem[Rs + Im] (unsigned)

    if (_Rt_) {
        m_needsStackFrame = true;
        auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
        delayedLoad.active = true;
        delayedLoad.index = _Rt_;
    }
    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0xfff0) == 0xbfc0) {
            if (!_Rt_) return;
            // since bios is readonly it won't change
            gen.mov(edi, psxRu32(addr));
            return;
        }
        if ((t & 0x1fe0) == 0) {
            if (!_Rt_) return;
            gen.mov(edi, dword[&PCSX::g_emulator->m_psxMem->g_psxM[addr & 0x1fffff]]);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            if (!_Rt_) return;
            gen.mov(edi, dword[&PCSX::g_emulator->m_psxMem->g_psxH[addr & 0xfff]]);
            return;
        }
        if (t == 0x1f80) {
            switch (addr) {
                case 0x1f801080:
                case 0x1f801084:
                case 0x1f801088:
                case 0x1f801090:
                case 0x1f801094:
                case 0x1f801098:
                case 0x1f8010a0:
                case 0x1f8010a4:
                case 0x1f8010a8:
                case 0x1f8010b0:
                case 0x1f8010b4:
                case 0x1f8010b8:
                case 0x1f8010c0:
                case 0x1f8010c4:
                case 0x1f8010c8:
                case 0x1f8010d0:
                case 0x1f8010d4:
                case 0x1f8010d8:
                case 0x1f8010e0:
                case 0x1f8010e4:
                case 0x1f8010e8:
                case 0x1f801070:
                case 0x1f801074:
                case 0x1f8010f0:
                case 0x1f8010f4:
                    if (!_Rt_) return;
                    gen.mov(edi, dword[&PCSX::g_emulator->m_psxMem->g_psxH[addr & 0xffff]]);
                    return;

                case 0x1f801810:
                    if (!_Rt_) return;
                    gen.call(&GPU_readDataWrapper);
                    gen.mov(edi, eax);
                    return;

                case 0x1f801814:
                    if (!_Rt_) return;
                    gen.call(&GPU_readStatusWrapper);
                    gen.mov(edi, eax);
                    return;
            }
        }
    }

    iPushOfB();
    gen.call(psxMemRead32Wrapper);
    if (_Rt_) gen.mov(edi, eax);
    gen.add(esp, 4);
}

void X86DynaRecCPU::recLWL() {
    // Rt = Rt Merge mem[Rs + Im]

    if (_Rt_) {
        m_needsStackFrame = true;
        auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
        delayedLoad.active = true;
        delayedLoad.index = _Rt_;
    }
    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;
        auto iLWLk = [&](uint32_t shift, uint32_t ptr) {
            gen.mov(eax, dword[ptr]);
            if (LWL_SHIFT[shift]) gen.shl(eax, LWL_SHIFT[shift]);
            gen.mov(edi, eax);
            if (LWL_MASK_INDEX[shift]) {
                gen.mov(ecx, LWL_MASK_INDEX[shift] << 16);
                gen.or_(ebx, ecx);
            }
        };

        if ((t & 0x1fe0) == 0) {
            iLWLk(addr & 3, (uint32_t)&PCSX::g_emulator->m_psxMem->g_psxM[addr & 0x1ffffc]);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            iLWLk(addr & 3, (uint32_t)&PCSX::g_emulator->m_psxMem->g_psxH[addr & 0xffc]);
            return;
        }
        gen.mov(eax, m_iRegs[_Rs_].k + _Imm_);
    } else {
        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        if (_Imm_) gen.add(eax, _Imm_);
    }
    gen.push(eax);
    gen.and_(eax, ~3);
    gen.push(eax);
    gen.call(psxMemRead32Wrapper);

    if (_Rt_) {
        gen.add(esp, 4);
        gen.pop(edx);
        gen.and_(edx, 0x3);  // shift = addr & 3;

        gen.mov(ecx, dword[(uint32_t)LWL_SHIFT + edx * 4]);
        gen.shl(eax, cl);  // mem(eax) << LWL_SHIFT[shift]
        gen.mov(edi, eax);

        gen.mov(ecx, dword[(uint32_t)LWL_MASK_INDEX + edx * 4]);
        gen.shl(ecx, 16);
        gen.movzx(ebx, bx);
        gen.or_(ebx, ecx);
    } else {
        gen.add(esp, 8);
    }
}

void X86DynaRecCPU::recLWR() {
    // Rt = Rt Merge mem[Rs + Im]

    if (_Rt_) {
        m_needsStackFrame = true;
        auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
        delayedLoad.active = true;
        delayedLoad.index = _Rt_;
    }
    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        auto iLWRk = [&](uint32_t shift, uint32_t ptr) {
            gen.mov(eax, dword[ptr]);
            if (LWR_SHIFT[shift]) gen.shl(eax, LWR_SHIFT[shift]);
            gen.mov(edi, eax);
            if (LWR_MASK_INDEX[shift]) {
                gen.mov(ecx, LWR_MASK_INDEX[shift] >> 16);
                gen.or_(ebx, ecx);
            }
        };

        if ((t & 0x1fe0) == 0) {
            iLWRk(addr & 3, (uint32_t)&PCSX::g_emulator->m_psxMem->g_psxM[addr & 0x1ffffc]);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            iLWRk(addr & 3, (uint32_t)&PCSX::g_emulator->m_psxMem->g_psxH[addr & 0xffc]);
            return;
        }
        gen.mov(eax, m_iRegs[_Rs_].k + _Imm_);
    } else {
        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        if (_Imm_) gen.add(eax, _Imm_);
    }
    gen.push(eax);
    gen.and_(eax, ~3);
    gen.push(eax);
    gen.call(psxMemRead32Wrapper);

    if (_Rt_) {
        gen.add(esp, 4);
        gen.pop(edx);
        gen.and_(edx, 0x3);  // shift = addr & 3;

        gen.mov(ecx, dword[(uint32_t)LWR_SHIFT + edx * 4]);
        gen.shr(eax, cl);  // mem(eax) << LWR_SHIFT[shift]
        gen.mov(edi, eax);

        gen.mov(ecx, dword[(uint32_t)LWR_MASK_INDEX + edx * 4]);
        gen.shl(ecx, 16);
        gen.movzx(ebx, bx);
        gen.or_(ebx, ecx);
    } else {
        gen.add(esp, 8);
    }
}

void X86DynaRecCPU::recSB() {
    // mem[Rs + Im] = Rt

    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0x1fe0) == 0 && (t & 0x1fff) != 0) {
            if (IsConst(_Rt_)) {
                gen.mov(Xbyak::util::byte[&PCSX::g_emulator->m_psxMem->g_psxM[addr & 0x1fffff]],
                        (uint8_t)m_iRegs[_Rt_].k);
            } else {
                gen.mov(al, Xbyak::util::byte[&m_psxRegs.GPR.r[_Rt_]]);
                gen.mov(Xbyak::util::byte[&PCSX::g_emulator->m_psxMem->g_psxM[addr & 0x1fffff]], al);
            }

            gen.push(dword, 1);
            gen.push(dword, addr & ~3);
            gen.push(dword, reinterpret_cast<uintptr_t>(this));
            gen.call(&recClearWrapper);
            gen.add(esp, 12);
            return;
        }

        if (t == 0x1f80 && addr < 0x1f801000) {
            if (IsConst(_Rt_)) {
                gen.mov(Xbyak::util::byte[&PCSX::g_emulator->m_psxMem->g_psxH[addr & 0xfff]], (uint8_t)m_iRegs[_Rt_].k);
            } else {
                gen.mov(al, Xbyak::util::byte[&m_psxRegs.GPR.r[_Rt_]]);
                gen.mov(Xbyak::util::byte[&PCSX::g_emulator->m_psxMem->g_psxH[addr & 0xfff]], al);
            }
            return;
        }
        //      PCSX::g_system->printf("unhandled w8 %x\n", addr);
    }

    if (IsConst(_Rt_)) {
        gen.push(dword, m_iRegs[_Rt_].k);
    } else {
        gen.push(dword[&m_psxRegs.GPR.r[_Rt_]]);
    }
    iPushOfB();
    gen.call(psxMemWrite8Wrapper);
    gen.add(esp, 8);
}

void X86DynaRecCPU::recSH() {
    // mem[Rs + Im] = Rt

    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0x1fe0) == 0 && (t & 0x1fff) != 0) {
            if (IsConst(_Rt_)) {
                gen.mov(word[&PCSX::g_emulator->m_psxMem->g_psxM[addr & 0x1fffff]], (uint16_t)m_iRegs[_Rt_].k);
            } else {
                gen.mov(ax, word[&m_psxRegs.GPR.r[_Rt_]]);
                gen.mov(word[&PCSX::g_emulator->m_psxMem->g_psxM[addr & 0x1fffff]], ax);
            }

            gen.push(dword, 1);
            gen.push(dword, addr & ~3);
            gen.push(dword, reinterpret_cast<uintptr_t>(this));
            gen.call(&recClearWrapper);
            gen.add(esp, 12);
            return;
        }

        if (t == 0x1f80 && addr < 0x1f801000) {
            if (IsConst(_Rt_)) {
                gen.mov(word[&PCSX::g_emulator->m_psxMem->g_psxH[addr & 0xfff]], (uint16_t)m_iRegs[_Rt_].k);
            } else {
                gen.mov(ax, word[&m_psxRegs.GPR.r[_Rt_]]);
                gen.mov(word[&PCSX::g_emulator->m_psxMem->g_psxH[addr & 0xfff]], ax);
            }
            return;
        }
        if (t == 0x1f80) {
            if (addr >= 0x1f801c00 && addr < 0x1f801e00) {
                if (IsConst(_Rt_)) {
                    gen.push(dword, m_iRegs[_Rt_].k);
                } else {
                    gen.push(dword[&m_psxRegs.GPR.r[_Rt_]]);
                }
                gen.push(dword, addr);
                gen.call(SPUwriteRegisterWrapper);
                gen.add(esp, 8);
                return;
            }
        }
        //      PCSX::g_system->printf("unhandled w16 %x\n", addr);
    }

    if (IsConst(_Rt_)) {
        gen.push(dword, m_iRegs[_Rt_].k);
    } else {
        gen.push(dword[&m_psxRegs.GPR.r[_Rt_]]);
    }
    iPushOfB();
    gen.call(psxMemWrite16Wrapper);
    gen.add(esp, 8);
}

void X86DynaRecCPU::recSW() {
    // mem[Rs + Im] = Rt

    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0x1fe0) == 0 && (t & 0x1fff) != 0) {
            if (IsConst(_Rt_)) {
                gen.mov(dword[&PCSX::g_emulator->m_psxMem->g_psxM[addr & 0x1fffff]], m_iRegs[_Rt_].k);
            } else {
                gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
                gen.mov(dword[&PCSX::g_emulator->m_psxMem->g_psxM[addr & 0x1fffff]], eax);
            }

            gen.push(dword, 1);
            gen.push(dword, addr);
            gen.push(dword, reinterpret_cast<uintptr_t>(this));
            gen.call(&recClearWrapper);
            gen.add(esp, 12);
            return;
        }

        if (t == 0x1f80 && addr < 0x1f801000) {
            if (IsConst(_Rt_)) {
                gen.mov(dword[&PCSX::g_emulator->m_psxMem->g_psxH[addr & 0xfff]], m_iRegs[_Rt_].k);
            } else {
                gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
                gen.mov(dword[&PCSX::g_emulator->m_psxMem->g_psxH[addr & 0xfff]], eax);
            }
            return;
        }
        if (t == 0x1f80) {
            switch (addr) {
                case 0x1f801080:
                case 0x1f801084:
                case 0x1f801090:
                case 0x1f801094:
                case 0x1f8010a0:
                case 0x1f8010a4:
                case 0x1f8010b0:
                case 0x1f8010b4:
                case 0x1f8010c0:
                case 0x1f8010c4:
                case 0x1f8010d0:
                case 0x1f8010d4:
                case 0x1f8010e0:
                case 0x1f8010e4:
                case 0x1f801074:
                case 0x1f8010f0:
                    if (IsConst(_Rt_)) {
                        gen.mov(dword[&PCSX::g_emulator->m_psxMem->g_psxH[addr & 0xffff]], m_iRegs[_Rt_].k);
                    } else {
                        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
                        gen.mov(dword[&PCSX::g_emulator->m_psxMem->g_psxH[addr & 0xffff]], eax);
                    }
                    return;

                case 0x1f801810:
                    if (IsConst(_Rt_)) {
                        gen.push(dword, m_iRegs[_Rt_].k);
                    } else {
                        gen.push(dword[&m_psxRegs.GPR.r[_Rt_]]);
                    }
                    gen.call(GPU_writeDataWrapper);
                    gen.add(esp, 4);
                    return;

                case 0x1f801814:
                    if (IsConst(_Rt_)) {
                        gen.push(dword, m_iRegs[_Rt_].k);
                    } else {
                        gen.push(dword[&m_psxRegs.GPR.r[_Rt_]]);
                    }
                    gen.call(&GPU_writeStatusWrapper);
                    gen.add(esp, 4);
                    return;
            }
        }
        //      PCSX::g_system->printf("unhandled w32 %x\n", addr);
    }

    if (IsConst(_Rt_)) {
        gen.push(dword, m_iRegs[_Rt_].k);
    } else {
        gen.push(dword[&m_psxRegs.GPR.r[_Rt_]]);
    }
    iPushOfB();
    gen.call(psxMemWrite32Wrapper);
    gen.add(esp, 8);
}

void X86DynaRecCPU::iSWLk(uint32_t shift) {
    if (IsConst(_Rt_)) {
        gen.mov(ecx, m_iRegs[_Rt_].k >> SWL_SHIFT[shift]);
    } else {
        gen.mov(ecx, dword[&m_psxRegs.GPR.r[_Rt_]]);
        gen.shr(ecx, SWL_SHIFT[shift]);
    }

    gen.and_(eax, SWL_MASK[shift]);
    gen.or_(eax, ecx);
}

void X86DynaRecCPU::recSWL() {
    // mem[Rs + Im] = Rt Merge mem[Rs + Im]

    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

#if 0
        if ((t & 0x1fe0) == 0 && (t & 0x1fff) != 0) {
            gen.MOV32MtoR(eax, (uint32_t)&PCSX::g_emulator->m_psxMem->g_psxM[addr & 0x1ffffc]);
            iSWLk(addr & 3);
            gen.MOV32RtoM((uint32_t)&PCSX::g_emulator->m_psxMem->g_psxM[addr & 0x1ffffc], eax);
            return;
        }
#endif
        if (t == 0x1f80 && addr < 0x1f801000) {
            gen.mov(eax, dword[&PCSX::g_emulator->m_psxMem->g_psxH[addr & 0xffc]]);
            iSWLk(addr & 3);
            gen.mov(dword[&PCSX::g_emulator->m_psxMem->g_psxH[addr & 0xffc]], eax);
            return;
        }
    }

    if (IsConst(_Rs_)) {
        gen.mov(eax, m_iRegs[_Rs_].k + _Imm_);
    } else {
        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        if (_Imm_) gen.add(eax, _Imm_);
    }
    gen.push(eax);
    gen.and_(eax, ~3);
    gen.push(eax);

    gen.call(psxMemRead32Wrapper);

    gen.add(esp, 4);
    gen.pop(edx);
    gen.and_(edx, 0x3);                                  // shift = addr & 3;
    gen.and_(eax, dword[(uint32_t)SWL_MASK + edx * 4]);  // mem & SWL_MASK[shift]

    gen.mov(ecx, dword[(uint32_t)SWL_SHIFT + edx * 4]);
    if (IsConst(_Rt_)) {
        gen.mov(edx, m_iRegs[_Rt_].k);
    } else {
        gen.mov(edx, dword[&m_psxRegs.GPR.r[_Rt_]]);
    }
    gen.shr(edx, cl);  // _rRt_ >> SWL_SHIFT[shift]

    gen.or_(eax, edx);
    gen.push(eax);

    if (IsConst(_Rs_))
        gen.mov(eax, m_iRegs[_Rs_].k + _Imm_);
    else {
        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        if (_Imm_) gen.add(eax, _Imm_);
    }
    gen.and_(eax, ~3);
    gen.push(eax);

    gen.call(psxMemWrite32Wrapper);
    gen.add(esp, 8);
}

void X86DynaRecCPU::iSWRk(uint32_t shift) {
    if (IsConst(_Rt_)) {
        gen.mov(ecx, m_iRegs[_Rt_].k);
    } else {
        gen.mov(ecx, dword[&m_psxRegs.GPR.r[_Rt_]]);
    }
    if (SWR_SHIFT[shift]) gen.shl(ecx, SWR_SHIFT[shift]);
    gen.and_(eax, SWR_MASK[shift]);
    gen.or_(eax, ecx);
}

void X86DynaRecCPU::recSWR() {
    // mem[Rs + Im] = Rt Merge mem[Rs + Im]

    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

#if 0
        if ((t & 0x1fe0) == 0 && (t & 0x1fff) != 0) {
            gen.MOV32MtoR(eax, (uint32_t)&PCSX::g_emulator->m_psxMem->g_psxM[addr & 0x1ffffc]);
            iSWRk(addr & 3);
            gen.MOV32RtoM((uint32_t)&PCSX::g_emulator->m_psxMem->g_psxM[addr & 0x1ffffc], eax);
            return;
        }
#endif
        if (t == 0x1f80 && addr < 0x1f801000) {
            gen.mov(eax, dword[&PCSX::g_emulator->m_psxMem->g_psxH[addr & 0xffc]]);
            iSWRk(addr & 3);
            gen.mov(dword[&PCSX::g_emulator->m_psxMem->g_psxH[addr & 0xffc]], eax);
            return;
        }
    }

    if (IsConst(_Rs_)) {
        gen.mov(eax, m_iRegs[_Rs_].k + _Imm_);
    } else {
        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        if (_Imm_) gen.add(eax, _Imm_);
    }
    gen.push(eax);
    gen.and_(eax, ~3);
    gen.push(eax);

    gen.call(psxMemRead32Wrapper);

    gen.add(esp, 4);
    gen.pop(edx);
    gen.and_(edx, 0x3);                                  // shift = addr & 3;
    gen.and_(eax, dword[(uint32_t)SWR_MASK + edx * 4]);  // mem & SWR_MASK[shift]

    gen.mov(ecx, dword[(uint32_t)SWR_SHIFT + edx * 4]);
    if (IsConst(_Rt_)) {
        gen.mov(edx, m_iRegs[_Rt_].k);
    } else {
        gen.mov(edx, dword[&m_psxRegs.GPR.r[_Rt_]]);
    }
    gen.shl(edx, cl);  // _rRt_ << SWR_SHIFT[shift]

    gen.or_(eax, edx);
    gen.push(eax);

    if (IsConst(_Rs_))
        gen.mov(eax, m_iRegs[_Rs_].k + _Imm_);
    else {
        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        if (_Imm_) gen.add(eax, _Imm_);
    }
    gen.and_(eax, ~3);
    gen.push(eax);

    gen.call(psxMemWrite32Wrapper);
    gen.add(esp, 8);
}

void X86DynaRecCPU::recSLL() {
    // Rd = Rt << Sa
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);

    if (IsConst(_Rt_)) {
        MapConst(_Rd_, m_iRegs[_Rt_].k << _Sa_);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
        if (_Sa_) gen.shl(eax, _Sa_);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    }
}

void X86DynaRecCPU::recSRL() {
    // Rd = Rt >> Sa
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);

    if (IsConst(_Rt_)) {
        MapConst(_Rd_, m_iRegs[_Rt_].k >> _Sa_);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
        if (_Sa_) gen.shr(eax, _Sa_);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    }
}

void X86DynaRecCPU::recSRA() {
    // Rd = Rt >> Sa
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);

    if (IsConst(_Rt_)) {
        MapConst(_Rd_, (int32_t)m_iRegs[_Rt_].k >> _Sa_);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
        if (_Sa_) gen.sar(eax, _Sa_);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    }
}

void X86DynaRecCPU::recSLLV() {
    // Rd = Rt << Rs
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);

    if (IsConst(_Rt_) && IsConst(_Rs_)) {
        MapConst(_Rd_, m_iRegs[_Rt_].k << (m_iRegs[_Rs_].k & 0x1f));
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
        gen.mov(ecx, m_iRegs[_Rs_].k & 0x1f);
        gen.shl(eax, cl);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, m_iRegs[_Rt_].k & 0x1f);
        gen.mov(ecx, dword[&m_psxRegs.GPR.r[_Rs_]]);
        // gen.and_(ecx,0x1f);  // MIPS spec says that the shift amount is masked by 31. however this
        // happens implicitly on all x86 processors except for 8086.
        // So no need to do it manually
        gen.shl(eax, cl);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
        gen.mov(ecx, dword[&m_psxRegs.GPR.r[_Rs_]]);
        // gen.and_(ecx,0x1f);  // MIPS spec says that the shift amount is masked by 31. however this
        // happens implicitly on all x86 processors except for 8086.
        // So no need to do it manually
        gen.shl(eax, cl);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    }
}

void X86DynaRecCPU::recSRLV() {
    // Rd = Rt >> Rs
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);

    if (IsConst(_Rt_) && IsConst(_Rs_)) {
        MapConst(_Rd_, m_iRegs[_Rt_].k >> (m_iRegs[_Rs_].k & 0x1f));
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
        gen.mov(ecx, m_iRegs[_Rs_].k & 0x1f);
        gen.shr(eax, cl);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, m_iRegs[_Rt_].k);
        gen.mov(ecx, dword[&m_psxRegs.GPR.r[_Rs_]]);  // place shift amount in ECX
        // gen.and_(ecx,0x1f);  // MIPS spec says that the shift amount is masked by 31. however this
        // happens implicitly
        // on all x86 processors except for 8086.
        // So no need to do it manually
        gen.shr(eax, cl);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
        gen.mov(ecx, dword[&m_psxRegs.GPR.r[_Rs_]]);
        // gen.and_(ecx, 0x1f); Commented out cause useless, see the rest of the comments about masking
        // shift amounts
        gen.shr(eax, cl);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    }
}

void X86DynaRecCPU::recSRAV() {
    // Rd = Rt >> Rs
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);

    if (IsConst(_Rt_) && IsConst(_Rs_)) {
        MapConst(_Rd_, (int32_t)m_iRegs[_Rt_].k >> (m_iRegs[_Rs_].k & 0x1f));
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
        gen.mov(ecx, m_iRegs[_Rs_].k & 0x1f);
        gen.sar(eax, cl);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, m_iRegs[_Rt_].k);
        gen.mov(ecx, dword[&m_psxRegs.GPR.r[_Rs_]]);
        // gen.and_(ecx,0x1f);  // MIPS spec says that the shift amount is masked by 31. however this
        // happens implicitly on all x86 processors except for 8086.
        // So no need to do it manually
        gen.sar(eax, cl);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
        gen.mov(ecx, dword[&m_psxRegs.GPR.r[_Rs_]]);
        // gen.and_(ecx,0x1f);  // MIPS spec says that the shift amount is masked by 31. however this
        // happens implicitly on all x86 processors except for 8086.
        // So no need to do it manually
        gen.sar(eax, cl);
        gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
    }
}

/// eax: scratch
/// ecx: Status Register
/// ebp: PC after the exception
/// This is slightly inefficient but BREAK/Syscall are extremely uncommon so it doesn't matter.
void X86DynaRecCPU::recException(Exception e) {
    gen.push(
        (int32_t)
            m_inDelaySlot);  // Push bd parameter, promoted to int32_t to avoid bool size being implementation-defined
    gen.push(static_cast<std::underlying_type<Exception>::type>(e) << 2);  // Push exception code parameter
    gen.push(reinterpret_cast<uintptr_t>(this));                           // Push pointer to this object
    gen.mov(dword[&m_psxRegs.pc],
            m_pc - 4);              // Store address of current instruction in PC for the exception wrapper to use
    gen.call(psxExceptionWrapper);  // Call the exception wrapper function
    gen.mov(ebp, eax);              // Move the new PC to EBP.
    gen.add(esp, 12);               // Fix up stack

    m_pcInEBP = true;          // The PC after the exception is now in EBP
    m_stopRecompile = true;    // Stop compilation (without a delay slot, as exceptions have none)
    m_needsStackFrame = true;  // Since we called a C++ function, we need to set up a stack frame
}

void X86DynaRecCPU::recSYSCALL() { recException(Exception::Syscall); }

void X86DynaRecCPU::recBREAK() { recException(Exception::Break); }

void X86DynaRecCPU::recMFHI() {
    // Rd = Hi
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);

    m_iRegs[_Rd_].state = ST_UNK;
    gen.mov(eax, dword[&m_psxRegs.GPR.n.hi]);
    gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
}

void X86DynaRecCPU::recMTHI() {
    // Hi = Rs

    if (IsConst(_Rs_)) {
        gen.mov(dword[&m_psxRegs.GPR.n.hi], m_iRegs[_Rs_].k);
    } else {
        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        gen.mov(dword[&m_psxRegs.GPR.n.hi], eax);
    }
}

void X86DynaRecCPU::recMFLO() {
    // Rd = Lo
    if (!_Rd_) return;
    maybeCancelDelayedLoad(_Rd_);

    m_iRegs[_Rd_].state = ST_UNK;
    gen.mov(eax, dword[&m_psxRegs.GPR.n.lo]);
    gen.mov(dword[&m_psxRegs.GPR.r[_Rd_]], eax);
}

void X86DynaRecCPU::recMTLO() {
    // Lo = Rs

    if (IsConst(_Rs_)) {
        gen.mov(dword[&m_psxRegs.GPR.n.lo], m_iRegs[_Rs_].k);
    } else {
        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        gen.mov(dword[&m_psxRegs.GPR.n.lo], eax);
    }
}

void X86DynaRecCPU::recBLTZ() {
    // Branch if Rs < 0
    uint32_t target = _Imm_ * 4 + m_pc;

    m_nextIsDelaySlot = true;
    if (target == m_pc + 4) return;

    if (IsConst(_Rs_)) {
        if ((int32_t)m_iRegs[_Rs_].k < 0) {
            m_pcInEBP = true;
            m_stopRecompile = true;
            gen.mov(ebp, target);
        }
        return;
    }

    m_pcInEBP = true;
    m_stopRecompile = true;

    gen.mov(eax, target);                       // eax = addr if jump taken
    gen.mov(ebp, m_pc + 4);                     // ebp = addr if jump not taken
    gen.cmp(dword[&m_psxRegs.GPR.r[_Rs_]], 0);  // check if rs < 0 (signed)
    gen.cmovl(ebp, eax);                        // if so, move the jump addr into ebp
}

void X86DynaRecCPU::recBGTZ() {
    // Branch if Rs > 0
    uint32_t target = _Imm_ * 4 + m_pc;

    m_nextIsDelaySlot = true;
    if (target == m_pc + 4) return;

    if (IsConst(_Rs_)) {
        if ((int32_t)m_iRegs[_Rs_].k > 0) {
            m_pcInEBP = true;
            m_stopRecompile = true;
            gen.mov(ebp, target);
        }
        return;
    }

    m_pcInEBP = true;
    m_stopRecompile = true;

    gen.mov(eax, target);                       // eax = addr if jump taken
    gen.mov(ebp, m_pc + 4);                     // ebp = addr if jump not taken
    gen.cmp(dword[&m_psxRegs.GPR.r[_Rs_]], 0);  // check if rs > 0 (signed)
    gen.cmovg(ebp, eax);                        // if so, move the jump addr into ebp
}

void X86DynaRecCPU::recBLTZAL() {
    // Branch if Rs < 0
    uint32_t target = _Imm_ * 4 + m_pc;
    maybeCancelDelayedLoad(31);
    gen.mov(edi, m_pc + 4);  // always link, whether the branch is taken or not

    m_nextIsDelaySlot = true;
    if (IsConst(_Rs_)) {
        if ((int32_t)m_iRegs[_Rs_].k < 0) {
            m_needsStackFrame = true;
            auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
            delayedLoad.active = true;
            delayedLoad.index = 31;
            m_pcInEBP = true;
            m_stopRecompile = true;
            gen.mov(ebp, target);
        }
        return;
    }

    iFlushReg(31);
    m_needsStackFrame = true;
    auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
    delayedLoad.active = true;
    delayedLoad.index = 31;
    m_pcInEBP = true;
    m_stopRecompile = true;

    gen.mov(eax, target);                       // eax = addr if jump taken
    gen.mov(ebp, m_pc + 4);                     // ebp = addr if jump not taken
    gen.cmp(dword[&m_psxRegs.GPR.r[_Rs_]], 0);  // check if rs < 0 (signed)
    gen.cmovl(ebp, eax);                        // if so, move the jump addr into ebp
}

void X86DynaRecCPU::recBGEZAL() {
    // Branch if Rs >= 0
    uint32_t target = _Imm_ * 4 + m_pc;
    maybeCancelDelayedLoad(31);
    gen.mov(edi, m_pc + 4);  // always link, whether branch is taken or not

    m_nextIsDelaySlot = true;
    if (IsConst(_Rs_)) {
        if ((int32_t)m_iRegs[_Rs_].k >= 0) {
            m_needsStackFrame = true;
            auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
            delayedLoad.active = true;
            delayedLoad.index = 31;
            m_pcInEBP = true;
            m_stopRecompile = true;
            gen.mov(ebp, target);
        }
        return;
    }

    iFlushReg(31);
    m_needsStackFrame = true;
    auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
    delayedLoad.active = true;
    delayedLoad.index = 31;

    m_pcInEBP = true;
    m_stopRecompile = true;

    gen.mov(eax, target);                       // eax = addr if jump taken
    gen.mov(ebp, m_pc + 4);                     // ebp = addr if jump not taken
    gen.cmp(dword[&m_psxRegs.GPR.r[_Rs_]], 0);  // check if rs >= 0 (signed)
    gen.cmovge(ebp, eax);                       // if so, move the jump addr into ebp
}

void X86DynaRecCPU::recJ() {
    // j target
    uint32_t target = _Target_ * 4 + (m_pc & 0xf0000000);
    m_nextIsDelaySlot = true;
    m_stopRecompile = true;
    m_pcInEBP = true;
    gen.mov(ebp, target);
}

void X86DynaRecCPU::recJAL() {
    // jal target
    maybeCancelDelayedLoad(31);
    m_needsStackFrame = true;
    auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
    delayedLoad.active = true;
    delayedLoad.index = 31;
    gen.mov(edi, m_pc + 4);
    uint32_t target = _Target_ * 4 + (m_pc & 0xf0000000);
    m_nextIsDelaySlot = true;
    m_stopRecompile = true;
    m_pcInEBP = true;
    gen.mov(ebp, target);
}

void X86DynaRecCPU::recJR() {
    // jr Rs
    m_nextIsDelaySlot = true;
    m_stopRecompile = true;
    m_pcInEBP = true;
    if (IsConst(_Rs_)) {
        gen.mov(ebp, m_iRegs[_Rs_].k & ~3);  // force align jump address
    } else {
        gen.mov(ebp, dword[&m_psxRegs.GPR.r[_Rs_]]);
        gen.and_(ebp, ~3);  // force align jump address
    }
}

void X86DynaRecCPU::recJALR() {
    // jalr Rs
    maybeCancelDelayedLoad(_Rd_);
    m_needsStackFrame = true;
    auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
    delayedLoad.active = true;
    delayedLoad.index = _Rd_;
    gen.mov(edi, m_pc + 4);
    m_nextIsDelaySlot = true;
    m_stopRecompile = true;
    m_pcInEBP = true;
    if (IsConst(_Rs_)) {
        gen.mov(ebp, m_iRegs[_Rs_].k & ~3);  // force align jump address
    } else {
        gen.mov(ebp, dword[&m_psxRegs.GPR.r[_Rs_]]);
        gen.and_(ebp, ~3);  // force align jump address
    }
}

void X86DynaRecCPU::recBEQ() {
    // Branch if Rs == Rt
    uint32_t target = _Imm_ * 4 + m_pc;

    m_nextIsDelaySlot = true;
    if (target == m_pc + 4) return;

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        if (m_iRegs[_Rs_].k == m_iRegs[_Rt_].k) {
            m_pcInEBP = true;
            m_stopRecompile = true;
            gen.mov(ebp, target);
        }
        return;
    } else if (IsConst(_Rs_)) {
        gen.cmp(dword[&m_psxRegs.GPR.r[_Rt_]], m_iRegs[_Rs_].k);
    } else if (IsConst(_Rt_)) {
        gen.cmp(dword[&m_psxRegs.GPR.r[_Rs_]], m_iRegs[_Rt_].k);
    } else {
        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        gen.cmp(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
    }
    m_pcInEBP = true;
    m_stopRecompile = true;

    gen.mov(ecx, target);    // ecx = addr if jump taken
    gen.mov(ebp, m_pc + 4);  // ebp = addr if jump not taken
    gen.cmove(ebp, ecx);     // if the values are equal, move the jump addr into ebp
}

void X86DynaRecCPU::recBNE() {
    // Branch if Rs != Rt
    uint32_t target = _Imm_ * 4 + m_pc;

    m_nextIsDelaySlot = true;
    if (target == m_pc + 4) return;

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        if (m_iRegs[_Rs_].k != m_iRegs[_Rt_].k) {
            m_pcInEBP = true;
            m_stopRecompile = true;
            gen.mov(ebp, target);
        }
        return;
    } else if (IsConst(_Rs_)) {
        gen.cmp(dword[&m_psxRegs.GPR.r[_Rt_]], m_iRegs[_Rs_].k);
    } else if (IsConst(_Rt_)) {
        gen.cmp(dword[&m_psxRegs.GPR.r[_Rs_]], m_iRegs[_Rt_].k);
    } else {
        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rs_]]);
        gen.cmp(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
    }
    m_pcInEBP = true;
    m_stopRecompile = true;

    gen.mov(ecx, target);    // ecx = addr if jump taken
    gen.mov(ebp, m_pc + 4);  // ebp = addr if jump not taken
    gen.cmovne(ebp, ecx);    // if so, move the jump addr into ebp
}

void X86DynaRecCPU::recBLEZ() {
    // Branch if Rs <= 0
    uint32_t target = _Imm_ * 4 + m_pc;

    m_nextIsDelaySlot = true;
    if (target == m_pc + 4) return;

    if (IsConst(_Rs_)) {
        if ((int32_t)m_iRegs[_Rs_].k <= 0) {
            m_pcInEBP = true;
            m_stopRecompile = true;
            gen.mov(ebp, target);
        }
        return;
    }

    m_pcInEBP = true;
    m_stopRecompile = true;

    gen.mov(eax, target);                       // eax = addr if jump taken
    gen.mov(ebp, m_pc + 4);                     // ebp = addr if jump not taken
    gen.cmp(dword[&m_psxRegs.GPR.r[_Rs_]], 0);  // check if rs < 0 (signed)
    gen.cmovle(ebp, eax);                       // if so, move the jump addr into ebp
}

void X86DynaRecCPU::recBGEZ() {
    // Branch if Rs >= 0
    uint32_t target = _Imm_ * 4 + m_pc;

    m_nextIsDelaySlot = true;
    if (target == m_pc + 4) return;

    if (IsConst(_Rs_)) {
        if ((int32_t)m_iRegs[_Rs_].k >= 0) {
            m_pcInEBP = true;
            m_stopRecompile = true;
            gen.mov(ebp, target);
        }
        return;
    }

    m_pcInEBP = true;
    m_stopRecompile = true;

    gen.mov(eax, target);                       // eax = addr if jump taken
    gen.mov(ebp, m_pc + 4);                     // ebp = addr if jump not taken
    gen.cmp(dword[&m_psxRegs.GPR.r[_Rs_]], 0);  // check if rs < 0 (signed)
    gen.cmovge(ebp, eax);                       // if so, move the jump addr into ebp
}

void X86DynaRecCPU::recMFC0() {
    // Rt = Cop0->Rd
    if (!_Rt_) return;
    maybeCancelDelayedLoad(_Rt_);

    m_iRegs[_Rt_].state = ST_UNK;
    gen.mov(eax, dword[&m_psxRegs.CP0.r[_Rd_]]);
    gen.mov(dword[&m_psxRegs.GPR.r[_Rt_]], eax);
}

void X86DynaRecCPU::recCFC0() {
    // Rt = Cop0->Rd

    recMFC0();
}

void X86DynaRecCPU::testSWInt() {
    Label label;
    if (!m_pcInEBP) gen.mov(ebp, (uint32_t)m_pc);

    m_pcInEBP = true;
    m_stopRecompile = true;
    m_needsStackFrame = true;

    gen.mov(eax, dword[&m_psxRegs.CP0.n.Status]);
    gen.test(eax, 1);                                 // Check if interrupts are enabled
    gen.jz(label, CodeGenerator::LabelType::T_NEAR);  // If not, skip to the end

    gen.mov(edx, dword[&m_psxRegs.CP0.n.Cause]);
    gen.and_(eax, edx);
    gen.and_(eax, 0x300);                             // Check if an interrupt was force-fired
    gen.jz(label, CodeGenerator::LabelType::T_NEAR);  // Skip to the end if not

    gen.push(
        (int32_t)
            m_inDelaySlot);  // Push bd parameter, promoted to int32_t to avoid bool size being implementation-defined
    gen.push(edx);  // Push exception code parameter (This gets masked in psxException) TODO: Mask here to be safe?
    gen.push(reinterpret_cast<uintptr_t>(this));  // Push pointer to this object
    gen.mov(dword[&m_psxRegs.pc],
            m_pc - 4);              // Store address of current instruction in PC for the exception wrapper to use
    gen.call(psxExceptionWrapper);  // Call the exception wrapper function
    gen.mov(ebp, eax);              // Move the new PC to EBP.
    gen.add(esp, 12);               // Fix up stack

    gen.L(label);
}

void X86DynaRecCPU::recMTC0() {
    // Cop0->Rd = Rt

    if (IsConst(_Rt_)) {
        if (_Rd_ == 13) {
            gen.mov(dword[&m_psxRegs.CP0.n.Cause], m_iRegs[_Rt_].k & ~(0xfc00));
        } else {
            gen.mov(dword[&m_psxRegs.CP0.r[_Rd_]], m_iRegs[_Rt_].k);
        }
    } else {
        gen.mov(eax, dword[&m_psxRegs.GPR.r[_Rt_]]);
        if (_Rd_ == 13) gen.and_(eax, ~(0xfc00));
        gen.mov(dword[&m_psxRegs.CP0.r[_Rd_]], eax);
    }

    if (_Rd_ == 12 || _Rd_ == 13) testSWInt();
}

void X86DynaRecCPU::recCTC0() {
    // Cop0->Rd = Rt

    recMTC0();
}

void X86DynaRecCPU::recRFE() {
    gen.mov(eax, dword[&m_psxRegs.CP0.n.Status]);
    gen.mov(ecx, eax);
    gen.and_(eax, 0xfffffff0);
    gen.and_(ecx, 0x3c);
    gen.shr(ecx, 2);
    gen.or_(eax, ecx);
    gen.mov(dword[&m_psxRegs.CP0.n.Status], eax);
    testSWInt();
}

const func_t X86DynaRecCPU::m_recBSC[64] = {
    &X86DynaRecCPU::recSPECIAL, &X86DynaRecCPU::recREGIMM, &X86DynaRecCPU::recJ,    &X86DynaRecCPU::recJAL,    // 00
    &X86DynaRecCPU::recBEQ,     &X86DynaRecCPU::recBNE,    &X86DynaRecCPU::recBLEZ, &X86DynaRecCPU::recBGTZ,   // 04
    &X86DynaRecCPU::recADDI,    &X86DynaRecCPU::recADDIU,  &X86DynaRecCPU::recSLTI, &X86DynaRecCPU::recSLTIU,  // 08
    &X86DynaRecCPU::recANDI,    &X86DynaRecCPU::recORI,    &X86DynaRecCPU::recXORI, &X86DynaRecCPU::recLUI,    // 0c
    &X86DynaRecCPU::recCOP0,    &X86DynaRecCPU::recNULL,   &X86DynaRecCPU::recCOP2, &X86DynaRecCPU::recNULL,   // 10
    &X86DynaRecCPU::recNULL,    &X86DynaRecCPU::recNULL,   &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,   // 14
    &X86DynaRecCPU::recNULL,    &X86DynaRecCPU::recNULL,   &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,   // 18
    &X86DynaRecCPU::recNULL,    &X86DynaRecCPU::recNULL,   &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,   // 1c
    &X86DynaRecCPU::recLB,      &X86DynaRecCPU::recLH,     &X86DynaRecCPU::recLWL,  &X86DynaRecCPU::recLW,     // 20
    &X86DynaRecCPU::recLBU,     &X86DynaRecCPU::recLHU,    &X86DynaRecCPU::recLWR,  &X86DynaRecCPU::recNULL,   // 24
    &X86DynaRecCPU::recSB,      &X86DynaRecCPU::recSH,     &X86DynaRecCPU::recSWL,  &X86DynaRecCPU::recSW,     // 28
    &X86DynaRecCPU::recNULL,    &X86DynaRecCPU::recNULL,   &X86DynaRecCPU::recSWR,  &X86DynaRecCPU::recNULL,   // 2c
    &X86DynaRecCPU::recNULL,    &X86DynaRecCPU::recNULL,   &X86DynaRecCPU::recLWC2, &X86DynaRecCPU::recNULL,   // 30
    &X86DynaRecCPU::recNULL,    &X86DynaRecCPU::recNULL,   &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,   // 34
    &X86DynaRecCPU::recNULL,    &X86DynaRecCPU::recNULL,   &X86DynaRecCPU::recSWC2, &X86DynaRecCPU::recNULL,   // 38
    &X86DynaRecCPU::recNULL,    &X86DynaRecCPU::recNULL,   &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,   // 3c
};

const func_t X86DynaRecCPU::m_recSPC[64] = {
    &X86DynaRecCPU::recSLL,     &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recSRL,  &X86DynaRecCPU::recSRA,   // 00
    &X86DynaRecCPU::recSLLV,    &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recSRLV, &X86DynaRecCPU::recSRAV,  // 04
    &X86DynaRecCPU::recJR,      &X86DynaRecCPU::recJALR,  &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 08
    &X86DynaRecCPU::recSYSCALL, &X86DynaRecCPU::recBREAK, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 0c
    &X86DynaRecCPU::recMFHI,    &X86DynaRecCPU::recMTHI,  &X86DynaRecCPU::recMFLO, &X86DynaRecCPU::recMTLO,  // 10
    &X86DynaRecCPU::recNULL,    &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 14
    &X86DynaRecCPU::recMULT,    &X86DynaRecCPU::recMULTU, &X86DynaRecCPU::recDIV,  &X86DynaRecCPU::recDIVU,  // 18
    &X86DynaRecCPU::recNULL,    &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 1c
    &X86DynaRecCPU::recADD,     &X86DynaRecCPU::recADDU,  &X86DynaRecCPU::recSUB,  &X86DynaRecCPU::recSUBU,  // 20
    &X86DynaRecCPU::recAND,     &X86DynaRecCPU::recOR,    &X86DynaRecCPU::recXOR,  &X86DynaRecCPU::recNOR,   // 24
    &X86DynaRecCPU::recNULL,    &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recSLT,  &X86DynaRecCPU::recSLTU,  // 28
    &X86DynaRecCPU::recNULL,    &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 2c
    &X86DynaRecCPU::recNULL,    &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 30
    &X86DynaRecCPU::recNULL,    &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 34
    &X86DynaRecCPU::recNULL,    &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 38
    &X86DynaRecCPU::recNULL,    &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 3c
};

const func_t X86DynaRecCPU::m_recREG[32] = {
    &X86DynaRecCPU::recBLTZ,   &X86DynaRecCPU::recBGEZ,   &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 00
    &X86DynaRecCPU::recNULL,   &X86DynaRecCPU::recNULL,   &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 04
    &X86DynaRecCPU::recNULL,   &X86DynaRecCPU::recNULL,   &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 08
    &X86DynaRecCPU::recNULL,   &X86DynaRecCPU::recNULL,   &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 0c
    &X86DynaRecCPU::recBLTZAL, &X86DynaRecCPU::recBGEZAL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 10
    &X86DynaRecCPU::recNULL,   &X86DynaRecCPU::recNULL,   &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 14
    &X86DynaRecCPU::recNULL,   &X86DynaRecCPU::recNULL,   &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 18
    &X86DynaRecCPU::recNULL,   &X86DynaRecCPU::recNULL,   &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 1c
};

const func_t X86DynaRecCPU::m_recCP0[32] = {
    &X86DynaRecCPU::recMFC0, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recCFC0, &X86DynaRecCPU::recNULL,  // 00
    &X86DynaRecCPU::recMTC0, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recCTC0, &X86DynaRecCPU::recNULL,  // 04
    &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 08
    &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 0c
    &X86DynaRecCPU::recRFE,  &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 10
    &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 14
    &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 18
    &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 1c
};

const func_t X86DynaRecCPU::m_recCP2[64] = {
    &X86DynaRecCPU::recBASIC, &X86DynaRecCPU::recRTPS,  &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL,  // 00
    &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNCLIP, &X86DynaRecCPU::recNULL,  // 04
    &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL,  // 08
    &X86DynaRecCPU::recOP,    &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL,  // 0c
    &X86DynaRecCPU::recDPCS,  &X86DynaRecCPU::recINTPL, &X86DynaRecCPU::recMVMVA, &X86DynaRecCPU::recNCDS,  // 10
    &X86DynaRecCPU::recCDP,   &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNCDT,  &X86DynaRecCPU::recNULL,  // 14
    &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNCCS,  // 18
    &X86DynaRecCPU::recCC,    &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNCS,   &X86DynaRecCPU::recNULL,  // 1c
    &X86DynaRecCPU::recNCT,   &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL,  // 20
    &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL,  // 24
    &X86DynaRecCPU::recSQR,   &X86DynaRecCPU::recDCPL,  &X86DynaRecCPU::recDPCT,  &X86DynaRecCPU::recNULL,  // 28
    &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recAVSZ3, &X86DynaRecCPU::recAVSZ4, &X86DynaRecCPU::recNULL,  // 2c
    &X86DynaRecCPU::recRTPT,  &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL,  // 30
    &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL,  // 34
    &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recNULL,  // 38
    &X86DynaRecCPU::recNULL,  &X86DynaRecCPU::recGPF,   &X86DynaRecCPU::recGPL,   &X86DynaRecCPU::recNCCT,  // 3c
};

const func_t X86DynaRecCPU::m_recCP2BSC[32] = {
    &X86DynaRecCPU::recMFC2, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recCFC2, &X86DynaRecCPU::recNULL,  // 00
    &X86DynaRecCPU::recMTC2, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recCTC2, &X86DynaRecCPU::recNULL,  // 04
    &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 08
    &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 0c
    &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 10
    &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 14
    &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 18
    &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL, &X86DynaRecCPU::recNULL,  // 1c
};

// Trace all functions using PGXP
const func_t X86DynaRecCPU::m_pgxpRecBSC[64] = {
    &X86DynaRecCPU::recSPECIAL,  &X86DynaRecCPU::recREGIMM,     // 00
    &X86DynaRecCPU::recJ,        &X86DynaRecCPU::recJAL,        // 02
    &X86DynaRecCPU::recBEQ,      &X86DynaRecCPU::recBNE,        // 04
    &X86DynaRecCPU::recBLEZ,     &X86DynaRecCPU::recBGTZ,       // 06
    &X86DynaRecCPU::pgxpRecADDI, &X86DynaRecCPU::pgxpRecADDIU,  // 08
    &X86DynaRecCPU::pgxpRecSLTI, &X86DynaRecCPU::pgxpRecSLTIU,  // 0a
    &X86DynaRecCPU::pgxpRecANDI, &X86DynaRecCPU::pgxpRecORI,    // 0c
    &X86DynaRecCPU::pgxpRecXORI, &X86DynaRecCPU::pgxpRecLUI,    // 0e
    &X86DynaRecCPU::recCOP0,     &X86DynaRecCPU::recNULL,       // 10
    &X86DynaRecCPU::recCOP2,     &X86DynaRecCPU::recNULL,       // 12
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 14
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 16
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 18
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 1a
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 1c
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 1e
    &X86DynaRecCPU::pgxpRecLB,   &X86DynaRecCPU::pgxpRecLH,     // 20
    &X86DynaRecCPU::pgxpRecLWL,  &X86DynaRecCPU::pgxpRecLW,     // 22
    &X86DynaRecCPU::pgxpRecLBU,  &X86DynaRecCPU::pgxpRecLHU,    // 24
    &X86DynaRecCPU::pgxpRecLWR,  &X86DynaRecCPU::recNULL,       // 26
    &X86DynaRecCPU::pgxpRecSB,   &X86DynaRecCPU::pgxpRecSH,     // 28
    &X86DynaRecCPU::pgxpRecSWL,  &X86DynaRecCPU::pgxpRecSW,     // 2a
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 2c
    &X86DynaRecCPU::pgxpRecSWR,  &X86DynaRecCPU::recNULL,       // 2e
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 30
    &X86DynaRecCPU::pgxpRecLWC2, &X86DynaRecCPU::recNULL,       // 32
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 34
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 36
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 38
    &X86DynaRecCPU::pgxpRecSWC2, &X86DynaRecCPU::recNULL,       // 3a
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 3c
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 3e
};

const func_t X86DynaRecCPU::m_pgxpRecSPC[64] = {
    &X86DynaRecCPU::pgxpRecSLL,  &X86DynaRecCPU::recNULL,       // 00
    &X86DynaRecCPU::pgxpRecSRL,  &X86DynaRecCPU::pgxpRecSRA,    // 02
    &X86DynaRecCPU::pgxpRecSLLV, &X86DynaRecCPU::recNULL,       // 04
    &X86DynaRecCPU::pgxpRecSRLV, &X86DynaRecCPU::pgxpRecSRAV,   // 06
    &X86DynaRecCPU::recJR,       &X86DynaRecCPU::recJALR,       // 08
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 0a
    &X86DynaRecCPU::recSYSCALL,  &X86DynaRecCPU::recBREAK,      // 0c
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 0e
    &X86DynaRecCPU::pgxpRecMFHI, &X86DynaRecCPU::pgxpRecMTHI,   // 10
    &X86DynaRecCPU::pgxpRecMFLO, &X86DynaRecCPU::pgxpRecMTLO,   // 12
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 14
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 16
    &X86DynaRecCPU::pgxpRecMULT, &X86DynaRecCPU::pgxpRecMULTU,  // 18
    &X86DynaRecCPU::pgxpRecDIV,  &X86DynaRecCPU::pgxpRecDIVU,   // 1a
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 1c
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 1e
    &X86DynaRecCPU::pgxpRecADD,  &X86DynaRecCPU::pgxpRecADDU,   // 20
    &X86DynaRecCPU::pgxpRecSUB,  &X86DynaRecCPU::pgxpRecSUBU,   // 22
    &X86DynaRecCPU::pgxpRecAND,  &X86DynaRecCPU::pgxpRecOR,     // 24
    &X86DynaRecCPU::pgxpRecXOR,  &X86DynaRecCPU::pgxpRecNOR,    // 26
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 28
    &X86DynaRecCPU::pgxpRecSLT,  &X86DynaRecCPU::pgxpRecSLTU,   // 2a
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 2c
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 2e
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 30
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 32
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 34
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 36
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 38
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 3a
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 3c
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,       // 3e
};

const func_t X86DynaRecCPU::m_pgxpRecCP0[32] = {
    &X86DynaRecCPU::pgxpRecMFC0, &X86DynaRecCPU::recNULL,  // 00
    &X86DynaRecCPU::pgxpRecCFC0, &X86DynaRecCPU::recNULL,  // 02
    &X86DynaRecCPU::pgxpRecMTC0, &X86DynaRecCPU::recNULL,  // 04
    &X86DynaRecCPU::pgxpRecCTC0, &X86DynaRecCPU::recNULL,  // 06
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,  // 08
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,  // 0a
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,  // 0c
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,  // 0e
    &X86DynaRecCPU::pgxpRecRFE,  &X86DynaRecCPU::recNULL,  // 10
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,  // 12
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,  // 14
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,  // 16
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,  // 18
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,  // 1a
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,  // 1c
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,  // 1e
};

const func_t X86DynaRecCPU::m_pgxpRecCP2BSC[32] = {
    &X86DynaRecCPU::pgxpRecMFC2, &X86DynaRecCPU::recNULL,  // 00
    &X86DynaRecCPU::pgxpRecCFC2, &X86DynaRecCPU::recNULL,  // 02
    &X86DynaRecCPU::pgxpRecMTC2, &X86DynaRecCPU::recNULL,  // 04
    &X86DynaRecCPU::pgxpRecCTC2, &X86DynaRecCPU::recNULL,  // 06
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,  // 08
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,  // 0a
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,  // 0c
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,  // 0e
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,  // 10
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,  // 12
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,  // 14
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,  // 16
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,  // 18
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,  // 1a
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,  // 1c
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,  // 1e
};

// Trace memory functions only
const func_t X86DynaRecCPU::m_pgxpRecBSCMem[64] = {
    &X86DynaRecCPU::recSPECIAL,  &X86DynaRecCPU::recREGIMM,   // 00
    &X86DynaRecCPU::recJ,        &X86DynaRecCPU::recJAL,      // 02
    &X86DynaRecCPU::recBEQ,      &X86DynaRecCPU::recBNE,      // 04
    &X86DynaRecCPU::recBLEZ,     &X86DynaRecCPU::recBGTZ,     // 06
    &X86DynaRecCPU::recADDI,     &X86DynaRecCPU::recADDIU,    // 08
    &X86DynaRecCPU::recSLTI,     &X86DynaRecCPU::recSLTIU,    // 0a
    &X86DynaRecCPU::recANDI,     &X86DynaRecCPU::recORI,      // 0c
    &X86DynaRecCPU::recXORI,     &X86DynaRecCPU::recLUI,      // 0e
    &X86DynaRecCPU::recCOP0,     &X86DynaRecCPU::recNULL,     // 10
    &X86DynaRecCPU::recCOP2,     &X86DynaRecCPU::recNULL,     // 12
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,     // 14
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,     // 16
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,     // 18
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,     // 1a
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,     // 1c
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,     // 1e
    &X86DynaRecCPU::pgxpRecLB,   &X86DynaRecCPU::pgxpRecLH,   // 20
    &X86DynaRecCPU::pgxpRecLWL,  &X86DynaRecCPU::pgxpRecLW,   // 22
    &X86DynaRecCPU::pgxpRecLBU,  &X86DynaRecCPU::pgxpRecLHU,  // 24
    &X86DynaRecCPU::pgxpRecLWR,  &X86DynaRecCPU::recNULL,     // 26
    &X86DynaRecCPU::pgxpRecSB,   &X86DynaRecCPU::pgxpRecSH,   // 28
    &X86DynaRecCPU::pgxpRecSWL,  &X86DynaRecCPU::pgxpRecSW,   // 2a
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,     // 2c
    &X86DynaRecCPU::pgxpRecSWR,  &X86DynaRecCPU::recNULL,     // 2e
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,     // 30
    &X86DynaRecCPU::pgxpRecLWC2, &X86DynaRecCPU::recNULL,     // 32
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,     // 34
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,     // 36
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,     // 38
    &X86DynaRecCPU::pgxpRecSWC2, &X86DynaRecCPU::recNULL,     // 3a
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,     // 3c
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,     // 3e
};

void X86DynaRecCPU::recRecompile() {
    /* if the code buffer reached the mem limit reset whole mem */
    if (gen.getSize() >= RECMEM_SIZE) {
        flushCache();
    } else {
        gen.align(32);
    }

    m_pc = m_psxRegs.pc;
    uint32_t old_pc = m_pc;
    const auto startPtr = (uintptr_t)gen.getCurr();

    (*(uintptr_t *)PC_REC(m_pc)) = startPtr;
    m_needsStackFrame = false;
    m_pcInEBP = false;
    m_nextIsDelaySlot = false;
    m_inDelaySlot = false;
    m_stopRecompile = false;
    m_currentDelayedLoad = 0;
    m_delayedLoadInfo[0].active = false;
    m_delayedLoadInfo[1].active = false;
    unsigned count = 0;

    // Set up stack frame.
    // If our block doesn't require one, this will be emitted, but the block address will be adjusted so it won't be
    // executed
    gen.push(ebp);
    gen.push(ebx);
    gen.xor_(ebx, ebx);
    gen.push(esi);
    gen.push(edi);
    const auto endStackFramePtr = (uintptr_t)gen.getCurr();
    handleKernelCall();  // Emit extra code if this is one of the kernel call vectors

    auto shouldContinue = [&]() {
        if (m_nextIsDelaySlot) {
            return true;
        }
        if (m_stopRecompile) {
            return false;
        }
        if (count >= DYNAREC_BLOCK && !m_delayedLoadInfo[0].active && !m_delayedLoadInfo[1].active) {
            return false;
        }
        return true;
    };

    auto processDelayedLoad = [&]() {
        m_currentDelayedLoad ^= 1;
        auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
        if (delayedLoad.active) {
            delayedLoad.active = false;
            const unsigned index = delayedLoad.index;
            gen.movzx(edx, bx);  // edx = ebx & 0xFFFF
            gen.mov(eax, dword[(uint32_t)MASKS + edx * 4]);
            if (IsConst(index)) {
                gen.and_(eax, m_iRegs[index].k);
                gen.or_(eax, esi);
                gen.mov(dword[&m_psxRegs.GPR.r[index]], eax);
                m_iRegs[index].state = ST_UNK;
            } else {
                gen.and_(dword[&m_psxRegs.GPR.r[index]], eax);
                gen.or_(dword[&m_psxRegs.GPR.r[index]], esi);
            }
        }
    };

    while (shouldContinue()) {
        m_inDelaySlot = m_nextIsDelaySlot;
        m_nextIsDelaySlot = false;

        const auto p = (uint8_t *)PSXM(m_pc);
        if (p == nullptr) {
            recError();
            return;
        }
        m_psxRegs.code = *(uint32_t *)p;
        m_pc += 4;
        count++;
        func_t func = m_pRecBSC[m_psxRegs.code >> 26];
        (*this.*func)();

        const bool isOtherActive = m_delayedLoadInfo[m_currentDelayedLoad].active;
        processDelayedLoad();
        if (isOtherActive) {
            gen.mov(esi, edi);
            gen.shr(ebx, 16);
        }
    }

    // This is slightly inexact: if there's a delayed load in the delay slot of a branch,
    // then we're flushing it early, before the next instruction had a chance to execute.
    // This might be fine still, but it can be arranged if needed.
    processDelayedLoad();

    iFlushRegs();
    gen.add(dword[&m_psxRegs.cycle], count * PCSX::Emulator::BIAS);

    if (m_pcInEBP) {
        gen.mov(eax, ebp);
    } else {
        gen.mov(eax, m_pc);
    }

    if (m_needsStackFrame || m_pcInEBP) {
        gen.pop(edi);
        gen.pop(esi);
        gen.pop(ebx);
        gen.pop(ebp);
        gen.ret();
    } else {
        const uintptr_t count = endStackFramePtr - startPtr;
        (*(uintptr_t *)PC_REC(old_pc)) = endStackFramePtr;
        gen.nop(count);
        gen.ret();
    }
}

void X86DynaRecCPU::SetPGXPMode(uint32_t pgxpMode) {
    switch (pgxpMode) {
        case 0:  // PGXP_MODE_DISABLED:
            m_pRecBSC = m_recBSC;
            m_pRecSPC = m_recSPC;
            m_pRecREG = m_recREG;
            m_pRecCP0 = m_recCP0;
            m_pRecCP2 = m_recCP2;
            m_pRecCP2BSC = m_recCP2BSC;
            break;
        case 1:  // PGXP_MODE_MEM:
            m_pRecBSC = m_pgxpRecBSCMem;
            m_pRecSPC = m_recSPC;
            m_pRecREG = m_recREG;
            m_pRecCP0 = m_pgxpRecCP0;
            m_pRecCP2 = m_recCP2;
            m_pRecCP2BSC = m_pgxpRecCP2BSC;
            break;
        case 2:  // PGXP_MODE_FULL:
            m_pRecBSC = m_pgxpRecBSC;
            m_pRecSPC = m_pgxpRecSPC;
            m_pRecREG = m_recREG;
            m_pRecCP0 = m_pgxpRecCP0;
            m_pRecCP2 = m_recCP2;
            m_pRecCP2BSC = m_pgxpRecCP2BSC;
            break;
    }

    // reset to ensure new func tables are used
    Reset();
}

#else

class X86DynaRecCPU : public PCSX::R3000Acpu {
  public:
    X86DynaRecCPU() : R3000Acpu("x86 DynaRec") {}
    virtual bool Implemented() final { return false; }
    virtual bool Init() final { return false; }
    virtual void Reset() final { abort(); }
    virtual void Execute() final { abort(); }
    virtual void Clear(uint32_t Addr, uint32_t Size) final { abort(); }
    virtual void Shutdown() final { abort(); }
    virtual void SetPGXPMode(uint32_t pgxpMode) final { abort(); }
    virtual bool isDynarec() final { abort(); }
};

#endif

}  // namespace

std::unique_ptr<PCSX::R3000Acpu> PCSX::Cpus::getX86DynaRec() {
    return std::unique_ptr<PCSX::R3000Acpu>(new X86DynaRecCPU());
}
