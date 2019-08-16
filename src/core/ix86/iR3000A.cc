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

#ifndef _WIN32
#include <sys/mman.h>
#ifndef MAP_ANONYMOUS
#ifdef MAP_ANON
#define MAP_ANONYMOUS MAP_ANON
#endif
#endif
#endif

#include "core/debug.h"
#include "core/disr3000a.h"
#include "core/gpu.h"
#include "core/gte.h"
#include "core/ix86/ix86.h"
#include "core/pgxp_cpu.h"
#include "core/pgxp_debug.h"
#include "core/pgxp_gte.h"
#include "core/psxemulator.h"
#include "core/r3000a.h"
#include "core/system.h"
#include "spu/interface.h"

namespace {

#if defined(__i386__) || defined(_M_IX86)

class X86DynaRecCPU;

typedef void (X86DynaRecCPU::*func_t)();
typedef const func_t cfunc_t;

uint8_t psxMemRead8Wrapper(uint32_t mem) { return PCSX::g_emulator.m_psxMem->psxMemRead8(mem); }
uint16_t psxMemRead16Wrapper(uint32_t mem) { return PCSX::g_emulator.m_psxMem->psxMemRead16(mem); }
uint32_t psxMemRead32Wrapper(uint32_t mem) { return PCSX::g_emulator.m_psxMem->psxMemRead32(mem); }
void psxMemWrite8Wrapper(uint32_t mem, uint8_t value) { PCSX::g_emulator.m_psxMem->psxMemWrite8(mem, value); }
void psxMemWrite16Wrapper(uint32_t mem, uint16_t value) { PCSX::g_emulator.m_psxMem->psxMemWrite16(mem, value); }
void psxMemWrite32Wrapper(uint32_t mem, uint32_t value) { PCSX::g_emulator.m_psxMem->psxMemWrite32(mem, value); }
uint32_t psxRcntRcountWrapper(uint32_t index) { return PCSX::g_emulator.m_psxCounters->psxRcntRcount(index); }
uint32_t psxRcntRmodeWrapper(uint32_t index) { return PCSX::g_emulator.m_psxCounters->psxRcntRmode(index); }
uint32_t psxRcntRtargetWrapper(uint32_t index) { return PCSX::g_emulator.m_psxCounters->psxRcntRtarget(index); }

unsigned long GPU_readDataWrapper() { return PCSX::g_emulator.m_gpu->readData(); }
unsigned long GPU_readStatusWrapper() { return PCSX::g_emulator.m_gpu->readStatus(); }
void GPU_writeDataWrapper(uint32_t gdata) { PCSX::g_emulator.m_gpu->writeData(gdata); }
void GPU_writeStatusWrapper(unsigned long gdata) { PCSX::g_emulator.m_gpu->writeStatus(gdata); }

unsigned short SPUreadRegisterWrapper(unsigned long addr) { return PCSX::g_emulator.m_spu->readRegister(addr); }
void SPUwriteRegisterWrapper(unsigned long addr, unsigned short value) {
    PCSX::g_emulator.m_spu->writeRegister(addr, value);
}

class X86DynaRecCPU : public PCSX::R3000Acpu {
    inline uintptr_t PC_REC(uint32_t addr) {
        uintptr_t base = m_psxRecLUT[addr >> 16];
        uint32_t offset = addr & 0xffff;
        return base + offset;
    }
    inline bool IsPcValid(uint32_t addr) { return m_psxRecLUT[addr >> 16]; }
    inline bool IsConst(unsigned reg) { return m_iRegs[reg].state == ST_CONST; }
    inline bool Implemented() final { return true; }

  public:
    X86DynaRecCPU() : R3000Acpu("x86 DynaRec") {}

  private:
    virtual bool Init() final;
    virtual void Reset() final;
    virtual void Execute() final;
    virtual void ExecuteHLEBlock() final;
    virtual void Clear(uint32_t Addr, uint32_t Size) final;
    virtual void Shutdown() final;
    virtual void SetPGXPMode(uint32_t pgxpMode) final;

    static void recClearWrapper(X86DynaRecCPU *that, uint32_t a, uint32_t s) { that->Clear(a, s); }

    PCSX::ix86 gen;

    uintptr_t *m_psxRecLUT;
    static const size_t RECMEM_SIZE = 8 * 1024 * 1024;

    int8_t *m_recMem; /* the recompiled blocks will be here */
    char *m_recRAM;   /* and the s_ptr to the blocks here */
    char *m_recROM;   /* and here */

    uint32_t m_pc; /* recompiler pc */

    bool m_needsStackFrame;
    bool m_pcInEBP;
    bool m_stopRecompile;

    uint32_t m_functionPtr;
    uint32_t m_arg1;
    uint32_t m_arg2;

    enum iRegState { ST_UNK = 0, ST_CONST = 1 };

    typedef struct {
        uint32_t k;
        iRegState state;
    } iRegisters;

    iRegisters m_iRegs[32];
    iRegisters m_iRegsSaved[32];

    cfunc_t *m_pRecBSC = NULL;
    cfunc_t *m_pRecSPC = NULL;
    cfunc_t *m_pRecREG = NULL;
    cfunc_t *m_pRecCP0 = NULL;
    cfunc_t *m_pRecCP2 = NULL;
    cfunc_t *m_pRecCP2BSC = NULL;

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
    void recHLE();

    void testSWInt();

    void recRecompile();

    static uint32_t gteMFC2Wrapper() { return PCSX::g_emulator.m_gte->MFC2(); }
    static uint32_t gteCFC2Wrapper() { return PCSX::g_emulator.m_gte->CFC2(); }
    void recMFC2() {
        gen.MOV32ItoM((uint32_t)&m_psxRegs.code, (uint32_t)m_psxRegs.code);
        gen.CALLFunc((uint32_t)gteMFC2Wrapper);
        gen.MOV32RtoR(PCSX::ix86::EDI, PCSX::ix86::EAX);
        m_needsStackFrame = true;
        auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
        delayedLoad.active = true;
        delayedLoad.index = _Rt_;
    }
    void recCFC2() {
        gen.MOV32ItoM((uint32_t)&m_psxRegs.code, (uint32_t)m_psxRegs.code);
        gen.CALLFunc((uint32_t)gteCFC2Wrapper);
        gen.MOV32RtoR(PCSX::ix86::EDI, PCSX::ix86::EAX);
        m_needsStackFrame = true;
        auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
        delayedLoad.active = true;
        delayedLoad.index = _Rt_;
    }

#define CP2_FUNC(f)                                                         \
    static void gte##f##Wrapper() { PCSX::g_emulator.m_gte->f(); }          \
    void rec##f() {                                                         \
        iFlushRegs();                                                       \
        gen.MOV32ItoM((uint32_t)&m_psxRegs.code, (uint32_t)m_psxRegs.code); \
        gen.CALLFunc((uint32_t)gte##f##Wrapper);                            \
        /*  branch = 2; */                                                  \
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
#define PGXP_DBG_OP_E(op)    \
    gen.PUSH32I(DBG_E_##op); \
    gen.ADD32ItoR(PCSX::ix86::ESP, 4);
#else
#define PGXP_REC_FUNC_OP(pu, op, nReg) PGXP_##pu##_##op
#define PGXP_DBG_OP_E(op)
#endif

#define PGXP_REC_FUNC_PASS(pu, op) \
    void pgxpRec##op() { rec##op(); }

#define PGXP_REC_FUNC(pu, op)                               \
    void pgxpRec##op() {                                    \
        gen.PUSH32I(m_psxRegs.code);                        \
        PGXP_DBG_OP_E(op)                                   \
        gen.CALLFunc((uint32_t)PGXP_REC_FUNC_OP(pu, op, )); \
        gen.ADD32ItoR(PCSX::ix86::ESP, 4);                  \
        rec##op();                                          \
    }

#define PGXP_REC_FUNC_1(pu, op, reg1)                        \
    void pgxpRec##op() {                                     \
        reg1;                                                \
        gen.PUSH32I(m_psxRegs.code);                         \
        PGXP_DBG_OP_E(op)                                    \
        gen.CALLFunc((uint32_t)PGXP_REC_FUNC_OP(pu, op, 1)); \
        gen.ADD32ItoR(PCSX::ix86::ESP, 8);                   \
        rec##op();                                           \
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
        gen.PUSH32I(m_psxRegs.code);                                  \
        PGXP_DBG_OP_E(op)                                             \
        gen.CALLFunc((uint32_t)PGXP_REC_FUNC_OP(pu, op, nReg));       \
        gen.ADD32ItoR(PCSX::ix86::ESP, (4 * nReg) + 4);               \
    }

#define PGXP_REC_FUNC_2(pu, op, reg1, reg2)                  \
    void pgxpRec##op() {                                     \
        reg1;                                                \
        reg2;                                                \
        gen.PUSH32I(m_psxRegs.code);                         \
        PGXP_DBG_OP_E(op)                                    \
        gen.CALLFunc((uint32_t)PGXP_REC_FUNC_OP(pu, op, 2)); \
        gen.ADD32ItoR(PCSX::ix86::ESP, 12);                  \
        rec##op();                                           \
    }

#define PGXP_REC_FUNC_ADDR_1(pu, op, reg1)                                    \
    void pgxpRec##op() {                                                      \
        if (IsConst(_Rs_)) {                                                  \
            gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k + _Imm_);          \
        } else {                                                              \
            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]); \
            if (_Imm_) {                                                      \
                gen.ADD32ItoR(PCSX::ix86::EAX, _Imm_);                        \
            }                                                                 \
        }                                                                     \
        gen.MOV32RtoM((uint32_t)&m_tempAddr, PCSX::ix86::EAX);                \
        rec##op();                                                            \
        gen.PUSH32M((uint32_t)&m_tempAddr);                                   \
        reg1;                                                                 \
        gen.PUSH32I(m_psxRegs.code);                                          \
        PGXP_DBG_OP_E(op)                                                     \
        gen.CALLFunc((uint32_t)PGXP_REC_FUNC_OP(pu, op, 2));                  \
        gen.ADD32ItoR(PCSX::ix86::ESP, 12);                                   \
    }

#define CPU_REG_NC(idx) gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[idx])

#define CPU_REG(idx)                                    \
    if (IsConst(idx))                                   \
        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[idx].k); \
    else                                                \
        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[idx]);

#define CP0_REG(idx) gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.CP0.r[idx])
#define GTE_DATA_REG(idx) gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.CP2D.r[idx])
#define GTE_CTRL_REG(idx) gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.CP2C.r[idx])

#define PGXP_REC_FUNC_R1_1(pu, op, test, reg1, reg2)           \
    void pgxpRec##op() {                                       \
        if (test) {                                            \
            rec##op();                                         \
            return;                                            \
        }                                                      \
        reg1;                                                  \
        gen.MOV32RtoM((uint32_t)&m_tempReg1, PCSX::ix86::EAX); \
        rec##op();                                             \
        gen.PUSH32M((uint32_t)&m_tempReg1);                    \
        reg2;                                                  \
        gen.PUSH32I(m_psxRegs.code);                           \
        PGXP_DBG_OP_E(op)                                      \
        gen.CALLFunc((uint32_t)PGXP_REC_FUNC_OP(pu, op, 2));   \
        gen.ADD32ItoR(PCSX::ix86::ESP, 12);                    \
    }

#define PGXP_REC_FUNC_R2_1(pu, op, test, reg1, reg2, reg3)     \
    void pgxpRec##op() {                                       \
        if (test) {                                            \
            rec##op();                                         \
            return;                                            \
        }                                                      \
        reg1;                                                  \
        gen.MOV32RtoM((uint32_t)&m_tempReg1, PCSX::ix86::EAX); \
        reg2;                                                  \
        gen.MOV32RtoM((uint32_t)&m_tempReg2, PCSX::ix86::EAX); \
        rec##op();                                             \
        gen.PUSH32M((uint32_t)&m_tempReg1);                    \
        gen.PUSH32M((uint32_t)&m_tempReg2);                    \
        reg3;                                                  \
        gen.PUSH32I(m_psxRegs.code);                           \
        PGXP_DBG_OP_E(op)                                      \
        gen.CALLFunc((uint32_t)PGXP_REC_FUNC_OP(pu, op, 3));   \
        gen.ADD32ItoR(PCSX::ix86::ESP, 16);                    \
    }

#define PGXP_REC_FUNC_R2_2(pu, op, test, reg1, reg2, reg3, reg4) \
    void pgxpRec##op() {                                         \
        if (test) {                                              \
            rec##op();                                           \
            return;                                              \
        }                                                        \
        reg1;                                                    \
        gen.MOV32RtoM((uint32_t)&m_tempReg1, PCSX::ix86::EAX);   \
        reg2;                                                    \
        gen.MOV32RtoM((uint32_t)&m_tempReg2, PCSX::ix86::EAX);   \
        rec##op();                                               \
        gen.PUSH32M((uint32_t)&m_tempReg1);                      \
        gen.PUSH32M((uint32_t)&m_tempReg2);                      \
        reg3;                                                    \
        reg4;                                                    \
        gen.PUSH32I(m_psxRegs.code);                             \
        PGXP_DBG_OP_E(op)                                        \
        gen.CALLFunc((uint32_t)PGXP_REC_FUNC_OP(pu, op, 4));     \
        gen.ADD32ItoR(PCSX::ix86::ESP, 20);                      \
    }

    //#define PGXP_REC_FUNC_R1i_1(pu, op, test, reg1, reg2) \
// void pgxpRec##op()   \
//{ \
//  if(test) { rec##op(); return; }\
//  if (IsConst(reg1))  \
//      gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[reg1].k);    \
//  else\
//      gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[reg1]);\
//  gen.MOV32RtoM((uint32_t)&gTempReg, PCSX::ix86::EAX);\
//  rec##op();\
//  gen.PUSH32M((uint32_t)&gTempReg);\
//  reg2;\
//  gen.PUSH32I(m_psxRegs.code);    \
//  gen.CALLFunc((uint32_t)PGXP_REC_FUNC_OP(pu, op, 2)); \
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
    PGXP_REC_FUNC_R2_2(CPU, MULT, 0, CPU_REG(_Rt_), CPU_REG(_Rs_), gen.PUSH32M((uint32_t)&m_psxRegs.GPR.n.lo),
                       gen.PUSH32M((uint32_t)&m_psxRegs.GPR.n.hi))
    PGXP_REC_FUNC_R2_2(CPU, MULTU, 0, CPU_REG(_Rt_), CPU_REG(_Rs_), gen.PUSH32M((uint32_t)&m_psxRegs.GPR.n.lo),
                       gen.PUSH32M((uint32_t)&m_psxRegs.GPR.n.hi))
    PGXP_REC_FUNC_R2_2(CPU, DIV, 0, CPU_REG(_Rt_), CPU_REG(_Rs_), gen.PUSH32M((uint32_t)&m_psxRegs.GPR.n.lo),
                       gen.PUSH32M((uint32_t)&m_psxRegs.GPR.n.hi))
    PGXP_REC_FUNC_R2_2(CPU, DIVU, 0, CPU_REG(_Rt_), CPU_REG(_Rs_), gen.PUSH32M((uint32_t)&m_psxRegs.GPR.n.lo),
                       gen.PUSH32M((uint32_t)&m_psxRegs.GPR.n.hi))

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
    PGXP_REC_FUNC_R1_1(CPU, MTHI, 0, CPU_REG(_Rd_), gen.PUSH32M((uint32_t)&m_psxRegs.GPR.n.hi))
    PGXP_REC_FUNC_R1_1(CPU, MFLO, !_Rd_, CPU_REG_NC(32), iPushReg(_Rd_))
    PGXP_REC_FUNC_R1_1(CPU, MTLO, 0, CPU_REG(_Rd_), gen.PUSH32M((uint32_t)&m_psxRegs.GPR.n.lo))

    // COP2 (GTE)
    PGXP_REC_FUNC_R1_1(GTE, MFC2, !_Rt_, GTE_DATA_REG(_Rd_), iPushReg(_Rt_))
    PGXP_REC_FUNC_R1_1(GTE, CFC2, !_Rt_, GTE_CTRL_REG(_Rd_), iPushReg(_Rt_))
    PGXP_REC_FUNC_R1_1(GTE, MTC2, 0, CPU_REG(_Rt_), gen.PUSH32M((uint32_t)&m_psxRegs.CP2D.r[_Rd_]))
    PGXP_REC_FUNC_R1_1(GTE, CTC2, 0, CPU_REG(_Rt_), gen.PUSH32M((uint32_t)&m_psxRegs.CP2C.r[_Rd_]))

    PGXP_REC_FUNC_ADDR_1(GTE, LWC2, gen.PUSH32M((uint32_t)&m_psxRegs.CP2D.r[_Rt_]))
    PGXP_REC_FUNC_ADDR_1(GTE, SWC2, gen.PUSH32M((uint32_t)&m_psxRegs.CP2D.r[_Rt_]))

    // COP0
    PGXP_REC_FUNC_R1_1(CP0, MFC0, !_Rd_, CP0_REG(_Rd_), iPushReg(_Rt_))
    PGXP_REC_FUNC_R1_1(CP0, CFC0, !_Rd_, CP0_REG(_Rd_), iPushReg(_Rt_))
    PGXP_REC_FUNC_R1_1(CP0, MTC0, !_Rt_, CPU_REG(_Rt_), gen.PUSH32M((uint32_t)&m_psxRegs.CP0.r[_Rd_]))
    PGXP_REC_FUNC_R1_1(CP0, CTC0, !_Rt_, CPU_REG(_Rt_), gen.PUSH32M((uint32_t)&m_psxRegs.CP0.r[_Rd_]))
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
        gen.MOV32ItoM((uint32_t)&m_psxRegs.GPR.r[reg], m_iRegs[reg].k);
    }
    m_iRegs[reg].state = ST_UNK;
}

void X86DynaRecCPU::iFlushRegs() {
    for (unsigned i = 1; i < 32; i++) iFlushReg(i);
}

void X86DynaRecCPU::iPushReg(unsigned reg) {
    if (IsConst(reg)) {
        gen.PUSH32I(m_iRegs[reg].k);
    } else {
        gen.PUSH32M((uint32_t)&m_psxRegs.GPR.r[reg]);
    }
}

#define REC_FUNC(f)                                                         \
    void psx##f();                                                          \
    void rec##f() {                                                         \
        iFlushRegs();                                                       \
        gen.MOV32ItoM((uint32_t)&m_psxRegs.code, (uint32_t)m_psxRegs.code); \
        gen.MOV32ItoM((uint32_t)&m_psxRegs.pc, (uint32_t)m_pc);             \
        gen.CALLFunc((uint32_t)psx##f);                                     \
        /*  branch = 2; */                                                  \
    }

#define REC_SYS(f)                                                          \
    void psx##f();                                                          \
    void rec##f() {                                                         \
        iFlushRegs();                                                       \
        gen.MOV32ItoM((uint32_t)&m_psxRegs.code, (uint32_t)m_psxRegs.code); \
        gen.MOV32ItoM((uint32_t)&m_psxRegs.pc, (uint32_t)m_pc);             \
        gen.CALLFunc((uint32_t)psx##f);                                     \
        branch = 2;                                                         \
        iRet();                                                             \
    }

#define REC_BRANCH(f)                                                       \
    void psx##f();                                                          \
    void rec##f() {                                                         \
        iFlushRegs();                                                       \
        gen.MOV32ItoM((uint32_t)&m_psxRegs.code, (uint32_t)m_psxRegs.code); \
        gen.MOV32ItoM((uint32_t)&m_psxRegs.pc, (uint32_t)m_pc);             \
        gen.CALLFunc((uint32_t)psx##f);                                     \
        branch = 2;                                                         \
        iRet();                                                             \
    }

bool X86DynaRecCPU::Init() {
    int i;

    m_psxRecLUT = (uintptr_t *)calloc(0x010000, sizeof(uintptr_t));

#ifndef _WIN32
    m_recMem = (int8_t *)mmap(0, ALLOC_SIZE, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#else
    m_recMem = (int8_t *)VirtualAlloc(NULL, ALLOC_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#endif
    memset(m_recMem, 0, ALLOC_SIZE);

    m_recRAM = (char *)calloc(0x200000, 1);
    m_recROM = (char *)calloc(0x080000, 1);
    if (m_recRAM == NULL || m_recROM == NULL || m_recMem == NULL || m_psxRecLUT == NULL) {
        PCSX::g_system->message("Error allocating memory");
        return false;
    }

    for (i = 0; i < 0x80; i++) m_psxRecLUT[i + 0x0000] = (uintptr_t)&m_recRAM[(i & 0x1f) << 16];
    memcpy(m_psxRecLUT + 0x8000, m_psxRecLUT, 0x80 * sizeof(uintptr_t));
    memcpy(m_psxRecLUT + 0xa000, m_psxRecLUT, 0x80 * sizeof(uintptr_t));

    for (i = 0; i < 0x08; i++) m_psxRecLUT[i + 0xbfc0] = (uintptr_t)&m_recROM[i << 16];

    gen.x86Init(m_recMem);

    return true;
}

void X86DynaRecCPU::Reset() {
    R3000Acpu::Reset();

    memset(m_recRAM, 0, 0x200000);
    memset(m_recROM, 0, 0x080000);

    gen.x86Init(m_recMem);

    memset(m_iRegs, 0, sizeof(m_iRegs));
    m_iRegs[0].state = ST_CONST;
    m_iRegs[0].k = 0;
}

void X86DynaRecCPU::Shutdown() {
    if (m_recMem == NULL) return;
    free(m_psxRecLUT);
#ifndef _WIN32
    munmap(m_recMem, ALLOC_SIZE);
#else
    VirtualFree(m_recMem, 0, MEM_RELEASE);
#endif
    free(m_recRAM);
    free(m_recROM);
    gen.x86Shutdown();
}

void X86DynaRecCPU::recError() {
    PCSX::g_system->hardReset();
    PCSX::g_system->stop();
    PCSX::g_system->message("Unrecoverable error while running recompiler\n");
    PCSX::g_system->runGui();
}

void X86DynaRecCPU::execute() {
    uint32_t (**recFunc)() = NULL;
    char *p;

    InterceptBIOS();

    p = (char *)PC_REC(m_psxRegs.pc);

    if (p != NULL && IsPcValid(m_psxRegs.pc)) {
        recFunc = (uint32_t(**)())(uint32_t)p;
    } else {
        recError();
        return;
    }

    const bool &debug = PCSX::g_emulator.settings.get<PCSX::Emulator::SettingDebug>();

    if (debug) PCSX::g_emulator.m_debug->processBefore();
    if (*recFunc == 0) recRecompile();
    uint32_t newPC = (*recFunc)();
    if (newPC != 0xffffffff) {
        m_psxRegs.pc = newPC;
        psxBranchTest();
    } else {
        void (*functionPtr)(uint32_t, uint32_t) = (void (*)(uint32_t, uint32_t))m_functionPtr;
        if (functionPtr) {
            functionPtr(m_arg1, m_arg2);
        } else {
            psxException(m_arg1, m_arg2);
        }
    }
    if (debug) PCSX::g_emulator.m_debug->processAfter();
}

void X86DynaRecCPU::Execute() {
    while (hasToRun()) execute();
}

void X86DynaRecCPU::ExecuteHLEBlock() { execute(); }

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
    PCSX::g_system->message("Unknown instruction for dynarec - address %08x, code %08x\n", m_pc, m_psxRegs.code);
    recError();
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
    gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.CP0.n.Status);
    gen.AND32ItoR(PCSX::ix86::EAX, 0x40000000);
    unsigned slot = gen.JZ8(0);

    func_t func = m_pRecCP2[_Funct_];
    (*this.*func)();

    gen.x86SetJ8(slot);
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

    if (_Rs_ == _Rt_) {
        if (IsConst(_Rt_)) {
            m_iRegs[_Rt_].k += _Imm_;
        } else {
            if (_Imm_ == 1) {
                gen.INC32M((uint32_t)&m_psxRegs.GPR.r[_Rt_]);
            } else if (_Imm_ == -1) {
                gen.DEC32M((uint32_t)&m_psxRegs.GPR.r[_Rt_]);
            } else if (_Imm_) {
                gen.ADD32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], _Imm_);
            }
        }
    } else {
        if (IsConst(_Rs_)) {
            MapConst(_Rt_, m_iRegs[_Rs_].k + _Imm_);
        } else {
            m_iRegs[_Rt_].state = ST_UNK;

            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
            if (_Imm_ == 1) {
                gen.INC32R(PCSX::ix86::EAX);
            } else if (_Imm_ == -1) {
                gen.DEC32R(PCSX::ix86::EAX);
            } else if (_Imm_) {
                gen.ADD32ItoR(PCSX::ix86::EAX, _Imm_);
            }
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
        }
    }
}

void X86DynaRecCPU::recADDI() {
    // Rt = Rs + Im
    if (!_Rt_) return;

    if (_Rs_ == _Rt_) {
        if (IsConst(_Rt_)) {
            m_iRegs[_Rt_].k += _Imm_;
        } else {
            if (_Imm_ == 1) {
                gen.INC32M((uint32_t)&m_psxRegs.GPR.r[_Rt_]);
            } else if (_Imm_ == -1) {
                gen.DEC32M((uint32_t)&m_psxRegs.GPR.r[_Rt_]);
            } else if (_Imm_) {
                gen.ADD32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], _Imm_);
            }
        }
    } else {
        if (IsConst(_Rs_)) {
            MapConst(_Rt_, m_iRegs[_Rs_].k + _Imm_);
        } else {
            m_iRegs[_Rt_].state = ST_UNK;

            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
            if (_Imm_ == 1) {
                gen.INC32R(PCSX::ix86::EAX);
            } else if (_Imm_ == -1) {
                gen.DEC32R(PCSX::ix86::EAX);
            } else if (_Imm_) {
                gen.ADD32ItoR(PCSX::ix86::EAX, _Imm_);
            }
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
        }
    }
}

void X86DynaRecCPU::recSLTI() {
    // Rt = Rs < Im (signed)
    if (!_Rt_) return;

    if (IsConst(_Rs_)) {
        MapConst(_Rt_, (int32_t)m_iRegs[_Rs_].k < _Imm_);
    } else {
        m_iRegs[_Rt_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.CMP32ItoR(PCSX::ix86::EAX, _Imm_);
        gen.SETL8R(PCSX::ix86::EAX);
        gen.AND32ItoR(PCSX::ix86::EAX, 0xff);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
    }
}

void X86DynaRecCPU::recSLTIU() {
    // Rt = Rs < Im (unsigned)
    if (!_Rt_) return;

    if (IsConst(_Rs_)) {
        MapConst(_Rt_, m_iRegs[_Rs_].k < _ImmU_);
    } else {
        m_iRegs[_Rt_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.CMP32ItoR(PCSX::ix86::EAX, _Imm_);
        gen.SETB8R(PCSX::ix86::EAX);
        gen.AND32ItoR(PCSX::ix86::EAX, 0xff);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
    }
}

void X86DynaRecCPU::recANDI() {
    // Rt = Rs And Im
    if (!_Rt_) return;

    if (_Rs_ == _Rt_) {
        if (IsConst(_Rt_)) {
            m_iRegs[_Rt_].k &= _ImmU_;
        } else {
            gen.AND32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], _ImmU_);
        }
    } else {
        if (IsConst(_Rs_)) {
            MapConst(_Rt_, m_iRegs[_Rs_].k & _ImmU_);
        } else {
            m_iRegs[_Rt_].state = ST_UNK;

            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
            gen.AND32ItoR(PCSX::ix86::EAX, _ImmU_);
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
        }
    }
}

void X86DynaRecCPU::recORI() {
    // Rt = Rs Or Im
    if (!_Rt_) return;

    if (_Rs_ == _Rt_) {
        if (IsConst(_Rt_)) {
            m_iRegs[_Rt_].k |= _ImmU_;
        } else {
            gen.OR32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], _ImmU_);
        }
    } else {
        if (IsConst(_Rs_)) {
            MapConst(_Rt_, m_iRegs[_Rs_].k | _ImmU_);
        } else {
            m_iRegs[_Rt_].state = ST_UNK;

            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
            if (_ImmU_) gen.OR32ItoR(PCSX::ix86::EAX, _ImmU_);
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
        }
    }
}

void X86DynaRecCPU::recXORI() {
    // Rt = Rs Xor Im
    if (!_Rt_) return;

    if (_Rs_ == _Rt_) {
        if (IsConst(_Rt_)) {
            m_iRegs[_Rt_].k ^= _ImmU_;
        } else {
            gen.XOR32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], _ImmU_);
        }
    } else {
        if (IsConst(_Rs_)) {
            MapConst(_Rt_, m_iRegs[_Rs_].k ^ _ImmU_);
        } else {
            m_iRegs[_Rt_].state = ST_UNK;

            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
            gen.XOR32ItoR(PCSX::ix86::EAX, _ImmU_);
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
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

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, m_iRegs[_Rs_].k + m_iRegs[_Rt_].k);
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        if (_Rt_ == _Rd_) {
            if (m_iRegs[_Rs_].k == 1) {
                gen.INC32M((uint32_t)&m_psxRegs.GPR.r[_Rd_]);
            } else if (m_iRegs[_Rs_].k == -1) {
                gen.DEC32M((uint32_t)&m_psxRegs.GPR.r[_Rd_]);
            } else if (m_iRegs[_Rs_].k) {
                gen.ADD32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], m_iRegs[_Rs_].k);
            }
        } else {
            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
            if (m_iRegs[_Rs_].k == 1) {
                gen.INC32R(PCSX::ix86::EAX);
            } else if (m_iRegs[_Rs_].k == 0xffffffff) {
                gen.DEC32R(PCSX::ix86::EAX);
            } else if (m_iRegs[_Rs_].k) {
                gen.ADD32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k);
            }
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
        }
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        if (_Rs_ == _Rd_) {
            if (m_iRegs[_Rt_].k == 1) {
                gen.INC32M((uint32_t)&m_psxRegs.GPR.r[_Rd_]);
            } else if (m_iRegs[_Rt_].k == -1) {
                gen.DEC32M((uint32_t)&m_psxRegs.GPR.r[_Rd_]);
            } else if (m_iRegs[_Rt_].k) {
                gen.ADD32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], m_iRegs[_Rt_].k);
            }
        } else {
            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
            if (m_iRegs[_Rt_].k == 1) {
                gen.INC32R(PCSX::ix86::EAX);
            } else if (m_iRegs[_Rt_].k == 0xffffffff) {
                gen.DEC32R(PCSX::ix86::EAX);
            } else if (m_iRegs[_Rt_].k) {
                gen.ADD32ItoR(PCSX::ix86::EAX, m_iRegs[_Rt_].k);
            }
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
        }
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        if (_Rs_ == _Rd_) {  // Rd+= Rt
            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
            gen.ADD32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
        } else if (_Rt_ == _Rd_) {  // Rd+= Rs
            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
            gen.ADD32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
        } else {  // Rd = Rs + Rt
            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
            gen.ADD32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
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

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, m_iRegs[_Rs_].k - m_iRegs[_Rt_].k);
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k);
        gen.SUB32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.SUB32ItoR(PCSX::ix86::EAX, m_iRegs[_Rt_].k);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.SUB32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    }
}

void X86DynaRecCPU::recSUB() {
    // Rd = Rs - Rt
    recSUBU();
}

void X86DynaRecCPU::recAND() {
    // Rd = Rs And Rt
    if (!_Rd_) return;

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, m_iRegs[_Rs_].k & m_iRegs[_Rt_].k);
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        if (_Rd_ == _Rt_) {  // Rd&= Rs
            gen.AND32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], m_iRegs[_Rs_].k);
        } else {
            gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k);
            gen.AND32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
        }
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        if (_Rd_ == _Rs_) {  // Rd&= kRt
            gen.AND32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], m_iRegs[_Rt_].k);
        } else {  // Rd = Rs & kRt
            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
            gen.AND32ItoR(PCSX::ix86::EAX, m_iRegs[_Rt_].k);
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
        }
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        if (_Rs_ == _Rd_) {  // Rd&= Rt
            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
            gen.AND32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
        } else if (_Rt_ == _Rd_) {  // Rd&= Rs
            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
            gen.AND32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
        } else {  // Rd = Rs & Rt
            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
            gen.AND32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
        }
    }
}

void X86DynaRecCPU::recOR() {
    // Rd = Rs Or Rt
    if (!_Rd_) return;

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, m_iRegs[_Rs_].k | m_iRegs[_Rt_].k);
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k);
        gen.OR32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.OR32ItoR(PCSX::ix86::EAX, m_iRegs[_Rt_].k);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.OR32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    }
}

void X86DynaRecCPU::recXOR() {
    // Rd = Rs Xor Rt
    if (!_Rd_) return;

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, m_iRegs[_Rs_].k ^ m_iRegs[_Rt_].k);
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k);
        gen.XOR32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.XOR32ItoR(PCSX::ix86::EAX, m_iRegs[_Rt_].k);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.XOR32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    }
}

void X86DynaRecCPU::recNOR() {
    // Rd = Rs Nor Rt
    if (!_Rd_) return;

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, ~(m_iRegs[_Rs_].k | m_iRegs[_Rt_].k));
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k);
        gen.OR32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.NOT32R(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.OR32ItoR(PCSX::ix86::EAX, m_iRegs[_Rt_].k);
        gen.NOT32R(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.OR32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.NOT32R(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    }
}

void X86DynaRecCPU::recSLT() {
    // Rd = Rs < Rt (signed)
    if (!_Rd_) return;

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, (int32_t)m_iRegs[_Rs_].k < (int32_t)m_iRegs[_Rt_].k);
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k);
        gen.CMP32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.SETL8R(PCSX::ix86::EAX);
        gen.AND32ItoR(PCSX::ix86::EAX, 0xff);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.CMP32ItoR(PCSX::ix86::EAX, m_iRegs[_Rt_].k);
        gen.SETL8R(PCSX::ix86::EAX);
        gen.AND32ItoR(PCSX::ix86::EAX, 0xff);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.CMP32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.SETL8R(PCSX::ix86::EAX);
        gen.AND32ItoR(PCSX::ix86::EAX, 0xff);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    }
}

void X86DynaRecCPU::recSLTU() {
    // Rd = Rs < Rt (unsigned)
    if (!_Rd_) return;

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, m_iRegs[_Rs_].k < m_iRegs[_Rt_].k);
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k);
        gen.CMP32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.SBB32RtoR(PCSX::ix86::EAX, PCSX::ix86::EAX);
        gen.NEG32R(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.CMP32ItoR(PCSX::ix86::EAX, m_iRegs[_Rt_].k);
        gen.SBB32RtoR(PCSX::ix86::EAX, PCSX::ix86::EAX);
        gen.NEG32R(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.CMP32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.SBB32RtoR(PCSX::ix86::EAX, PCSX::ix86::EAX);
        gen.NEG32R(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
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
        gen.XOR32RtoR(PCSX::ix86::EAX, PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.lo, PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.hi, PCSX::ix86::EAX);
        return;
    }

    if (IsConst(_Rs_)) {
        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
    }
    if (IsConst(_Rt_)) {
        gen.MOV32ItoR(PCSX::ix86::EDX, m_iRegs[_Rt_].k);
        gen.IMUL32R(PCSX::ix86::EDX);
    } else {
        gen.IMUL32M((uint32_t)&m_psxRegs.GPR.r[_Rt_]);
    }
    gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.lo, PCSX::ix86::EAX);
    gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.hi, PCSX::ix86::EDX);
}

void X86DynaRecCPU::recMULTU() {
    // Lo/Hi = Rs * Rt (unsigned)

    if ((IsConst(_Rs_) && m_iRegs[_Rs_].k == 0) || (IsConst(_Rt_) && m_iRegs[_Rt_].k == 0)) {
        gen.XOR32RtoR(PCSX::ix86::EAX, PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.lo, PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.hi, PCSX::ix86::EAX);
        return;
    }

    if (IsConst(_Rs_)) {
        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
    }
    if (IsConst(_Rt_)) {
        gen.MOV32ItoR(PCSX::ix86::EDX, m_iRegs[_Rt_].k);
        gen.MUL32R(PCSX::ix86::EDX);
    } else {
        gen.MUL32M((uint32_t)&m_psxRegs.GPR.r[_Rt_]);
    }
    gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.lo, PCSX::ix86::EAX);
    gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.hi, PCSX::ix86::EDX);
}

void X86DynaRecCPU::recDIV() {
    // Lo/Hi = Rs / Rt (signed)

    unsigned slot1;

    if (IsConst(_Rt_)) {
        if (m_iRegs[_Rt_].k == 0) {
            gen.MOV32ItoM((uint32_t)&m_psxRegs.GPR.n.lo, 0xffffffff);
            if (IsConst(_Rs_)) {
                gen.MOV32ItoM((uint32_t)&m_psxRegs.GPR.n.hi, m_iRegs[_Rs_].k);
            } else {
                gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
                gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.hi, PCSX::ix86::EAX);
            }
            return;
        }
        gen.MOV32ItoR(PCSX::ix86::ECX, m_iRegs[_Rt_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::ECX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.CMP32ItoR(PCSX::ix86::ECX, 0);
        slot1 = gen.JE8(0);
    }
    if (IsConst(_Rs_)) {
        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
    }
    gen.CDQ();
    gen.IDIV32R(PCSX::ix86::ECX);
    gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.lo, PCSX::ix86::EAX);
    gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.hi, PCSX::ix86::EDX);

    if (!IsConst(_Rt_)) {
        unsigned slot2 = gen.JMP8(0);

        gen.x86SetJ8(slot1);

        gen.MOV32ItoM((uint32_t)&m_psxRegs.GPR.n.lo, 0xffffffff);
        if (IsConst(_Rs_)) {
            gen.MOV32ItoM((uint32_t)&m_psxRegs.GPR.n.hi, m_iRegs[_Rs_].k);
        } else {
            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.hi, PCSX::ix86::EAX);
        }

        gen.x86SetJ8(slot2);
    }
}

void X86DynaRecCPU::recDIVU() {
    // Lo/Hi = Rs / Rt (unsigned)

    unsigned slot1;

    if (IsConst(_Rt_)) {
        if (m_iRegs[_Rt_].k == 0) {
            gen.MOV32ItoM((uint32_t)&m_psxRegs.GPR.n.lo, 0xffffffff);
            if (IsConst(_Rs_)) {
                gen.MOV32ItoM((uint32_t)&m_psxRegs.GPR.n.hi, m_iRegs[_Rs_].k);
            } else {
                gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
                gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.hi, PCSX::ix86::EAX);
            }
            return;
        }
        gen.MOV32ItoR(PCSX::ix86::ECX, m_iRegs[_Rt_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::ECX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.CMP32ItoR(PCSX::ix86::ECX, 0);
        slot1 = gen.JE8(0);
    }
    if (IsConst(_Rs_)) {
        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
    }
    gen.XOR32RtoR(PCSX::ix86::EDX, PCSX::ix86::EDX);
    gen.DIV32R(PCSX::ix86::ECX);
    gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.lo, PCSX::ix86::EAX);
    gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.hi, PCSX::ix86::EDX);

    if (!IsConst(_Rt_)) {
        unsigned slot2 = gen.JMP8(0);

        gen.x86SetJ8(slot1);

        gen.MOV32ItoM((uint32_t)&m_psxRegs.GPR.n.lo, 0xffffffff);
        if (IsConst(_Rs_)) {
            gen.MOV32ItoM((uint32_t)&m_psxRegs.GPR.n.hi, m_iRegs[_Rs_].k);
        } else {
            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.hi, PCSX::ix86::EAX);
        }

        gen.x86SetJ8(slot2);
    }
}
// End of * Register mult/div & Register trap logic

/* Push OfB for Stores/Loads */
void X86DynaRecCPU::iPushOfB() {
    if (IsConst(_Rs_)) {
        gen.PUSH32I(m_iRegs[_Rs_].k + _Imm_);
    } else {
        if (_Imm_) {
            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
            gen.ADD32ItoR(PCSX::ix86::EAX, _Imm_);
            gen.PUSH32R(PCSX::ix86::EAX);
        } else {
            gen.PUSH32M((uint32_t)&m_psxRegs.GPR.r[_Rs_]);
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
            gen.MOV32ItoR(PCSX::ix86::EDI, psxRs8(addr));
            return;
        }
        if ((t & 0x1fe0) == 0) {
            if (!_Rt_) return;
            gen.MOVSX32M8toR(PCSX::ix86::EDI, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1fffff]);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            if (!_Rt_) return;
            gen.MOVSX32M8toR(PCSX::ix86::EDI, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xfff]);
            return;
        }
    }

    iPushOfB();
    gen.CALLFunc((uint32_t)psxMemRead8Wrapper);
    if (_Rt_) gen.MOVSX32R8toR(PCSX::ix86::EDI, PCSX::ix86::EAX);
    gen.ADD32ItoR(PCSX::ix86::ESP, 4);
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
            gen.MOV32ItoR(PCSX::ix86::EDI, psxRu8(addr));
            return;
        }
        if ((t & 0x1fe0) == 0) {
            if (!_Rt_) return;
            gen.MOVZX32M8toR(PCSX::ix86::EDI, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1fffff]);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            if (!_Rt_) return;
            gen.MOVZX32M8toR(PCSX::ix86::EDI, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xfff]);
            return;
        }
    }

    iPushOfB();
    gen.CALLFunc((uint32_t)psxMemRead8Wrapper);
    if (_Rt_) gen.MOVZX32R8toR(PCSX::ix86::EDI, PCSX::ix86::EAX);
    gen.ADD32ItoR(PCSX::ix86::ESP, 4);
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
            gen.MOV32ItoR(PCSX::ix86::EDI, psxRs16(addr));
            return;
        }
        if ((t & 0x1fe0) == 0) {
            if (!_Rt_) return;
            gen.MOVSX32M16toR(PCSX::ix86::EDI, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1fffff]);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            if (!_Rt_) return;
            gen.MOVSX32M16toR(PCSX::ix86::EDI, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xfff]);
            return;
        }
    }

    iPushOfB();
    gen.CALLFunc((uint32_t)psxMemRead16Wrapper);
    if (_Rt_) gen.MOVSX32R16toR(PCSX::ix86::EDI, PCSX::ix86::EAX);
    gen.ADD32ItoR(PCSX::ix86::ESP, 4);
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
            gen.MOV32ItoR(PCSX::ix86::EDI, psxRu16(addr));
            return;
        }
        if ((t & 0x1fe0) == 0) {
            if (!_Rt_) return;
            gen.MOVZX32M16toR(PCSX::ix86::EDI, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1fffff]);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            if (!_Rt_) return;
            gen.MOVZX32M16toR(PCSX::ix86::EDI, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xfff]);
            return;
        }
        if (t == 0x1f80) {
            if (addr >= 0x1f801c00 && addr < 0x1f801e00) {
                if (!_Rt_) return;
                gen.PUSH32I(addr);
                gen.CALLFunc((uint32_t)SPUreadRegisterWrapper);
                gen.MOVZX32R16toR(PCSX::ix86::EDI, PCSX::ix86::EAX);
                gen.ADD32ItoR(PCSX::ix86::ESP, 4);
                return;
            }
            switch (addr) {
                case 0x1f801100:
                case 0x1f801110:
                case 0x1f801120:
                    if (!_Rt_) return;
                    gen.PUSH32I((addr >> 4) & 0x3);
                    gen.CALLFunc((uint32_t)psxRcntRcountWrapper);
                    gen.MOVZX32R16toR(PCSX::ix86::EDI, PCSX::ix86::EAX);
                    gen.ADD32ItoR(PCSX::ix86::ESP, 4);
                    return;

                case 0x1f801104:
                case 0x1f801114:
                case 0x1f801124:
                    if (!_Rt_) return;
                    gen.PUSH32I((addr >> 4) & 0x3);
                    gen.CALLFunc((uint32_t)psxRcntRmodeWrapper);
                    gen.MOVZX32R16toR(PCSX::ix86::EDI, PCSX::ix86::EAX);
                    gen.ADD32ItoR(PCSX::ix86::ESP, 4);
                    return;

                case 0x1f801108:
                case 0x1f801118:
                case 0x1f801128:
                    if (!_Rt_) return;
                    gen.PUSH32I((addr >> 4) & 0x3);
                    gen.CALLFunc((uint32_t)psxRcntRtargetWrapper);
                    gen.MOVZX32R16toR(PCSX::ix86::EDI, PCSX::ix86::EAX);
                    gen.ADD32ItoR(PCSX::ix86::ESP, 4);
                    return;
            }
        }
    }

    iPushOfB();
    gen.CALLFunc((uint32_t)psxMemRead16Wrapper);
    if (_Rt_) gen.MOVZX32R16toR(PCSX::ix86::EDI, PCSX::ix86::EAX);
    gen.ADD32ItoR(PCSX::ix86::ESP, 4);
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
            gen.MOV32ItoR(PCSX::ix86::EDI, psxRu32(addr));
            return;
        }
        if ((t & 0x1fe0) == 0) {
            if (!_Rt_) return;
            gen.MOV32MtoR(PCSX::ix86::EDI, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1fffff]);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            if (!_Rt_) return;
            gen.MOV32MtoR(PCSX::ix86::EDI, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xfff]);
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
                    gen.MOV32MtoR(PCSX::ix86::EDI, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xffff]);
                    return;

                case 0x1f801810:
                    if (!_Rt_) return;
                    gen.CALLFunc((uint32_t)&GPU_readDataWrapper);
                    gen.MOV32RtoR(PCSX::ix86::EDI, PCSX::ix86::EAX);
                    return;

                case 0x1f801814:
                    if (!_Rt_) return;
                    gen.CALLFunc((uint32_t)&GPU_readStatusWrapper);
                    gen.MOV32RtoR(PCSX::ix86::EDI, PCSX::ix86::EAX);
                    return;
            }
        }
    }

    iPushOfB();
    gen.CALLFunc((uint32_t)psxMemRead32Wrapper);
    if (_Rt_) gen.MOV32RtoR(PCSX::ix86::EDI, PCSX::ix86::EAX);
    gen.ADD32ItoR(PCSX::ix86::ESP, 4);
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
            gen.MOV32MtoR(PCSX::ix86::EAX, ptr);
            if (LWL_SHIFT[shift]) gen.SHL32ItoR(PCSX::ix86::EAX, LWL_SHIFT[shift]);
            gen.MOV32RtoR(PCSX::ix86::EDI, PCSX::ix86::EAX);
            if (LWL_MASK_INDEX[shift]) {
                gen.MOV32ItoR(PCSX::ix86::ECX, LWL_MASK_INDEX[shift]);
                gen.SHL32ItoR(PCSX::ix86::ECX, 16);
                gen.OR32RtoR(PCSX::ix86::EBX, PCSX::ix86::ECX);
            }
        };

        if ((t & 0x1fe0) == 0) {
            iLWLk(addr & 3, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1ffffc]);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            iLWLk(addr & 3, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xffc]);
            return;
        }
        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k + _Imm_);
    } else {
        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        if (_Imm_) gen.ADD32ItoR(PCSX::ix86::EAX, _Imm_);
    }
    gen.PUSH32R(PCSX::ix86::EAX);
    gen.AND32ItoR(PCSX::ix86::EAX, ~3);
    gen.PUSH32R(PCSX::ix86::EAX);
    gen.CALLFunc((uint32_t)psxMemRead32Wrapper);

    if (_Rt_) {
        gen.ADD32ItoR(PCSX::ix86::ESP, 4);
        gen.POP32R(PCSX::ix86::EDX);
        gen.AND32ItoR(PCSX::ix86::EDX, 0x3);  // shift = addr & 3;

        gen.MOV32ItoR(PCSX::ix86::ECX, (uint32_t)LWL_SHIFT);
        gen.MOV32RmStoR(PCSX::ix86::ECX, PCSX::ix86::ECX, PCSX::ix86::EDX, 2);
        gen.SHL32CLtoR(PCSX::ix86::EAX);  // mem(PCSX::ix86::EAX) << LWL_SHIFT[shift]
        gen.MOV32RtoR(PCSX::ix86::EDI, PCSX::ix86::EAX);

        gen.MOV32ItoR(PCSX::ix86::ECX, (uint32_t)LWL_MASK_INDEX);
        gen.MOV32RmStoR(PCSX::ix86::ECX, PCSX::ix86::ECX, PCSX::ix86::EDX, 2);
        gen.SHL32ItoR(PCSX::ix86::ECX, 16);
        gen.AND32ItoR(PCSX::ix86::EBX, 0xffff);
        gen.OR32RtoR(PCSX::ix86::EBX, PCSX::ix86::ECX);
    } else {
        gen.ADD32ItoR(PCSX::ix86::ESP, 8);
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
            gen.MOV32MtoR(PCSX::ix86::EAX, ptr);
            if (LWR_SHIFT[shift]) gen.SHL32ItoR(PCSX::ix86::EAX, LWR_SHIFT[shift]);
            gen.MOV32RtoR(PCSX::ix86::EDI, PCSX::ix86::EAX);
            if (LWR_MASK_INDEX[shift]) {
                gen.MOV32ItoR(PCSX::ix86::ECX, LWR_MASK_INDEX[shift]);
                gen.SHR32ItoR(PCSX::ix86::ECX, 16);
                gen.OR32RtoR(PCSX::ix86::EBX, PCSX::ix86::ECX);
            }
        };

        if ((t & 0x1fe0) == 0) {
            iLWRk(addr & 3, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1ffffc]);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            iLWRk(addr & 3, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xffc]);
            return;
        }
        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k + _Imm_);
    } else {
        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        if (_Imm_) gen.ADD32ItoR(PCSX::ix86::EAX, _Imm_);
    }
    gen.PUSH32R(PCSX::ix86::EAX);
    gen.AND32ItoR(PCSX::ix86::EAX, ~3);
    gen.PUSH32R(PCSX::ix86::EAX);
    gen.CALLFunc((uint32_t)psxMemRead32Wrapper);

    if (_Rt_) {
        gen.ADD32ItoR(PCSX::ix86::ESP, 4);
        gen.POP32R(PCSX::ix86::EDX);
        gen.AND32ItoR(PCSX::ix86::EDX, 0x3);  // shift = addr & 3;

        gen.MOV32ItoR(PCSX::ix86::ECX, (uint32_t)LWR_SHIFT);
        gen.MOV32RmStoR(PCSX::ix86::ECX, PCSX::ix86::ECX, PCSX::ix86::EDX, 2);
        gen.SHR32CLtoR(PCSX::ix86::EAX);  // mem(PCSX::ix86::EAX) << LWR_SHIFT[shift]
        gen.MOV32RtoR(PCSX::ix86::EDI, PCSX::ix86::EAX);

        gen.MOV32ItoR(PCSX::ix86::ECX, (uint32_t)LWR_MASK_INDEX);
        gen.MOV32RmStoR(PCSX::ix86::ECX, PCSX::ix86::ECX, PCSX::ix86::EDX, 2);
        gen.SHL32ItoR(PCSX::ix86::ECX, 16);
        gen.AND32ItoR(PCSX::ix86::EBX, 0xffff);
        gen.OR32RtoR(PCSX::ix86::EBX, PCSX::ix86::ECX);
    } else {
        gen.ADD32ItoR(PCSX::ix86::ESP, 8);
    }
}

void X86DynaRecCPU::recSB() {
    // mem[Rs + Im] = Rt

    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0x1fe0) == 0 && (t & 0x1fff) != 0) {
            if (IsConst(_Rt_)) {
                gen.MOV8ItoM((uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1fffff], (uint8_t)m_iRegs[_Rt_].k);
            } else {
                gen.MOV8MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
                gen.MOV8RtoM((uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1fffff], PCSX::ix86::EAX);
            }

            gen.PUSH32I(1);
            gen.PUSH32I(addr & ~3);
            gen.PUSH32I(reinterpret_cast<uintptr_t>(this));
            gen.CALLFunc((uint32_t)&recClearWrapper);
            gen.ADD32ItoR(PCSX::ix86::ESP, 12);
            return;
        }

        if (t == 0x1f80 && addr < 0x1f801000) {
            if (IsConst(_Rt_)) {
                gen.MOV8ItoM((uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xfff], (uint8_t)m_iRegs[_Rt_].k);
            } else {
                gen.MOV8MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
                gen.MOV8RtoM((uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xfff], PCSX::ix86::EAX);
            }
            return;
        }
        //      PCSX::g_system->printf("unhandled w8 %x\n", addr);
    }

    if (IsConst(_Rt_)) {
        gen.PUSH32I(m_iRegs[_Rt_].k);
    } else {
        gen.PUSH32M((uint32_t)&m_psxRegs.GPR.r[_Rt_]);
    }
    iPushOfB();
    gen.CALLFunc((uint32_t)psxMemWrite8Wrapper);
    gen.ADD32ItoR(PCSX::ix86::ESP, 8);
}

void X86DynaRecCPU::recSH() {
    // mem[Rs + Im] = Rt

    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0x1fe0) == 0 && (t & 0x1fff) != 0) {
            if (IsConst(_Rt_)) {
                gen.MOV16ItoM((uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1fffff], (uint16_t)m_iRegs[_Rt_].k);
            } else {
                gen.MOV16MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
                gen.MOV16RtoM((uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1fffff], PCSX::ix86::EAX);
            }

            gen.PUSH32I(1);
            gen.PUSH32I(addr & ~3);
            gen.PUSH32I(reinterpret_cast<uintptr_t>(this));
            gen.CALLFunc((uint32_t)&recClearWrapper);
            gen.ADD32ItoR(PCSX::ix86::ESP, 12);
            return;
        }

        if (t == 0x1f80 && addr < 0x1f801000) {
            if (IsConst(_Rt_)) {
                gen.MOV16ItoM((uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xfff], (uint16_t)m_iRegs[_Rt_].k);
            } else {
                gen.MOV16MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
                gen.MOV16RtoM((uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xfff], PCSX::ix86::EAX);
            }
            return;
        }
        if (t == 0x1f80) {
            if (addr >= 0x1f801c00 && addr < 0x1f801e00) {
                if (IsConst(_Rt_)) {
                    gen.PUSH32I(m_iRegs[_Rt_].k);
                } else {
                    gen.PUSH32M((uint32_t)&m_psxRegs.GPR.r[_Rt_]);
                }
                gen.PUSH32I(addr);
                gen.CALLFunc((uint32_t)SPUwriteRegisterWrapper);
                gen.ADD32ItoR(PCSX::ix86::ESP, 8);
                return;
            }
        }
        //      PCSX::g_system->printf("unhandled w16 %x\n", addr);
    }

    if (IsConst(_Rt_)) {
        gen.PUSH32I(m_iRegs[_Rt_].k);
    } else {
        gen.PUSH32M((uint32_t)&m_psxRegs.GPR.r[_Rt_]);
    }
    iPushOfB();
    gen.CALLFunc((uint32_t)psxMemWrite16Wrapper);
    gen.ADD32ItoR(PCSX::ix86::ESP, 8);
}

void X86DynaRecCPU::recSW() {
    // mem[Rs + Im] = Rt

    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0x1fe0) == 0 && (t & 0x1fff) != 0) {
            if (IsConst(_Rt_)) {
                gen.MOV32ItoM((uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1fffff], m_iRegs[_Rt_].k);
            } else {
                gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
                gen.MOV32RtoM((uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1fffff], PCSX::ix86::EAX);
            }

            gen.PUSH32I(1);
            gen.PUSH32I(addr);
            gen.PUSH32I(reinterpret_cast<uintptr_t>(this));
            gen.CALLFunc((uint32_t)&recClearWrapper);
            gen.ADD32ItoR(PCSX::ix86::ESP, 12);
            return;
        }

        if (t == 0x1f80 && addr < 0x1f801000) {
            if (IsConst(_Rt_)) {
                gen.MOV32ItoM((uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xfff], m_iRegs[_Rt_].k);
            } else {
                gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
                gen.MOV32RtoM((uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xfff], PCSX::ix86::EAX);
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
                        gen.MOV32ItoM((uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xffff], m_iRegs[_Rt_].k);
                    } else {
                        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
                        gen.MOV32RtoM((uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xffff], PCSX::ix86::EAX);
                    }
                    return;

                case 0x1f801810:
                    if (IsConst(_Rt_)) {
                        gen.PUSH32I(m_iRegs[_Rt_].k);
                    } else {
                        gen.PUSH32M((uint32_t)&m_psxRegs.GPR.r[_Rt_]);
                    }
                    gen.CALLFunc((uint32_t)GPU_writeDataWrapper);
                    gen.ADD32ItoR(PCSX::ix86::ESP, 4);
                    return;

                case 0x1f801814:
                    if (IsConst(_Rt_)) {
                        gen.PUSH32I(m_iRegs[_Rt_].k);
                    } else {
                        gen.PUSH32M((uint32_t)&m_psxRegs.GPR.r[_Rt_]);
                    }
                    gen.CALLFunc((uint32_t)&GPU_writeStatusWrapper);
                    gen.ADD32ItoR(PCSX::ix86::ESP, 4);
                    return;
            }
        }
        //      PCSX::g_system->printf("unhandled w32 %x\n", addr);
    }

    if (IsConst(_Rt_)) {
        gen.PUSH32I(m_iRegs[_Rt_].k);
    } else {
        gen.PUSH32M((uint32_t)&m_psxRegs.GPR.r[_Rt_]);
    }
    iPushOfB();
    gen.CALLFunc((uint32_t)psxMemWrite32Wrapper);
    gen.ADD32ItoR(PCSX::ix86::ESP, 8);
}

void X86DynaRecCPU::iSWLk(uint32_t shift) {
    if (IsConst(_Rt_)) {
        gen.MOV32ItoR(PCSX::ix86::ECX, m_iRegs[_Rt_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::ECX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
    }
    gen.SHR32ItoR(PCSX::ix86::ECX, SWL_SHIFT[shift]);
    gen.AND32ItoR(PCSX::ix86::EAX, SWL_MASK[shift]);
    gen.OR32RtoR(PCSX::ix86::EAX, PCSX::ix86::ECX);
}

void X86DynaRecCPU::recSWL() {
    // mem[Rs + Im] = Rt Merge mem[Rs + Im]

    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

#if 0
        if ((t & 0x1fe0) == 0 && (t & 0x1fff) != 0) {
            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1ffffc]);
            iSWLk(addr & 3);
            gen.MOV32RtoM((uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1ffffc], PCSX::ix86::EAX);
            return;
        }
#endif
        if (t == 0x1f80 && addr < 0x1f801000) {
            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xffc]);
            iSWLk(addr & 3);
            gen.MOV32RtoM((uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xffc], PCSX::ix86::EAX);
            return;
        }
    }

    if (IsConst(_Rs_)) {
        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k + _Imm_);
    } else {
        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        if (_Imm_) gen.ADD32ItoR(PCSX::ix86::EAX, _Imm_);
    }
    gen.PUSH32R(PCSX::ix86::EAX);
    gen.AND32ItoR(PCSX::ix86::EAX, ~3);
    gen.PUSH32R(PCSX::ix86::EAX);

    gen.CALLFunc((uint32_t)psxMemRead32Wrapper);

    gen.ADD32ItoR(PCSX::ix86::ESP, 4);
    gen.POP32R(PCSX::ix86::EDX);
    gen.AND32ItoR(PCSX::ix86::EDX, 0x3);  // shift = addr & 3;

    gen.MOV32ItoR(PCSX::ix86::ECX, (uint32_t)SWL_MASK);
    gen.MOV32RmStoR(PCSX::ix86::ECX, PCSX::ix86::ECX, PCSX::ix86::EDX, 2);
    gen.AND32RtoR(PCSX::ix86::EAX, PCSX::ix86::ECX);  // mem & SWL_MASK[shift]

    gen.MOV32ItoR(PCSX::ix86::ECX, (uint32_t)SWL_SHIFT);
    gen.MOV32RmStoR(PCSX::ix86::ECX, PCSX::ix86::ECX, PCSX::ix86::EDX, 2);
    if (IsConst(_Rt_)) {
        gen.MOV32ItoR(PCSX::ix86::EDX, m_iRegs[_Rt_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::EDX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
    }
    gen.SHR32CLtoR(PCSX::ix86::EDX);  // _rRt_ >> SWL_SHIFT[shift]

    gen.OR32RtoR(PCSX::ix86::EAX, PCSX::ix86::EDX);
    gen.PUSH32R(PCSX::ix86::EAX);

    if (IsConst(_Rs_))
        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k + _Imm_);
    else {
        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        if (_Imm_) gen.ADD32ItoR(PCSX::ix86::EAX, _Imm_);
    }
    gen.AND32ItoR(PCSX::ix86::EAX, ~3);
    gen.PUSH32R(PCSX::ix86::EAX);

    gen.CALLFunc((uint32_t)psxMemWrite32Wrapper);
    gen.ADD32ItoR(PCSX::ix86::ESP, 8);
}

void X86DynaRecCPU::iSWRk(uint32_t shift) {
    if (IsConst(_Rt_)) {
        gen.MOV32ItoR(PCSX::ix86::ECX, m_iRegs[_Rt_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::ECX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
    }
    gen.SHL32ItoR(PCSX::ix86::ECX, SWR_SHIFT[shift]);
    gen.AND32ItoR(PCSX::ix86::EAX, SWR_MASK[shift]);
    gen.OR32RtoR(PCSX::ix86::EAX, PCSX::ix86::ECX);
}

void X86DynaRecCPU::recSWR() {
    // mem[Rs + Im] = Rt Merge mem[Rs + Im]

    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

#if 0
        if ((t & 0x1fe0) == 0 && (t & 0x1fff) != 0) {
            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1ffffc]);
            iSWRk(addr & 3);
            gen.MOV32RtoM((uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1ffffc], PCSX::ix86::EAX);
            return;
        }
#endif
        if (t == 0x1f80 && addr < 0x1f801000) {
            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xffc]);
            iSWRk(addr & 3);
            gen.MOV32RtoM((uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xffc], PCSX::ix86::EAX);
            return;
        }
    }

    if (IsConst(_Rs_)) {
        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k + _Imm_);
    } else {
        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        if (_Imm_) gen.ADD32ItoR(PCSX::ix86::EAX, _Imm_);
    }
    gen.PUSH32R(PCSX::ix86::EAX);
    gen.AND32ItoR(PCSX::ix86::EAX, ~3);
    gen.PUSH32R(PCSX::ix86::EAX);

    gen.CALLFunc((uint32_t)psxMemRead32Wrapper);

    gen.ADD32ItoR(PCSX::ix86::ESP, 4);
    gen.POP32R(PCSX::ix86::EDX);
    gen.AND32ItoR(PCSX::ix86::EDX, 0x3);  // shift = addr & 3;

    gen.MOV32ItoR(PCSX::ix86::ECX, (uint32_t)SWR_MASK);
    gen.MOV32RmStoR(PCSX::ix86::ECX, PCSX::ix86::ECX, PCSX::ix86::EDX, 2);
    gen.AND32RtoR(PCSX::ix86::EAX, PCSX::ix86::ECX);  // mem & SWR_MASK[shift]

    gen.MOV32ItoR(PCSX::ix86::ECX, (uint32_t)SWR_SHIFT);
    gen.MOV32RmStoR(PCSX::ix86::ECX, PCSX::ix86::ECX, PCSX::ix86::EDX, 2);
    if (IsConst(_Rt_)) {
        gen.MOV32ItoR(PCSX::ix86::EDX, m_iRegs[_Rt_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::EDX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
    }
    gen.SHL32CLtoR(PCSX::ix86::EDX);  // _rRt_ << SWR_SHIFT[shift]

    gen.OR32RtoR(PCSX::ix86::EAX, PCSX::ix86::EDX);
    gen.PUSH32R(PCSX::ix86::EAX);

    if (IsConst(_Rs_))
        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k + _Imm_);
    else {
        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        if (_Imm_) gen.ADD32ItoR(PCSX::ix86::EAX, _Imm_);
    }
    gen.AND32ItoR(PCSX::ix86::EAX, ~3);
    gen.PUSH32R(PCSX::ix86::EAX);

    gen.CALLFunc((uint32_t)psxMemWrite32Wrapper);
    gen.ADD32ItoR(PCSX::ix86::ESP, 8);
}

void X86DynaRecCPU::recSLL() {
    // Rd = Rt << Sa
    if (!_Rd_) return;

    if (IsConst(_Rt_)) {
        MapConst(_Rd_, m_iRegs[_Rt_].k << _Sa_);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        if (_Sa_) gen.SHL32ItoR(PCSX::ix86::EAX, _Sa_);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    }
}

void X86DynaRecCPU::recSRL() {
    // Rd = Rt >> Sa
    if (!_Rd_) return;

    if (IsConst(_Rt_)) {
        MapConst(_Rd_, m_iRegs[_Rt_].k >> _Sa_);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        if (_Sa_) gen.SHR32ItoR(PCSX::ix86::EAX, _Sa_);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    }
}

void X86DynaRecCPU::recSRA() {
    // Rd = Rt >> Sa
    if (!_Rd_) return;

    if (IsConst(_Rt_)) {
        MapConst(_Rd_, (int32_t)m_iRegs[_Rt_].k >> _Sa_);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        if (_Sa_) gen.SAR32ItoR(PCSX::ix86::EAX, _Sa_);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    }
}

void X86DynaRecCPU::recSLLV() {
    // Rd = Rt << Rs
    if (!_Rd_) return;

    if (IsConst(_Rt_) && IsConst(_Rs_)) {
        MapConst(_Rd_, m_iRegs[_Rt_].k << (m_iRegs[_Rs_].k & 0x1f));
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.MOV32ItoR(PCSX::ix86::ECX, m_iRegs[_Rs_].k & 0x1f);
        gen.SHL32CLtoR(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rt_].k & 0x1f);
        gen.MOV32MtoR(PCSX::ix86::ECX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.AND32ItoR(PCSX::ix86::ECX, 0x1f);
        gen.SHL32CLtoR(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.MOV32MtoR(PCSX::ix86::ECX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.AND32ItoR(PCSX::ix86::ECX, 0x1f);
        gen.SHL32CLtoR(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    }
}

void X86DynaRecCPU::recSRLV() {
    // Rd = Rt >> Rs
    if (!_Rd_) return;

    if (IsConst(_Rt_) && IsConst(_Rs_)) {
        MapConst(_Rd_, m_iRegs[_Rt_].k >> (m_iRegs[_Rs_].k & 0x1f));
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.MOV32ItoR(PCSX::ix86::ECX, m_iRegs[_Rs_].k & 0x1f);
        gen.SHR32CLtoR(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rt_].k);
        gen.MOV32MtoR(PCSX::ix86::ECX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.AND32ItoR(PCSX::ix86::ECX, 0x1f);
        gen.SHR32CLtoR(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.MOV32MtoR(PCSX::ix86::ECX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.AND32ItoR(PCSX::ix86::ECX, 0x1f);
        gen.SHR32CLtoR(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    }
}

void X86DynaRecCPU::recSRAV() {
    // Rd = Rt >> Rs
    if (!_Rd_) return;

    if (IsConst(_Rt_) && IsConst(_Rs_)) {
        MapConst(_Rd_, (int32_t)m_iRegs[_Rt_].k >> (m_iRegs[_Rs_].k & 0x1f));
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.MOV32ItoR(PCSX::ix86::ECX, m_iRegs[_Rs_].k & 0x1f);
        gen.SAR32CLtoR(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rt_].k);
        gen.MOV32MtoR(PCSX::ix86::ECX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.AND32ItoR(PCSX::ix86::ECX, 0x1f);
        gen.SAR32CLtoR(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.MOV32MtoR(PCSX::ix86::ECX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.AND32ItoR(PCSX::ix86::ECX, 0x1f);
        gen.SAR32CLtoR(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    }
}

void X86DynaRecCPU::recSYSCALL() {
    gen.MOV32ItoM((uint32_t)&m_psxRegs.pc, (uint32_t)m_pc - 4);
    gen.MOV32ItoR(PCSX::ix86::EBP, 0xffffffff);
    gen.MOV32ItoM((uint32_t)&m_arg2, m_inDelaySlot ? 1 : 0);
    gen.MOV32ItoM((uint32_t)&m_arg1, 0x20);
    gen.MOV32ItoM((uint32_t)&m_functionPtr, 0);

    m_pcInEBP = true;
    m_stopRecompile = true;
}

void X86DynaRecCPU::recBREAK() {}

void X86DynaRecCPU::recMFHI() {
    // Rd = Hi
    if (!_Rd_) return;

    m_iRegs[_Rd_].state = ST_UNK;
    gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.n.hi);
    gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
}

void X86DynaRecCPU::recMTHI() {
    // Hi = Rs

    if (IsConst(_Rs_)) {
        gen.MOV32ItoM((uint32_t)&m_psxRegs.GPR.n.hi, m_iRegs[_Rs_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.hi, PCSX::ix86::EAX);
    }
}

void X86DynaRecCPU::recMFLO() {
    // Rd = Lo
    if (!_Rd_) return;

    m_iRegs[_Rd_].state = ST_UNK;
    gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.n.lo);
    gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
}

void X86DynaRecCPU::recMTLO() {
    // Lo = Rs

    if (IsConst(_Rs_)) {
        gen.MOV32ItoM((uint32_t)&m_psxRegs.GPR.n.lo, m_iRegs[_Rs_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.lo, PCSX::ix86::EAX);
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
            gen.MOV32ItoR(PCSX::ix86::EBP, target);
        }
        return;
    }

    m_pcInEBP = true;
    m_stopRecompile = true;
    gen.MOV32ItoR(PCSX::ix86::EBP, target);
    gen.CMP32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rs_], 0);
    unsigned slot = gen.JL32(0);
    gen.MOV32ItoR(PCSX::ix86::EBP, m_pc + 4);
    gen.x86SetJ32(slot);
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
            gen.MOV32ItoR(PCSX::ix86::EBP, target);
        }
        return;
    }

    m_pcInEBP = true;
    m_stopRecompile = true;
    gen.MOV32ItoR(PCSX::ix86::EBP, target);
    gen.CMP32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rs_], 0);
    unsigned slot = gen.JG32(0);
    gen.MOV32ItoR(PCSX::ix86::EBP, m_pc + 4);
    gen.x86SetJ32(slot);
}

void X86DynaRecCPU::recBLTZAL() {
    // Branch if Rs < 0
    uint32_t target = _Imm_ * 4 + m_pc;

    m_nextIsDelaySlot = true;
    if (IsConst(_Rs_)) {
        if ((int32_t)m_iRegs[_Rs_].k < 0) {
            m_needsStackFrame = true;
            auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
            delayedLoad.active = true;
            delayedLoad.index = 31;
            gen.MOV32ItoR(PCSX::ix86::EDI, m_pc + 4);
            m_pcInEBP = true;
            m_stopRecompile = true;
            gen.MOV32ItoR(PCSX::ix86::EBP, target);
        }
        return;
    }

    iFlushReg(31);
    m_needsStackFrame = true;
    auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
    delayedLoad.active = true;
    delayedLoad.index = 31;
    gen.MOV32MtoR(PCSX::ix86::EDI, (uint32_t)&m_psxRegs.GPR.n.ra);
    m_pcInEBP = true;
    m_stopRecompile = true;
    gen.MOV32ItoR(PCSX::ix86::EBP, m_pc + 4);
    gen.CMP32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rs_], 0);
    unsigned slot = gen.JGE32(0);
    gen.MOV32ItoR(PCSX::ix86::EDI, m_pc + 4);
    gen.MOV32ItoR(PCSX::ix86::EBP, target);
    gen.x86SetJ32(slot);
}

void X86DynaRecCPU::recBGEZAL() {
    // Branch if Rs >= 0
    uint32_t target = _Imm_ * 4 + m_pc;

    m_nextIsDelaySlot = true;
    if (IsConst(_Rs_)) {
        if ((int32_t)m_iRegs[_Rs_].k >= 0) {
            m_needsStackFrame = true;
            auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
            delayedLoad.active = true;
            delayedLoad.index = 31;
            gen.MOV32ItoR(PCSX::ix86::EDI, m_pc + 4);
            m_pcInEBP = true;
            m_stopRecompile = true;
            gen.MOV32ItoR(PCSX::ix86::EBP, target);
        }
        return;
    }

    iFlushReg(31);
    m_needsStackFrame = true;
    auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
    delayedLoad.active = true;
    delayedLoad.index = 31;
    gen.MOV32MtoR(PCSX::ix86::EDI, (uint32_t)&m_psxRegs.GPR.n.ra);
    m_pcInEBP = true;
    m_stopRecompile = true;
    gen.MOV32ItoR(PCSX::ix86::EBP, m_pc + 4);
    gen.CMP32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rs_], 0);
    unsigned slot = gen.JL32(0);
    gen.MOV32ItoR(PCSX::ix86::EDI, m_pc + 4);
    gen.MOV32ItoR(PCSX::ix86::EBP, target);
    gen.x86SetJ32(slot);
}

void X86DynaRecCPU::recJ() {
    // j target
    uint32_t target = _Target_ * 4 + (m_pc & 0xf0000000);
    m_nextIsDelaySlot = true;
    m_stopRecompile = true;
    m_pcInEBP = true;
    gen.MOV32ItoR(PCSX::ix86::EBP, target);
}

void X86DynaRecCPU::recJAL() {
    // jal target
    m_needsStackFrame = true;
    auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
    delayedLoad.active = true;
    delayedLoad.index = 31;
    gen.MOV32ItoR(PCSX::ix86::EDI, m_pc + 4);
    uint32_t target = _Target_ * 4 + (m_pc & 0xf0000000);
    m_nextIsDelaySlot = true;
    m_stopRecompile = true;
    m_pcInEBP = true;
    gen.MOV32ItoR(PCSX::ix86::EBP, target);
}

void X86DynaRecCPU::recJR() {
    // jr Rs
    m_nextIsDelaySlot = true;
    m_stopRecompile = true;
    m_pcInEBP = true;
    if (IsConst(_Rs_)) {
        gen.MOV32ItoR(PCSX::ix86::EBP, m_iRegs[_Rs_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::EBP, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
    }
}

void X86DynaRecCPU::recJALR() {
    // jalr Rs
    m_needsStackFrame = true;
    auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
    delayedLoad.active = true;
    delayedLoad.index = _Rd_;
    gen.MOV32ItoR(PCSX::ix86::EDI, m_pc + 4);
    m_nextIsDelaySlot = true;
    m_stopRecompile = true;
    m_pcInEBP = true;
    if (IsConst(_Rs_)) {
        gen.MOV32ItoR(PCSX::ix86::EBP, m_iRegs[_Rs_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::EBP, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
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
            gen.MOV32ItoR(PCSX::ix86::EBP, target);
        }
        return;
    } else if (IsConst(_Rs_)) {
        gen.CMP32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], m_iRegs[_Rs_].k);
    } else if (IsConst(_Rt_)) {
        gen.CMP32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rs_], m_iRegs[_Rt_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.CMP32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
    }
    m_pcInEBP = true;
    m_stopRecompile = true;
    gen.MOV32ItoR(PCSX::ix86::EBP, target);
    unsigned slot = gen.JE32(0);
    gen.MOV32ItoR(PCSX::ix86::EBP, m_pc + 4);
    gen.x86SetJ32(slot);
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
            gen.MOV32ItoR(PCSX::ix86::EBP, target);
        }
        return;
    } else if (IsConst(_Rs_)) {
        gen.CMP32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], m_iRegs[_Rs_].k);
    } else if (IsConst(_Rt_)) {
        gen.CMP32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rs_], m_iRegs[_Rt_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.CMP32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
    }
    m_pcInEBP = true;
    m_stopRecompile = true;
    gen.MOV32ItoR(PCSX::ix86::EBP, target);
    unsigned slot = gen.JNE32(0);
    gen.MOV32ItoR(PCSX::ix86::EBP, m_pc + 4);
    gen.x86SetJ32(slot);
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
            gen.MOV32ItoR(PCSX::ix86::EBP, target);
        }
        return;
    }

    m_pcInEBP = true;
    m_stopRecompile = true;
    gen.MOV32ItoR(PCSX::ix86::EBP, target);
    gen.CMP32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rs_], 0);
    unsigned slot = gen.JLE32(0);
    gen.MOV32ItoR(PCSX::ix86::EBP, m_pc + 4);
    gen.x86SetJ32(slot);
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
            gen.MOV32ItoR(PCSX::ix86::EBP, target);
        }
        return;
    }

    m_pcInEBP = true;
    m_stopRecompile = true;
    gen.MOV32ItoR(PCSX::ix86::EBP, target);
    gen.CMP32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rs_], 0);
    unsigned slot = gen.JGE32(0);
    gen.MOV32ItoR(PCSX::ix86::EBP, m_pc + 4);
    gen.x86SetJ32(slot);
}

void X86DynaRecCPU::recMFC0() {
    // Rt = Cop0->Rd
    if (!_Rt_) return;

    m_iRegs[_Rt_].state = ST_UNK;
    gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.CP0.r[_Rd_]);
    gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
}

void X86DynaRecCPU::recCFC0() {
    // Rt = Cop0->Rd

    recMFC0();
}

void X86DynaRecCPU::testSWInt() {
    if (!m_pcInEBP) gen.MOV32ItoR(PCSX::ix86::EBP, (uint32_t)m_pc);

    m_pcInEBP = true;
    m_stopRecompile = true;

    gen.MOV32MtoR(PCSX::ix86::EDX, (uint32_t)&m_psxRegs.CP0.n.Cause);
    gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.CP0.n.Status);
    gen.AND32RtoR(PCSX::ix86::EAX, PCSX::ix86::EDX);
    gen.AND32ItoR(PCSX::ix86::EAX, 0x300);
    gen.TEST32RtoR(PCSX::ix86::EAX, PCSX::ix86::EAX);
    unsigned slot1 = gen.JE8(0);
    gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.CP0.n.Status);
    gen.AND32ItoR(PCSX::ix86::EAX, 1);
    gen.TEST32RtoR(PCSX::ix86::EAX, PCSX::ix86::EAX);
    unsigned slot2 = gen.JE8(0);
    gen.MOV32ItoM((uint32_t)&m_functionPtr, 0);
    gen.MOV32RtoM((uint32_t)&m_arg1, PCSX::ix86::EDX);
    gen.MOV32ItoM((uint32_t)&m_arg2, m_inDelaySlot);
    gen.MOV32RtoM((uint32_t)&m_psxRegs.pc, PCSX::ix86::EBP);
    gen.MOV32ItoR(PCSX::ix86::EBP, 0xffffffff);
    gen.x86SetJ8(slot1);
    gen.x86SetJ8(slot2);
}

void X86DynaRecCPU::recMTC0() {
    // Cop0->Rd = Rt

    if (IsConst(_Rt_)) {
        if (_Rd_ == 13) {
            gen.MOV32ItoM((uint32_t)&m_psxRegs.CP0.n.Cause, m_iRegs[_Rt_].k & ~(0xfc00));
        } else {
            gen.MOV32ItoM((uint32_t)&m_psxRegs.CP0.r[_Rd_], m_iRegs[_Rt_].k);
        }
    } else {
        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        if (_Rd_ == 13) gen.AND32ItoR(PCSX::ix86::EAX, ~(0xfc00));
        gen.MOV32RtoM((uint32_t)&m_psxRegs.CP0.r[_Rd_], PCSX::ix86::EAX);
    }

    if (_Rd_ == 12 || _Rd_ == 13) testSWInt();
}

void X86DynaRecCPU::recCTC0() {
    // Cop0->Rd = Rt

    recMTC0();
}

void X86DynaRecCPU::recRFE() {
    gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.CP0.n.Status);
    gen.MOV32RtoR(PCSX::ix86::ECX, PCSX::ix86::EAX);
    gen.AND32ItoR(PCSX::ix86::EAX, 0xfffffff0);
    gen.AND32ItoR(PCSX::ix86::ECX, 0x3c);
    gen.SHR32ItoR(PCSX::ix86::ECX, 2);
    gen.OR32RtoR(PCSX::ix86::EAX, PCSX::ix86::ECX);
    gen.MOV32RtoM((uint32_t)&m_psxRegs.CP0.n.Status, PCSX::ix86::EAX);
    testSWInt();
}

// HLEs

void X86DynaRecCPU::recHLE() {
    uint32_t hleCode = PCSX::g_emulator.m_psxCpu->m_psxRegs.code & 0x03ffffff;
    if (hleCode >= (sizeof(psxHLEt) / sizeof(psxHLEt[0]))) {
        recNULL();
    } else {
        if (m_pcInEBP) {
            gen.MOV32RtoM((uint32_t)&m_psxRegs.pc, PCSX::ix86::EBP);
        } else {
            gen.MOV32ItoM((uint32_t)&m_psxRegs.pc, (uint32_t)m_pc);
        }
        gen.MOV32ItoR(PCSX::ix86::EBP, 0xffffffff);
        gen.MOV32ItoM((uint32_t)&m_functionPtr, (uint32_t)psxHLEt[hleCode]);

        m_pcInEBP = true;
        m_stopRecompile = true;
    }
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
    &X86DynaRecCPU::recNULL,    &X86DynaRecCPU::recNULL,   &X86DynaRecCPU::recSWC2, &X86DynaRecCPU::recHLE,    // 38
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
    &X86DynaRecCPU::pgxpRecSWC2, &X86DynaRecCPU::recHLE,        // 3a
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
    &X86DynaRecCPU::pgxpRecSWC2, &X86DynaRecCPU::recHLE,      // 3a
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,     // 3c
    &X86DynaRecCPU::recNULL,     &X86DynaRecCPU::recNULL,     // 3e
};

void X86DynaRecCPU::recRecompile() {
    char *p;

    /* if gen.m_x86Ptr reached the mem limit reset whole mem */
    if (((uint32_t)gen.x86GetPtr() - (uint32_t)m_recMem) >= RECMEM_SIZE) {
        Reset();
    } else {
        gen.x86Align(32);
    }

    m_pc = m_psxRegs.pc;
    uint32_t old_pc = m_pc;
    int8_t *startPtr = gen.x86GetPtr();
    (*(uint32_t *)PC_REC(m_pc)) = (uint32_t)startPtr;
    m_needsStackFrame = false;
    m_pcInEBP = false;
    m_nextIsDelaySlot = false;
    m_inDelaySlot = false;
    m_stopRecompile = false;
    m_currentDelayedLoad = 0;
    m_delayedLoadInfo[0].active = false;
    m_delayedLoadInfo[1].active = false;
    unsigned count = 0;
    gen.PUSH32R(PCSX::ix86::EBP);
    gen.PUSH32R(PCSX::ix86::EBX);
    gen.XOR32RtoR(PCSX::ix86::EBX, PCSX::ix86::EBX);
    gen.PUSH32R(PCSX::ix86::ESI);
    gen.PUSH32R(PCSX::ix86::EDI);
    int8_t *endStackFramePtr = gen.x86GetPtr();

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
            gen.MOV32RtoR(PCSX::ix86::EDX, PCSX::ix86::EBX);
            gen.AND32ItoR(PCSX::ix86::EDX, 0xffff);
            gen.MOV32ItoR(PCSX::ix86::ECX, (uint32_t)MASKS);
            gen.MOV32RmStoR(PCSX::ix86::EAX, PCSX::ix86::ECX, PCSX::ix86::EDX, 2);
            if (IsConst(index)) {
                gen.AND32ItoR(PCSX::ix86::EAX, m_iRegs[index].k);
                gen.OR32RtoR(PCSX::ix86::EAX, PCSX::ix86::ESI);
                gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[index], PCSX::ix86::EAX);
                m_iRegs[index].state = ST_UNK;
            } else {
                gen.AND32RtoM((uint32_t)&m_psxRegs.GPR.r[index], PCSX::ix86::EAX);
                gen.OR32RtoM((uint32_t)&m_psxRegs.GPR.r[index], PCSX::ix86::ESI);
            }
        }
    };

    while (shouldContinue()) {
        if (m_nextIsDelaySlot) {
            m_inDelaySlot = true;
            m_nextIsDelaySlot = false;
        }
        p = (char *)PSXM(m_pc);
        if (p == NULL) {
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
            gen.MOV32RtoR(PCSX::ix86::ESI, PCSX::ix86::EDI);
            gen.SHR32ItoR(PCSX::ix86::EBX, 16);
        }
    }

    // This is slightly inexact: if there's a delayed load in the delay slot of a branch,
    // then we're flushing it early, before the next instruction had a chance to execute.
    // This might be fine still, but it can be arranged if needed.
    processDelayedLoad();

    iFlushRegs();

    count = ((m_pc - old_pc) / 4) * PCSX::Emulator::BIAS;
    gen.ADD32ItoM((uint32_t)&m_psxRegs.cycle, count);

    if (m_pcInEBP) {
        gen.MOV32RtoR(PCSX::ix86::EAX, PCSX::ix86::EBP);
    } else {
        gen.MOV32ItoR(PCSX::ix86::EAX, m_pc);
    }

    if (m_needsStackFrame || m_pcInEBP) {
        gen.POP32R(PCSX::ix86::EDI);
        gen.POP32R(PCSX::ix86::ESI);
        gen.POP32R(PCSX::ix86::EBX);
        gen.POP32R(PCSX::ix86::EBP);
        gen.RET();
    } else {
        ptrdiff_t count = endStackFramePtr - startPtr;
        (*(uint32_t *)PC_REC(old_pc)) = (uint32_t)endStackFramePtr;
        gen.NOP(count, startPtr);
        gen.RET();
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
    virtual void ExecuteHLEBlock() final { abort(); }
    virtual void Clear(uint32_t Addr, uint32_t Size) final { abort(); }
    virtual void Shutdown() final { abort(); }
    virtual void SetPGXPMode(uint32_t pgxpMode) final { abort(); }
};

#endif

}  // namespace

std::unique_ptr<PCSX::R3000Acpu> PCSX::Cpus::getX86DynaRec() {
    return std::unique_ptr<PCSX::R3000Acpu>(new X86DynaRecCPU());
}
