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

#include "core/disr3000a.h"
#include "core/gpu.h"
#include "core/gte.h"
#include "core/ix86/ix86.h"
#include "core/pgxp_cpu.h"
#include "core/pgxp_debug.h"
#include "core/pgxp_gte.h"
#include "core/psxemulator.h"
#include "core/r3000a.h"
#include "spu/interface.h"

namespace {

#if defined(__i386__) || defined(_M_IX86)

#ifndef _WIN32
#ifndef MAP_ANONYMOUS
#ifdef MAP_ANON
#define MAP_ANONYMOUS MAP_ANON
#endif
#endif
#endif

class X86DynaRecCPU;

typedef void (X86DynaRecCPU::*func_t)();
typedef const func_t cfunc_t;

void SysBiosPrintfWrapper(const char *fmt, ...) {
    va_list a;
    va_start(a, fmt);
    PCSX::g_system->biosPrintf(fmt, a);
    va_end(a);
}
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

#undef PC_REC
#undef PC_REC8
#undef PC_REC16
#undef PC_REC32
#define PC_REC(x) (m_psxRecLUT[(x) >> 16] + ((x)&0xffff))
#define PC_REC8(x) (*(uint8_t *)PC_REC(x))
#define PC_REC16(x) (*(uint16_t *)PC_REC(x))
#define PC_REC32(x) (*(uint32_t *)PC_REC(x))

#define IsConst(reg) (m_iRegs[reg].state == ST_CONST)
#define IsMapped(reg) (m_iRegs[reg].state == ST_MAPPED)

class X86DynaRecCPU : public PCSX::InterpretedCPU {
  public:
    X86DynaRecCPU() : InterpretedCPU("x86 DynaRec") {}

  private:
    virtual bool Init() final;
    virtual void Reset() final;
    virtual void Execute() final;
    virtual void ExecuteBlock() final;
    virtual void Clear(uint32_t Addr, uint32_t Size) final;
    virtual void Shutdown() final;
    virtual void SetPGXPMode(uint32_t pgxpMode) final;

    static void psxDelayTestWrapper(X86DynaRecCPU *that, int reg, uint32_t bpc) { that->psxDelayTest(reg, bpc); }
    static void psxTestSWIntsWrapper(X86DynaRecCPU *that) { that->psxTestSWInts(); }
    static void psxBranchTestWrapper(X86DynaRecCPU *that) { that->psxBranchTest(); }
    static void psxExceptionWrapper(X86DynaRecCPU *that, uint32_t c, uint32_t bd) { that->psxException(c, bd); }
    static void recClearWrapper(X86DynaRecCPU *that, uint32_t a, uint32_t s) { that->Clear(a, s); }

    PCSX::ix86 gen;

    uintptr_t *m_psxRecLUT;
    static const size_t RECMEM_SIZE = 8 * 1024 * 1024;

    int8_t *m_recMem; /* the recompiled blocks will be here */
    char *m_recRAM;   /* and the s_ptr to the blocks here */
    char *m_recROM;   /* and here */

    uint32_t m_pc;     /* recompiler pc */
    uint32_t m_old_pc; /* recompiler oldpc */
    uint32_t m_count;  /* recompiler intruction count */
    int m_branch;      /* set for branch */
    uint32_t m_target; /* branch target */
    uint32_t m_resp;

    typedef struct {
        int state;
        uint32_t k;
        int reg;
    } iRegisters;

    iRegisters m_iRegs[32];
    iRegisters m_iRegsS[32];

    static inline const char *txt0 = "PCSX::ix86::EAX = %x : PCSX::ix86::ECX = %x : PCSX::ix86::EDX = %x\n";
    static inline const char *txt1 = "PCSX::ix86::EAX = %x\n";
    static inline const char *txt2 = "M32 = %x\n";

    enum { ST_UNK = 0, ST_CONST = 1, ST_MAPPED = 2 };

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

    static const unsigned int DYNAREC_BLOCK = 50;
    static const size_t ALLOC_SIZE = RECMEM_SIZE + 0x1000;

    void MapConst(int reg, uint32_t _const);
    void iFlushReg(int reg);
    void iFlushRegs();
    void iPushReg(int reg);
    void iStoreCycle();
    void iRet();
    int iLoadTest();
    void SetBranch();
    void iJump(uint32_t branchPC);
    void iBranch(uint32_t branchPC, int savectx);
    void iLogX86();
    void iLogEAX();
    void iLogM32(uint32_t mem);
    void iDumpRegs();
    void iDumpBlock(int8_t *ptr);

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

    void iLWLk(uint32_t shift);
    void recLWL();
    void recLWBlock(int count);

    void iLWRk(uint32_t shift);
    void recLWR();

    void recSB();
    void recSH();
    void recSW();
    void recSWBlock(int count);

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

    void recRecompile();

#define CP2_FUNC(f)                                                         \
    static void gte##f##Wrapper() { PCSX::g_emulator.m_gte->f(); }          \
    void rec##f() {                                                         \
        iFlushRegs();                                                       \
        gen.MOV32ItoM((uint32_t)&m_psxRegs.code, (uint32_t)m_psxRegs.code); \
        gen.CALLFunc((uint32_t)gte##f##Wrapper);                            \
        /*  branch = 2; */                                                  \
    }

    CP2_FUNC(MFC2);
    CP2_FUNC(MTC2);
    CP2_FUNC(CFC2);
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

    void pgxpRecNULL() {}

    uint32_t m_tempAddr = 0;
    uint32_t m_tempReg1 = 0;
    uint32_t m_tempReg2 = 0;

// Choose between debug and direct function
#ifdef PGXP_CPU_DEBUG
#define PGXP_REC_FUNC_OP(pu, op, nReg) PGXP_psxTraceOp##nReg
#define PGXP_DBG_OP_E(op)    \
    gen.PUSH32I(DBG_E_##op); \
    m_resp += 4;
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
        m_resp += 4;                                        \
        rec##op();                                          \
    }

#define PGXP_REC_FUNC_1(pu, op, reg1)                        \
    void pgxpRec##op() {                                     \
        reg1;                                                \
        gen.PUSH32I(m_psxRegs.code);                         \
        PGXP_DBG_OP_E(op)                                    \
        gen.CALLFunc((uint32_t)PGXP_REC_FUNC_OP(pu, op, 1)); \
        m_resp += 8;                                         \
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
        m_resp += (4 * nReg) + 4;                                     \
    }

#define PGXP_REC_FUNC_2(pu, op, reg1, reg2)                  \
    void pgxpRec##op() {                                     \
        reg1;                                                \
        reg2;                                                \
        gen.PUSH32I(m_psxRegs.code);                         \
        PGXP_DBG_OP_E(op)                                    \
        gen.CALLFunc((uint32_t)PGXP_REC_FUNC_OP(pu, op, 2)); \
        m_resp += 12;                                        \
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
        m_resp += 12;                                                         \
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
        m_resp += 12;                                          \
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
        m_resp += 16;                                          \
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
        m_resp += 20;                                            \
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

void X86DynaRecCPU::MapConst(int reg, uint32_t _const) {
    m_iRegs[reg].k = _const;
    m_iRegs[reg].state = ST_CONST;
}

void X86DynaRecCPU::iFlushReg(int reg) {
    if (IsConst(reg)) {
        gen.MOV32ItoM((uint32_t)&m_psxRegs.GPR.r[reg], m_iRegs[reg].k);
    }
    m_iRegs[reg].state = ST_UNK;
}

void X86DynaRecCPU::iFlushRegs() {
    for (int i = 1; i < 32; i++) {
        iFlushReg(i);
    }
}

void X86DynaRecCPU::iPushReg(int reg) {
    if (IsConst(reg)) {
        gen.PUSH32I(m_iRegs[reg].k);
    } else {
        gen.PUSH32M((uint32_t)&m_psxRegs.GPR.r[reg]);
    }
}

void X86DynaRecCPU::iStoreCycle() {
    m_count = ((m_pc - m_old_pc) / 4) * PCSX::Emulator::BIAS;
    gen.ADD32ItoM((uint32_t)&m_psxRegs.cycle, m_count);
}

void X86DynaRecCPU::iRet() {
    iStoreCycle();
    if (m_resp) gen.ADD32ItoR(PCSX::ix86::ESP, m_resp);
    gen.RET();
}

int X86DynaRecCPU::iLoadTest() {
    // check for load delay
    uint32_t tmp = m_psxRegs.code >> 26;
    switch (tmp) {
        case 0x10:  // COP0
            switch (_Rs_) {
                case 0x00:  // MFC0
                case 0x02:  // CFC0
                    return 1;
            }
            break;
        case 0x12:  // COP2
            switch (_Funct_) {
                case 0x00:
                    switch (_Rs_) {
                        case 0x00:  // MFC2
                        case 0x02:  // CFC2
                            return 1;
                    }
                    break;
            }
            break;
        case 0x32:  // LWC2
            return 1;
        default:
            if (tmp >= 0x20 && tmp <= 0x26) {  // LB/LH/LWL/LW/LBU/LHU/LWR
                return 1;
            }
            break;
    }
    return 0;
}

/* set a pending branch */
void X86DynaRecCPU::SetBranch() {
    func_t func;
    m_branch = 1;
    m_psxRegs.code = PSXMu32(m_pc);
    m_pc += 4;

    if (iLoadTest() == 1) {
        iFlushRegs();
        gen.MOV32ItoM((uint32_t)&m_psxRegs.code, m_psxRegs.code);
        /* store cycle */
        m_count = ((m_pc - m_old_pc) / 4) * PCSX::Emulator::BIAS;
        gen.ADD32ItoM((uint32_t)&m_psxRegs.cycle, m_count);
        if (m_resp) gen.ADD32ItoR(PCSX::ix86::ESP, m_resp);

        gen.PUSH32M((uint32_t)&m_target);
        gen.PUSH32I(_Rt_);
        gen.PUSH32I(reinterpret_cast<uintptr_t>(this));
        gen.CALLFunc((uint32_t)psxDelayTestWrapper);
        gen.ADD32ItoR(PCSX::ix86::ESP, 3 * 4);

        gen.RET();
        return;
    }
    switch (m_psxRegs.code >> 26) {
        // Lode Runner (jr - beq)

        // bltz - bgez - bltzal - bgezal / beq - bne - blez - bgtz
        case 0x01:
        case 0x04:
        case 0x05:
        case 0x06:
        case 0x07:
            break;

        default:
            func = m_pRecBSC[m_psxRegs.code >> 26];
            (*this.*func)();
            break;
    }

    iFlushRegs();
    iStoreCycle();
    gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_target);
    gen.MOV32RtoM((uint32_t)&m_psxRegs.pc, PCSX::ix86::EAX);
    gen.PUSH32I(reinterpret_cast<uintptr_t>(this));
    gen.CALLFunc((uint32_t)psxBranchTestWrapper);
    m_resp += 4;

    if (m_resp) gen.ADD32ItoR(PCSX::ix86::ESP, m_resp);
    gen.RET();
}

void X86DynaRecCPU::iJump(uint32_t branchPC) {
    m_branch = 1;
    m_psxRegs.code = PSXMu32(m_pc);
    m_pc += 4;

    if (iLoadTest() == 1) {
        iFlushRegs();
        gen.MOV32ItoM((uint32_t)&m_psxRegs.code, m_psxRegs.code);
        /* store cycle */
        m_count = ((m_pc - m_old_pc) / 4) * PCSX::Emulator::BIAS;
        gen.ADD32ItoM((uint32_t)&m_psxRegs.cycle, m_count);
        if (m_resp) gen.ADD32ItoR(PCSX::ix86::ESP, m_resp);

        gen.PUSH32I(branchPC);
        gen.PUSH32I(_Rt_);
        gen.PUSH32I(reinterpret_cast<uintptr_t>(this));
        gen.CALLFunc((uint32_t)psxDelayTestWrapper);
        gen.ADD32ItoR(PCSX::ix86::ESP, 3 * 4);

        gen.RET();
        return;
    }

    func_t func = m_pRecBSC[m_psxRegs.code >> 26];
    (*this.*func)();

    iFlushRegs();
    iStoreCycle();
    gen.MOV32ItoM((uint32_t)&m_psxRegs.pc, branchPC);
    gen.PUSH32I(reinterpret_cast<uintptr_t>(this));
    gen.CALLFunc((uint32_t)psxBranchTestWrapper);
    m_resp += 4;

    if (m_resp) gen.ADD32ItoR(PCSX::ix86::ESP, m_resp);

    // maybe just happened an interruption, check so
    gen.CMP32ItoM((uint32_t)&m_psxRegs.pc, branchPC);
    unsigned slot1 = gen.JE8(0);
    gen.RET();

    gen.x86SetJ8(slot1);
    gen.MOV32MtoR(PCSX::ix86::EAX, PC_REC(branchPC));
    gen.TEST32RtoR(PCSX::ix86::EAX, PCSX::ix86::EAX);
    unsigned slot2 = gen.JNE8(0);
    gen.RET();

    gen.x86SetJ8(slot2);
    gen.RET();
    gen.JMP32R(PCSX::ix86::EAX);
}

void X86DynaRecCPU::iBranch(uint32_t branchPC, int savectx) {
    uint32_t respold = 0;

    if (savectx) {
        respold = m_resp;
        memcpy(m_iRegsS, m_iRegs, sizeof(m_iRegs));
    }

    m_branch = 1;
    m_psxRegs.code = PSXMu32(m_pc);

    // the delay test is only made when the branch is taken
    // savectx == 0 will mean that :)
    if (savectx == 0 && iLoadTest() == 1) {
        iFlushRegs();
        gen.MOV32ItoM((uint32_t)&m_psxRegs.code, m_psxRegs.code);
        /* store cycle */
        m_count = (((m_pc + 4) - m_old_pc) / 4) * PCSX::Emulator::BIAS;
        gen.ADD32ItoM((uint32_t)&m_psxRegs.cycle, m_count);
        if (m_resp) gen.ADD32ItoR(PCSX::ix86::ESP, m_resp);

        gen.PUSH32I(branchPC);
        gen.PUSH32I(_Rt_);
        gen.PUSH32I(reinterpret_cast<uintptr_t>(this));
        gen.CALLFunc((uint32_t)psxDelayTestWrapper);
        gen.ADD32ItoR(PCSX::ix86::ESP, 3 * 4);

        gen.RET();
        return;
    }

    m_pc += 4;
    func_t func = m_pRecBSC[m_psxRegs.code >> 26];
    (*this.*func)();

    iFlushRegs();
    iStoreCycle();
    gen.MOV32ItoM((uint32_t)&m_psxRegs.pc, branchPC);
    gen.PUSH32I(reinterpret_cast<uintptr_t>(this));
    gen.CALLFunc((uint32_t)psxBranchTestWrapper);
    m_resp += 4;

    if (m_resp) gen.ADD32ItoR(PCSX::ix86::ESP, m_resp);

    // maybe just happened an interruption, check so
    gen.CMP32ItoM((uint32_t)&m_psxRegs.pc, branchPC);
    unsigned slot1 = gen.JE8(0);
    gen.RET();

    gen.x86SetJ8(slot1);
    gen.MOV32MtoR(PCSX::ix86::EAX, PC_REC(branchPC));
    gen.TEST32RtoR(PCSX::ix86::EAX, PCSX::ix86::EAX);
    unsigned slot2 = gen.JNE8(0);
    gen.RET();

    gen.x86SetJ8(slot2);
    gen.JMP32R(PCSX::ix86::EAX);

    m_pc -= 4;
    if (savectx) {
        m_resp = respold;
        memcpy(m_iRegs, m_iRegsS, sizeof(m_iRegs));
    }
}

void X86DynaRecCPU::iLogX86() {
    gen.PUSHA32();

    gen.PUSH32R(PCSX::ix86::EDX);
    gen.PUSH32R(PCSX::ix86::ECX);
    gen.PUSH32R(PCSX::ix86::EAX);
    gen.PUSH32M((uint32_t)&txt0);
    gen.CALLFunc((uint32_t)SysBiosPrintfWrapper);
    gen.ADD32ItoR(PCSX::ix86::ESP, 4 * 4);

    gen.POPA32();
}

void X86DynaRecCPU::iLogEAX() {
    gen.PUSH32R(PCSX::ix86::EAX);
    gen.PUSH32M((uint32_t)&txt1);
    gen.CALLFunc((uint32_t)SysBiosPrintfWrapper);
    gen.ADD32ItoR(PCSX::ix86::ESP, 4 * 2);
}

void X86DynaRecCPU::iLogM32(uint32_t mem) {
    gen.PUSH32M(mem);
    gen.PUSH32M((uint32_t)&txt2);
    gen.CALLFunc((uint32_t)SysBiosPrintfWrapper);
    gen.ADD32ItoR(PCSX::ix86::ESP, 4 * 2);
}

void X86DynaRecCPU::iDumpRegs() {
    int i, j;

    printf("%x %x\n", m_psxRegs.pc, m_psxRegs.cycle);
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 8; j++) printf("%x ", m_psxRegs.GPR.r[j * i]);
        printf("\n");
    }
}

void X86DynaRecCPU::iDumpBlock(int8_t *ptr) {
    FILE *f;
    uint32_t i;

    PCSX::g_system->printf("dump1 %x:%x, %x\n", m_psxRegs.pc, m_pc, m_psxRegs.cycle);

    for (i = m_psxRegs.pc; i < m_pc; i += 4) {
        std::string ins = PCSX::Disasm::asString(PSXMu32(i), 0, i);
        PCSX::g_system->printf("%s\n", ins.c_str());
    }

    fflush(stdout);
    f = fopen("dump1", "w");
    fwrite(ptr, 1, (uint32_t)gen.x86GetPtr() - (uint32_t)ptr, f);
    fclose(f);
    system("ndisasmw -u dump1");
    fflush(stdout);
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
    recMem = (int8_t *)mmap(0, ALLOC_SIZE, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
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
    memset(m_recRAM, 0, 0x200000);
    memset(m_recROM, 0, 0x080000);

    gen.x86Init(m_recMem);

    m_branch = 0;
    memset(m_iRegs, 0, sizeof(m_iRegs));
    m_iRegs[0].state = ST_CONST;
    m_iRegs[0].k = 0;

    InterpretedCPU::Reset();
}

void X86DynaRecCPU::Shutdown() {
    if (m_recMem == NULL) return;
    free(m_psxRecLUT);
#ifndef _WIN32
    munmap(recMem, ALLOC_SIZE);
#else
    VirtualFree(m_recMem, ALLOC_SIZE, MEM_RELEASE);
#endif
    free(m_recRAM);
    free(m_recROM);
    gen.x86Shutdown();
}

void X86DynaRecCPU::recError() {
    PCSX::g_system->hardReset();
    // ClosePlugins();
    PCSX::g_system->message("Unrecoverable error while running recompiler\n");
    PCSX::g_system->runGui();
}

void X86DynaRecCPU::execute() {
    void (**recFunc)() = NULL;
    char *p;
    uint32_t pc = m_psxRegs.pc;

    p = (char *)PC_REC(m_psxRegs.pc);

    if (p != NULL) {
        recFunc = (void (**)())(uint32_t)p;
    } else {
        recError();
        return;
    }

    if (*recFunc == 0) {
        recRecompile();
    }
    (*recFunc)();
}

void X86DynaRecCPU::Execute() {
    while (PCSX::g_system->running()) execute();
}

void X86DynaRecCPU::ExecuteBlock() { execute(); }

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
    //  PCSX::g_system->message("recUNK: %8.8x\n", m_psxRegs.code);
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

    //  iFlushRegs();

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

    //  iFlushRegs();

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

    //  iFlushRegs();

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

    //  iFlushRegs();

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

    //  iFlushRegs();

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

    //  iFlushRegs();

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

    //  iFlushRegs();

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
//#endif
// end of * Arithmetic with immediate operand

/*********************************************************
 * Load higher 16 bits of the first word in GPR with imm  *
 * Format:  OP rt, immediate                              *
 *********************************************************/
/*REC_FUNC(LUI);
#if 0*/
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

    //  iFlushRegs();

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

    //  iFlushRegs();

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

    //  iFlushRegs();

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

    //  iFlushRegs();

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

    //  iFlushRegs();

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

    //  iFlushRegs();

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

    //  iFlushRegs();

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

    //  iFlushRegs();

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
//#endif
// End of * Register arithmetic

/*********************************************************
 * Register mult/div & Register trap logic                *
 * Format:  OP rs, rt                                     *
 *********************************************************/

/*REC_FUNC(MULT);
REC_FUNC(MULTU);
REC_FUNC(DIV);
REC_FUNC(DIVU);
#if 0*/
void X86DynaRecCPU::recMULT() {
    // Lo/Hi = Rs * Rt (signed)

    //  iFlushRegs();

    if ((IsConst(_Rs_) && m_iRegs[_Rs_].k == 0) || (IsConst(_Rt_) && m_iRegs[_Rt_].k == 0)) {
        gen.XOR32RtoR(PCSX::ix86::EAX, PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.lo, PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.hi, PCSX::ix86::EAX);
        return;
    }

    if (IsConst(_Rs_)) {
        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k);  // printf("multrsk %x\n", m_iRegs[_Rs_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
    }
    if (IsConst(_Rt_)) {
        gen.MOV32ItoR(PCSX::ix86::EDX, m_iRegs[_Rt_].k);  // printf("multrtk %x\n", m_iRegs[_Rt_].k);
        gen.IMUL32R(PCSX::ix86::EDX);
    } else {
        gen.IMUL32M((uint32_t)&m_psxRegs.GPR.r[_Rt_]);
    }
    gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.lo, PCSX::ix86::EAX);
    gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.hi, PCSX::ix86::EDX);
}

void X86DynaRecCPU::recMULTU() {
    // Lo/Hi = Rs * Rt (unsigned)

    //  iFlushRegs();

    if ((IsConst(_Rs_) && m_iRegs[_Rs_].k == 0) || (IsConst(_Rt_) && m_iRegs[_Rt_].k == 0)) {
        gen.XOR32RtoR(PCSX::ix86::EAX, PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.lo, PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.hi, PCSX::ix86::EAX);
        return;
    }

    if (IsConst(_Rs_)) {
        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k);  // printf("multursk %x\n", m_iRegs[_Rs_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
    }
    if (IsConst(_Rt_)) {
        gen.MOV32ItoR(PCSX::ix86::EDX, m_iRegs[_Rt_].k);  // printf("multurtk %x\n", m_iRegs[_Rt_].k);
        gen.MUL32R(PCSX::ix86::EDX);
    } else {
        gen.MUL32M((uint32_t)&m_psxRegs.GPR.r[_Rt_]);
    }
    gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.lo, PCSX::ix86::EAX);
    gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.n.hi, PCSX::ix86::EDX);
}

void X86DynaRecCPU::recDIV() {
    // Lo/Hi = Rs / Rt (signed)

    //  iFlushRegs();
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
        gen.MOV32ItoR(PCSX::ix86::ECX, m_iRegs[_Rt_].k);  // printf("divrtk %x\n", m_iRegs[_Rt_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::ECX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.CMP32ItoR(PCSX::ix86::ECX, 0);
        slot1 = gen.JE8(0);
    }
    if (IsConst(_Rs_)) {
        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k);  // printf("divrsk %x\n", m_iRegs[_Rs_].k);
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

    //  iFlushRegs();
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
        gen.MOV32ItoR(PCSX::ix86::ECX, m_iRegs[_Rt_].k);  // printf("divurtk %x\n", m_iRegs[_Rt_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::ECX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.CMP32ItoR(PCSX::ix86::ECX, 0);
        slot1 = gen.JE8(0);
    }
    if (IsConst(_Rs_)) {
        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k);  // printf("divursk %x\n", m_iRegs[_Rs_].k);
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

//#if 0
void X86DynaRecCPU::recLB() {
    // Rt = mem[Rs + Im] (signed)

    //  iFlushRegs();

    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0xfff0) == 0xbfc0) {
            if (!_Rt_) return;
            // since bios is readonly it won't change
            MapConst(_Rt_, psxRs8(addr));
            return;
        }
        if ((t & 0x1fe0) == 0) {
            if (!_Rt_) return;
            m_iRegs[_Rt_].state = ST_UNK;

            gen.MOVSX32M8toR(PCSX::ix86::EAX, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1fffff]);
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            if (!_Rt_) return;
            m_iRegs[_Rt_].state = ST_UNK;

            gen.MOVSX32M8toR(PCSX::ix86::EAX, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xfff]);
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
            return;
        }
        //      PCSX::g_system->printf("unhandled r8 %x\n", addr);
    }

    iPushOfB();
    gen.CALLFunc((uint32_t)psxMemRead8Wrapper);
    if (_Rt_) {
        m_iRegs[_Rt_].state = ST_UNK;
        gen.MOVSX32R8toR(PCSX::ix86::EAX, PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
    }
    //  gen.ADD32ItoR(PCSX::ix86::ESP, 4);
    m_resp += 4;
}

void X86DynaRecCPU::recLBU() {
    // Rt = mem[Rs + Im] (unsigned)

    //  iFlushRegs();

    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0xfff0) == 0xbfc0) {
            if (!_Rt_) return;
            // since bios is readonly it won't change
            MapConst(_Rt_, psxRu8(addr));
            return;
        }
        if ((t & 0x1fe0) == 0) {
            if (!_Rt_) return;
            m_iRegs[_Rt_].state = ST_UNK;

            gen.MOVZX32M8toR(PCSX::ix86::EAX, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1fffff]);
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            if (!_Rt_) return;
            m_iRegs[_Rt_].state = ST_UNK;

            gen.MOVZX32M8toR(PCSX::ix86::EAX, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xfff]);
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
            return;
        }
        //      PCSX::g_system->printf("unhandled r8u %x\n", addr);
    }

    iPushOfB();
    gen.CALLFunc((uint32_t)psxMemRead8Wrapper);
    if (_Rt_) {
        m_iRegs[_Rt_].state = ST_UNK;
        gen.MOVZX32R8toR(PCSX::ix86::EAX, PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
    }
    //  gen.ADD32ItoR(PCSX::ix86::ESP, 4);
    m_resp += 4;
}

void X86DynaRecCPU::recLH() {
    // Rt = mem[Rs + Im] (signed)

    //  iFlushRegs();

    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0xfff0) == 0xbfc0) {
            if (!_Rt_) return;
            // since bios is readonly it won't change
            MapConst(_Rt_, psxRs16(addr));
            return;
        }
        if ((t & 0x1fe0) == 0) {
            if (!_Rt_) return;
            m_iRegs[_Rt_].state = ST_UNK;

            gen.MOVSX32M16toR(PCSX::ix86::EAX, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1fffff]);
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            if (!_Rt_) return;
            m_iRegs[_Rt_].state = ST_UNK;

            gen.MOVSX32M16toR(PCSX::ix86::EAX, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xfff]);
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
            return;
        }
        //      PCSX::g_system->printf("unhandled r16 %x\n", addr);
    }

    iPushOfB();
    gen.CALLFunc((uint32_t)psxMemRead16Wrapper);
    if (_Rt_) {
        m_iRegs[_Rt_].state = ST_UNK;
        gen.MOVSX32R16toR(PCSX::ix86::EAX, PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
    }
    //  gen.ADD32ItoR(PCSX::ix86::ESP, 4);
    m_resp += 4;
}

void X86DynaRecCPU::recLHU() {
    // Rt = mem[Rs + Im] (unsigned)

    //  iFlushRegs();

    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0xfff0) == 0xbfc0) {
            if (!_Rt_) return;
            // since bios is readonly it won't change
            MapConst(_Rt_, psxRu16(addr));
            return;
        }
        if ((t & 0x1fe0) == 0) {
            if (!_Rt_) return;
            m_iRegs[_Rt_].state = ST_UNK;

            gen.MOVZX32M16toR(PCSX::ix86::EAX, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1fffff]);
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            if (!_Rt_) return;
            m_iRegs[_Rt_].state = ST_UNK;

            gen.MOVZX32M16toR(PCSX::ix86::EAX, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xfff]);
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
            return;
        }
        if (t == 0x1f80) {
            if (addr >= 0x1f801c00 && addr < 0x1f801e00) {
                if (!_Rt_) return;
                m_iRegs[_Rt_].state = ST_UNK;

                gen.PUSH32I(addr);
                gen.CALLFunc((uint32_t)SPUreadRegisterWrapper);
                gen.MOVZX32R16toR(PCSX::ix86::EAX, PCSX::ix86::EAX);
                gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
#ifndef __WIN33
                m_resp += 4;
#endif
                return;
            }
            switch (addr) {
                case 0x1f801100:
                case 0x1f801110:
                case 0x1f801120:
                    if (!_Rt_) return;
                    m_iRegs[_Rt_].state = ST_UNK;

                    gen.PUSH32I((addr >> 4) & 0x3);
                    gen.CALLFunc((uint32_t)psxRcntRcountWrapper);
                    gen.MOVZX32R16toR(PCSX::ix86::EAX, PCSX::ix86::EAX);
                    gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
                    m_resp += 4;
                    return;

                case 0x1f801104:
                case 0x1f801114:
                case 0x1f801124:
                    if (!_Rt_) return;
                    m_iRegs[_Rt_].state = ST_UNK;

                    gen.PUSH32I((addr >> 4) & 0x3);
                    gen.CALLFunc((uint32_t)psxRcntRmodeWrapper);
                    gen.MOVZX32R16toR(PCSX::ix86::EAX, PCSX::ix86::EAX);
                    gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
                    m_resp += 4;
                    return;

                case 0x1f801108:
                case 0x1f801118:
                case 0x1f801128:
                    if (!_Rt_) return;
                    m_iRegs[_Rt_].state = ST_UNK;

                    gen.PUSH32I((addr >> 4) & 0x3);
                    gen.CALLFunc((uint32_t)psxRcntRtargetWrapper);
                    gen.MOVZX32R16toR(PCSX::ix86::EAX, PCSX::ix86::EAX);
                    gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
                    m_resp += 4;
                    return;
            }
        }
        //      PCSX::g_system->printf("unhandled r16u %x\n", addr);
    }

    iPushOfB();
    gen.CALLFunc((uint32_t)psxMemRead16Wrapper);
    if (_Rt_) {
        m_iRegs[_Rt_].state = ST_UNK;
        gen.MOVZX32R16toR(PCSX::ix86::EAX, PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
    }
    //  gen.ADD32ItoR(PCSX::ix86::ESP, 4);
    m_resp += 4;
}

void X86DynaRecCPU::recLW() {
    // Rt = mem[Rs + Im] (unsigned)

    //  iFlushRegs();

    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0xfff0) == 0xbfc0) {
            if (!_Rt_) return;
            // since bios is readonly it won't change
            MapConst(_Rt_, psxRu32(addr));
            return;
        }
        if ((t & 0x1fe0) == 0) {
            if (!_Rt_) return;
            m_iRegs[_Rt_].state = ST_UNK;

            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1fffff]);
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            if (!_Rt_) return;
            m_iRegs[_Rt_].state = ST_UNK;

            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xfff]);
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
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
                    m_iRegs[_Rt_].state = ST_UNK;

                    gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xffff]);
                    gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
                    return;

                case 0x1f801810:
                    if (!_Rt_) return;
                    m_iRegs[_Rt_].state = ST_UNK;

                    gen.CALLFunc((uint32_t)&GPU_readDataWrapper);
                    gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
                    return;

                case 0x1f801814:
                    if (!_Rt_) return;
                    m_iRegs[_Rt_].state = ST_UNK;

                    gen.CALLFunc((uint32_t)&GPU_readStatusWrapper);
                    gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
                    return;
            }
        }
        //      PCSX::g_system->printf("unhandled r32 %x\n", addr);
    }

    iPushOfB();
    gen.CALLFunc((uint32_t)psxMemRead32Wrapper);
    if (_Rt_) {
        m_iRegs[_Rt_].state = ST_UNK;
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
    }
    //  gen.ADD32ItoR(PCSX::ix86::ESP, 4);
    m_resp += 4;
}

void X86DynaRecCPU::iLWLk(uint32_t shift) {
    if (IsConst(_Rt_)) {
        gen.MOV32ItoR(PCSX::ix86::ECX, m_iRegs[_Rt_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::ECX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
    }
    gen.AND32ItoR(PCSX::ix86::ECX, g_LWL_MASK[shift]);
    gen.SHL32ItoR(PCSX::ix86::EAX, g_LWL_SHIFT[shift]);
    gen.OR32RtoR(PCSX::ix86::EAX, PCSX::ix86::ECX);
}

void X86DynaRecCPU::recLWL() {
    // Rt = Rt Merge mem[Rs + Im]

    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0x1fe0) == 0) {
            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1ffffc]);
            iLWLk(addr & 3);

            m_iRegs[_Rt_].state = ST_UNK;
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xffc]);
            iLWLk(addr & 3);

            m_iRegs[_Rt_].state = ST_UNK;
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
            return;
        }
    }

    if (IsConst(_Rs_))
        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k + _Imm_);
    else {
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

        gen.MOV32ItoR(PCSX::ix86::ECX, (uint32_t)g_LWL_SHIFT);
        gen.MOV32RmStoR(PCSX::ix86::ECX, PCSX::ix86::ECX, PCSX::ix86::EDX, 2);
        gen.SHL32CLtoR(PCSX::ix86::EAX);  // mem(PCSX::ix86::EAX) << g_LWL_SHIFT[shift]

        gen.MOV32ItoR(PCSX::ix86::ECX, (uint32_t)g_LWL_MASK);
        gen.MOV32RmStoR(PCSX::ix86::ECX, PCSX::ix86::ECX, PCSX::ix86::EDX, 2);
        if (IsConst(_Rt_)) {
            gen.MOV32ItoR(PCSX::ix86::EDX, m_iRegs[_Rt_].k);
        } else {
            gen.MOV32MtoR(PCSX::ix86::EDX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        }
        gen.AND32RtoR(PCSX::ix86::EDX, PCSX::ix86::ECX);  // _rRt_ & g_LWL_MASK[shift]

        gen.OR32RtoR(PCSX::ix86::EAX, PCSX::ix86::EDX);

        m_iRegs[_Rt_].state = ST_UNK;
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
    } else {
        //      gen.ADD32ItoR(PCSX::ix86::ESP, 8);
        m_resp += 8;
    }
}

#if 0
 void X86DynaRecCPU::recLWBlock(int count) {
    uint32_t *code = (uint32_t *)PSXM(pc);
    int i, respsave;
// Rt = mem[Rs + Im] (unsigned)

//  iFlushRegs();

    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0xfff0) == 0xbfc0) {
            // since bios is readonly it won't change
            for (i = 0; i < count; i++, code++, addr += 4) {
                if (_fRt_(*code)) {
                    MapConst(_fRt_(*code), psxRu32(addr));
                }
            }
            return;
        }
        if ((t & 0x1fe0) == 0) {
            for (i = 0; i < count; i++, code++, addr += 4) {
                if (!_fRt_(*code))
                    return;
                m_iRegs[_fRt_(*code)].state = ST_UNK;

                gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1fffff]);
                gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_fRt_(*code)], PCSX::ix86::EAX);
            }
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            for (i = 0; i < count; i++, code++, addr += 4) {
                if (!_fRt_(*code))
                    return;
                m_iRegs[_fRt_(*code)].state = ST_UNK;

                gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&g_psxH[addr & 0xfff]);
                gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_fRt_(*code)], PCSX::ix86::EAX);
            }
            return;
        }
    }

    PCSX::g_system->printf("recLWBlock %d: %d\n", count, IsConst(_Rs_));
    iPushOfB();
    gen.CALLFunc((uint32_t)psxMemPointer);
//  gen.ADD32ItoR(PCSX::ix86::ESP, 4);
    m_resp += 4;

    respsave = m_resp; m_resp = 0;
    gen.TEST32RtoR(PCSX::ix86::EAX, PCSX::ix86::EAX);
    unsigned slot1 = gen.JZ32(0);
    gen.XOR32RtoR(PCSX::ix86::ECX, PCSX::ix86::ECX);
    for (i = 0; i < count; i++, code++) {
        if (_fRt_(*code)) {
            m_iRegs[_fRt_(*code)].state = ST_UNK;

            gen.MOV32RmStoR(PCSX::ix86::EDX, PCSX::ix86::EAX, PCSX::ix86::ECX, 2);
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_fRt_(*code)], PCSX::ix86::EDX);
        }
        if (i != (count - 1))
            gen.INC32R(PCSX::ix86::ECX);
    }
    unsigned slot2 = JMP32(0);
    gen.x86SetJ32(slot1);
    for (i = 0, code = (uint32_t *)PSXM(pc); i < count; i++, code++) {
        m_psxRegs.code = *code;
        recLW();
    }
    gen.ADD32ItoR(PCSX::ix86::ESP, m_resp);
    gen.x86SetJ32(slot2);
    m_resp = respsave;
}
#endif

void X86DynaRecCPU::iLWRk(uint32_t shift) {
    if (IsConst(_Rt_)) {
        gen.MOV32ItoR(PCSX::ix86::ECX, m_iRegs[_Rt_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::ECX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
    }
    gen.AND32ItoR(PCSX::ix86::ECX, g_LWR_MASK[shift]);
    gen.SHR32ItoR(PCSX::ix86::EAX, g_LWR_SHIFT[shift]);
    gen.OR32RtoR(PCSX::ix86::EAX, PCSX::ix86::ECX);
}

void X86DynaRecCPU::recLWR() {
    // Rt = Rt Merge mem[Rs + Im]

    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0x1fe0) == 0) {
            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1ffffc]);
            iLWRk(addr & 3);

            m_iRegs[_Rt_].state = ST_UNK;
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&PCSX::g_emulator.m_psxMem->g_psxH[addr & 0xffc]);
            iLWRk(addr & 3);

            m_iRegs[_Rt_].state = ST_UNK;
            gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
            return;
        }
    }

    if (IsConst(_Rs_))
        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rs_].k + _Imm_);
    else {
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

        gen.MOV32ItoR(PCSX::ix86::ECX, (uint32_t)g_LWR_SHIFT);
        gen.MOV32RmStoR(PCSX::ix86::ECX, PCSX::ix86::ECX, PCSX::ix86::EDX, 2);
        gen.SHR32CLtoR(PCSX::ix86::EAX);  // mem(PCSX::ix86::EAX) >> g_LWR_SHIFT[shift]

        gen.MOV32ItoR(PCSX::ix86::ECX, (uint32_t)g_LWR_MASK);
        gen.MOV32RmStoR(PCSX::ix86::ECX, PCSX::ix86::ECX, PCSX::ix86::EDX, 2);

        if (IsConst(_Rt_)) {
            gen.MOV32ItoR(PCSX::ix86::EDX, m_iRegs[_Rt_].k);
        } else {
            gen.MOV32MtoR(PCSX::ix86::EDX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        }
        gen.AND32RtoR(PCSX::ix86::EDX, PCSX::ix86::ECX);  // _rRt_ & g_LWR_MASK[shift]

        gen.OR32RtoR(PCSX::ix86::EAX, PCSX::ix86::EDX);

        m_iRegs[_Rt_].state = ST_UNK;
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], PCSX::ix86::EAX);
    } else {
        //      gen.ADD32ItoR(PCSX::ix86::ESP, 8);
        m_resp += 8;
    }
}

void X86DynaRecCPU::recSB() {
    // mem[Rs + Im] = Rt

    //  iFlushRegs();

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
            m_resp += 12;
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
    //  gen.ADD32ItoR(PCSX::ix86::ESP, 8);
    m_resp += 8;
}

void X86DynaRecCPU::recSH() {
    // mem[Rs + Im] = Rt

    //  iFlushRegs();

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
            m_resp += 12;
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
                m_resp += 8;
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
    //  gen.ADD32ItoR(PCSX::ix86::ESP, 8);
    m_resp += 8;
}

void X86DynaRecCPU::recSW() {
    // mem[Rs + Im] = Rt

    //  iFlushRegs();

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
            m_resp += 12;
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
                    m_resp += 4;
                    return;

                case 0x1f801814:
                    if (IsConst(_Rt_)) {
                        gen.PUSH32I(m_iRegs[_Rt_].k);
                    } else {
                        gen.PUSH32M((uint32_t)&m_psxRegs.GPR.r[_Rt_]);
                    }
                    gen.CALLFunc((uint32_t)&GPU_writeStatusWrapper);
                    m_resp += 4;
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
    //  gen.ADD32ItoR(PCSX::ix86::ESP, 8);
    m_resp += 8;
}
//#endif

#if 0
 void X86DynaRecCPU::recSWBlock(int count) {
    uint32_t *code;
    int i, respsave;
// mem[Rs + Im] = Rt

//  iFlushRegs();

    if (IsConst(_Rs_)) {
        uint32_t addr = m_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;
        code = (uint32_t *)PSXM(pc);

        if ((t & 0x1fe0) == 0 && (t & 0x1fff) != 0) {
            for (i = 0; i < count; i++, code++, addr += 4) {
                if (IsConst(_fRt_(*code))) {
                    gen.MOV32ItoM((uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1fffff], m_iRegs[_fRt_(*code)].k);
                } else {
                    gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_fRt_(*code)]);
                    gen.MOV32RtoM((uint32_t)&PCSX::g_emulator.m_psxMem->g_psxM[addr & 0x1fffff], PCSX::ix86::EAX);
                }
            }
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            for (i = 0; i < count; i++, code++, addr += 4) {
                if (!_fRt_(*code))
                    return;
                m_iRegs[_fRt_(*code)].state = ST_UNK;

                gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&g_psxH[addr & 0xfff]);
                gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_fRt_(*code)], PCSX::ix86::EAX);
            }
            return;
        }
    }

    PCSX::g_system->printf("recSWBlock %d: %d\n", count, IsConst(_Rs_));
    iPushOfB();
    gen.CALLFunc((uint32_t)psxMemPointer);
//  gen.ADD32ItoR(PCSX::ix86::ESP, 4);
    m_resp += 4;

    respsave = m_resp;
    m_resp = 0;
    gen.TEST32RtoR(PCSX::ix86::EAX, PCSX::ix86::EAX);
    unsigned slot1 = gen.JZ32(0);
    gen.XOR32RtoR(PCSX::ix86::ECX, PCSX::ix86::ECX);
    for (i = 0, code = (uint32_t *)PSXM(pc); i < count; i++, code++) {
        if (IsConst(_fRt_(*code))) {
            gen.MOV32ItoR(PCSX::ix86::EDX, m_iRegs[_fRt_(*code)].k);
        } else {
            gen.MOV32MtoR(PCSX::ix86::EDX, (uint32_t)&m_psxRegs.GPR.r[_fRt_(*code)]);
        }
        gen.MOV32RtoRmS(PCSX::ix86::EAX, PCSX::ix86::ECX, 2, PCSX::ix86::EDX);
        if (i != (count - 1))
            gen.INC32R(PCSX::ix86::ECX);
    }
    unsigned slot2 = JMP32(0);
    gen.x86SetJ32(slot1);
    for (i = 0, code = (uint32_t *)PSXM(pc); i < count; i++, code++) {
        m_psxRegs.code = *code;
        recSW();
    }
    gen.ADD32ItoR(PCSX::ix86::ESP, m_resp);
    gen.x86SetJ32(slot2);
    m_resp = respsave;
}
#endif

void X86DynaRecCPU::iSWLk(uint32_t shift) {
    if (IsConst(_Rt_)) {
        gen.MOV32ItoR(PCSX::ix86::ECX, m_iRegs[_Rt_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::ECX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
    }
    gen.SHR32ItoR(PCSX::ix86::ECX, g_SWL_SHIFT[shift]);
    gen.AND32ItoR(PCSX::ix86::EAX, g_SWL_MASK[shift]);
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

    gen.MOV32ItoR(PCSX::ix86::ECX, (uint32_t)g_SWL_MASK);
    gen.MOV32RmStoR(PCSX::ix86::ECX, PCSX::ix86::ECX, PCSX::ix86::EDX, 2);
    gen.AND32RtoR(PCSX::ix86::EAX, PCSX::ix86::ECX);  // mem & g_SWL_MASK[shift]

    gen.MOV32ItoR(PCSX::ix86::ECX, (uint32_t)g_SWL_SHIFT);
    gen.MOV32RmStoR(PCSX::ix86::ECX, PCSX::ix86::ECX, PCSX::ix86::EDX, 2);
    if (IsConst(_Rt_)) {
        gen.MOV32ItoR(PCSX::ix86::EDX, m_iRegs[_Rt_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::EDX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
    }
    gen.SHR32CLtoR(PCSX::ix86::EDX);  // _rRt_ >> g_SWL_SHIFT[shift]

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
    //  gen.ADD32ItoR(PCSX::ix86::ESP, 8);
    m_resp += 8;
}

void X86DynaRecCPU::iSWRk(uint32_t shift) {
    if (IsConst(_Rt_)) {
        gen.MOV32ItoR(PCSX::ix86::ECX, m_iRegs[_Rt_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::ECX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
    }
    gen.SHL32ItoR(PCSX::ix86::ECX, g_SWR_SHIFT[shift]);
    gen.AND32ItoR(PCSX::ix86::EAX, g_SWR_MASK[shift]);
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

    gen.MOV32ItoR(PCSX::ix86::ECX, (uint32_t)g_SWR_MASK);
    gen.MOV32RmStoR(PCSX::ix86::ECX, PCSX::ix86::ECX, PCSX::ix86::EDX, 2);
    gen.AND32RtoR(PCSX::ix86::EAX, PCSX::ix86::ECX);  // mem & g_SWR_MASK[shift]

    gen.MOV32ItoR(PCSX::ix86::ECX, (uint32_t)g_SWR_SHIFT);
    gen.MOV32RmStoR(PCSX::ix86::ECX, PCSX::ix86::ECX, PCSX::ix86::EDX, 2);
    if (IsConst(_Rt_)) {
        gen.MOV32ItoR(PCSX::ix86::EDX, m_iRegs[_Rt_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::EDX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
    }
    gen.SHL32CLtoR(PCSX::ix86::EDX);  // _rRt_ << g_SWR_SHIFT[shift]

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
    //  gen.ADD32ItoR(PCSX::ix86::ESP, 8);
    m_resp += 8;
}

void X86DynaRecCPU::recSLL() {
    // Rd = Rt << Sa
    if (!_Rd_) return;

    //  iFlushRegs();

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

    //  iFlushRegs();

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
        MapConst(_Rd_, m_iRegs[_Rt_].k << m_iRegs[_Rs_].k);
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.MOV32ItoR(PCSX::ix86::ECX, m_iRegs[_Rs_].k);
        gen.SHL32CLtoR(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rt_].k);
        gen.MOV32MtoR(PCSX::ix86::ECX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.SHL32CLtoR(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.MOV32MtoR(PCSX::ix86::ECX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.SHL32CLtoR(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    }
}

void X86DynaRecCPU::recSRLV() {
    // Rd = Rt >> Rs
    if (!_Rd_) return;

    if (IsConst(_Rt_) && IsConst(_Rs_)) {
        MapConst(_Rd_, m_iRegs[_Rt_].k >> m_iRegs[_Rs_].k);
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.MOV32ItoR(PCSX::ix86::ECX, m_iRegs[_Rs_].k);
        gen.SHR32CLtoR(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rt_].k);
        gen.MOV32MtoR(PCSX::ix86::ECX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.SHR32CLtoR(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.MOV32MtoR(PCSX::ix86::ECX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.SHR32CLtoR(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    }
}

void X86DynaRecCPU::recSRAV() {
    // Rd = Rt >> Rs
    if (!_Rd_) return;

    if (IsConst(_Rt_) && IsConst(_Rs_)) {
        MapConst(_Rd_, (int32_t)m_iRegs[_Rt_].k >> m_iRegs[_Rs_].k);
    } else if (IsConst(_Rs_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.MOV32ItoR(PCSX::ix86::ECX, m_iRegs[_Rs_].k);
        gen.SAR32CLtoR(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else if (IsConst(_Rt_)) {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32ItoR(PCSX::ix86::EAX, m_iRegs[_Rt_].k);
        gen.MOV32MtoR(PCSX::ix86::ECX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.SAR32CLtoR(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    } else {
        m_iRegs[_Rd_].state = ST_UNK;

        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        gen.MOV32MtoR(PCSX::ix86::ECX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.SAR32CLtoR(PCSX::ix86::EAX);
        gen.MOV32RtoM((uint32_t)&m_psxRegs.GPR.r[_Rd_], PCSX::ix86::EAX);
    }
}

void X86DynaRecCPU::recSYSCALL() {
    iFlushRegs();

    gen.MOV32ItoR(PCSX::ix86::EAX, m_pc - 4);
    gen.MOV32RtoM((uint32_t)&m_psxRegs.pc, PCSX::ix86::EAX);
    gen.PUSH32I(m_branch == 1 ? 1 : 0);
    gen.PUSH32I(0x20);
    gen.PUSH32I(reinterpret_cast<uintptr_t>(this));
    gen.CALLFunc((uint32_t)psxExceptionWrapper);
    gen.ADD32ItoR(PCSX::ix86::ESP, 12);

    m_branch = 2;
    iRet();
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
    uint32_t bpc = _Imm_ * 4 + m_pc;

    //  iFlushRegs();

    if (bpc == m_pc + 4 && psxTestLoadDelay(_Rs_, PSXMu32(bpc)) == 0) {
        return;
    }

    if (IsConst(_Rs_)) {
        if ((int32_t)m_iRegs[_Rs_].k < 0) {
            iJump(bpc);
            return;
        } else {
            iJump(m_pc + 4);
            return;
        }
    }

    gen.CMP32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rs_], 0);
    unsigned slot = gen.JL32(0);

    iBranch(m_pc + 4, 1);

    gen.x86SetJ32(slot);

    iBranch(bpc, 0);
    m_pc += 4;
}

void X86DynaRecCPU::recBGTZ() {
    // Branch if Rs > 0
    uint32_t bpc = _Imm_ * 4 + m_pc;

    //  iFlushRegs();
    if (bpc == m_pc + 4 && psxTestLoadDelay(_Rs_, PSXMu32(bpc)) == 0) {
        return;
    }

    if (IsConst(_Rs_)) {
        if ((int32_t)m_iRegs[_Rs_].k > 0) {
            iJump(bpc);
            return;
        } else {
            iJump(m_pc + 4);
            return;
        }
    }

    gen.CMP32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rs_], 0);
    unsigned slot = gen.JG32(0);

    iBranch(m_pc + 4, 1);

    gen.x86SetJ32(slot);

    iBranch(bpc, 0);
    m_pc += 4;
}

void X86DynaRecCPU::recBLTZAL() {
    // Branch if Rs < 0
    uint32_t bpc = _Imm_ * 4 + m_pc;

    //  iFlushRegs();
    if (bpc == m_pc + 4 && psxTestLoadDelay(_Rs_, PSXMu32(bpc)) == 0) {
        return;
    }

    if (IsConst(_Rs_)) {
        if ((int32_t)m_iRegs[_Rs_].k < 0) {
            gen.MOV32ItoM((uint32_t)&m_psxRegs.GPR.r[31], m_pc + 4);
            iJump(bpc);
            return;
        } else {
            iJump(m_pc + 4);
            return;
        }
    }

    gen.CMP32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rs_], 0);
    unsigned slot = gen.JL32(0);

    iBranch(m_pc + 4, 1);

    gen.x86SetJ32(slot);

    gen.MOV32ItoM((uint32_t)&m_psxRegs.GPR.r[31], m_pc + 4);
    iBranch(bpc, 0);
    m_pc += 4;
}

void X86DynaRecCPU::recBGEZAL() {
    // Branch if Rs >= 0
    uint32_t bpc = _Imm_ * 4 + m_pc;

    //  iFlushRegs();
    if (bpc == m_pc + 4 && psxTestLoadDelay(_Rs_, PSXMu32(bpc)) == 0) {
        return;
    }

    if (IsConst(_Rs_)) {
        if ((int32_t)m_iRegs[_Rs_].k >= 0) {
            gen.MOV32ItoM((uint32_t)&m_psxRegs.GPR.r[31], m_pc + 4);
            iJump(bpc);
            return;
        } else {
            iJump(m_pc + 4);
            return;
        }
    }

    gen.CMP32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rs_], 0);
    unsigned slot = gen.JGE32(0);

    iBranch(m_pc + 4, 1);

    gen.x86SetJ32(slot);

    gen.MOV32ItoM((uint32_t)&m_psxRegs.GPR.r[31], m_pc + 4);
    iBranch(bpc, 0);
    m_pc += 4;
}

void X86DynaRecCPU::recJ() {
    // j target

    iJump(_Target_ * 4 + (m_pc & 0xf0000000));
}

void X86DynaRecCPU::recJAL() {
    // jal target

    MapConst(31, m_pc + 4);

    iJump(_Target_ * 4 + (m_pc & 0xf0000000));
}

void X86DynaRecCPU::recJR() {
    // jr Rs

    if (IsConst(_Rs_)) {
        gen.MOV32ItoM((uint32_t)&m_target, m_iRegs[_Rs_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.MOV32RtoM((uint32_t)&m_target, PCSX::ix86::EAX);
    }

    SetBranch();
}

void X86DynaRecCPU::recJALR() {
    // jalr Rs

    if (IsConst(_Rs_)) {
        gen.MOV32ItoM((uint32_t)&m_target, m_iRegs[_Rs_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.MOV32RtoM((uint32_t)&m_target, PCSX::ix86::EAX);
    }

    if (_Rd_) {
        MapConst(_Rd_, m_pc + 4);
    }

    SetBranch();
}

void X86DynaRecCPU::recBEQ() {
    // Branch if Rs == Rt
    uint32_t bpc = _Imm_ * 4 + m_pc;

    //  iFlushRegs();
    if (bpc == m_pc + 4 && psxTestLoadDelay(_Rs_, PSXMu32(bpc)) == 0) {
        return;
    }

    if (_Rs_ == _Rt_) {
        iJump(bpc);
    } else {
        if (IsConst(_Rs_) && IsConst(_Rt_)) {
            if (m_iRegs[_Rs_].k == m_iRegs[_Rt_].k) {
                iJump(bpc);
                return;
            } else {
                iJump(m_pc + 4);
                return;
            }
        } else if (IsConst(_Rs_)) {
            gen.CMP32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], m_iRegs[_Rs_].k);
        } else if (IsConst(_Rt_)) {
            gen.CMP32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rs_], m_iRegs[_Rt_].k);
        } else {
            gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
            gen.CMP32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        }

        unsigned slot = gen.JE32(0);

        iBranch(m_pc + 4, 1);

        gen.x86SetJ32(slot);

        iBranch(bpc, 0);
        m_pc += 4;
    }
}

void X86DynaRecCPU::recBNE() {
    // Branch if Rs != Rt
    uint32_t bpc = _Imm_ * 4 + m_pc;

    //  iFlushRegs();
    if (bpc == m_pc + 4 && psxTestLoadDelay(_Rs_, PSXMu32(bpc)) == 0) {
        return;
    }

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        if (m_iRegs[_Rs_].k != m_iRegs[_Rt_].k) {
            iJump(bpc);
            return;
        } else {
            iJump(m_pc + 4);
            return;
        }
    } else if (IsConst(_Rs_)) {
        gen.CMP32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rt_], m_iRegs[_Rs_].k);
    } else if (IsConst(_Rt_)) {
        gen.CMP32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rs_], m_iRegs[_Rt_].k);
    } else {
        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rs_]);
        gen.CMP32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
    }
    unsigned slot = gen.JNE32(0);

    iBranch(m_pc + 4, 1);

    gen.x86SetJ32(slot);

    iBranch(bpc, 0);
    m_pc += 4;
}

void X86DynaRecCPU::recBLEZ() {
    // Branch if Rs <= 0
    uint32_t bpc = _Imm_ * 4 + m_pc;

    //  iFlushRegs();
    if (bpc == m_pc + 4 && psxTestLoadDelay(_Rs_, PSXMu32(bpc)) == 0) {
        return;
    }

    if (IsConst(_Rs_)) {
        if ((int32_t)m_iRegs[_Rs_].k <= 0) {
            iJump(bpc);
            return;
        } else {
            iJump(m_pc + 4);
            return;
        }
    }

    gen.CMP32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rs_], 0);
    unsigned slot = gen.JLE32(0);

    iBranch(m_pc + 4, 1);

    gen.x86SetJ32(slot);

    iBranch(bpc, 0);
    m_pc += 4;
}

void X86DynaRecCPU::recBGEZ() {
    // Branch if Rs >= 0
    uint32_t bpc = _Imm_ * 4 + m_pc;

    //  iFlushRegs();
    if (bpc == m_pc + 4 && psxTestLoadDelay(_Rs_, PSXMu32(bpc)) == 0) {
        return;
    }

    if (IsConst(_Rs_)) {
        if ((int32_t)m_iRegs[_Rs_].k >= 0) {
            iJump(bpc);
            return;
        } else {
            iJump(m_pc + 4);
            return;
        }
    }

    gen.CMP32ItoM((uint32_t)&m_psxRegs.GPR.r[_Rs_], 0);
    unsigned slot = gen.JGE32(0);

    iBranch(m_pc + 4, 1);

    gen.x86SetJ32(slot);

    iBranch(bpc, 0);
    m_pc += 4;
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

void X86DynaRecCPU::recMTC0() {
    // Cop0->Rd = Rt

    if (IsConst(_Rt_)) {
        switch (_Rd_) {
            case 12:
                gen.MOV32ItoM((uint32_t)&m_psxRegs.CP0.r[_Rd_], m_iRegs[_Rt_].k);
                break;
            case 13:
                gen.MOV32ItoM((uint32_t)&m_psxRegs.CP0.r[_Rd_], m_iRegs[_Rt_].k & ~(0xfc00));
                break;
            default:
                gen.MOV32ItoM((uint32_t)&m_psxRegs.CP0.r[_Rd_], m_iRegs[_Rt_].k);
                break;
        }
    } else {
        gen.MOV32MtoR(PCSX::ix86::EAX, (uint32_t)&m_psxRegs.GPR.r[_Rt_]);
        switch (_Rd_) {
            case 13:
                gen.AND32ItoR(PCSX::ix86::EAX, ~(0xfc00));
                break;
        }
        gen.MOV32RtoM((uint32_t)&m_psxRegs.CP0.r[_Rd_], PCSX::ix86::EAX);
    }

    if (_Rd_ == 12 || _Rd_ == 13) {
        iFlushRegs();
        gen.MOV32ItoM((uint32_t)&m_psxRegs.pc, (uint32_t)m_pc);
        gen.PUSH32I(reinterpret_cast<uintptr_t>(this));
        gen.CALLFunc((uint32_t)psxTestSWIntsWrapper);
        gen.ADD32ItoR(PCSX::ix86::ESP, 4);
        if (m_branch == 0) {
            m_branch = 2;
            iRet();
        }
    }
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

    iFlushRegs();
    gen.MOV32ItoM((uint32_t)&m_psxRegs.pc, (uint32_t)m_pc);
    gen.PUSH32I(reinterpret_cast<uintptr_t>(this));
    gen.CALLFunc((uint32_t)psxTestSWIntsWrapper);
    gen.ADD32ItoR(PCSX::ix86::ESP, 4);
    if (m_branch == 0) {
        m_branch = 2;
        iRet();
    }
}

//

void X86DynaRecCPU::recHLE() {
    iFlushRegs();

    uint32_t hleCode = PCSX::g_emulator.m_psxCpu->m_psxRegs.code & 0x03ffffff;
    if (hleCode >= (sizeof(psxHLEt) / sizeof(psxHLEt[0]))) {
        recNULL();
    } else {
        gen.MOV32ItoR(PCSX::ix86::EAX, (uint32_t)psxHLEt[hleCode]);
        gen.CALL32R(PCSX::ix86::EAX);
        m_branch = 2;
        iRet();
    }
}

const func_t X86DynaRecCPU::m_recBSC[64] = {
    &recSPECIAL, &recREGIMM, &recJ,    &recJAL,   &recBEQ,  &recBNE,  &recBLEZ, &recBGTZ,  // 00
    &recADDI,    &recADDIU,  &recSLTI, &recSLTIU, &recANDI, &recORI,  &recXORI, &recLUI,   // 08
    &recCOP0,    &recNULL,   &recCOP2, &recNULL,  &recNULL, &recNULL, &recNULL, &recNULL,  // 10
    &recNULL,    &recNULL,   &recNULL, &recNULL,  &recNULL, &recNULL, &recNULL, &recNULL,  // 18
    &recLB,      &recLH,     &recLWL,  &recLW,    &recLBU,  &recLHU,  &recLWR,  &recNULL,  // 20
    &recSB,      &recSH,     &recSWL,  &recSW,    &recNULL, &recNULL, &recSWR,  &recNULL,  // 28
    &recNULL,    &recNULL,   &recLWC2, &recNULL,  &recNULL, &recNULL, &recNULL, &recNULL,  // 30
    &recNULL,    &recNULL,   &recSWC2, &recHLE,   &recNULL, &recNULL, &recNULL, &recNULL,  // 38
};

const func_t X86DynaRecCPU::m_recSPC[64] = {
    &recSLL,  &recNULL,  &recSRL,  &recSRA,  &recSLLV,    &recNULL,  &recSRLV, &recSRAV,  // 00
    &recJR,   &recJALR,  &recNULL, &recNULL, &recSYSCALL, &recBREAK, &recNULL, &recNULL,  // 08
    &recMFHI, &recMTHI,  &recMFLO, &recMTLO, &recNULL,    &recNULL,  &recNULL, &recNULL,  // 10
    &recMULT, &recMULTU, &recDIV,  &recDIVU, &recNULL,    &recNULL,  &recNULL, &recNULL,  // 18
    &recADD,  &recADDU,  &recSUB,  &recSUBU, &recAND,     &recOR,    &recXOR,  &recNOR,   // 20
    &recNULL, &recNULL,  &recSLT,  &recSLTU, &recNULL,    &recNULL,  &recNULL, &recNULL,  // 28
    &recNULL, &recNULL,  &recNULL, &recNULL, &recNULL,    &recNULL,  &recNULL, &recNULL,  // 30
    &recNULL, &recNULL,  &recNULL, &recNULL, &recNULL,    &recNULL,  &recNULL, &recNULL,  // 38
};

const func_t X86DynaRecCPU::m_recREG[32] = {
    &recBLTZ,   &recBGEZ,   &recNULL, &recNULL,  // 00
    &recNULL,   &recNULL,   &recNULL, &recNULL,  // 04
    &recNULL,   &recNULL,   &recNULL, &recNULL,  // 08
    &recNULL,   &recNULL,   &recNULL, &recNULL,  // 0c
    &recBLTZAL, &recBGEZAL, &recNULL, &recNULL,  // 10
    &recNULL,   &recNULL,   &recNULL, &recNULL,  // 14
    &recNULL,   &recNULL,   &recNULL, &recNULL,  // 18
    &recNULL,   &recNULL,   &recNULL, &recNULL,  // 1c
};

const func_t X86DynaRecCPU::m_recCP0[32] = {
    &recMFC0, &recNULL, &recCFC0, &recNULL,  // 00
    &recMTC0, &recNULL, &recCTC0, &recNULL,  // 04
    &recNULL, &recNULL, &recNULL, &recNULL,  // 08
    &recNULL, &recNULL, &recNULL, &recNULL,  // 0c
    &recRFE,  &recNULL, &recNULL, &recNULL,  // 10
    &recNULL, &recNULL, &recNULL, &recNULL,  // 14
    &recNULL, &recNULL, &recNULL, &recNULL,  // 18
    &recNULL, &recNULL, &recNULL, &recNULL,  // 1c
};

const func_t X86DynaRecCPU::m_recCP2[64] = {
    &recBASIC, &recRTPS,  &recNULL,  &recNULL, &recNULL, &recNULL,  &recNCLIP, &recNULL,  // 00
    &recNULL,  &recNULL,  &recNULL,  &recNULL, &recOP,   &recNULL,  &recNULL,  &recNULL,  // 08
    &recDPCS,  &recINTPL, &recMVMVA, &recNCDS, &recCDP,  &recNULL,  &recNCDT,  &recNULL,  // 10
    &recNULL,  &recNULL,  &recNULL,  &recNCCS, &recCC,   &recNULL,  &recNCS,   &recNULL,  // 18
    &recNCT,   &recNULL,  &recNULL,  &recNULL, &recNULL, &recNULL,  &recNULL,  &recNULL,  // 20
    &recSQR,   &recDCPL,  &recDPCT,  &recNULL, &recNULL, &recAVSZ3, &recAVSZ4, &recNULL,  // 28
    &recRTPT,  &recNULL,  &recNULL,  &recNULL, &recNULL, &recNULL,  &recNULL,  &recNULL,  // 30
    &recNULL,  &recNULL,  &recNULL,  &recNULL, &recNULL, &recGPF,   &recGPL,   &recNCCT,  // 38
};

const func_t X86DynaRecCPU::m_recCP2BSC[32] = {
    &recMFC2, &recNULL, &recCFC2, &recNULL,  // 00
    &recMTC2, &recNULL, &recCTC2, &recNULL,  // 04
    &recNULL, &recNULL, &recNULL, &recNULL,  // 08
    &recNULL, &recNULL, &recNULL, &recNULL,  // 0c
    &recNULL, &recNULL, &recNULL, &recNULL,  // 10
    &recNULL, &recNULL, &recNULL, &recNULL,  // 14
    &recNULL, &recNULL, &recNULL, &recNULL,  // 18
    &recNULL, &recNULL, &recNULL, &recNULL,  // 1c
};

// Trace all functions using PGXP
const func_t X86DynaRecCPU::m_pgxpRecBSC[64] = {
    &recSPECIAL,  &recREGIMM,    &recJ,        &recJAL,        // 00
    &recBEQ,      &recBNE,       &recBLEZ,     &recBGTZ,       // 04
    &pgxpRecADDI, &pgxpRecADDIU, &pgxpRecSLTI, &pgxpRecSLTIU,  // 08
    &pgxpRecANDI, &pgxpRecORI,   &pgxpRecXORI, &pgxpRecLUI,    // 0c
    &recCOP0,     &recNULL,      &recCOP2,     &recNULL,       // 10
    &recNULL,     &recNULL,      &recNULL,     &recNULL,       // 14
    &recNULL,     &recNULL,      &recNULL,     &recNULL,       // 18
    &recNULL,     &recNULL,      &recNULL,     &recNULL,       // 1c
    &pgxpRecLB,   &pgxpRecLH,    &pgxpRecLWL,  &pgxpRecLW,     // 20
    &pgxpRecLBU,  &pgxpRecLHU,   &pgxpRecLWR,  &pgxpRecNULL,   // 24
    &pgxpRecSB,   &pgxpRecSH,    &pgxpRecSWL,  &pgxpRecSW,     // 28
    &pgxpRecNULL, &pgxpRecNULL,  &pgxpRecSWR,  &pgxpRecNULL,   // 2c
    &recNULL,     &recNULL,      &pgxpRecLWC2, &recNULL,       // 30
    &recNULL,     &recNULL,      &recNULL,     &recNULL,       // 34
    &recNULL,     &recNULL,      &pgxpRecSWC2, &recHLE,        // 38
    &recNULL,     &recNULL,      &recNULL,     &recNULL,       // 3c
};

const func_t X86DynaRecCPU::m_pgxpRecSPC[64] = {
    &pgxpRecSLL,  &pgxpRecNULL,  &pgxpRecSRL,  &pgxpRecSRA,   // 00
    &pgxpRecSLLV, &pgxpRecNULL,  &pgxpRecSRLV, &pgxpRecSRAV,  // 04
    &recJR,       &recJALR,      &recNULL,     &recNULL,      // 08
    &recSYSCALL,  &recBREAK,     &recNULL,     &recNULL,      // 0c
    &pgxpRecMFHI, &pgxpRecMTHI,  &pgxpRecMFLO, &pgxpRecMTLO,  // 10
    &pgxpRecNULL, &pgxpRecNULL,  &pgxpRecNULL, &pgxpRecNULL,  // 14
    &pgxpRecMULT, &pgxpRecMULTU, &pgxpRecDIV,  &pgxpRecDIVU,  // 18
    &pgxpRecNULL, &pgxpRecNULL,  &pgxpRecNULL, &pgxpRecNULL,  // 1c
    &pgxpRecADD,  &pgxpRecADDU,  &pgxpRecSUB,  &pgxpRecSUBU,  // 20
    &pgxpRecAND,  &pgxpRecOR,    &pgxpRecXOR,  &pgxpRecNOR,   // 24
    &pgxpRecNULL, &pgxpRecNULL,  &pgxpRecSLT,  &pgxpRecSLTU,  // 28
    &pgxpRecNULL, &pgxpRecNULL,  &pgxpRecNULL, &pgxpRecNULL,  // 2c
    &pgxpRecNULL, &pgxpRecNULL,  &pgxpRecNULL, &pgxpRecNULL,  // 30
    &pgxpRecNULL, &pgxpRecNULL,  &pgxpRecNULL, &pgxpRecNULL,  // 34
    &pgxpRecNULL, &pgxpRecNULL,  &pgxpRecNULL, &pgxpRecNULL,  // 38
    &pgxpRecNULL, &pgxpRecNULL,  &pgxpRecNULL, &pgxpRecNULL,  // 3c
};

const func_t X86DynaRecCPU::m_pgxpRecCP0[32] = {
    &pgxpRecMFC0, &pgxpRecNULL, &pgxpRecCFC0, &pgxpRecNULL,  // 00
    &pgxpRecMTC0, &pgxpRecNULL, &pgxpRecCTC0, &pgxpRecNULL,  // 04
    &pgxpRecNULL, &pgxpRecNULL, &pgxpRecNULL, &pgxpRecNULL,  // 08
    &pgxpRecNULL, &pgxpRecNULL, &pgxpRecNULL, &pgxpRecNULL,  // 0c
    &pgxpRecRFE,  &pgxpRecNULL, &pgxpRecNULL, &pgxpRecNULL,  // 10
    &pgxpRecNULL, &pgxpRecNULL, &pgxpRecNULL, &pgxpRecNULL,  // 14
    &pgxpRecNULL, &pgxpRecNULL, &pgxpRecNULL, &pgxpRecNULL,  // 18
    &pgxpRecNULL, &pgxpRecNULL, &pgxpRecNULL, &pgxpRecNULL,  // 1c
};

const func_t X86DynaRecCPU::m_pgxpRecCP2BSC[32] = {
    &pgxpRecMFC2, &pgxpRecNULL, &pgxpRecCFC2, &pgxpRecNULL,  // 00
    &pgxpRecMTC2, &pgxpRecNULL, &pgxpRecCTC2, &pgxpRecNULL,  // 04
    &pgxpRecNULL, &pgxpRecNULL, &pgxpRecNULL, &pgxpRecNULL,  // 08
    &pgxpRecNULL, &pgxpRecNULL, &pgxpRecNULL, &pgxpRecNULL,  // 0c
    &pgxpRecNULL, &pgxpRecNULL, &pgxpRecNULL, &pgxpRecNULL,  // 10
    &pgxpRecNULL, &pgxpRecNULL, &pgxpRecNULL, &pgxpRecNULL,  // 14
    &pgxpRecNULL, &pgxpRecNULL, &pgxpRecNULL, &pgxpRecNULL,  // 18
    &pgxpRecNULL, &pgxpRecNULL, &pgxpRecNULL, &pgxpRecNULL,  // 1c
};

// Trace memory functions only
const func_t X86DynaRecCPU::m_pgxpRecBSCMem[64] = {
    &recSPECIAL, &recREGIMM, &recJ,        &recJAL,    &recBEQ,      &recBNE,      &recBLEZ,    &recBGTZ,      // 00
    &recADDI,    &recADDIU,  &recSLTI,     &recSLTIU,  &recANDI,     &recORI,      &recXORI,    &recLUI,       // 08
    &recCOP0,    &recNULL,   &recCOP2,     &recNULL,   &recNULL,     &recNULL,     &recNULL,    &recNULL,      // 10
    &recNULL,    &recNULL,   &recNULL,     &recNULL,   &recNULL,     &recNULL,     &recNULL,    &recNULL,      // 18
    &pgxpRecLB,  &pgxpRecLH, &pgxpRecLWL,  &pgxpRecLW, &pgxpRecLBU,  &pgxpRecLHU,  &pgxpRecLWR, &pgxpRecNULL,  // 20
    &pgxpRecSB,  &pgxpRecSH, &pgxpRecSWL,  &pgxpRecSW, &pgxpRecNULL, &pgxpRecNULL, &pgxpRecSWR, &pgxpRecNULL,  // 28
    &recNULL,    &recNULL,   &pgxpRecLWC2, &recNULL,   &recNULL,     &recNULL,     &recNULL,    &recNULL,      // 30
    &recNULL,    &recNULL,   &pgxpRecSWC2, &recHLE,    &recNULL,     &recNULL,     &recNULL,    &recNULL,      // 38
};

void X86DynaRecCPU::recRecompile() {
    char *p;
    int8_t *ptr;

    m_resp = 0;

    /* if gen.m_x86Ptr reached the mem limit reset whole mem */
    if (((uint32_t)gen.x86GetPtr() - (uint32_t)m_recMem) >= (RECMEM_SIZE - 0x10000)) Reset();

    gen.x86Align(32);
    ptr = gen.x86GetPtr();

    PC_REC32(m_psxRegs.pc) = (uint32_t)gen.x86GetPtr();
    m_pc = m_psxRegs.pc;
    m_old_pc = m_pc;

    for (m_count = 0; m_count < DYNAREC_BLOCK;) {
        p = (char *)PSXM(m_pc);
        if (p == NULL) recError();
        m_psxRegs.code = *(uint32_t *)p;
        m_pc += 4;
        m_count++;
        func_t func = m_pRecBSC[m_psxRegs.code >> 26];
        (*this.*func)();

        if (m_branch) {
            m_branch = 0;
            return;
        }
    }

    iFlushRegs();

    gen.MOV32ItoM((uint32_t)&m_psxRegs.pc, m_pc);

    iRet();
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

    // set interpreter mode too
    InterpretedCPU::SetPGXPMode(pgxpMode);
    // reset to ensure new func tables are used
    Reset();
}

#else

class X86DynaRecCPU : public PCSX::R3000Acpu {
  public:
    X86DynaRecCPU() : R3000Acpu("x86 DynaRec") {}
    virtual bool Implemented() final { return false; }
    virtual bool Init() final { return false; }
    virtual void Reset() final { assert(0); }
    virtual void Execute() final { assert(0); }
    virtual void ExecuteBlock() final { assert(0); }
    virtual void Clear(uint32_t Addr, uint32_t Size) final { assert(0); }
    virtual void Shutdown() final { assert(0); }
    virtual void SetPGXPMode(uint32_t pgxpMode) final { assert(0); }
};

#endif

}  // namespace

std::unique_ptr<PCSX::R3000Acpu> PCSX::Cpus::getX86DynaRec() {
    return std::unique_ptr<PCSX::R3000Acpu>(new X86DynaRecCPU());
}
