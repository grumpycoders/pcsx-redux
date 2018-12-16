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

#if defined(__i386__) || defined(_M_IX86)

#include "core/ix86/ix86.h"
#include "core/pgxp_cpu.h"
#include "core/pgxp_debug.h"
#include "core/pgxp_gte.h"
#include "core/psxcommon.h"

#ifndef MAP_ANONYMOUS
#ifdef MAP_ANON
#define MAP_ANONYMOUS MAP_ANON
#endif
#endif

static u32 *s_psxRecLUT;

#undef PC_REC
#undef PC_REC8
#undef PC_REC16
#undef PC_REC32
#define PC_REC(x) (s_psxRecLUT[(x) >> 16] + ((x)&0xffff))
#define PC_REC8(x) (*(u8 *)PC_REC(x))
#define PC_REC16(x) (*(u16 *)PC_REC(x))
#define PC_REC32(x) (*(u32 *)PC_REC(x))

static const size_t RECMEM_SIZE = 8 * 1024 * 1024;

static char *s_recMem; /* the recompiled blocks will be here */
static char *s_recRAM; /* and the s_ptr to the blocks here */
static char *s_recROM; /* and here */

static u32 s_pc;      /* recompiler pc */
static u32 s_old_pc;  /* recompiler oldpc */
static u32 s_count;   /* recompiler intruction count */
static int s_branch;  /* set for branch */
static u32 s_target;  /* branch target */
static u32 s_resp;

typedef struct {
    int state;
    u32 k;
    int reg;
} iRegisters;

static iRegisters s_iRegs[32];
static iRegisters s_iRegsS[32];

enum {
    ST_UNK = 0,
    ST_CONST = 1,
    ST_MAPPED = 2
};

#define IsConst(reg) (s_iRegs[reg].state == ST_CONST)
#define IsMapped(reg) (s_iRegs[reg].state == ST_MAPPED)

///

static void recReset();

static void (**s_pRecBSC)();
static void (**s_pRecSPC)();
static void (**s_pRecREG)();
static void (**s_pRecCP0)();
static void (**s_pRecCP2)();
static void (**s_pRecCP2BSC)();

static const unsigned int DYNAREC_BLOCK = 50;

static void MapConst(int reg, u32 _const) {
    s_iRegs[reg].k = _const;
    s_iRegs[reg].state = ST_CONST;
}

static void iFlushReg(int reg) {
    if (IsConst(reg)) {
        MOV32ItoM((u32)&g_psxRegs.GPR.r[reg], s_iRegs[reg].k);
    }
    s_iRegs[reg].state = ST_UNK;
}

static void iFlushRegs() {
    for (int i = 1; i < 32; i++) {
        iFlushReg(i);
    }
}

static void iPushReg(int reg) {
    if (IsConst(reg)) {
        PUSH32I(s_iRegs[reg].k);
    } else {
        PUSH32M((u32)&g_psxRegs.GPR.r[reg]);
    }
}

static void iStoreCycle() {
    s_count = ((s_pc - s_old_pc) / 4) * BIAS;
    ADD32ItoM((u32)&g_psxRegs.cycle, s_count);
}

static void iRet() {
    iStoreCycle();
    if (s_resp) ADD32ItoR(ESP, s_resp);
    RET();
}

static int iLoadTest() {
    // check for load delay
    u32 tmp = g_psxRegs.code >> 26;
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
static void SetBranch() {
    s_branch = 1;
    g_psxRegs.code = PSXMu32(s_pc);
    s_pc += 4;

    if (iLoadTest() == 1) {
        iFlushRegs();
        MOV32ItoM((u32)&g_psxRegs.code, g_psxRegs.code);
        /* store cycle */
        s_count = ((s_pc - s_old_pc) / 4) * BIAS;
        ADD32ItoM((u32)&g_psxRegs.cycle, s_count);
        if (s_resp) ADD32ItoR(ESP, s_resp);

        PUSH32M((u32)&s_target);
        PUSH32I(_Rt_);
        CALLFunc((u32)psxDelayTest);
        ADD32ItoR(ESP, 2 * 4);

        RET();
        return;
    }
    switch (g_psxRegs.code >> 26) {
        // Lode Runner (jr - beq)

        // bltz - bgez - bltzal - bgezal / beq - bne - blez - bgtz
        case 0x01:
        case 0x04:
        case 0x05:
        case 0x06:
        case 0x07:
            break;

        default:
            s_pRecBSC[g_psxRegs.code >> 26]();
            break;
    }

    iFlushRegs();
    iStoreCycle();
    MOV32MtoR(EAX, (u32)&s_target);
    MOV32RtoM((u32)&g_psxRegs.pc, EAX);
    CALLFunc((u32)psxBranchTest);

    if (s_resp) ADD32ItoR(ESP, s_resp);
    RET();
}

static void iJump(u32 branchPC) {
    s_branch = 1;
    g_psxRegs.code = PSXMu32(s_pc);
    s_pc += 4;

    if (iLoadTest() == 1) {
        iFlushRegs();
        MOV32ItoM((u32)&g_psxRegs.code, g_psxRegs.code);
        /* store cycle */
        s_count = ((s_pc - s_old_pc) / 4) * BIAS;
        ADD32ItoM((u32)&g_psxRegs.cycle, s_count);
        if (s_resp) ADD32ItoR(ESP, s_resp);

        PUSH32I(branchPC);
        PUSH32I(_Rt_);
        CALLFunc((u32)psxDelayTest);
        ADD32ItoR(ESP, 2 * 4);

        RET();
        return;
    }

    s_pRecBSC[g_psxRegs.code >> 26]();

    iFlushRegs();
    iStoreCycle();
    MOV32ItoM((u32)&g_psxRegs.pc, branchPC);
    CALLFunc((u32)psxBranchTest);

    if (s_resp) ADD32ItoR(ESP, s_resp);

    // maybe just happened an interruption, check so
    CMP32ItoM((u32)&g_psxRegs.pc, branchPC);
    g_j8Ptr[0] = JE8(0);
    RET();

    x86SetJ8(g_j8Ptr[0]);
    MOV32MtoR(EAX, PC_REC(branchPC));
    TEST32RtoR(EAX, EAX);
    g_j8Ptr[1] = JNE8(0);
    RET();

    x86SetJ8(g_j8Ptr[1]);
    RET();
    JMP32R(EAX);
}

static void iBranch(u32 branchPC, int savectx) {
    u32 respold = 0;

    if (savectx) {
        respold = s_resp;
        memcpy(s_iRegsS, s_iRegs, sizeof(s_iRegs));
    }

    s_branch = 1;
    g_psxRegs.code = PSXMu32(s_pc);

    // the delay test is only made when the branch is taken
    // savectx == 0 will mean that :)
    if (savectx == 0 && iLoadTest() == 1) {
        iFlushRegs();
        MOV32ItoM((u32)&g_psxRegs.code, g_psxRegs.code);
        /* store cycle */
        s_count = (((s_pc + 4) - s_old_pc) / 4) * BIAS;
        ADD32ItoM((u32)&g_psxRegs.cycle, s_count);
        if (s_resp) ADD32ItoR(ESP, s_resp);

        PUSH32I(branchPC);
        PUSH32I(_Rt_);
        CALLFunc((u32)psxDelayTest);
        ADD32ItoR(ESP, 2 * 4);

        RET();
        return;
    }

    s_pc += 4;
    s_pRecBSC[g_psxRegs.code >> 26]();

    iFlushRegs();
    iStoreCycle();
    MOV32ItoM((u32)&g_psxRegs.pc, branchPC);
    CALLFunc((u32)psxBranchTest);

    if (s_resp) ADD32ItoR(ESP, s_resp);

    // maybe just happened an interruption, check so
    CMP32ItoM((u32)&g_psxRegs.pc, branchPC);
    g_j8Ptr[1] = JE8(0);
    RET();

    x86SetJ8(g_j8Ptr[1]);
    MOV32MtoR(EAX, PC_REC(branchPC));
    TEST32RtoR(EAX, EAX);
    g_j8Ptr[2] = JNE8(0);
    RET();

    x86SetJ8(g_j8Ptr[2]);
    JMP32R(EAX);

    s_pc -= 4;
    if (savectx) {
        s_resp = respold;
        memcpy(s_iRegs, s_iRegsS, sizeof(s_iRegs));
    }
}

char *txt0 = "EAX = %x : ECX = %x : EDX = %x\n";
char *txt1 = "EAX = %x\n";
char *txt2 = "M32 = %x\n";

void iLogX86() {
    PUSHA32();

    PUSH32R(EDX);
    PUSH32R(ECX);
    PUSH32R(EAX);
    PUSH32M((u32)&txt0);
    CALLFunc((u32)SysPrintf);
    ADD32ItoR(ESP, 4 * 4);

    POPA32();
}

void iLogEAX() {
    PUSH32R(EAX);
    PUSH32M((u32)&txt1);
    CALLFunc((u32)SysPrintf);
    ADD32ItoR(ESP, 4 * 2);
}

void iLogM32(u32 mem) {
    PUSH32M(mem);
    PUSH32M((u32)&txt2);
    CALLFunc((u32)SysPrintf);
    ADD32ItoR(ESP, 4 * 2);
}

#if 0
static void iDumpRegs() {
	int i, j;

	printf("%x %x\n", g_psxRegs.pc, g_psxRegs.cycle);
	for (i = 0; i < 4; i++) {
		for (j = 0; j < 8; j++)
			printf("%x ", g_psxRegs.GPR.r[j * i]);
		printf("\n");
	}
}
#endif

void iDumpBlock(char *ptr) {
    FILE *f;
    u32 i;

    SysPrintf("dump1 %x:%x, %x\n", g_psxRegs.pc, s_pc, g_psxRegs.cycle);

    for (i = g_psxRegs.pc; i < s_pc; i += 4) SysPrintf("%s\n", disR3000AF(PSXMu32(i), i));

    fflush(stdout);
    f = fopen("dump1", "w");
    fwrite(ptr, 1, (u32)g_x86Ptr - (u32)ptr, f);
    fclose(f);
    system("ndisasmw -u dump1");
    fflush(stdout);
}

#define REC_FUNC(f)                                       \
    void psx##f();                                        \
    static void rec##f() {                                \
        iFlushRegs();                                     \
        MOV32ItoM((u32)&g_psxRegs.code, (u32)g_psxRegs.code); \
        MOV32ItoM((u32)&g_psxRegs.pc, (u32)s_pc);             \
        CALLFunc((u32)psx##f);                            \
        /*	branch = 2; */                                 \
    }

#define REC_SYS(f)                                        \
    void psx##f();                                        \
    static void rec##f() {                                \
        iFlushRegs();                                     \
        MOV32ItoM((u32)&g_psxRegs.code, (u32)g_psxRegs.code); \
        MOV32ItoM((u32)&g_psxRegs.pc, (u32)s_pc);             \
        CALLFunc((u32)psx##f);                            \
        branch = 2;                                       \
        iRet();                                           \
    }

#define REC_BRANCH(f)                                     \
    void psx##f();                                        \
    static void rec##f() {                                \
        iFlushRegs();                                     \
        MOV32ItoM((u32)&g_psxRegs.code, (u32)g_psxRegs.code); \
        MOV32ItoM((u32)&g_psxRegs.pc, (u32)s_pc);             \
        CALLFunc((u32)psx##f);                            \
        branch = 2;                                       \
        iRet();                                           \
    }

static void recRecompile();

static int recInit() {
    int i;

    s_psxRecLUT = (u32 *)malloc(0x010000 * 4);

#ifndef _WIN32
    recMem = mmap(0, RECMEM_SIZE + 0x1000, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#else
    s_recMem = ((char *)VirtualAlloc(NULL, RECMEM_SIZE + 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
#endif

    s_recRAM = (char *)malloc(0x200000);
    s_recROM = (char *)malloc(0x080000);
    if (s_recRAM == NULL || s_recROM == NULL || s_recMem == NULL || s_psxRecLUT == NULL) {
        SysMessage("Error allocating memory");
        return -1;
    }

    for (i = 0; i < 0x80; i++) s_psxRecLUT[i + 0x0000] = (u32)&s_recRAM[(i & 0x1f) << 16];
    memcpy(s_psxRecLUT + 0x8000, s_psxRecLUT, 0x80 * 4);
    memcpy(s_psxRecLUT + 0xa000, s_psxRecLUT, 0x80 * 4);

    for (i = 0; i < 0x08; i++) s_psxRecLUT[i + 0xbfc0] = (u32)&s_recROM[i << 16];

    x86Init();

    return 0;
}

static void recReset() {
    memset(s_recRAM, 0, 0x200000);
    memset(s_recROM, 0, 0x080000);

    x86SetPtr(s_recMem);

    s_branch = 0;
    memset(s_iRegs, 0, sizeof(s_iRegs));
    s_iRegs[0].state = ST_CONST;
    s_iRegs[0].k = 0;
}

static void recShutdown() {
    if (s_recMem == NULL) return;
    free(s_psxRecLUT);
#ifndef _WIN32
    munmap(recMem, RECMEM_SIZE + 0x1000);
#else
    VirtualFree(s_recMem, RECMEM_SIZE + 0x1000, MEM_RELEASE);
#endif
    free(s_recRAM);
    free(s_recROM);
    x86Shutdown();
}

static void recError() {
    SysReset();
    // ClosePlugins();
    SysMessage("Unrecoverable error while running recompiler\n");
    SysRunGui();
}

__inline static void execute() {
    void (**recFunc)() = NULL;
    char *p;

    p = (char *)PC_REC(g_psxRegs.pc);
    if (p != NULL)
        recFunc = (void (**)())(u32)p;
    else {
        recError();
        return;
    }

    if (*recFunc == 0) {
        recRecompile();
    }
    (*recFunc)();
}

static void recExecute() {
    for (;;) execute();
}

static void recExecuteBlock() { execute(); }

static void recClear(u32 Addr, u32 Size) {
    u32 bank, offset;

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

static void recNULL() {
    //	SysMessage("recUNK: %8.8x\n", g_psxRegs.code);
}

/*********************************************************
 * goes to opcodes tables...                              *
 * Format:  table[something....]                          *
 *********************************************************/

// REC_SYS(SPECIAL);
static void recSPECIAL() { s_pRecSPC[_Funct_](); }

static void recREGIMM() { s_pRecREG[_Rt_](); }

static void recCOP0() { s_pRecCP0[_Rs_](); }

// REC_SYS(COP2);
static void recCOP2() {
    MOV32MtoR(EAX, (u32)&g_psxRegs.CP0.n.Status);
    AND32ItoR(EAX, 0x40000000);
    g_j8Ptr[31] = JZ8(0);

    s_pRecCP2[_Funct_]();

    x86SetJ8(g_j8Ptr[31]);
}

static void recBASIC() { s_pRecCP2BSC[_Rs_](); }

// end of Tables opcodes...

/*********************************************************
 * Arithmetic with immediate operand                      *
 * Format:  OP rt, rs, immediate                          *
 *********************************************************/

/*REC_FUNC(ADDI);
REC_FUNC(ADDIU);
REC_FUNC(ANDI);
REC_FUNC(ORI);
REC_FUNC(XORI);
REC_FUNC(SLTI);
REC_FUNC(SLTIU);
#if 0*/
static void recADDIU() {
    // Rt = Rs + Im
    if (!_Rt_) return;

    //	iFlushRegs();

    if (_Rs_ == _Rt_) {
        if (IsConst(_Rt_)) {
            s_iRegs[_Rt_].k += _Imm_;
        } else {
            if (_Imm_ == 1) {
                INC32M((u32)&g_psxRegs.GPR.r[_Rt_]);
            } else if (_Imm_ == -1) {
                DEC32M((u32)&g_psxRegs.GPR.r[_Rt_]);
            } else if (_Imm_) {
                ADD32ItoM((u32)&g_psxRegs.GPR.r[_Rt_], _Imm_);
            }
        }
    } else {
        if (IsConst(_Rs_)) {
            MapConst(_Rt_, s_iRegs[_Rs_].k + _Imm_);
        } else {
            s_iRegs[_Rt_].state = ST_UNK;

            MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
            if (_Imm_ == 1) {
                INC32R(EAX);
            } else if (_Imm_ == -1) {
                DEC32R(EAX);
            } else if (_Imm_) {
                ADD32ItoR(EAX, _Imm_);
            }
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
        }
    }
}

static void recADDI() {
    // Rt = Rs + Im
    if (!_Rt_) return;

    //	iFlushRegs();

    if (_Rs_ == _Rt_) {
        if (IsConst(_Rt_)) {
            s_iRegs[_Rt_].k += _Imm_;
        } else {
            if (_Imm_ == 1) {
                INC32M((u32)&g_psxRegs.GPR.r[_Rt_]);
            } else if (_Imm_ == -1) {
                DEC32M((u32)&g_psxRegs.GPR.r[_Rt_]);
            } else if (_Imm_) {
                ADD32ItoM((u32)&g_psxRegs.GPR.r[_Rt_], _Imm_);
            }
        }
    } else {
        if (IsConst(_Rs_)) {
            MapConst(_Rt_, s_iRegs[_Rs_].k + _Imm_);
        } else {
            s_iRegs[_Rt_].state = ST_UNK;

            MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
            if (_Imm_ == 1) {
                INC32R(EAX);
            } else if (_Imm_ == -1) {
                DEC32R(EAX);
            } else if (_Imm_) {
                ADD32ItoR(EAX, _Imm_);
            }
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
        }
    }
}

static void recSLTI() {
    // Rt = Rs < Im (signed)
    if (!_Rt_) return;

    //	iFlushRegs();

    if (IsConst(_Rs_)) {
        MapConst(_Rt_, (s32)s_iRegs[_Rs_].k < _Imm_);
    } else {
        s_iRegs[_Rt_].state = ST_UNK;

        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        CMP32ItoR(EAX, _Imm_);
        SETL8R(EAX);
        AND32ItoR(EAX, 0xff);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
    }
}

static void recSLTIU() {
    // Rt = Rs < Im (unsigned)
    if (!_Rt_) return;

    //	iFlushRegs();

    if (IsConst(_Rs_)) {
        MapConst(_Rt_, s_iRegs[_Rs_].k < _ImmU_);
    } else {
        s_iRegs[_Rt_].state = ST_UNK;

        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        CMP32ItoR(EAX, _Imm_);
        SETB8R(EAX);
        AND32ItoR(EAX, 0xff);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
    }
}

static void recANDI() {
    // Rt = Rs And Im
    if (!_Rt_) return;

    //	iFlushRegs();

    if (_Rs_ == _Rt_) {
        if (IsConst(_Rt_)) {
            s_iRegs[_Rt_].k &= _ImmU_;
        } else {
            AND32ItoM((u32)&g_psxRegs.GPR.r[_Rt_], _ImmU_);
        }
    } else {
        if (IsConst(_Rs_)) {
            MapConst(_Rt_, s_iRegs[_Rs_].k & _ImmU_);
        } else {
            s_iRegs[_Rt_].state = ST_UNK;

            MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
            AND32ItoR(EAX, _ImmU_);
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
        }
    }
}

static void recORI() {
    // Rt = Rs Or Im
    if (!_Rt_) return;

    //	iFlushRegs();

    if (_Rs_ == _Rt_) {
        if (IsConst(_Rt_)) {
            s_iRegs[_Rt_].k |= _ImmU_;
        } else {
            OR32ItoM((u32)&g_psxRegs.GPR.r[_Rt_], _ImmU_);
        }
    } else {
        if (IsConst(_Rs_)) {
            MapConst(_Rt_, s_iRegs[_Rs_].k | _ImmU_);
        } else {
            s_iRegs[_Rt_].state = ST_UNK;

            MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
            if (_ImmU_) OR32ItoR(EAX, _ImmU_);
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
        }
    }
}

static void recXORI() {
    // Rt = Rs Xor Im
    if (!_Rt_) return;

    //	iFlushRegs();

    if (_Rs_ == _Rt_) {
        if (IsConst(_Rt_)) {
            s_iRegs[_Rt_].k ^= _ImmU_;
        } else {
            XOR32ItoM((u32)&g_psxRegs.GPR.r[_Rt_], _ImmU_);
        }
    } else {
        if (IsConst(_Rs_)) {
            MapConst(_Rt_, s_iRegs[_Rs_].k ^ _ImmU_);
        } else {
            s_iRegs[_Rt_].state = ST_UNK;

            MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
            XOR32ItoR(EAX, _ImmU_);
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
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
static void recLUI() {
    // Rt = Imm << 16
    if (!_Rt_) return;

    MapConst(_Rt_, g_psxRegs.code << 16);
}
//#endif
// End of Load Higher .....

/*********************************************************
 * Register arithmetic                                    *
 * Format:  OP rd, rs, rt                                 *
 *********************************************************/

/*REC_FUNC(ADD);
REC_FUNC(ADDU);
REC_FUNC(SUB);
REC_FUNC(SUBU);
REC_FUNC(AND);
REC_FUNC(OR);
REC_FUNC(XOR);
REC_FUNC(NOR);
REC_FUNC(SLT);
REC_FUNC(SLTU);

#if 0*/
static void recADDU() {
    // Rd = Rs + Rt
    if (!_Rd_) return;

    //	iFlushRegs();

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, s_iRegs[_Rs_].k + s_iRegs[_Rt_].k);
    } else if (IsConst(_Rs_)) {
        s_iRegs[_Rd_].state = ST_UNK;

        if (_Rt_ == _Rd_) {
            if (s_iRegs[_Rs_].k == 1) {
                INC32M((u32)&g_psxRegs.GPR.r[_Rd_]);
            } else if (s_iRegs[_Rs_].k == -1) {
                DEC32M((u32)&g_psxRegs.GPR.r[_Rd_]);
            } else if (s_iRegs[_Rs_].k) {
                ADD32ItoM((u32)&g_psxRegs.GPR.r[_Rd_], s_iRegs[_Rs_].k);
            }
        } else {
            MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
            if (s_iRegs[_Rs_].k == 1) {
                INC32R(EAX);
            } else if (s_iRegs[_Rs_].k == 0xffffffff) {
                DEC32R(EAX);
            } else if (s_iRegs[_Rs_].k) {
                ADD32ItoR(EAX, s_iRegs[_Rs_].k);
            }
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
        }
    } else if (IsConst(_Rt_)) {
        s_iRegs[_Rd_].state = ST_UNK;

        if (_Rs_ == _Rd_) {
            if (s_iRegs[_Rt_].k == 1) {
                INC32M((u32)&g_psxRegs.GPR.r[_Rd_]);
            } else if (s_iRegs[_Rt_].k == -1) {
                DEC32M((u32)&g_psxRegs.GPR.r[_Rd_]);
            } else if (s_iRegs[_Rt_].k) {
                ADD32ItoM((u32)&g_psxRegs.GPR.r[_Rd_], s_iRegs[_Rt_].k);
            }
        } else {
            MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
            if (s_iRegs[_Rt_].k == 1) {
                INC32R(EAX);
            } else if (s_iRegs[_Rt_].k == 0xffffffff) {
                DEC32R(EAX);
            } else if (s_iRegs[_Rt_].k) {
                ADD32ItoR(EAX, s_iRegs[_Rt_].k);
            }
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
        }
    } else {
        s_iRegs[_Rd_].state = ST_UNK;

        if (_Rs_ == _Rd_) {  // Rd+= Rt
            MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
            ADD32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
        } else if (_Rt_ == _Rd_) {  // Rd+= Rs
            MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
            ADD32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
        } else {  // Rd = Rs + Rt
            MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
            ADD32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
        }
    }
}

static void recADD() {
    // Rd = Rs + Rt
    recADDU();
}

static void recSUBU() {
    // Rd = Rs - Rt
    if (!_Rd_) return;

    //	iFlushRegs();

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, s_iRegs[_Rs_].k - s_iRegs[_Rt_].k);
    } else if (IsConst(_Rs_)) {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32ItoR(EAX, s_iRegs[_Rs_].k);
        SUB32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    } else if (IsConst(_Rt_)) {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        SUB32ItoR(EAX, s_iRegs[_Rt_].k);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    } else {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        SUB32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    }
}

static void recSUB() {
    // Rd = Rs - Rt
    recSUBU();
}

static void recAND() {
    // Rd = Rs And Rt
    if (!_Rd_) return;

    //	iFlushRegs();

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, s_iRegs[_Rs_].k & s_iRegs[_Rt_].k);
    } else if (IsConst(_Rs_)) {
        s_iRegs[_Rd_].state = ST_UNK;

        if (_Rd_ == _Rt_) {  // Rd&= Rs
            AND32ItoM((u32)&g_psxRegs.GPR.r[_Rd_], s_iRegs[_Rs_].k);
        } else {
            MOV32ItoR(EAX, s_iRegs[_Rs_].k);
            AND32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
        }
    } else if (IsConst(_Rt_)) {
        s_iRegs[_Rd_].state = ST_UNK;

        if (_Rd_ == _Rs_) {  // Rd&= kRt
            AND32ItoM((u32)&g_psxRegs.GPR.r[_Rd_], s_iRegs[_Rt_].k);
        } else {  // Rd = Rs & kRt
            MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
            AND32ItoR(EAX, s_iRegs[_Rt_].k);
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
        }
    } else {
        s_iRegs[_Rd_].state = ST_UNK;

        if (_Rs_ == _Rd_) {  // Rd&= Rt
            MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
            AND32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
        } else if (_Rt_ == _Rd_) {  // Rd&= Rs
            MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
            AND32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
        } else {  // Rd = Rs & Rt
            MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
            AND32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
        }
    }
}

static void recOR() {
    // Rd = Rs Or Rt
    if (!_Rd_) return;

    //	iFlushRegs();

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, s_iRegs[_Rs_].k | s_iRegs[_Rt_].k);
    } else if (IsConst(_Rs_)) {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32ItoR(EAX, s_iRegs[_Rs_].k);
        OR32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    } else if (IsConst(_Rt_)) {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        OR32ItoR(EAX, s_iRegs[_Rt_].k);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    } else {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        OR32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    }
}

static void recXOR() {
    // Rd = Rs Xor Rt
    if (!_Rd_) return;

    //	iFlushRegs();

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, s_iRegs[_Rs_].k ^ s_iRegs[_Rt_].k);
    } else if (IsConst(_Rs_)) {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32ItoR(EAX, s_iRegs[_Rs_].k);
        XOR32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    } else if (IsConst(_Rt_)) {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        XOR32ItoR(EAX, s_iRegs[_Rt_].k);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    } else {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        XOR32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    }
}

static void recNOR() {
    // Rd = Rs Nor Rt
    if (!_Rd_) return;

    //	iFlushRegs();

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, ~(s_iRegs[_Rs_].k | s_iRegs[_Rt_].k));
    } else if (IsConst(_Rs_)) {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32ItoR(EAX, s_iRegs[_Rs_].k);
        OR32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        NOT32R(EAX);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    } else if (IsConst(_Rt_)) {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        OR32ItoR(EAX, s_iRegs[_Rt_].k);
        NOT32R(EAX);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    } else {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        OR32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        NOT32R(EAX);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    }
}

static void recSLT() {
    // Rd = Rs < Rt (signed)
    if (!_Rd_) return;

    //	iFlushRegs();

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, (s32)s_iRegs[_Rs_].k < (s32)s_iRegs[_Rt_].k);
    } else if (IsConst(_Rs_)) {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32ItoR(EAX, s_iRegs[_Rs_].k);
        CMP32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        SETL8R(EAX);
        AND32ItoR(EAX, 0xff);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    } else if (IsConst(_Rt_)) {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        CMP32ItoR(EAX, s_iRegs[_Rt_].k);
        SETL8R(EAX);
        AND32ItoR(EAX, 0xff);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    } else {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        CMP32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        SETL8R(EAX);
        AND32ItoR(EAX, 0xff);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    }
}

static void recSLTU() {
    // Rd = Rs < Rt (unsigned)
    if (!_Rd_) return;

    //	iFlushRegs();

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        MapConst(_Rd_, s_iRegs[_Rs_].k < s_iRegs[_Rt_].k);
    } else if (IsConst(_Rs_)) {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32ItoR(EAX, s_iRegs[_Rs_].k);
        CMP32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        SBB32RtoR(EAX, EAX);
        NEG32R(EAX);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    } else if (IsConst(_Rt_)) {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        CMP32ItoR(EAX, s_iRegs[_Rt_].k);
        SBB32RtoR(EAX, EAX);
        NEG32R(EAX);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    } else {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        CMP32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        SBB32RtoR(EAX, EAX);
        NEG32R(EAX);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
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
static void recMULT() {
    // Lo/Hi = Rs * Rt (signed)

    //	iFlushRegs();

    if ((IsConst(_Rs_) && s_iRegs[_Rs_].k == 0) || (IsConst(_Rt_) && s_iRegs[_Rt_].k == 0)) {
        XOR32RtoR(EAX, EAX);
        MOV32RtoM((u32)&g_psxRegs.GPR.n.lo, EAX);
        MOV32RtoM((u32)&g_psxRegs.GPR.n.hi, EAX);
        return;
    }

    if (IsConst(_Rs_)) {
        MOV32ItoR(EAX, s_iRegs[_Rs_].k);  // printf("multrsk %x\n", s_iRegs[_Rs_].k);
    } else {
        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
    }
    if (IsConst(_Rt_)) {
        MOV32ItoR(EDX, s_iRegs[_Rt_].k);  // printf("multrtk %x\n", s_iRegs[_Rt_].k);
        IMUL32R(EDX);
    } else {
        IMUL32M((u32)&g_psxRegs.GPR.r[_Rt_]);
    }
    MOV32RtoM((u32)&g_psxRegs.GPR.n.lo, EAX);
    MOV32RtoM((u32)&g_psxRegs.GPR.n.hi, EDX);
}

static void recMULTU() {
    // Lo/Hi = Rs * Rt (unsigned)

    //	iFlushRegs();

    if ((IsConst(_Rs_) && s_iRegs[_Rs_].k == 0) || (IsConst(_Rt_) && s_iRegs[_Rt_].k == 0)) {
        XOR32RtoR(EAX, EAX);
        MOV32RtoM((u32)&g_psxRegs.GPR.n.lo, EAX);
        MOV32RtoM((u32)&g_psxRegs.GPR.n.hi, EAX);
        return;
    }

    if (IsConst(_Rs_)) {
        MOV32ItoR(EAX, s_iRegs[_Rs_].k);  // printf("multursk %x\n", s_iRegs[_Rs_].k);
    } else {
        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
    }
    if (IsConst(_Rt_)) {
        MOV32ItoR(EDX, s_iRegs[_Rt_].k);  // printf("multurtk %x\n", s_iRegs[_Rt_].k);
        MUL32R(EDX);
    } else {
        MUL32M((u32)&g_psxRegs.GPR.r[_Rt_]);
    }
    MOV32RtoM((u32)&g_psxRegs.GPR.n.lo, EAX);
    MOV32RtoM((u32)&g_psxRegs.GPR.n.hi, EDX);
}

static void recDIV() {
    // Lo/Hi = Rs / Rt (signed)

    //	iFlushRegs();

    if (IsConst(_Rt_)) {
        if (s_iRegs[_Rt_].k == 0) {
            MOV32ItoM((u32)&g_psxRegs.GPR.n.lo, 0xffffffff);
            if (IsConst(_Rs_)) {
                MOV32ItoM((u32)&g_psxRegs.GPR.n.hi, s_iRegs[_Rs_].k);
            } else {
                MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
                MOV32RtoM((u32)&g_psxRegs.GPR.n.hi, EAX);
            }
            return;
        }
        MOV32ItoR(ECX, s_iRegs[_Rt_].k);  // printf("divrtk %x\n", s_iRegs[_Rt_].k);
    } else {
        MOV32MtoR(ECX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        CMP32ItoR(ECX, 0);
        g_j8Ptr[0] = JE8(0);
    }
    if (IsConst(_Rs_)) {
        MOV32ItoR(EAX, s_iRegs[_Rs_].k);  // printf("divrsk %x\n", s_iRegs[_Rs_].k);
    } else {
        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
    }
    CDQ();
    IDIV32R(ECX);
    MOV32RtoM((u32)&g_psxRegs.GPR.n.lo, EAX);
    MOV32RtoM((u32)&g_psxRegs.GPR.n.hi, EDX);

    if (!IsConst(_Rt_)) {
        g_j8Ptr[1] = JMP8(1);

        x86SetJ8(g_j8Ptr[0]);

        MOV32ItoM((u32)&g_psxRegs.GPR.n.lo, 0xffffffff);
        if (IsConst(_Rs_)) {
            MOV32ItoM((u32)&g_psxRegs.GPR.n.hi, s_iRegs[_Rs_].k);
        } else {
            MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
            MOV32RtoM((u32)&g_psxRegs.GPR.n.hi, EAX);
        }

        x86SetJ8(g_j8Ptr[1]);
    }
}

static void recDIVU() {
    // Lo/Hi = Rs / Rt (unsigned)

    //	iFlushRegs();

    if (IsConst(_Rt_)) {
        if (s_iRegs[_Rt_].k == 0) {
            MOV32ItoM((u32)&g_psxRegs.GPR.n.lo, 0xffffffff);
            if (IsConst(_Rs_)) {
                MOV32ItoM((u32)&g_psxRegs.GPR.n.hi, s_iRegs[_Rs_].k);
            } else {
                MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
                MOV32RtoM((u32)&g_psxRegs.GPR.n.hi, EAX);
            }
            return;
        }
        MOV32ItoR(ECX, s_iRegs[_Rt_].k);  // printf("divurtk %x\n", s_iRegs[_Rt_].k);
    } else {
        MOV32MtoR(ECX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        CMP32ItoR(ECX, 0);
        g_j8Ptr[0] = JE8(0);
    }
    if (IsConst(_Rs_)) {
        MOV32ItoR(EAX, s_iRegs[_Rs_].k);  // printf("divursk %x\n", s_iRegs[_Rs_].k);
    } else {
        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
    }
    XOR32RtoR(EDX, EDX);
    DIV32R(ECX);
    MOV32RtoM((u32)&g_psxRegs.GPR.n.lo, EAX);
    MOV32RtoM((u32)&g_psxRegs.GPR.n.hi, EDX);

    if (!IsConst(_Rt_)) {
        g_j8Ptr[1] = JMP8(1);

        x86SetJ8(g_j8Ptr[0]);

        MOV32ItoM((u32)&g_psxRegs.GPR.n.lo, 0xffffffff);
        if (IsConst(_Rs_)) {
            MOV32ItoM((u32)&g_psxRegs.GPR.n.hi, s_iRegs[_Rs_].k);
        } else {
            MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
            MOV32RtoM((u32)&g_psxRegs.GPR.n.hi, EAX);
        }

        x86SetJ8(g_j8Ptr[1]);
    }
}
//#endif
// End of * Register mult/div & Register trap logic

/*REC_FUNC(LB);
REC_FUNC(LBU);
REC_FUNC(LH);
REC_FUNC(LHU);
REC_FUNC(LW);

REC_FUNC(SB);
REC_FUNC(SH);
REC_FUNC(SW);*/

// REC_FUNC(LWL);
// REC_FUNC(LWR);
// REC_FUNC(SWL);
// REC_FUNC(SWR);

/* Push OfB for Stores/Loads */
static void iPushOfB() {
    if (IsConst(_Rs_)) {
        PUSH32I(s_iRegs[_Rs_].k + _Imm_);
    } else {
        if (_Imm_) {
            MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
            ADD32ItoR(EAX, _Imm_);
            PUSH32R(EAX);
        } else {
            PUSH32M((u32)&g_psxRegs.GPR.r[_Rs_]);
        }
    }
}

//#if 0
static void recLB() {
    // Rt = mem[Rs + Im] (signed)

    //	iFlushRegs();

    if (IsConst(_Rs_)) {
        u32 addr = s_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0xfff0) == 0xbfc0) {
            if (!_Rt_) return;
            // since bios is readonly it won't change
            MapConst(_Rt_, psxRs8(addr));
            return;
        }
        if ((t & 0x1fe0) == 0) {
            if (!_Rt_) return;
            s_iRegs[_Rt_].state = ST_UNK;

            MOVSX32M8toR(EAX, (u32)&g_psxM[addr & 0x1fffff]);
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            if (!_Rt_) return;
            s_iRegs[_Rt_].state = ST_UNK;

            MOVSX32M8toR(EAX, (u32)&g_psxH[addr & 0xfff]);
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
            return;
        }
        //		SysPrintf("unhandled r8 %x\n", addr);
    }

    iPushOfB();
    CALLFunc((u32)psxMemRead8);
    if (_Rt_) {
        s_iRegs[_Rt_].state = ST_UNK;
        MOVSX32R8toR(EAX, EAX);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
    }
    //	ADD32ItoR(ESP, 4);
    s_resp += 4;
}

static void recLBU() {
    // Rt = mem[Rs + Im] (unsigned)

    //	iFlushRegs();

    if (IsConst(_Rs_)) {
        u32 addr = s_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0xfff0) == 0xbfc0) {
            if (!_Rt_) return;
            // since bios is readonly it won't change
            MapConst(_Rt_, psxRu8(addr));
            return;
        }
        if ((t & 0x1fe0) == 0) {
            if (!_Rt_) return;
            s_iRegs[_Rt_].state = ST_UNK;

            MOVZX32M8toR(EAX, (u32)&g_psxM[addr & 0x1fffff]);
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            if (!_Rt_) return;
            s_iRegs[_Rt_].state = ST_UNK;

            MOVZX32M8toR(EAX, (u32)&g_psxH[addr & 0xfff]);
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
            return;
        }
        //		SysPrintf("unhandled r8u %x\n", addr);
    }

    iPushOfB();
    CALLFunc((u32)psxMemRead8);
    if (_Rt_) {
        s_iRegs[_Rt_].state = ST_UNK;
        MOVZX32R8toR(EAX, EAX);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
    }
    //	ADD32ItoR(ESP, 4);
    s_resp += 4;
}

static void recLH() {
    // Rt = mem[Rs + Im] (signed)

    //	iFlushRegs();

    if (IsConst(_Rs_)) {
        u32 addr = s_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0xfff0) == 0xbfc0) {
            if (!_Rt_) return;
            // since bios is readonly it won't change
            MapConst(_Rt_, psxRs16(addr));
            return;
        }
        if ((t & 0x1fe0) == 0) {
            if (!_Rt_) return;
            s_iRegs[_Rt_].state = ST_UNK;

            MOVSX32M16toR(EAX, (u32)&g_psxM[addr & 0x1fffff]);
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            if (!_Rt_) return;
            s_iRegs[_Rt_].state = ST_UNK;

            MOVSX32M16toR(EAX, (u32)&g_psxH[addr & 0xfff]);
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
            return;
        }
        //		SysPrintf("unhandled r16 %x\n", addr);
    }

    iPushOfB();
    CALLFunc((u32)psxMemRead16);
    if (_Rt_) {
        s_iRegs[_Rt_].state = ST_UNK;
        MOVSX32R16toR(EAX, EAX);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
    }
    //	ADD32ItoR(ESP, 4);
    s_resp += 4;
}

static void recLHU() {
    // Rt = mem[Rs + Im] (unsigned)

    //	iFlushRegs();

    if (IsConst(_Rs_)) {
        u32 addr = s_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0xfff0) == 0xbfc0) {
            if (!_Rt_) return;
            // since bios is readonly it won't change
            MapConst(_Rt_, psxRu16(addr));
            return;
        }
        if ((t & 0x1fe0) == 0) {
            if (!_Rt_) return;
            s_iRegs[_Rt_].state = ST_UNK;

            MOVZX32M16toR(EAX, (u32)&g_psxM[addr & 0x1fffff]);
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            if (!_Rt_) return;
            s_iRegs[_Rt_].state = ST_UNK;

            MOVZX32M16toR(EAX, (u32)&g_psxH[addr & 0xfff]);
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
            return;
        }
        if (t == 0x1f80) {
            if (addr >= 0x1f801c00 && addr < 0x1f801e00) {
                if (!_Rt_) return;
                s_iRegs[_Rt_].state = ST_UNK;

                PUSH32I(addr);
                CALL32M((u32)&SPU_readRegister);
                MOVZX32R16toR(EAX, EAX);
                MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
#ifndef __WIN32__
                s_resp += 4;
#endif
                return;
            }
            switch (addr) {
                case 0x1f801100:
                case 0x1f801110:
                case 0x1f801120:
                    if (!_Rt_) return;
                    s_iRegs[_Rt_].state = ST_UNK;

                    PUSH32I((addr >> 4) & 0x3);
                    CALLFunc((u32)psxRcntRcount);
                    MOVZX32R16toR(EAX, EAX);
                    MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
                    s_resp += 4;
                    return;

                case 0x1f801104:
                case 0x1f801114:
                case 0x1f801124:
                    if (!_Rt_) return;
                    s_iRegs[_Rt_].state = ST_UNK;

                    PUSH32I((addr >> 4) & 0x3);
                    CALLFunc((u32)psxRcntRmode);
                    MOVZX32R16toR(EAX, EAX);
                    MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
                    s_resp += 4;
                    return;

                case 0x1f801108:
                case 0x1f801118:
                case 0x1f801128:
                    if (!_Rt_) return;
                    s_iRegs[_Rt_].state = ST_UNK;

                    PUSH32I((addr >> 4) & 0x3);
                    CALLFunc((u32)psxRcntRtarget);
                    MOVZX32R16toR(EAX, EAX);
                    MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
                    s_resp += 4;
                    return;
            }
        }
        //		SysPrintf("unhandled r16u %x\n", addr);
    }

    iPushOfB();
    CALLFunc((u32)psxMemRead16);
    if (_Rt_) {
        s_iRegs[_Rt_].state = ST_UNK;
        MOVZX32R16toR(EAX, EAX);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
    }
    //	ADD32ItoR(ESP, 4);
    s_resp += 4;
}

static void recLW() {
    // Rt = mem[Rs + Im] (unsigned)

    //	iFlushRegs();

    if (IsConst(_Rs_)) {
        u32 addr = s_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0xfff0) == 0xbfc0) {
            if (!_Rt_) return;
            // since bios is readonly it won't change
            MapConst(_Rt_, psxRu32(addr));
            return;
        }
        if ((t & 0x1fe0) == 0) {
            if (!_Rt_) return;
            s_iRegs[_Rt_].state = ST_UNK;

            MOV32MtoR(EAX, (u32)&g_psxM[addr & 0x1fffff]);
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            if (!_Rt_) return;
            s_iRegs[_Rt_].state = ST_UNK;

            MOV32MtoR(EAX, (u32)&g_psxH[addr & 0xfff]);
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
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
                    s_iRegs[_Rt_].state = ST_UNK;

                    MOV32MtoR(EAX, (u32)&g_psxH[addr & 0xffff]);
                    MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
                    return;

                case 0x1f801810:
                    if (!_Rt_) return;
                    s_iRegs[_Rt_].state = ST_UNK;

                    CALL32M((u32)&GPU_readData);
                    MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
                    return;

                case 0x1f801814:
                    if (!_Rt_) return;
                    s_iRegs[_Rt_].state = ST_UNK;

                    CALL32M((u32)&GPU_readStatus);
                    MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
                    return;
            }
        }
        //		SysPrintf("unhandled r32 %x\n", addr);
    }

    iPushOfB();
    CALLFunc((u32)psxMemRead32);
    if (_Rt_) {
        s_iRegs[_Rt_].state = ST_UNK;
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
    }
    //	ADD32ItoR(ESP, 4);
    s_resp += 4;
}

extern const u32 LWL_MASK[4];
extern const u32 LWL_SHIFT[4];

void iLWLk(u32 shift) {
    if (IsConst(_Rt_)) {
        MOV32ItoR(ECX, s_iRegs[_Rt_].k);
    } else {
        MOV32MtoR(ECX, (u32)&g_psxRegs.GPR.r[_Rt_]);
    }
    AND32ItoR(ECX, LWL_MASK[shift]);
    SHL32ItoR(EAX, LWL_SHIFT[shift]);
    OR32RtoR(EAX, ECX);
}

void recLWL() {
    // Rt = Rt Merge mem[Rs + Im]

    if (IsConst(_Rs_)) {
        u32 addr = s_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0x1fe0) == 0) {
            MOV32MtoR(EAX, (u32)&g_psxM[addr & 0x1ffffc]);
            iLWLk(addr & 3);

            s_iRegs[_Rt_].state = ST_UNK;
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            MOV32MtoR(EAX, (u32)&g_psxH[addr & 0xffc]);
            iLWLk(addr & 3);

            s_iRegs[_Rt_].state = ST_UNK;
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
            return;
        }
    }

    if (IsConst(_Rs_))
        MOV32ItoR(EAX, s_iRegs[_Rs_].k + _Imm_);
    else {
        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        if (_Imm_) ADD32ItoR(EAX, _Imm_);
    }
    PUSH32R(EAX);
    AND32ItoR(EAX, ~3);
    PUSH32R(EAX);
    CALLFunc((u32)psxMemRead32);

    if (_Rt_) {
        ADD32ItoR(ESP, 4);
        POP32R(EDX);
        AND32ItoR(EDX, 0x3);  // shift = addr & 3;

        MOV32ItoR(ECX, (u32)LWL_SHIFT);
        MOV32RmStoR(ECX, ECX, EDX, 2);
        SHL32CLtoR(EAX);  // mem(EAX) << LWL_SHIFT[shift]

        MOV32ItoR(ECX, (u32)LWL_MASK);
        MOV32RmStoR(ECX, ECX, EDX, 2);
        if (IsConst(_Rt_)) {
            MOV32ItoR(EDX, s_iRegs[_Rt_].k);
        } else {
            MOV32MtoR(EDX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        }
        AND32RtoR(EDX, ECX);  // _rRt_ & LWL_MASK[shift]

        OR32RtoR(EAX, EDX);

        s_iRegs[_Rt_].state = ST_UNK;
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
    } else {
        //		ADD32ItoR(ESP, 8);
        s_resp += 8;
    }
}

#if 0
static void recLWBlock(int count) {
	u32 *code = (u32 *)PSXM(pc);
	int i, respsave;
// Rt = mem[Rs + Im] (unsigned)

//	iFlushRegs();

	if (IsConst(_Rs_)) {
		u32 addr = s_iRegs[_Rs_].k + _Imm_;
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
				s_iRegs[_fRt_(*code)].state = ST_UNK;

				MOV32MtoR(EAX, (u32)&g_psxM[addr & 0x1fffff]);
				MOV32RtoM((u32)&g_psxRegs.GPR.r[_fRt_(*code)], EAX);
			}
			return;
		}
		if (t == 0x1f80 && addr < 0x1f801000) {
			for (i = 0; i < count; i++, code++, addr += 4) {
				if (!_fRt_(*code))
					return;
				s_iRegs[_fRt_(*code)].state = ST_UNK;

				MOV32MtoR(EAX, (u32)&g_psxH[addr & 0xfff]);
				MOV32RtoM((u32)&g_psxRegs.GPR.r[_fRt_(*code)], EAX);
			}
			return;
		}
	}

	SysPrintf("recLWBlock %d: %d\n", count, IsConst(_Rs_));
	iPushOfB();
	CALLFunc((u32)psxMemPointer);
//	ADD32ItoR(ESP, 4);
	s_resp += 4;

	respsave = s_resp; s_resp = 0;
	TEST32RtoR(EAX, EAX);
	g_j32Ptr[4] = JZ32(0);
	XOR32RtoR(ECX, ECX);
	for (i = 0; i < count; i++, code++) {
		if (_fRt_(*code)) {
			s_iRegs[_fRt_(*code)].state = ST_UNK;

			MOV32RmStoR(EDX, EAX, ECX, 2);
			MOV32RtoM((u32)&g_psxRegs.GPR.r[_fRt_(*code)], EDX);
		}
		if (i != (count - 1))
			INC32R(ECX);
	}
	g_j32Ptr[5] = JMP32(0);
	x86SetJ32(g_j32Ptr[4]);
	for (i = 0, code = (u32 *)PSXM(pc); i < count; i++, code++) {
		g_psxRegs.code = *code;
		recLW();
	}
	ADD32ItoR(ESP, s_resp);
	x86SetJ32(g_j32Ptr[5]);
	s_resp = respsave;
}
#endif

extern const u32 LWR_MASK[4];
extern const u32 LWR_SHIFT[4];

void iLWRk(u32 shift) {
    if (IsConst(_Rt_)) {
        MOV32ItoR(ECX, s_iRegs[_Rt_].k);
    } else {
        MOV32MtoR(ECX, (u32)&g_psxRegs.GPR.r[_Rt_]);
    }
    AND32ItoR(ECX, LWR_MASK[shift]);
    SHR32ItoR(EAX, LWR_SHIFT[shift]);
    OR32RtoR(EAX, ECX);
}

void recLWR() {
    // Rt = Rt Merge mem[Rs + Im]

    if (IsConst(_Rs_)) {
        u32 addr = s_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0x1fe0) == 0) {
            MOV32MtoR(EAX, (u32)&g_psxM[addr & 0x1ffffc]);
            iLWRk(addr & 3);

            s_iRegs[_Rt_].state = ST_UNK;
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
            return;
        }
        if (t == 0x1f80 && addr < 0x1f801000) {
            MOV32MtoR(EAX, (u32)&g_psxH[addr & 0xffc]);
            iLWRk(addr & 3);

            s_iRegs[_Rt_].state = ST_UNK;
            MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
            return;
        }
    }

    if (IsConst(_Rs_))
        MOV32ItoR(EAX, s_iRegs[_Rs_].k + _Imm_);
    else {
        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        if (_Imm_) ADD32ItoR(EAX, _Imm_);
    }
    PUSH32R(EAX);
    AND32ItoR(EAX, ~3);
    PUSH32R(EAX);
    CALLFunc((u32)psxMemRead32);

    if (_Rt_) {
        ADD32ItoR(ESP, 4);
        POP32R(EDX);
        AND32ItoR(EDX, 0x3);  // shift = addr & 3;

        MOV32ItoR(ECX, (u32)LWR_SHIFT);
        MOV32RmStoR(ECX, ECX, EDX, 2);
        SHR32CLtoR(EAX);  // mem(EAX) >> LWR_SHIFT[shift]

        MOV32ItoR(ECX, (u32)LWR_MASK);
        MOV32RmStoR(ECX, ECX, EDX, 2);

        if (IsConst(_Rt_)) {
            MOV32ItoR(EDX, s_iRegs[_Rt_].k);
        } else {
            MOV32MtoR(EDX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        }
        AND32RtoR(EDX, ECX);  // _rRt_ & LWR_MASK[shift]

        OR32RtoR(EAX, EDX);

        s_iRegs[_Rt_].state = ST_UNK;
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
    } else {
        //		ADD32ItoR(ESP, 8);
        s_resp += 8;
    }
}

static void recSB() {
    // mem[Rs + Im] = Rt

    //	iFlushRegs();

    if (IsConst(_Rs_)) {
        u32 addr = s_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0x1fe0) == 0 && (t & 0x1fff) != 0) {
            if (IsConst(_Rt_)) {
                MOV8ItoM((u32)&g_psxM[addr & 0x1fffff], (u8)s_iRegs[_Rt_].k);
            } else {
                MOV8MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
                MOV8RtoM((u32)&g_psxM[addr & 0x1fffff], EAX);
            }

            PUSH32I(1);
            PUSH32I(addr & ~3);
            CALLFunc((u32)&recClear);
            s_resp += 8;
            return;
        }

        if (t == 0x1f80 && addr < 0x1f801000) {
            if (IsConst(_Rt_)) {
                MOV8ItoM((u32)&g_psxH[addr & 0xfff], (u8)s_iRegs[_Rt_].k);
            } else {
                MOV8MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
                MOV8RtoM((u32)&g_psxH[addr & 0xfff], EAX);
            }
            return;
        }
        //		SysPrintf("unhandled w8 %x\n", addr);
    }

    if (IsConst(_Rt_)) {
        PUSH32I(s_iRegs[_Rt_].k);
    } else {
        PUSH32M((u32)&g_psxRegs.GPR.r[_Rt_]);
    }
    iPushOfB();
    CALLFunc((u32)psxMemWrite8);
    //	ADD32ItoR(ESP, 8);
    s_resp += 8;
}

static void recSH() {
    // mem[Rs + Im] = Rt

    //	iFlushRegs();

    if (IsConst(_Rs_)) {
        u32 addr = s_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0x1fe0) == 0 && (t & 0x1fff) != 0) {
            if (IsConst(_Rt_)) {
                MOV16ItoM((u32)&g_psxM[addr & 0x1fffff], (u16)s_iRegs[_Rt_].k);
            } else {
                MOV16MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
                MOV16RtoM((u32)&g_psxM[addr & 0x1fffff], EAX);
            }

            PUSH32I(1);
            PUSH32I(addr & ~3);
            CALLFunc((u32)&recClear);
            s_resp += 8;
            return;
        }

        if (t == 0x1f80 && addr < 0x1f801000) {
            if (IsConst(_Rt_)) {
                MOV16ItoM((u32)&g_psxH[addr & 0xfff], (u16)s_iRegs[_Rt_].k);
            } else {
                MOV16MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
                MOV16RtoM((u32)&g_psxH[addr & 0xfff], EAX);
            }
            return;
        }
        if (t == 0x1f80) {
            if (addr >= 0x1f801c00 && addr < 0x1f801e00) {
                if (IsConst(_Rt_)) {
                    PUSH32I(s_iRegs[_Rt_].k);
                } else {
                    PUSH32M((u32)&g_psxRegs.GPR.r[_Rt_]);
                }
                PUSH32I(addr);
                CALL32M((u32)&SPU_writeRegister);
#ifndef __WIN32__
                s_resp += 8;
#endif
                return;
            }
        }
        //		SysPrintf("unhandled w16 %x\n", addr);
    }

    if (IsConst(_Rt_)) {
        PUSH32I(s_iRegs[_Rt_].k);
    } else {
        PUSH32M((u32)&g_psxRegs.GPR.r[_Rt_]);
    }
    iPushOfB();
    CALLFunc((u32)psxMemWrite16);
    //	ADD32ItoR(ESP, 8);
    s_resp += 8;
}

static void recSW() {
    // mem[Rs + Im] = Rt

    //	iFlushRegs();

    if (IsConst(_Rs_)) {
        u32 addr = s_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

        if ((t & 0x1fe0) == 0 && (t & 0x1fff) != 0) {
            if (IsConst(_Rt_)) {
                MOV32ItoM((u32)&g_psxM[addr & 0x1fffff], s_iRegs[_Rt_].k);
            } else {
                MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
                MOV32RtoM((u32)&g_psxM[addr & 0x1fffff], EAX);
            }

            PUSH32I(1);
            PUSH32I(addr);
            CALLFunc((u32)&recClear);
            s_resp += 8;
            return;
        }

        if (t == 0x1f80 && addr < 0x1f801000) {
            if (IsConst(_Rt_)) {
                MOV32ItoM((u32)&g_psxH[addr & 0xfff], s_iRegs[_Rt_].k);
            } else {
                MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
                MOV32RtoM((u32)&g_psxH[addr & 0xfff], EAX);
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
                        MOV32ItoM((u32)&g_psxH[addr & 0xffff], s_iRegs[_Rt_].k);
                    } else {
                        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
                        MOV32RtoM((u32)&g_psxH[addr & 0xffff], EAX);
                    }
                    return;

                case 0x1f801810:
                    if (IsConst(_Rt_)) {
                        PUSH32I(s_iRegs[_Rt_].k);
                    } else {
                        PUSH32M((u32)&g_psxRegs.GPR.r[_Rt_]);
                    }
                    CALL32M((u32)&GPU_writeData);
#ifndef __WIN32__
                    s_resp += 4;
#endif
                    return;

                case 0x1f801814:
                    if (IsConst(_Rt_)) {
                        PUSH32I(s_iRegs[_Rt_].k);
                    } else {
                        PUSH32M((u32)&g_psxRegs.GPR.r[_Rt_]);
                    }
                    CALL32M((u32)&GPU_writeStatus);
#ifndef __WIN32__
                    s_resp += 4;
#endif
                    return;
            }
        }
        //		SysPrintf("unhandled w32 %x\n", addr);
    }

    if (IsConst(_Rt_)) {
        PUSH32I(s_iRegs[_Rt_].k);
    } else {
        PUSH32M((u32)&g_psxRegs.GPR.r[_Rt_]);
    }
    iPushOfB();
    CALLFunc((u32)psxMemWrite32);
    //	ADD32ItoR(ESP, 8);
    s_resp += 8;
}
//#endif

#if 0
static void recSWBlock(int count) {
	u32 *code;
	int i, respsave;
// mem[Rs + Im] = Rt

//	iFlushRegs();

	if (IsConst(_Rs_)) {
		u32 addr = s_iRegs[_Rs_].k + _Imm_;
		int t = addr >> 16;
		code = (u32 *)PSXM(pc);

		if ((t & 0x1fe0) == 0 && (t & 0x1fff) != 0) {
			for (i = 0; i < count; i++, code++, addr += 4) {
				if (IsConst(_fRt_(*code))) {
					MOV32ItoM((u32)&g_psxM[addr & 0x1fffff], s_iRegs[_fRt_(*code)].k);
				} else {
					MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_fRt_(*code)]);
					MOV32RtoM((u32)&g_psxM[addr & 0x1fffff], EAX);
				}
			}
			return;
		}
		if (t == 0x1f80 && addr < 0x1f801000) {
			for (i = 0; i < count; i++, code++, addr += 4) {
				if (!_fRt_(*code))
					return;
				s_iRegs[_fRt_(*code)].state = ST_UNK;

				MOV32MtoR(EAX, (u32)&g_psxH[addr & 0xfff]);
				MOV32RtoM((u32)&g_psxRegs.GPR.r[_fRt_(*code)], EAX);
			}
			return;
		}
	}

	SysPrintf("recSWBlock %d: %d\n", count, IsConst(_Rs_));
	iPushOfB();
	CALLFunc((u32)psxMemPointer);
//	ADD32ItoR(ESP, 4);
	s_resp += 4;

	respsave = s_resp;
	s_resp = 0;
	TEST32RtoR(EAX, EAX);
	g_j32Ptr[4] = JZ32(0);
	XOR32RtoR(ECX, ECX);
	for (i = 0, code = (u32 *)PSXM(pc); i < count; i++, code++) {
		if (IsConst(_fRt_(*code))) {
			MOV32ItoR(EDX, s_iRegs[_fRt_(*code)].k);
		} else {
			MOV32MtoR(EDX, (u32)&g_psxRegs.GPR.r[_fRt_(*code)]);
		}
		MOV32RtoRmS(EAX, ECX, 2, EDX);
		if (i != (count - 1))
			INC32R(ECX);
	}
	g_j32Ptr[5] = JMP32(0);
	x86SetJ32(g_j32Ptr[4]);
	for (i = 0, code = (u32 *)PSXM(pc); i < count; i++, code++) {
		g_psxRegs.code = *code;
		recSW();
	}
	ADD32ItoR(ESP, s_resp);
	x86SetJ32(g_j32Ptr[5]);
	s_resp = respsave;
}
#endif

extern const u32 SWL_MASK[4];
extern const u32 SWL_SHIFT[4];

void iSWLk(u32 shift) {
    if (IsConst(_Rt_)) {
        MOV32ItoR(ECX, s_iRegs[_Rt_].k);
    } else {
        MOV32MtoR(ECX, (u32)&g_psxRegs.GPR.r[_Rt_]);
    }
    SHR32ItoR(ECX, SWL_SHIFT[shift]);
    AND32ItoR(EAX, SWL_MASK[shift]);
    OR32RtoR(EAX, ECX);
}

void recSWL() {
    // mem[Rs + Im] = Rt Merge mem[Rs + Im]

    if (IsConst(_Rs_)) {
        u32 addr = s_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

#if 0
		if ((t & 0x1fe0) == 0 && (t & 0x1fff) != 0) {
			MOV32MtoR(EAX, (u32)&g_psxM[addr & 0x1ffffc]);
			iSWLk(addr & 3);
			MOV32RtoM((u32)&g_psxM[addr & 0x1ffffc], EAX);
			return;
		}
#endif
        if (t == 0x1f80 && addr < 0x1f801000) {
            MOV32MtoR(EAX, (u32)&g_psxH[addr & 0xffc]);
            iSWLk(addr & 3);
            MOV32RtoM((u32)&g_psxH[addr & 0xffc], EAX);
            return;
        }
    }

    if (IsConst(_Rs_)) {
        MOV32ItoR(EAX, s_iRegs[_Rs_].k + _Imm_);
    } else {
        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        if (_Imm_) ADD32ItoR(EAX, _Imm_);
    }
    PUSH32R(EAX);
    AND32ItoR(EAX, ~3);
    PUSH32R(EAX);

    CALLFunc((u32)psxMemRead32);

    ADD32ItoR(ESP, 4);
    POP32R(EDX);
    AND32ItoR(EDX, 0x3);  // shift = addr & 3;

    MOV32ItoR(ECX, (u32)SWL_MASK);
    MOV32RmStoR(ECX, ECX, EDX, 2);
    AND32RtoR(EAX, ECX);  // mem & SWL_MASK[shift]

    MOV32ItoR(ECX, (u32)SWL_SHIFT);
    MOV32RmStoR(ECX, ECX, EDX, 2);
    if (IsConst(_Rt_)) {
        MOV32ItoR(EDX, s_iRegs[_Rt_].k);
    } else {
        MOV32MtoR(EDX, (u32)&g_psxRegs.GPR.r[_Rt_]);
    }
    SHR32CLtoR(EDX);  // _rRt_ >> SWL_SHIFT[shift]

    OR32RtoR(EAX, EDX);
    PUSH32R(EAX);

    if (IsConst(_Rs_))
        MOV32ItoR(EAX, s_iRegs[_Rs_].k + _Imm_);
    else {
        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        if (_Imm_) ADD32ItoR(EAX, _Imm_);
    }
    AND32ItoR(EAX, ~3);
    PUSH32R(EAX);

    CALLFunc((u32)psxMemWrite32);
    //	ADD32ItoR(ESP, 8);
    s_resp += 8;
}

extern const u32 SWR_MASK[4];
extern const u32 SWR_SHIFT[4];

void iSWRk(u32 shift) {
    if (IsConst(_Rt_)) {
        MOV32ItoR(ECX, s_iRegs[_Rt_].k);
    } else {
        MOV32MtoR(ECX, (u32)&g_psxRegs.GPR.r[_Rt_]);
    }
    SHL32ItoR(ECX, SWR_SHIFT[shift]);
    AND32ItoR(EAX, SWR_MASK[shift]);
    OR32RtoR(EAX, ECX);
}

void recSWR() {
    // mem[Rs + Im] = Rt Merge mem[Rs + Im]

    if (IsConst(_Rs_)) {
        u32 addr = s_iRegs[_Rs_].k + _Imm_;
        int t = addr >> 16;

#if 0
		if ((t & 0x1fe0) == 0 && (t & 0x1fff) != 0) {
			MOV32MtoR(EAX, (u32)&g_psxM[addr & 0x1ffffc]);
			iSWRk(addr & 3);
			MOV32RtoM((u32)&g_psxM[addr & 0x1ffffc], EAX);
			return;
		}
#endif
        if (t == 0x1f80 && addr < 0x1f801000) {
            MOV32MtoR(EAX, (u32)&g_psxH[addr & 0xffc]);
            iSWRk(addr & 3);
            MOV32RtoM((u32)&g_psxH[addr & 0xffc], EAX);
            return;
        }
    }

    if (IsConst(_Rs_)) {
        MOV32ItoR(EAX, s_iRegs[_Rs_].k + _Imm_);
    } else {
        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        if (_Imm_) ADD32ItoR(EAX, _Imm_);
    }
    PUSH32R(EAX);
    AND32ItoR(EAX, ~3);
    PUSH32R(EAX);

    CALLFunc((u32)psxMemRead32);

    ADD32ItoR(ESP, 4);
    POP32R(EDX);
    AND32ItoR(EDX, 0x3);  // shift = addr & 3;

    MOV32ItoR(ECX, (u32)SWR_MASK);
    MOV32RmStoR(ECX, ECX, EDX, 2);
    AND32RtoR(EAX, ECX);  // mem & SWR_MASK[shift]

    MOV32ItoR(ECX, (u32)SWR_SHIFT);
    MOV32RmStoR(ECX, ECX, EDX, 2);
    if (IsConst(_Rt_)) {
        MOV32ItoR(EDX, s_iRegs[_Rt_].k);
    } else {
        MOV32MtoR(EDX, (u32)&g_psxRegs.GPR.r[_Rt_]);
    }
    SHL32CLtoR(EDX);  // _rRt_ << SWR_SHIFT[shift]

    OR32RtoR(EAX, EDX);
    PUSH32R(EAX);

    if (IsConst(_Rs_))
        MOV32ItoR(EAX, s_iRegs[_Rs_].k + _Imm_);
    else {
        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        if (_Imm_) ADD32ItoR(EAX, _Imm_);
    }
    AND32ItoR(EAX, ~3);
    PUSH32R(EAX);

    CALLFunc((u32)psxMemWrite32);
    //	ADD32ItoR(ESP, 8);
    s_resp += 8;
}

/*REC_FUNC(SLL);
REC_FUNC(SRL);
REC_FUNC(SRA);
#if 0*/
static void recSLL() {
    // Rd = Rt << Sa
    if (!_Rd_) return;

    //	iFlushRegs();

    if (IsConst(_Rt_)) {
        MapConst(_Rd_, s_iRegs[_Rt_].k << _Sa_);
    } else {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        if (_Sa_) SHL32ItoR(EAX, _Sa_);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    }
}

static void recSRL() {
    // Rd = Rt >> Sa
    if (!_Rd_) return;

    //	iFlushRegs();

    if (IsConst(_Rt_)) {
        MapConst(_Rd_, s_iRegs[_Rt_].k >> _Sa_);
    } else {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        if (_Sa_) SHR32ItoR(EAX, _Sa_);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    }
}

static void recSRA() {
    // Rd = Rt >> Sa
    if (!_Rd_) return;

    //	iFlushRegs();

    if (IsConst(_Rt_)) {
        MapConst(_Rd_, (s32)s_iRegs[_Rt_].k >> _Sa_);
    } else {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        if (_Sa_) SAR32ItoR(EAX, _Sa_);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    }
}
//#endif

/*REC_FUNC(SLLV);
REC_FUNC(SRLV);
REC_FUNC(SRAV);
#if 0*/
static void recSLLV() {
    // Rd = Rt << Rs
    if (!_Rd_) return;

    //	iFlushRegs();

    if (IsConst(_Rt_) && IsConst(_Rs_)) {
        MapConst(_Rd_, s_iRegs[_Rt_].k << s_iRegs[_Rs_].k);
    } else if (IsConst(_Rs_)) {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        MOV32ItoR(ECX, s_iRegs[_Rs_].k);
        SHL32CLtoR(EAX);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    } else if (IsConst(_Rt_)) {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32ItoR(EAX, s_iRegs[_Rt_].k);
        MOV32MtoR(ECX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        SHL32CLtoR(EAX);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    } else {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        MOV32MtoR(ECX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        SHL32CLtoR(EAX);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    }
}

static void recSRLV() {
    // Rd = Rt >> Rs
    if (!_Rd_) return;

    //	iFlushRegs();

    if (IsConst(_Rt_) && IsConst(_Rs_)) {
        MapConst(_Rd_, s_iRegs[_Rt_].k >> s_iRegs[_Rs_].k);
    } else if (IsConst(_Rs_)) {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        MOV32ItoR(ECX, s_iRegs[_Rs_].k);
        SHR32CLtoR(EAX);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    } else if (IsConst(_Rt_)) {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32ItoR(EAX, s_iRegs[_Rt_].k);
        MOV32MtoR(ECX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        SHR32CLtoR(EAX);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    } else {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        MOV32MtoR(ECX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        SHR32CLtoR(EAX);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    }
}

static void recSRAV() {
    // Rd = Rt >> Rs
    if (!_Rd_) return;

    //	iFlushRegs();

    if (IsConst(_Rt_) && IsConst(_Rs_)) {
        MapConst(_Rd_, (s32)s_iRegs[_Rt_].k >> s_iRegs[_Rs_].k);
    } else if (IsConst(_Rs_)) {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        MOV32ItoR(ECX, s_iRegs[_Rs_].k);
        SAR32CLtoR(EAX);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    } else if (IsConst(_Rt_)) {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32ItoR(EAX, s_iRegs[_Rt_].k);
        MOV32MtoR(ECX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        SAR32CLtoR(EAX);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    } else {
        s_iRegs[_Rd_].state = ST_UNK;

        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        MOV32MtoR(ECX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        SAR32CLtoR(EAX);
        MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
    }
}
//#endif

/*REC_SYS(SYSCALL);
REC_SYS(BREAK);

#if 0*/
int dump;
static void recSYSCALL() {
    //	dump = 1;
    iFlushRegs();

    MOV32ItoR(EAX, s_pc - 4);
    MOV32RtoM((u32)&g_psxRegs.pc, EAX);
    PUSH32I(s_branch == 1 ? 1 : 0);
    PUSH32I(0x20);
    CALLFunc((u32)psxException);
    ADD32ItoR(ESP, 8);

    s_branch = 2;
    iRet();
}

static void recBREAK() {}
//#endif

/*REC_FUNC(MFHI);
REC_FUNC(MTHI);
REC_FUNC(MFLO);
REC_FUNC(MTLO);
#if 0*/
static void recMFHI() {
    // Rd = Hi
    if (!_Rd_) return;

    s_iRegs[_Rd_].state = ST_UNK;
    MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.n.hi);
    MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
}

static void recMTHI() {
    // Hi = Rs

    if (IsConst(_Rs_)) {
        MOV32ItoM((u32)&g_psxRegs.GPR.n.hi, s_iRegs[_Rs_].k);
    } else {
        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        MOV32RtoM((u32)&g_psxRegs.GPR.n.hi, EAX);
    }
}

static void recMFLO() {
    // Rd = Lo
    if (!_Rd_) return;

    s_iRegs[_Rd_].state = ST_UNK;
    MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.n.lo);
    MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rd_], EAX);
}

static void recMTLO() {
    // Lo = Rs

    if (IsConst(_Rs_)) {
        MOV32ItoM((u32)&g_psxRegs.GPR.n.lo, s_iRegs[_Rs_].k);
    } else {
        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        MOV32RtoM((u32)&g_psxRegs.GPR.n.lo, EAX);
    }
}
//#endif

/*REC_BRANCH(J);
REC_BRANCH(JR);
REC_BRANCH(JAL);
REC_BRANCH(JALR);
REC_BRANCH(BLTZ);
REC_BRANCH(BGTZ);
REC_BRANCH(BLTZAL);
REC_BRANCH(BGEZAL);
REC_BRANCH(BNE);
REC_BRANCH(BEQ);
REC_BRANCH(BLEZ);
REC_BRANCH(BGEZ);*/

//#if 0
static void recBLTZ() {
    // Branch if Rs < 0
    u32 bpc = _Imm_ * 4 + s_pc;

    //	iFlushRegs();

    if (bpc == s_pc + 4 && psxTestLoadDelay(_Rs_, PSXMu32(bpc)) == 0) {
        return;
    }

    if (IsConst(_Rs_)) {
        if ((s32)s_iRegs[_Rs_].k < 0) {
            iJump(bpc);
            return;
        } else {
            iJump(s_pc + 4);
            return;
        }
    }

    CMP32ItoM((u32)&g_psxRegs.GPR.r[_Rs_], 0);
    g_j32Ptr[4] = JL32(0);

    iBranch(s_pc + 4, 1);

    x86SetJ32(g_j32Ptr[4]);

    iBranch(bpc, 0);
    s_pc += 4;
}

static void recBGTZ() {
    // Branch if Rs > 0
    u32 bpc = _Imm_ * 4 + s_pc;

    //	iFlushRegs();
    if (bpc == s_pc + 4 && psxTestLoadDelay(_Rs_, PSXMu32(bpc)) == 0) {
        return;
    }

    if (IsConst(_Rs_)) {
        if ((s32)s_iRegs[_Rs_].k > 0) {
            iJump(bpc);
            return;
        } else {
            iJump(s_pc + 4);
            return;
        }
    }

    CMP32ItoM((u32)&g_psxRegs.GPR.r[_Rs_], 0);
    g_j32Ptr[4] = JG32(0);

    iBranch(s_pc + 4, 1);

    x86SetJ32(g_j32Ptr[4]);

    iBranch(bpc, 0);
    s_pc += 4;
}

static void recBLTZAL() {
    // Branch if Rs < 0
    u32 bpc = _Imm_ * 4 + s_pc;

    //	iFlushRegs();
    if (bpc == s_pc + 4 && psxTestLoadDelay(_Rs_, PSXMu32(bpc)) == 0) {
        return;
    }

    if (IsConst(_Rs_)) {
        if ((s32)s_iRegs[_Rs_].k < 0) {
            MOV32ItoM((u32)&g_psxRegs.GPR.r[31], s_pc + 4);
            iJump(bpc);
            return;
        } else {
            iJump(s_pc + 4);
            return;
        }
    }

    CMP32ItoM((u32)&g_psxRegs.GPR.r[_Rs_], 0);
    g_j32Ptr[4] = JL32(0);

    iBranch(s_pc + 4, 1);

    x86SetJ32(g_j32Ptr[4]);

    MOV32ItoM((u32)&g_psxRegs.GPR.r[31], s_pc + 4);
    iBranch(bpc, 0);
    s_pc += 4;
}

static void recBGEZAL() {
    // Branch if Rs >= 0
    u32 bpc = _Imm_ * 4 + s_pc;

    //	iFlushRegs();
    if (bpc == s_pc + 4 && psxTestLoadDelay(_Rs_, PSXMu32(bpc)) == 0) {
        return;
    }

    if (IsConst(_Rs_)) {
        if ((s32)s_iRegs[_Rs_].k >= 0) {
            MOV32ItoM((u32)&g_psxRegs.GPR.r[31], s_pc + 4);
            iJump(bpc);
            return;
        } else {
            iJump(s_pc + 4);
            return;
        }
    }

    CMP32ItoM((u32)&g_psxRegs.GPR.r[_Rs_], 0);
    g_j32Ptr[4] = JGE32(0);

    iBranch(s_pc + 4, 1);

    x86SetJ32(g_j32Ptr[4]);

    MOV32ItoM((u32)&g_psxRegs.GPR.r[31], s_pc + 4);
    iBranch(bpc, 0);
    s_pc += 4;
}

static void recJ() {
    // j target

    iJump(_Target_ * 4 + (s_pc & 0xf0000000));
}

static void recJAL() {
    // jal target

    MapConst(31, s_pc + 4);

    iJump(_Target_ * 4 + (s_pc & 0xf0000000));
}

static void recJR() {
    // jr Rs

    if (IsConst(_Rs_)) {
        MOV32ItoM((u32)&s_target, s_iRegs[_Rs_].k);
    } else {
        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        MOV32RtoM((u32)&s_target, EAX);
    }

    SetBranch();
}

static void recJALR() {
    // jalr Rs

    if (IsConst(_Rs_)) {
        MOV32ItoM((u32)&s_target, s_iRegs[_Rs_].k);
    } else {
        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        MOV32RtoM((u32)&s_target, EAX);
    }

    if (_Rd_) {
        MapConst(_Rd_, s_pc + 4);
    }

    SetBranch();
}

static void recBEQ() {
    // Branch if Rs == Rt
    u32 bpc = _Imm_ * 4 + s_pc;

    //	iFlushRegs();
    if (bpc == s_pc + 4 && psxTestLoadDelay(_Rs_, PSXMu32(bpc)) == 0) {
        return;
    }

    if (_Rs_ == _Rt_) {
        iJump(bpc);
    } else {
        if (IsConst(_Rs_) && IsConst(_Rt_)) {
            if (s_iRegs[_Rs_].k == s_iRegs[_Rt_].k) {
                iJump(bpc);
                return;
            } else {
                iJump(s_pc + 4);
                return;
            }
        } else if (IsConst(_Rs_)) {
            CMP32ItoM((u32)&g_psxRegs.GPR.r[_Rt_], s_iRegs[_Rs_].k);
        } else if (IsConst(_Rt_)) {
            CMP32ItoM((u32)&g_psxRegs.GPR.r[_Rs_], s_iRegs[_Rt_].k);
        } else {
            MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
            CMP32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        }

        g_j32Ptr[4] = JE32(0);

        iBranch(s_pc + 4, 1);

        x86SetJ32(g_j32Ptr[4]);

        iBranch(bpc, 0);
        s_pc += 4;
    }
}

static void recBNE() {
    // Branch if Rs != Rt
    u32 bpc = _Imm_ * 4 + s_pc;

    //	iFlushRegs();
    if (bpc == s_pc + 4 && psxTestLoadDelay(_Rs_, PSXMu32(bpc)) == 0) {
        return;
    }

    if (IsConst(_Rs_) && IsConst(_Rt_)) {
        if (s_iRegs[_Rs_].k != s_iRegs[_Rt_].k) {
            iJump(bpc);
            return;
        } else {
            iJump(s_pc + 4);
            return;
        }
    } else if (IsConst(_Rs_)) {
        CMP32ItoM((u32)&g_psxRegs.GPR.r[_Rt_], s_iRegs[_Rs_].k);
    } else if (IsConst(_Rt_)) {
        CMP32ItoM((u32)&g_psxRegs.GPR.r[_Rs_], s_iRegs[_Rt_].k);
    } else {
        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]);
        CMP32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
    }
    g_j32Ptr[4] = JNE32(0);

    iBranch(s_pc + 4, 1);

    x86SetJ32(g_j32Ptr[4]);

    iBranch(bpc, 0);
    s_pc += 4;
}

static void recBLEZ() {
    // Branch if Rs <= 0
    u32 bpc = _Imm_ * 4 + s_pc;

    //	iFlushRegs();
    if (bpc == s_pc + 4 && psxTestLoadDelay(_Rs_, PSXMu32(bpc)) == 0) {
        return;
    }

    if (IsConst(_Rs_)) {
        if ((s32)s_iRegs[_Rs_].k <= 0) {
            iJump(bpc);
            return;
        } else {
            iJump(s_pc + 4);
            return;
        }
    }

    CMP32ItoM((u32)&g_psxRegs.GPR.r[_Rs_], 0);
    g_j32Ptr[4] = JLE32(0);

    iBranch(s_pc + 4, 1);

    x86SetJ32(g_j32Ptr[4]);

    iBranch(bpc, 0);
    s_pc += 4;
}

static void recBGEZ() {
    // Branch if Rs >= 0
    u32 bpc = _Imm_ * 4 + s_pc;

    //	iFlushRegs();
    if (bpc == s_pc + 4 && psxTestLoadDelay(_Rs_, PSXMu32(bpc)) == 0) {
        return;
    }

    if (IsConst(_Rs_)) {
        if ((s32)s_iRegs[_Rs_].k >= 0) {
            iJump(bpc);
            return;
        } else {
            iJump(s_pc + 4);
            return;
        }
    }

    CMP32ItoM((u32)&g_psxRegs.GPR.r[_Rs_], 0);
    g_j32Ptr[4] = JGE32(0);

    iBranch(s_pc + 4, 1);

    x86SetJ32(g_j32Ptr[4]);

    iBranch(bpc, 0);
    s_pc += 4;
}
//#endif

/*REC_FUNC(MFC0);
REC_SYS(MTC0);
REC_FUNC(CFC0);
REC_SYS(CTC0);
REC_FUNC(RFE);
#if 0*/
static void recMFC0() {
    // Rt = Cop0->Rd
    if (!_Rt_) return;

    s_iRegs[_Rt_].state = ST_UNK;
    MOV32MtoR(EAX, (u32)&g_psxRegs.CP0.r[_Rd_]);
    MOV32RtoM((u32)&g_psxRegs.GPR.r[_Rt_], EAX);
}

static void recCFC0() {
    // Rt = Cop0->Rd

    recMFC0();
}

void psxMTC0();
static void recMTC0() {
    // Cop0->Rd = Rt

    if (IsConst(_Rt_)) {
        switch (_Rd_) {
            case 12:
                MOV32ItoM((u32)&g_psxRegs.CP0.r[_Rd_], s_iRegs[_Rt_].k);
                break;
            case 13:
                MOV32ItoM((u32)&g_psxRegs.CP0.r[_Rd_], s_iRegs[_Rt_].k & ~(0xfc00));
                break;
            default:
                MOV32ItoM((u32)&g_psxRegs.CP0.r[_Rd_], s_iRegs[_Rt_].k);
                break;
        }
    } else {
        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rt_]);
        switch (_Rd_) {
            case 13:
                AND32ItoR(EAX, ~(0xfc00));
                break;
        }
        MOV32RtoM((u32)&g_psxRegs.CP0.r[_Rd_], EAX);
    }

    if (_Rd_ == 12 || _Rd_ == 13) {
        iFlushRegs();
        MOV32ItoM((u32)&g_psxRegs.pc, (u32)s_pc);
        CALLFunc((u32)psxTestSWInts);
        if (s_branch == 0) {
            s_branch = 2;
            iRet();
        }
    }
}

static void recCTC0() {
    // Cop0->Rd = Rt

    recMTC0();
}

static void recRFE() {
    MOV32MtoR(EAX, (u32)&g_psxRegs.CP0.n.Status);
    MOV32RtoR(ECX, EAX);
    AND32ItoR(EAX, 0xfffffff0);
    AND32ItoR(ECX, 0x3c);
    SHR32ItoR(ECX, 2);
    OR32RtoR(EAX, ECX);
    MOV32RtoM((u32)&g_psxRegs.CP0.n.Status, EAX);

    iFlushRegs();
    MOV32ItoM((u32)&g_psxRegs.pc, (u32)s_pc);
    CALLFunc((u32)psxTestSWInts);
    if (s_branch == 0) {
        s_branch = 2;
        iRet();
    }
}
//#endif

#include "iGte.h"

//

static void recHLE() {
    iFlushRegs();

    MOV32ItoR(EAX, (u32)psxHLEt[g_psxRegs.code & 0xffff]);
    CALL32R(EAX);
    s_branch = 2;
    iRet();
}

//
/////////////////////////////////////////////
// PGXP wrapper functions
/////////////////////////////////////////////

pgxpRecNULL() {}

// Choose between debug and direct function
#ifdef PGXP_CPU_DEBUG
#define PGXP_REC_FUNC_OP(pu, op, nReg) PGXP_psxTraceOp##nReg
#define PGXP_DBG_OP_E(op) \
    PUSH32I(DBG_E_##op);  \
    s_resp += 4;
#else
#define PGXP_REC_FUNC_OP(pu, op, nReg) PGXP_##pu##_##op
#define PGXP_DBG_OP_E(op)
#endif

#define PGXP_REC_FUNC_PASS(pu, op) \
    static void pgxpRec##op() { rec##op(); }

#define PGXP_REC_FUNC(pu, op)                      \
    static void pgxpRec##op() {                    \
        PUSH32I(g_psxRegs.code);                     \
        PGXP_DBG_OP_E(op)                          \
        CALLFunc((u32)PGXP_REC_FUNC_OP(pu, op, )); \
        s_resp += 4;                               \
        rec##op();                                 \
    }

#define PGXP_REC_FUNC_1(pu, op, reg1)               \
    static void pgxpRec##op() {                     \
        reg1;                                       \
        PUSH32I(g_psxRegs.code);                      \
        PGXP_DBG_OP_E(op)                           \
        CALLFunc((u32)PGXP_REC_FUNC_OP(pu, op, 1)); \
        s_resp += 8;                                \
        rec##op();                                  \
    }

#define PGXP_REC_FUNC_2_2(pu, op, test, nReg, reg1, reg2, reg3, reg4) \
    static void pgxpRec##op() {                                       \
        if (test) {                                                   \
            rec##op();                                                \
            return;                                                   \
        }                                                             \
        reg1;                                                         \
        reg2;                                                         \
        rec##op();                                                    \
        reg3;                                                         \
        reg4;                                                         \
        PUSH32I(g_psxRegs.code);                                        \
        PGXP_DBG_OP_E(op)                                             \
        CALLFunc((u32)PGXP_REC_FUNC_OP(pu, op, nReg));                \
        s_resp += (4 * nReg) + 4;                                     \
    }

#define PGXP_REC_FUNC_2(pu, op, reg1, reg2)         \
    static void pgxpRec##op() {                     \
        reg1;                                       \
        reg2;                                       \
        PUSH32I(g_psxRegs.code);                      \
        PGXP_DBG_OP_E(op)                           \
        CALLFunc((u32)PGXP_REC_FUNC_OP(pu, op, 2)); \
        s_resp += 12;                               \
        rec##op();                                  \
    }

static u32 gTempAddr = 0;
#define PGXP_REC_FUNC_ADDR_1(pu, op, reg1)             \
    static void pgxpRec##op() {                        \
        if (IsConst(_Rs_)) {                           \
            MOV32ItoR(EAX, s_iRegs[_Rs_].k + _Imm_);     \
        } else {                                       \
            MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[_Rs_]); \
            if (_Imm_) {                               \
                ADD32ItoR(EAX, _Imm_);                 \
            }                                          \
        }                                              \
        MOV32RtoM((u32)&gTempAddr, EAX);               \
        rec##op();                                     \
        PUSH32M((u32)&gTempAddr);                      \
        reg1;                                          \
        PUSH32I(g_psxRegs.code);                         \
        PGXP_DBG_OP_E(op)                              \
        CALLFunc((u32)PGXP_REC_FUNC_OP(pu, op, 2));    \
        s_resp += 12;                                  \
    }

#define CPU_REG_NC(idx) MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[idx])

#define CPU_REG(idx)                  \
    if (IsConst(idx))                 \
        MOV32ItoR(EAX, s_iRegs[idx].k); \
    else                              \
        MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[idx]);

#define CP0_REG(idx) MOV32MtoR(EAX, (u32)&g_psxRegs.CP0.r[idx])
#define GTE_DATA_REG(idx) MOV32MtoR(EAX, (u32)&g_psxRegs.CP2D.r[idx])
#define GTE_CTRL_REG(idx) MOV32MtoR(EAX, (u32)&g_psxRegs.CP2C.r[idx])

static u32 gTempInstr = 0;
static u32 gTempReg1 = 0;
static u32 gTempReg2 = 0;
#define PGXP_REC_FUNC_R1_1(pu, op, test, reg1, reg2) \
    static void pgxpRec##op() {                      \
        if (test) {                                  \
            rec##op();                               \
            return;                                  \
        }                                            \
        reg1;                                        \
        MOV32RtoM((u32)&gTempReg1, EAX);             \
        rec##op();                                   \
        PUSH32M((u32)&gTempReg1);                    \
        reg2;                                        \
        PUSH32I(g_psxRegs.code);                       \
        PGXP_DBG_OP_E(op)                            \
        CALLFunc((u32)PGXP_REC_FUNC_OP(pu, op, 2));  \
        s_resp += 12;                                \
    }

#define PGXP_REC_FUNC_R2_1(pu, op, test, reg1, reg2, reg3) \
    static void pgxpRec##op() {                            \
        if (test) {                                        \
            rec##op();                                     \
            return;                                        \
        }                                                  \
        reg1;                                              \
        MOV32RtoM((u32)&gTempReg1, EAX);                   \
        reg2;                                              \
        MOV32RtoM((u32)&gTempReg2, EAX);                   \
        rec##op();                                         \
        PUSH32M((u32)&gTempReg1);                          \
        PUSH32M((u32)&gTempReg2);                          \
        reg3;                                              \
        PUSH32I(g_psxRegs.code);                             \
        PGXP_DBG_OP_E(op)                                  \
        CALLFunc((u32)PGXP_REC_FUNC_OP(pu, op, 3));        \
        s_resp += 16;                                      \
    }

#define PGXP_REC_FUNC_R2_2(pu, op, test, reg1, reg2, reg3, reg4) \
    static void pgxpRec##op() {                                  \
        if (test) {                                              \
            rec##op();                                           \
            return;                                              \
        }                                                        \
        reg1;                                                    \
        MOV32RtoM((u32)&gTempReg1, EAX);                         \
        reg2;                                                    \
        MOV32RtoM((u32)&gTempReg2, EAX);                         \
        rec##op();                                               \
        PUSH32M((u32)&gTempReg1);                                \
        PUSH32M((u32)&gTempReg2);                                \
        reg3;                                                    \
        reg4;                                                    \
        PUSH32I(g_psxRegs.code);                                   \
        PGXP_DBG_OP_E(op)                                        \
        CALLFunc((u32)PGXP_REC_FUNC_OP(pu, op, 4));              \
        s_resp += 20;                                            \
    }

//#define PGXP_REC_FUNC_R1i_1(pu, op, test, reg1, reg2) \
//static void pgxpRec##op()	\
//{	\
//	if(test) { rec##op(); return; }\
//	if (IsConst(reg1))	\
//		MOV32ItoR(EAX, s_iRegs[reg1].k);	\
//	else\
//		MOV32MtoR(EAX, (u32)&g_psxRegs.GPR.r[reg1]);\
//	MOV32RtoM((u32)&gTempReg, EAX);\
//	rec##op();\
//	PUSH32M((u32)&gTempReg);\
//	reg2;\
//	PUSH32I(g_psxRegs.code);	\
//	CALLFunc((u32)PGXP_REC_FUNC_OP(pu, op, 2)); \
//	s_resp += 12; \
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
PGXP_REC_FUNC_R2_2(CPU, MULT, 0, CPU_REG(_Rt_), CPU_REG(_Rs_), PUSH32M((u32)&g_psxRegs.GPR.n.lo),
                   PUSH32M((u32)&g_psxRegs.GPR.n.hi))
PGXP_REC_FUNC_R2_2(CPU, MULTU, 0, CPU_REG(_Rt_), CPU_REG(_Rs_), PUSH32M((u32)&g_psxRegs.GPR.n.lo),
                   PUSH32M((u32)&g_psxRegs.GPR.n.hi))
PGXP_REC_FUNC_R2_2(CPU, DIV, 0, CPU_REG(_Rt_), CPU_REG(_Rs_), PUSH32M((u32)&g_psxRegs.GPR.n.lo),
                   PUSH32M((u32)&g_psxRegs.GPR.n.hi))
PGXP_REC_FUNC_R2_2(CPU, DIVU, 0, CPU_REG(_Rt_), CPU_REG(_Rs_), PUSH32M((u32)&g_psxRegs.GPR.n.lo),
                   PUSH32M((u32)&g_psxRegs.GPR.n.hi))

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
PGXP_REC_FUNC_R1_1(CPU, MTHI, 0, CPU_REG(_Rd_), PUSH32M((u32)&g_psxRegs.GPR.n.hi))
PGXP_REC_FUNC_R1_1(CPU, MFLO, !_Rd_, CPU_REG_NC(32), iPushReg(_Rd_))
PGXP_REC_FUNC_R1_1(CPU, MTLO, 0, CPU_REG(_Rd_), PUSH32M((u32)&g_psxRegs.GPR.n.lo))

// COP2 (GTE)
PGXP_REC_FUNC_R1_1(GTE, MFC2, !_Rt_, GTE_DATA_REG(_Rd_), iPushReg(_Rt_))
PGXP_REC_FUNC_R1_1(GTE, CFC2, !_Rt_, GTE_CTRL_REG(_Rd_), iPushReg(_Rt_))
PGXP_REC_FUNC_R1_1(GTE, MTC2, 0, CPU_REG(_Rt_), PUSH32M((u32)&g_psxRegs.CP2D.r[_Rd_]))
PGXP_REC_FUNC_R1_1(GTE, CTC2, 0, CPU_REG(_Rt_), PUSH32M((u32)&g_psxRegs.CP2C.r[_Rd_]))

PGXP_REC_FUNC_ADDR_1(GTE, LWC2, PUSH32M((u32)&g_psxRegs.CP2D.r[_Rt_]))
PGXP_REC_FUNC_ADDR_1(GTE, SWC2, PUSH32M((u32)&g_psxRegs.CP2D.r[_Rt_]))

// COP0
PGXP_REC_FUNC_R1_1(CP0, MFC0, !_Rd_, CP0_REG(_Rd_), iPushReg(_Rt_))
PGXP_REC_FUNC_R1_1(CP0, CFC0, !_Rd_, CP0_REG(_Rd_), iPushReg(_Rt_))
PGXP_REC_FUNC_R1_1(CP0, MTC0, !_Rt_, CPU_REG(_Rt_), PUSH32M((u32)&g_psxRegs.CP0.r[_Rd_]))
PGXP_REC_FUNC_R1_1(CP0, CTC0, !_Rt_, CPU_REG(_Rt_), PUSH32M((u32)&g_psxRegs.CP0.r[_Rd_]))
PGXP_REC_FUNC(CP0, RFE)

// End of PGXP wrappers

static void (*s_recBSC[64])() = {
    recSPECIAL, recREGIMM, recJ,    recJAL,  recBEQ,  recBNE,  recBLEZ, recBGTZ, recADDI, recADDIU, recSLTI,
    recSLTIU,   recANDI,   recORI,  recXORI, recLUI,  recCOP0, recNULL, recCOP2, recNULL, recNULL,  recNULL,
    recNULL,    recNULL,   recNULL, recNULL, recNULL, recNULL, recNULL, recNULL, recNULL, recNULL,  recLB,
    recLH,      recLWL,    recLW,   recLBU,  recLHU,  recLWR,  recNULL, recSB,   recSH,   recSWL,   recSW,
    recNULL,    recNULL,   recSWR,  recNULL, recNULL, recNULL, recLWC2, recNULL, recNULL, recNULL,  recNULL,
    recNULL,    recNULL,   recNULL, recSWC2, recHLE,  recNULL, recNULL, recNULL, recNULL};

static void (*s_recSPC[64])() = {
    recSLL,  recNULL,    recSRL,   recSRA,   recSLLV, recNULL, recSRLV, recSRAV, recJR,   recJALR, recNULL,
    recNULL, recSYSCALL, recBREAK, recNULL,  recNULL, recMFHI, recMTHI, recMFLO, recMTLO, recNULL, recNULL,
    recNULL, recNULL,    recMULT,  recMULTU, recDIV,  recDIVU, recNULL, recNULL, recNULL, recNULL, recADD,
    recADDU, recSUB,     recSUBU,  recAND,   recOR,   recXOR,  recNOR,  recNULL, recNULL, recSLT,  recSLTU,
    recNULL, recNULL,    recNULL,  recNULL,  recNULL, recNULL, recNULL, recNULL, recNULL, recNULL, recNULL,
    recNULL, recNULL,    recNULL,  recNULL,  recNULL, recNULL, recNULL, recNULL, recNULL};

static void (*s_recREG[32])() = {recBLTZ,   recBGEZ,   recNULL, recNULL, recNULL, recNULL, recNULL, recNULL,
                               recNULL,   recNULL,   recNULL, recNULL, recNULL, recNULL, recNULL, recNULL,
                               recBLTZAL, recBGEZAL, recNULL, recNULL, recNULL, recNULL, recNULL, recNULL,
                               recNULL,   recNULL,   recNULL, recNULL, recNULL, recNULL, recNULL, recNULL};

static void (*s_recCP0[32])() = {recMFC0, recNULL, recCFC0, recNULL, recMTC0, recNULL, recCTC0, recNULL,
                               recNULL, recNULL, recNULL, recNULL, recNULL, recNULL, recNULL, recNULL,
                               recRFE,  recNULL, recNULL, recNULL, recNULL, recNULL, recNULL, recNULL,
                               recNULL, recNULL, recNULL, recNULL, recNULL, recNULL, recNULL, recNULL};

static void (*s_recCP2[64])() = {
    recBASIC, recRTPS,  recNULL,  recNULL, recNULL, recNULL,  recNCLIP, recNULL,  // 00
    recNULL,  recNULL,  recNULL,  recNULL, recOP,   recNULL,  recNULL,  recNULL,  // 08
    recDPCS,  recINTPL, recMVMVA, recNCDS, recCDP,  recNULL,  recNCDT,  recNULL,  // 10
    recNULL,  recNULL,  recNULL,  recNCCS, recCC,   recNULL,  recNCS,   recNULL,  // 18
    recNCT,   recNULL,  recNULL,  recNULL, recNULL, recNULL,  recNULL,  recNULL,  // 20
    recSQR,   recDCPL,  recDPCT,  recNULL, recNULL, recAVSZ3, recAVSZ4, recNULL,  // 28
    recRTPT,  recNULL,  recNULL,  recNULL, recNULL, recNULL,  recNULL,  recNULL,  // 30
    recNULL,  recNULL,  recNULL,  recNULL, recNULL, recGPF,   recGPL,   recNCCT   // 38
};

static void (*s_recCP2BSC[32])() = {recMFC2, recNULL, recCFC2, recNULL, recMTC2, recNULL, recCTC2, recNULL,
                                  recNULL, recNULL, recNULL, recNULL, recNULL, recNULL, recNULL, recNULL,
                                  recNULL, recNULL, recNULL, recNULL, recNULL, recNULL, recNULL, recNULL,
                                  recNULL, recNULL, recNULL, recNULL, recNULL, recNULL, recNULL, recNULL};

// Trace all functions using PGXP
static void (*s_pgxpRecBSC[64])() = {
    recSPECIAL,  recREGIMM,    recJ,        recJAL,       recBEQ,      recBNE,      recBLEZ,     recBGTZ,
    pgxpRecADDI, pgxpRecADDIU, pgxpRecSLTI, pgxpRecSLTIU, pgxpRecANDI, pgxpRecORI,  pgxpRecXORI, pgxpRecLUI,
    recCOP0,     recNULL,      recCOP2,     recNULL,      recNULL,     recNULL,     recNULL,     recNULL,
    recNULL,     recNULL,      recNULL,     recNULL,      recNULL,     recNULL,     recNULL,     recNULL,
    pgxpRecLB,   pgxpRecLH,    pgxpRecLWL,  pgxpRecLW,    pgxpRecLBU,  pgxpRecLHU,  pgxpRecLWR,  pgxpRecNULL,
    pgxpRecSB,   pgxpRecSH,    pgxpRecSWL,  pgxpRecSW,    pgxpRecNULL, pgxpRecNULL, pgxpRecSWR,  pgxpRecNULL,
    recNULL,     recNULL,      pgxpRecLWC2, recNULL,      recNULL,     recNULL,     recNULL,     recNULL,
    recNULL,     recNULL,      pgxpRecSWC2, recHLE,       recNULL,     recNULL,     recNULL,     recNULL};

static void (*s_pgxpRecSPC[64])() = {
    pgxpRecSLL,  pgxpRecNULL,  pgxpRecSRL,  pgxpRecSRA,  pgxpRecSLLV, pgxpRecNULL, pgxpRecSRLV, pgxpRecSRAV,
    recJR,       recJALR,      recNULL,     recNULL,     recSYSCALL,  recBREAK,    recNULL,     recNULL,
    pgxpRecMFHI, pgxpRecMTHI,  pgxpRecMFLO, pgxpRecMTLO, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL,
    pgxpRecMULT, pgxpRecMULTU, pgxpRecDIV,  pgxpRecDIVU, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL,
    pgxpRecADD,  pgxpRecADDU,  pgxpRecSUB,  pgxpRecSUBU, pgxpRecAND,  pgxpRecOR,   pgxpRecXOR,  pgxpRecNOR,
    pgxpRecNULL, pgxpRecNULL,  pgxpRecSLT,  pgxpRecSLTU, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL,
    pgxpRecNULL, pgxpRecNULL,  pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL,
    pgxpRecNULL, pgxpRecNULL,  pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL};

static void (*s_pgxpRecCP0[32])() = {
    pgxpRecMFC0, pgxpRecNULL, pgxpRecCFC0, pgxpRecNULL, pgxpRecMTC0, pgxpRecNULL, pgxpRecCTC0, pgxpRecNULL,
    pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL,
    pgxpRecRFE,  pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL,
    pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL};

static void (*s_pgxpRecCP2BSC[32])() = {
    pgxpRecMFC2, pgxpRecNULL, pgxpRecCFC2, pgxpRecNULL, pgxpRecMTC2, pgxpRecNULL, pgxpRecCTC2, pgxpRecNULL,
    pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL,
    pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL,
    pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL, pgxpRecNULL};

// Trace memory functions only
static void (*s_pgxpRecBSCMem[64])() = {
    recSPECIAL, recREGIMM, recJ,        recJAL,    recBEQ,      recBNE,      recBLEZ,    recBGTZ,
    recADDI,    recADDIU,  recSLTI,     recSLTIU,  recANDI,     recORI,      recXORI,    recLUI,
    recCOP0,    recNULL,   recCOP2,     recNULL,   recNULL,     recNULL,     recNULL,    recNULL,
    recNULL,    recNULL,   recNULL,     recNULL,   recNULL,     recNULL,     recNULL,    recNULL,
    pgxpRecLB,  pgxpRecLH, pgxpRecLWL,  pgxpRecLW, pgxpRecLBU,  pgxpRecLHU,  pgxpRecLWR, pgxpRecNULL,
    pgxpRecSB,  pgxpRecSH, pgxpRecSWL,  pgxpRecSW, pgxpRecNULL, pgxpRecNULL, pgxpRecSWR, pgxpRecNULL,
    recNULL,    recNULL,   pgxpRecLWC2, recNULL,   recNULL,     recNULL,     recNULL,    recNULL,
    recNULL,    recNULL,   pgxpRecSWC2, recHLE,    recNULL,     recNULL,     recNULL,    recNULL};

static void recRecompile() {
    char *p;
    char *ptr;

    dump = 0;
    s_resp = 0;

    /* if g_x86Ptr reached the mem limit reset whole mem */
    if (((u32)g_x86Ptr - (u32)s_recMem) >= (RECMEM_SIZE - 0x10000)) recReset();

    x86Align(32);
    ptr = g_x86Ptr;

    PC_REC32(g_psxRegs.pc) = (u32)g_x86Ptr;
    s_pc = g_psxRegs.pc;
    s_old_pc = s_pc;

    for (s_count = 0; s_count < DYNAREC_BLOCK;) {
        p = (char *)PSXM(s_pc);
        if (p == NULL) recError();
        g_psxRegs.code = *(u32 *)p;
        /*
                        if ((g_psxRegs.code >> 26) == 0x23) { // LW
                                int i;
                                u32 code;

                                for (i=1;; i++) {
                                        p = (char *)PSXM(pc+i*4);
                                        if (p == NULL) recError();
                                        code = *(u32 *)p;

                                        if ((code >> 26) != 0x23 ||
                                                _fRs_(code)  != _Rs_ ||
                                                _fImm_(code) != (_Imm_+i*4))
                                                break;
                                }
                                if (i > 1) {
                                        recLWBlock(i);
                                        pc = pc + i*4; continue;
                                }
                        }

                        if ((g_psxRegs.code >> 26) == 0x2b) { // SW
                                int i;
                                u32 code;

                                for (i=1;; i++) {
                                        p = (char *)PSXM(pc+i*4);
                                        if (p == NULL) recError();
                                        code = *(u32 *)p;

                                        if ((code >> 26) != 0x2b ||
                                                _fRs_(code)  != _Rs_ ||
                                                _fImm_(code) != (_Imm_+i*4))
                                                break;
                                }
                                if (i > 1) {
                                        recSWBlock(i);
                                        pc = pc + i*4; continue;
                                }
                        }*/

        s_pc += 4;
        s_count++;
        s_pRecBSC[g_psxRegs.code >> 26]();

        if (s_branch) {
            s_branch = 0;
            if (dump) iDumpBlock(ptr);
            return;
        }
    }

    iFlushRegs();

    MOV32ItoM((u32)&g_psxRegs.pc, s_pc);

    iRet();
}

static void recSetPGXPMode(u32 pgxpMode) {
    switch (pgxpMode) {
        case 0:  // PGXP_MODE_DISABLED:
            s_pRecBSC = s_recBSC;
            s_pRecSPC = s_recSPC;
            s_pRecREG = s_recREG;
            s_pRecCP0 = s_recCP0;
            s_pRecCP2 = s_recCP2;
            s_pRecCP2BSC = s_recCP2BSC;
            break;
        case 1:  // PGXP_MODE_MEM:
            s_pRecBSC = s_pgxpRecBSCMem;
            s_pRecSPC = s_recSPC;
            s_pRecREG = s_recREG;
            s_pRecCP0 = s_pgxpRecCP0;
            s_pRecCP2 = s_recCP2;
            s_pRecCP2BSC = s_pgxpRecCP2BSC;
            break;
        case 2:  // PGXP_MODE_FULL:
            s_pRecBSC = s_pgxpRecBSC;
            s_pRecSPC = s_pgxpRecSPC;
            s_pRecREG = s_recREG;
            s_pRecCP0 = s_pgxpRecCP0;
            s_pRecCP2 = s_recCP2;
            s_pRecCP2BSC = s_pgxpRecCP2BSC;
            break;
    }

    // set interpreter mode too
    g_psxInt.SetPGXPMode(pgxpMode);
    // reset to ensure new func tables are used
    recReset();
}

R3000Acpu g_psxRec = {recInit, recReset, recExecute, recExecuteBlock, recClear, recShutdown, recSetPGXPMode};

#endif
