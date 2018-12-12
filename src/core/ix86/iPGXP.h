#ifndef _I_PGXP_H_
#define _I_PGXP_H_

/////////////////////////////////////////////
// PGXP wrapper functions
/////////////////////////////////////////////

pgxpRecNULL() {}

// Choose between debug and direct function
#ifdef PGXP_CPU_DEBUG
#define PGXP_REC_FUNC_OP(pu, op, nReg) PGXP_psxTraceOp##nReg
#define PGXP_DBG_OP_E(op) \
    PUSH32I(DBG_E_##op);  \
    resp += 4;
#else
#define PGXP_REC_FUNC_OP(pu, op, nReg) PGXP_##pu##_##op
#define PGXP_DBG_OP_E(op)
#endif

#define PGXP_REC_FUNC_PASS(pu, op) \
    static void pgxpRec##op() { rec##op(); }

#define PGXP_REC_FUNC(pu, op)                      \
    static void pgxpRec##op() {                    \
        PUSH32I(psxRegs.code);                     \
        PGXP_DBG_OP_E(op)                          \
        CALLFunc((u32)PGXP_REC_FUNC_OP(pu, op, )); \
        resp += 4;                                 \
        rec##op();                                 \
    }

#define PGXP_REC_FUNC_1(pu, op, reg1)               \
    static void pgxpRec##op() {                     \
        reg1;                                       \
        PUSH32I(psxRegs.code);                      \
        PGXP_DBG_OP_E(op)                           \
        CALLFunc((u32)PGXP_REC_FUNC_OP(pu, op, 1)); \
        resp += 8;                                  \
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
        PUSH32I(psxRegs.code);                                        \
        PGXP_DBG_OP_E(op)                                             \
        CALLFunc((u32)PGXP_REC_FUNC_OP(pu, op, nReg));                \
        resp += (4 * nReg) + 4;                                       \
    }

#define PGXP_REC_FUNC_2(pu, op, reg1, reg2)         \
    static void pgxpRec##op() {                     \
        reg1;                                       \
        reg2;                                       \
        PUSH32I(psxRegs.code);                      \
        PGXP_DBG_OP_E(op)                           \
        CALLFunc((u32)PGXP_REC_FUNC_OP(pu, op, 2)); \
        resp += 12;                                 \
        rec##op();                                  \
    }

static u32 gTempAddr = 0;
#define PGXP_REC_FUNC_ADDR_1(pu, op, reg1)             \
    static void pgxpRec##op() {                        \
        if (IsConst(_Rs_)) {                           \
            MOV32ItoR(EAX, iRegs[_Rs_].k + _Imm_);     \
        } else {                                       \
            MOV32MtoR(EAX, (u32)&psxRegs.GPR.r[_Rs_]); \
            if (_Imm_) {                               \
                ADD32ItoR(EAX, _Imm_);                 \
            }                                          \
        }                                              \
        MOV32RtoM((u32)&gTempAddr, EAX);               \
        rec##op();                                     \
        PUSH32M((u32)&gTempAddr);                      \
        reg1;                                          \
        PUSH32I(psxRegs.code);                         \
        PGXP_DBG_OP_E(op)                              \
        CALLFunc((u32)PGXP_REC_FUNC_OP(pu, op, 2));    \
        resp += 12;                                    \
    }

#define CPU_REG_NC(idx) MOV32MtoR(EAX, (u32)&psxRegs.GPR.r[idx])

#define CPU_REG(idx)                  \
    if (IsConst(idx))                 \
        MOV32ItoR(EAX, iRegs[idx].k); \
    else                              \
        MOV32MtoR(EAX, (u32)&psxRegs.GPR.r[idx]);

#define CP0_REG(idx) MOV32MtoR(EAX, (u32)&psxRegs.CP0.r[idx])
#define GTE_DATA_REG(idx) MOV32MtoR(EAX, (u32)&psxRegs.CP2D.r[idx])
#define GTE_CTRL_REG(idx) MOV32MtoR(EAX, (u32)&psxRegs.CP2C.r[idx])

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
        PUSH32I(psxRegs.code);                       \
        PGXP_DBG_OP_E(op)                            \
        CALLFunc((u32)PGXP_REC_FUNC_OP(pu, op, 2));  \
        resp += 12;                                  \
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
        PUSH32I(psxRegs.code);                             \
        PGXP_DBG_OP_E(op)                                  \
        CALLFunc((u32)PGXP_REC_FUNC_OP(pu, op, 3));        \
        resp += 16;                                        \
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
        PUSH32I(psxRegs.code);                                   \
        PGXP_DBG_OP_E(op)                                        \
        CALLFunc((u32)PGXP_REC_FUNC_OP(pu, op, 4));              \
        resp += 20;                                              \
    }

//#define PGXP_REC_FUNC_R1i_1(pu, op, test, reg1, reg2) \
//static void pgxpRec##op()	\
//{	\
//	if(test) { rec##op(); return; }\
//	if (IsConst(reg1))	\
//		MOV32ItoR(EAX, iRegs[reg1].k);	\
//	else\
//		MOV32MtoR(EAX, (u32)&psxRegs.GPR.r[reg1]);\
//	MOV32RtoM((u32)&gTempReg, EAX);\
//	rec##op();\
//	PUSH32M((u32)&gTempReg);\
//	reg2;\
//	PUSH32I(psxRegs.code);	\
//	CALLFunc((u32)PGXP_REC_FUNC_OP(pu, op, 2)); \
//	resp += 12; \
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
PGXP_REC_FUNC_R2_2(CPU, MULT, 0, CPU_REG(_Rt_), CPU_REG(_Rs_), PUSH32M((u32)&psxRegs.GPR.n.lo),
                   PUSH32M((u32)&psxRegs.GPR.n.hi))
PGXP_REC_FUNC_R2_2(CPU, MULTU, 0, CPU_REG(_Rt_), CPU_REG(_Rs_), PUSH32M((u32)&psxRegs.GPR.n.lo),
                   PUSH32M((u32)&psxRegs.GPR.n.hi))
PGXP_REC_FUNC_R2_2(CPU, DIV, 0, CPU_REG(_Rt_), CPU_REG(_Rs_), PUSH32M((u32)&psxRegs.GPR.n.lo),
                   PUSH32M((u32)&psxRegs.GPR.n.hi))
PGXP_REC_FUNC_R2_2(CPU, DIVU, 0, CPU_REG(_Rt_), CPU_REG(_Rs_), PUSH32M((u32)&psxRegs.GPR.n.lo),
                   PUSH32M((u32)&psxRegs.GPR.n.hi))

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
PGXP_REC_FUNC_R1_1(CPU, MTHI, 0, CPU_REG(_Rd_), PUSH32M((u32)&psxRegs.GPR.n.hi))
PGXP_REC_FUNC_R1_1(CPU, MFLO, !_Rd_, CPU_REG_NC(32), iPushReg(_Rd_))
PGXP_REC_FUNC_R1_1(CPU, MTLO, 0, CPU_REG(_Rd_), PUSH32M((u32)&psxRegs.GPR.n.lo))

// COP2 (GTE)
PGXP_REC_FUNC_R1_1(GTE, MFC2, !_Rt_, GTE_DATA_REG(_Rd_), iPushReg(_Rt_))
PGXP_REC_FUNC_R1_1(GTE, CFC2, !_Rt_, GTE_CTRL_REG(_Rd_), iPushReg(_Rt_))
PGXP_REC_FUNC_R1_1(GTE, MTC2, 0, CPU_REG(_Rt_), PUSH32M((u32)&psxRegs.CP2D.r[_Rd_]))
PGXP_REC_FUNC_R1_1(GTE, CTC2, 0, CPU_REG(_Rt_), PUSH32M((u32)&psxRegs.CP2C.r[_Rd_]))

PGXP_REC_FUNC_ADDR_1(GTE, LWC2, PUSH32M((u32)&psxRegs.CP2D.r[_Rt_]))
PGXP_REC_FUNC_ADDR_1(GTE, SWC2, PUSH32M((u32)&psxRegs.CP2D.r[_Rt_]))

// COP0
PGXP_REC_FUNC_R1_1(CP0, MFC0, !_Rd_, CP0_REG(_Rd_), iPushReg(_Rt_))
PGXP_REC_FUNC_R1_1(CP0, CFC0, !_Rd_, CP0_REG(_Rd_), iPushReg(_Rt_))
PGXP_REC_FUNC_R1_1(CP0, MTC0, !_Rt_, CPU_REG(_Rt_), PUSH32M((u32)&psxRegs.CP0.r[_Rd_]))
PGXP_REC_FUNC_R1_1(CP0, CTC0, !_Rt_, CPU_REG(_Rt_), PUSH32M((u32)&psxRegs.CP0.r[_Rd_]))
PGXP_REC_FUNC(CP0, RFE)

#endif  //_I_PGXP_H_
