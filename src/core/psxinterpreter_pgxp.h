#ifndef _PSX_INTERPRETER_PGXP_H_
#define _PSX_INTERPRETER_PGXP_H_

/////////////////////////////////////////////
// PGXP wrapper functions
/////////////////////////////////////////////

void pgxpPsxNULL() {}

#define psxMTC2 gteMTC2
#define psxCTC2 gteCTC2
#define psxLWC2 gteLWC2
#define psxSWC2 gteSWC2

// Choose between debug and direct function
#ifdef PGXP_CPU_DEBUG
#define PGXP_PSX_FUNC_OP(pu, op, nReg) PGXP_psxTraceOp##nReg
#define PGXP_DBG_OP_E(op) DBG_E_##op,
#else
#define PGXP_PSX_FUNC_OP(pu, op, nReg) PGXP_##pu##_##op
#define PGXP_DBG_OP_E(op)
#endif

#define PGXP_INT_FUNC(pu, op)                                       \
    static void pgxpPsx##op() {                                     \
        PGXP_PSX_FUNC_OP(pu, op, )(PGXP_DBG_OP_E(op) psxRegs.code); \
        psx##op();                                                  \
    }

#define PGXP_INT_FUNC_0_1(pu, op, test, nReg, reg1)                        \
    static void pgxpPsx##op() {                                            \
        if (test) {                                                        \
            psx##op();                                                     \
            return;                                                        \
        }                                                                  \
        u32 tempInstr = psxRegs.code;                                      \
        psx##op();                                                         \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, reg1); \
    }

#define PGXP_INT_FUNC_1_0(pu, op, test, nReg, reg1)                           \
    static void pgxpPsx##op() {                                               \
        if (test) {                                                           \
            psx##op();                                                        \
            return;                                                           \
        }                                                                     \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) psxRegs.code, reg1); \
        psx##op();                                                            \
    }

#define PGXP_INT_FUNC_1_1(pu, op, test, nReg, reg1, reg2)                         \
    static void pgxpPsx##op() {                                                   \
        if (test) {                                                               \
            psx##op();                                                            \
            return;                                                               \
        }                                                                         \
        u32 tempInstr = psxRegs.code;                                             \
        u32 temp2 = reg2;                                                         \
        psx##op();                                                                \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, reg1, temp2); \
    }

#define PGXP_INT_FUNC_0_2(pu, op, test, nReg, reg1, reg2)                        \
    static void pgxpPsx##op() {                                                  \
        if (test) {                                                              \
            psx##op();                                                           \
            return;                                                              \
        }                                                                        \
        u32 tempInstr = psxRegs.code;                                            \
        psx##op();                                                               \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, reg1, reg2); \
    }

#define PGXP_INT_FUNC_2_0(pu, op, test, nReg, reg1, reg2)                          \
    static void pgxpPsx##op() {                                                    \
        if (test) {                                                                \
            psx##op();                                                             \
            return;                                                                \
        }                                                                          \
        u32 tempInstr = psxRegs.code;                                              \
        u32 temp1 = reg1;                                                          \
        u32 temp2 = reg2;                                                          \
        psx##op();                                                                 \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, temp1, temp2); \
    }

#define PGXP_INT_FUNC_2_1(pu, op, test, nReg, reg1, reg2, reg3)                          \
    static void pgxpPsx##op() {                                                          \
        if (test) {                                                                      \
            psx##op();                                                                   \
            return;                                                                      \
        }                                                                                \
        u32 tempInstr = psxRegs.code;                                                    \
        u32 temp2 = reg2;                                                                \
        u32 temp3 = reg3;                                                                \
        psx##op();                                                                       \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, reg1, temp2, temp3); \
    }

#define PGXP_INT_FUNC_2_2(pu, op, test, nReg, reg1, reg2, reg3, reg4)                          \
    static void pgxpPsx##op() {                                                                \
        if (test) {                                                                            \
            psx##op();                                                                         \
            return;                                                                            \
        }                                                                                      \
        u32 tempInstr = psxRegs.code;                                                          \
        u32 temp3 = reg3;                                                                      \
        u32 temp4 = reg4;                                                                      \
        psx##op();                                                                             \
        PGXP_PSX_FUNC_OP(pu, op, nReg)(PGXP_DBG_OP_E(op) tempInstr, reg1, reg2, temp3, temp4); \
    }

// Rt = Rs op imm
PGXP_INT_FUNC_1_1(CPU, ADDI, !_Rt_, 2, psxRegs.GPR.r[_Rt_], psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, ADDIU, !_Rt_, 2, psxRegs.GPR.r[_Rt_], psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, ANDI, !_Rt_, 2, psxRegs.GPR.r[_Rt_], psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, ORI, !_Rt_, 2, psxRegs.GPR.r[_Rt_], psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, XORI, !_Rt_, 2, psxRegs.GPR.r[_Rt_], psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, SLTI, !_Rt_, 2, psxRegs.GPR.r[_Rt_], psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_1_1(CPU, SLTIU, !_Rt_, 2, psxRegs.GPR.r[_Rt_], psxRegs.GPR.r[_Rs_])

// Rt = imm
PGXP_INT_FUNC_0_1(CPU, LUI, !_Rt_, 1, psxRegs.GPR.r[_Rt_])

// Rd = Rs op Rt
PGXP_INT_FUNC_2_1(CPU, ADD, !_Rd_, 3, psxRegs.GPR.r[_Rd_], psxRegs.GPR.r[_Rs_], psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, ADDU, !_Rd_, 3, psxRegs.GPR.r[_Rd_], psxRegs.GPR.r[_Rs_], psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, SUB, !_Rd_, 3, psxRegs.GPR.r[_Rd_], psxRegs.GPR.r[_Rs_], psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, SUBU, !_Rd_, 3, psxRegs.GPR.r[_Rd_], psxRegs.GPR.r[_Rs_], psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, AND, !_Rd_, 3, psxRegs.GPR.r[_Rd_], psxRegs.GPR.r[_Rs_], psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, OR, !_Rd_, 3, psxRegs.GPR.r[_Rd_], psxRegs.GPR.r[_Rs_], psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, XOR, !_Rd_, 3, psxRegs.GPR.r[_Rd_], psxRegs.GPR.r[_Rs_], psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, NOR, !_Rd_, 3, psxRegs.GPR.r[_Rd_], psxRegs.GPR.r[_Rs_], psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, SLT, !_Rd_, 3, psxRegs.GPR.r[_Rd_], psxRegs.GPR.r[_Rs_], psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_1(CPU, SLTU, !_Rd_, 3, psxRegs.GPR.r[_Rd_], psxRegs.GPR.r[_Rs_], psxRegs.GPR.r[_Rt_])

// Hi/Lo = Rs op Rt
PGXP_INT_FUNC_2_2(CPU, MULT, 0, 4, psxRegs.GPR.n.hi, psxRegs.GPR.n.lo, psxRegs.GPR.r[_Rs_], psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_2(CPU, MULTU, 0, 4, psxRegs.GPR.n.hi, psxRegs.GPR.n.lo, psxRegs.GPR.r[_Rs_], psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_2(CPU, DIV, 0, 4, psxRegs.GPR.n.hi, psxRegs.GPR.n.lo, psxRegs.GPR.r[_Rs_], psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_2_2(CPU, DIVU, 0, 4, psxRegs.GPR.n.hi, psxRegs.GPR.n.lo, psxRegs.GPR.r[_Rs_], psxRegs.GPR.r[_Rt_])

// Mem[addr] = Rt
PGXP_INT_FUNC_1_1(CPU, SB, 0, 2, psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, SH, 0, 2, psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, SW, 0, 2, psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, SWL, 0, 2, psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, SWR, 0, 2, psxRegs.GPR.r[_Rt_], _oB_)

// Rt = Mem[addr]
PGXP_INT_FUNC_1_1(CPU, LWL, 0, 2, psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LW, 0, 2, psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LWR, 0, 2, psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LH, 0, 2, psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LHU, 0, 2, psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LB, 0, 2, psxRegs.GPR.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(CPU, LBU, 0, 2, psxRegs.GPR.r[_Rt_], _oB_)

// Rd = Rt op Sa
PGXP_INT_FUNC_1_1(CPU, SLL, !_Rd_, 2, psxRegs.GPR.r[_Rd_], psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_1_1(CPU, SRL, !_Rd_, 2, psxRegs.GPR.r[_Rd_], psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_1_1(CPU, SRA, !_Rd_, 2, psxRegs.GPR.r[_Rd_], psxRegs.GPR.r[_Rt_])

// Rd = Rt op Rs
PGXP_INT_FUNC_2_1(CPU, SLLV, !_Rd_, 3, psxRegs.GPR.r[_Rd_], psxRegs.GPR.r[_Rt_], psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_2_1(CPU, SRLV, !_Rd_, 3, psxRegs.GPR.r[_Rd_], psxRegs.GPR.r[_Rt_], psxRegs.GPR.r[_Rs_])
PGXP_INT_FUNC_2_1(CPU, SRAV, !_Rd_, 3, psxRegs.GPR.r[_Rd_], psxRegs.GPR.r[_Rt_], psxRegs.GPR.r[_Rs_])

PGXP_INT_FUNC_1_1(CPU, MFHI, !_Rd_, 2, psxRegs.GPR.r[_Rd_], psxRegs.GPR.n.hi)
PGXP_INT_FUNC_1_1(CPU, MTHI, 0, 2, psxRegs.GPR.n.hi, psxRegs.GPR.r[_Rd_])
PGXP_INT_FUNC_1_1(CPU, MFLO, !_Rd_, 2, psxRegs.GPR.r[_Rd_], psxRegs.GPR.n.lo)
PGXP_INT_FUNC_1_1(CPU, MTLO, 0, 2, psxRegs.GPR.n.lo, psxRegs.GPR.r[_Rd_])

// COP2 (GTE)
PGXP_INT_FUNC_1_1(GTE, MFC2, !_Rt_, 2, psxRegs.GPR.r[_Rt_], psxRegs.CP2D.r[_Rd_])
PGXP_INT_FUNC_1_1(GTE, CFC2, !_Rt_, 2, psxRegs.GPR.r[_Rt_], psxRegs.CP2C.r[_Rd_])
PGXP_INT_FUNC_1_1(GTE, MTC2, 0, 2, psxRegs.CP2D.r[_Rd_], psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_1_1(GTE, CTC2, 0, 2, psxRegs.CP2C.r[_Rd_], psxRegs.GPR.r[_Rt_])

PGXP_INT_FUNC_1_1(GTE, LWC2, 0, 2, psxRegs.CP2D.r[_Rt_], _oB_)
PGXP_INT_FUNC_1_1(GTE, SWC2, 0, 2, psxRegs.CP2D.r[_Rt_], _oB_)

// COP0
PGXP_INT_FUNC_1_1(CP0, MFC0, !_Rd_, 2, psxRegs.GPR.r[_Rt_], psxRegs.CP0.r[_Rd_])
PGXP_INT_FUNC_1_1(CP0, CFC0, !_Rd_, 2, psxRegs.GPR.r[_Rt_], psxRegs.CP0.r[_Rd_])
PGXP_INT_FUNC_1_1(CP0, MTC0, !_Rt_, 2, psxRegs.CP0.r[_Rd_], psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC_1_1(CP0, CTC0, !_Rt_, 2, psxRegs.CP0.r[_Rd_], psxRegs.GPR.r[_Rt_])
PGXP_INT_FUNC(CP0, RFE)

#endif  //_PSX_INTERPRETER_PGXP_H_
