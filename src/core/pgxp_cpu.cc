
#include "core/pgxp_cpu.h"
#include "core/pgxp_debug.h"
#include "core/pgxp_mem.h"
#include "core/pgxp_value.h"

// CPU registers
static PGXP_value s_CPU_reg_mem[34];
// PGXP_value CPU_Hi, CPU_Lo;
static PGXP_value s_CP0_reg_mem[32];

PGXP_value* g_CPU_reg = s_CPU_reg_mem;
PGXP_value* g_CP0_reg = s_CP0_reg_mem;

// Instruction register decoding
#define op(_instr) (_instr >> 26)           // The op part of the instruction register
#define func(_instr) ((_instr)&0x3F)        // The funct part of the instruction register
#define sa(_instr) ((_instr >> 6) & 0x1F)   // The sa part of the instruction register
#define rd(_instr) ((_instr >> 11) & 0x1F)  // The rd part of the instruction register
#define rt(_instr) ((_instr >> 16) & 0x1F)  // The rt part of the instruction register
#define rs(_instr) ((_instr >> 21) & 0x1F)  // The rs part of the instruction register
#define imm(_instr) (_instr & 0xFFFF)       // The immediate part of the instruction register

void PGXP_InitCPU() {
    memset(s_CPU_reg_mem, 0, sizeof(s_CPU_reg_mem));
    memset(s_CP0_reg_mem, 0, sizeof(s_CP0_reg_mem));
}

// invalidate register (invalid 8 bit read)
void InvalidLoad(uint32_t addr, uint32_t code, uint32_t value) {
    uint32_t reg = ((code >> 16) & 0x1F);  // The rt part of the instruction register
    PGXP_value* pD = NULL;
    PGXP_value p;

    p.x = p.y = -1337;  // default values

    // p.valid = 0;
    // p.count = value;
    pD = PGXP_ReadMem(addr);

    if (pD) {
        p.count = addr;
        p = *pD;
    } else {
        p.count = value;
    }

    p.flags = 0;

    // invalidate register
    g_CPU_reg[reg] = p;
}

// invalidate memory address (invalid 8 bit write)
void InvalidStore(uint32_t addr, uint32_t code, uint32_t value) {
    uint32_t reg = ((code >> 16) & 0x1F);  // The rt part of the instruction register
    PGXP_value* pD = NULL;
    PGXP_value p;

    pD = PGXP_ReadMem(addr);

    p.x = p.y = -2337;

    if (pD) p = *pD;

    p.flags = 0;
    p.count = (reg * 1000) + value;

    // invalidate memory
    WriteMem(&p, addr);
}

////////////////////////////////////
// Arithmetic with immediate value
////////////////////////////////////
void PGXP_CPU_ADDI(uint32_t instr, uint32_t rtVal, uint32_t rsVal) {
    // Rt = Rs + Imm (signed)
    psx_value tempImm;
    PGXP_value ret;

    Validate(&g_CPU_reg[rs(instr)], rsVal);
    ret = g_CPU_reg[rs(instr)];
    tempImm.d = imm(instr);
    tempImm.sd = (tempImm.sd << 16) >> 16;  // sign extend

    ret.x = f16Unsign(ret.x);
    ret.x += tempImm.w.l;

    // carry on over/underflow
    float of = (ret.x > USHRT_MAX) ? 1.f : (ret.x < 0) ? -1.f : 0.f;
    ret.x = f16Sign(ret.x);
    // ret.x -= of * (USHRT_MAX + 1);
    ret.y += tempImm.sw.h + of;

    // truncate on overflow/underflow
    ret.y += (ret.y > SHRT_MAX) ? -(USHRT_MAX + 1) : (ret.y < SHRT_MIN) ? USHRT_MAX + 1 : 0.f;

    g_CPU_reg[rt(instr)] = ret;
    g_CPU_reg[rt(instr)].value = rtVal;
}

void PGXP_CPU_ADDIU(uint32_t instr, uint32_t rtVal, uint32_t rsVal) {
    // Rt = Rs + Imm (signed) (unsafe?)
    PGXP_CPU_ADDI(instr, rtVal, rsVal);
}

void PGXP_CPU_ANDI(uint32_t instr, uint32_t rtVal, uint32_t rsVal) {
    // Rt = Rs & Imm
    psx_value vRt;
    PGXP_value ret;

    Validate(&g_CPU_reg[rs(instr)], rsVal);
    ret = g_CPU_reg[rs(instr)];

    vRt.d = rtVal;

    ret.y = 0.f;  // remove upper 16-bits

    switch (imm(instr)) {
        case 0:
            // if 0 then x == 0
            ret.x = 0.f;
            break;
        case 0xFFFF:
            // if saturated then x == x
            break;
        default:
            // otherwise x is low precision value
            ret.x = vRt.sw.l;
            ret.flags |= VALID_0;
    }

    ret.flags |= VALID_1;

    g_CPU_reg[rt(instr)] = ret;
    g_CPU_reg[rt(instr)].value = rtVal;
}

void PGXP_CPU_ORI(uint32_t instr, uint32_t rtVal, uint32_t rsVal) {
    // Rt = Rs | Imm
    psx_value vRt;
    PGXP_value ret;

    Validate(&g_CPU_reg[rs(instr)], rsVal);
    ret = g_CPU_reg[rs(instr)];

    vRt.d = rtVal;

    switch (imm(instr)) {
        case 0:
            // if 0 then x == x
            break;
        default:
            // otherwise x is low precision value
            ret.x = vRt.sw.l;
            ret.flags |= VALID_0;
    }

    ret.value = rtVal;
    g_CPU_reg[rt(instr)] = ret;
}

void PGXP_CPU_XORI(uint32_t instr, uint32_t rtVal, uint32_t rsVal) {
    // Rt = Rs ^ Imm
    psx_value vRt;
    PGXP_value ret;

    Validate(&g_CPU_reg[rs(instr)], rsVal);
    ret = g_CPU_reg[rs(instr)];

    vRt.d = rtVal;

    switch (imm(instr)) {
        case 0:
            // if 0 then x == x
            break;
        default:
            // otherwise x is low precision value
            ret.x = vRt.sw.l;
            ret.flags |= VALID_0;
    }

    ret.value = rtVal;
    g_CPU_reg[rt(instr)] = ret;
}

void PGXP_CPU_SLTI(uint32_t instr, uint32_t rtVal, uint32_t rsVal) {
    // Rt = Rs < Imm (signed)
    psx_value tempImm;
    PGXP_value ret;

    Validate(&g_CPU_reg[rs(instr)], rsVal);
    ret = g_CPU_reg[rs(instr)];

    tempImm.w.h = imm(instr);
    ret.y = 0.f;
    ret.x = (g_CPU_reg[rs(instr)].x < tempImm.sw.h) ? 1.f : 0.f;
    ret.flags |= VALID_1;
    ret.value = rtVal;

    g_CPU_reg[rt(instr)] = ret;
}

void PGXP_CPU_SLTIU(uint32_t instr, uint32_t rtVal, uint32_t rsVal) {
    // Rt = Rs < Imm (Unsigned)
    psx_value tempImm;
    PGXP_value ret;

    Validate(&g_CPU_reg[rs(instr)], rsVal);
    ret = g_CPU_reg[rs(instr)];

    tempImm.w.h = imm(instr);
    ret.y = 0.f;
    ret.x = (f16Unsign(g_CPU_reg[rs(instr)].x) < tempImm.w.h) ? 1.f : 0.f;
    ret.flags |= VALID_1;
    ret.value = rtVal;

    g_CPU_reg[rt(instr)] = ret;
}

////////////////////////////////////
// Load Upper
////////////////////////////////////
void PGXP_CPU_LUI(uint32_t instr, uint32_t rtVal) {
    // Rt = Imm << 16
    g_CPU_reg[rt(instr)] = PGXP_value_zero;
    g_CPU_reg[rt(instr)].y = (float)(int16_t)imm(instr);
    g_CPU_reg[rt(instr)].hFlags = VALID_HALF;
    g_CPU_reg[rt(instr)].value = rtVal;
    g_CPU_reg[rt(instr)].flags = VALID_01;
}

////////////////////////////////////
// Register Arithmetic
////////////////////////////////////

void PGXP_CPU_ADD(uint32_t instr, uint32_t rdVal, uint32_t rsVal, uint32_t rtVal) {
    // Rd = Rs + Rt (signed)
    PGXP_value ret;
    Validate(&g_CPU_reg[rs(instr)], rsVal);
    Validate(&g_CPU_reg[rt(instr)], rtVal);

    // iCB: Only require one valid input
    if (((g_CPU_reg[rt(instr)].flags & VALID_01) != VALID_01) !=
        ((g_CPU_reg[rs(instr)].flags & VALID_01) != VALID_01)) {
        MakeValid(&g_CPU_reg[rs(instr)], rsVal);
        MakeValid(&g_CPU_reg[rt(instr)], rtVal);
    }

    ret = g_CPU_reg[rs(instr)];

    ret.x = f16Unsign(ret.x);
    ret.x += f16Unsign(g_CPU_reg[rt(instr)].x);

    // carry on over/underflow
    float of = (ret.x > USHRT_MAX) ? 1.f : (ret.x < 0) ? -1.f : 0.f;
    ret.x = f16Sign(ret.x);
    // ret.x -= of * (USHRT_MAX + 1);
    ret.y += g_CPU_reg[rt(instr)].y + of;

    // truncate on overflow/underflow
    ret.y += (ret.y > SHRT_MAX) ? -(USHRT_MAX + 1) : (ret.y < SHRT_MIN) ? USHRT_MAX + 1 : 0.f;

    // TODO: decide which "z/w" component to use

    ret.halfFlags[0] &= g_CPU_reg[rt(instr)].halfFlags[0];
    ret.gFlags |= g_CPU_reg[rt(instr)].gFlags;
    ret.lFlags |= g_CPU_reg[rt(instr)].lFlags;
    ret.hFlags |= g_CPU_reg[rt(instr)].hFlags;

    ret.value = rdVal;

    g_CPU_reg[rd(instr)] = ret;
}

void PGXP_CPU_ADDU(uint32_t instr, uint32_t rdVal, uint32_t rsVal, uint32_t rtVal) {
    // Rd = Rs + Rt (signed) (unsafe?)
    PGXP_CPU_ADD(instr, rdVal, rsVal, rtVal);
}

void PGXP_CPU_SUB(uint32_t instr, uint32_t rdVal, uint32_t rsVal, uint32_t rtVal) {
    // Rd = Rs - Rt (signed)
    PGXP_value ret;
    Validate(&g_CPU_reg[rs(instr)], rsVal);
    Validate(&g_CPU_reg[rt(instr)], rtVal);

    // iCB: Only require one valid input
    if (((g_CPU_reg[rt(instr)].flags & VALID_01) != VALID_01) !=
        ((g_CPU_reg[rs(instr)].flags & VALID_01) != VALID_01)) {
        MakeValid(&g_CPU_reg[rs(instr)], rsVal);
        MakeValid(&g_CPU_reg[rt(instr)], rtVal);
    }

    ret = g_CPU_reg[rs(instr)];

    ret.x = f16Unsign(ret.x);
    ret.x -= f16Unsign(g_CPU_reg[rt(instr)].x);

    // carry on over/underflow
    float of = (ret.x > USHRT_MAX) ? 1.f : (ret.x < 0) ? -1.f : 0.f;
    ret.x = f16Sign(ret.x);
    // ret.x -= of * (USHRT_MAX + 1);
    ret.y -= g_CPU_reg[rt(instr)].y - of;

    // truncate on overflow/underflow
    ret.y += (ret.y > SHRT_MAX) ? -(USHRT_MAX + 1) : (ret.y < SHRT_MIN) ? USHRT_MAX + 1 : 0.f;

    ret.halfFlags[0] &= g_CPU_reg[rt(instr)].halfFlags[0];
    ret.gFlags |= g_CPU_reg[rt(instr)].gFlags;
    ret.lFlags |= g_CPU_reg[rt(instr)].lFlags;
    ret.hFlags |= g_CPU_reg[rt(instr)].hFlags;

    ret.value = rdVal;

    g_CPU_reg[rd(instr)] = ret;
}

void PGXP_CPU_SUBU(uint32_t instr, uint32_t rdVal, uint32_t rsVal, uint32_t rtVal) {
    // Rd = Rs - Rt (signed) (unsafe?)
    PGXP_CPU_SUB(instr, rdVal, rsVal, rtVal);
}

void PGXP_CPU_AND(uint32_t instr, uint32_t rdVal, uint32_t rsVal, uint32_t rtVal) {
    // Rd = Rs & Rt
    psx_value vald, vals, valt;
    PGXP_value ret;

    Validate(&g_CPU_reg[rs(instr)], rsVal);
    Validate(&g_CPU_reg[rt(instr)], rtVal);

    // iCB: Only require one valid input
    if (((g_CPU_reg[rt(instr)].flags & VALID_01) != VALID_01) !=
        ((g_CPU_reg[rs(instr)].flags & VALID_01) != VALID_01)) {
        MakeValid(&g_CPU_reg[rs(instr)], rsVal);
        MakeValid(&g_CPU_reg[rt(instr)], rtVal);
    }

    vald.d = rdVal;
    vals.d = rsVal;
    valt.d = rtVal;

    //  g_CPU_reg[rd(instr)].valid = g_CPU_reg[rs(instr)].valid && g_CPU_reg[rt(instr)].valid;
    ret.flags = VALID_01;

    if (vald.w.l == 0) {
        ret.x = 0.f;
        ret.lFlags = VALID_HALF;
    } else if (vald.w.l == vals.w.l) {
        ret.x = g_CPU_reg[rs(instr)].x;
        ret.lFlags = g_CPU_reg[rs(instr)].lFlags;
        ret.compFlags[0] = g_CPU_reg[rs(instr)].compFlags[0];
    } else if (vald.w.l == valt.w.l) {
        ret.x = g_CPU_reg[rt(instr)].x;
        ret.lFlags = g_CPU_reg[rt(instr)].lFlags;
        ret.compFlags[0] = g_CPU_reg[rt(instr)].compFlags[0];
    } else {
        ret.x = (float)vald.sw.l;
        ret.compFlags[0] = VALID;
        ret.lFlags = 0;
    }

    if (vald.w.h == 0) {
        ret.y = 0.f;
        ret.hFlags = VALID_HALF;
    } else if (vald.w.h == vals.w.h) {
        ret.y = g_CPU_reg[rs(instr)].y;
        ret.hFlags = g_CPU_reg[rs(instr)].hFlags;
        ret.compFlags[1] &= g_CPU_reg[rs(instr)].compFlags[1];
    } else if (vald.w.h == valt.w.h) {
        ret.y = g_CPU_reg[rt(instr)].y;
        ret.hFlags = g_CPU_reg[rt(instr)].hFlags;
        ret.compFlags[1] &= g_CPU_reg[rt(instr)].compFlags[1];
    } else {
        ret.y = (float)vald.sw.h;
        ret.compFlags[1] = VALID;
        ret.hFlags = 0;
    }

    // iCB Hack: Force validity if even one half is valid
    // if ((ret.hFlags & VALID_HALF) || (ret.lFlags & VALID_HALF))
    //  ret.valid = 1;
    // /iCB Hack

    // Get a valid W
    if ((g_CPU_reg[rs(instr)].flags & VALID_2) == VALID_2) {
        ret.z = g_CPU_reg[rs(instr)].z;
        ret.compFlags[2] = g_CPU_reg[rs(instr)].compFlags[2];
    } else if ((g_CPU_reg[rt(instr)].flags & VALID_2) == VALID_2) {
        ret.z = g_CPU_reg[rt(instr)].z;
        ret.compFlags[2] = g_CPU_reg[rt(instr)].compFlags[2];
    }

    ret.value = rdVal;
    g_CPU_reg[rd(instr)] = ret;
}

void PGXP_CPU_OR(uint32_t instr, uint32_t rdVal, uint32_t rsVal, uint32_t rtVal) {
    // Rd = Rs | Rt
    PGXP_CPU_AND(instr, rdVal, rsVal, rtVal);
}

void PGXP_CPU_XOR(uint32_t instr, uint32_t rdVal, uint32_t rsVal, uint32_t rtVal) {
    // Rd = Rs ^ Rt
    PGXP_CPU_AND(instr, rdVal, rsVal, rtVal);
}

void PGXP_CPU_NOR(uint32_t instr, uint32_t rdVal, uint32_t rsVal, uint32_t rtVal) {
    // Rd = Rs NOR Rt
    PGXP_CPU_AND(instr, rdVal, rsVal, rtVal);
}

void PGXP_CPU_SLT(uint32_t instr, uint32_t rdVal, uint32_t rsVal, uint32_t rtVal) {
    // Rd = Rs < Rt (signed)
    PGXP_value ret;
    Validate(&g_CPU_reg[rs(instr)], rsVal);
    Validate(&g_CPU_reg[rt(instr)], rtVal);

    // iCB: Only require one valid input
    if (((g_CPU_reg[rt(instr)].flags & VALID_01) != VALID_01) !=
        ((g_CPU_reg[rs(instr)].flags & VALID_01) != VALID_01)) {
        MakeValid(&g_CPU_reg[rs(instr)], rsVal);
        MakeValid(&g_CPU_reg[rt(instr)], rtVal);
    }

    ret = g_CPU_reg[rs(instr)];
    ret.y = 0.f;
    ret.compFlags[1] = VALID;

    ret.x = (g_CPU_reg[rs(instr)].y < g_CPU_reg[rt(instr)].y)
                ? 1.f
                : (f16Unsign(g_CPU_reg[rs(instr)].x) < f16Unsign(g_CPU_reg[rt(instr)].x)) ? 1.f : 0.f;

    ret.value = rdVal;
    g_CPU_reg[rd(instr)] = ret;
}

void PGXP_CPU_SLTU(uint32_t instr, uint32_t rdVal, uint32_t rsVal, uint32_t rtVal) {
    // Rd = Rs < Rt (unsigned)
    PGXP_value ret;
    Validate(&g_CPU_reg[rs(instr)], rsVal);
    Validate(&g_CPU_reg[rt(instr)], rtVal);

    // iCB: Only require one valid input
    if (((g_CPU_reg[rt(instr)].flags & VALID_01) != VALID_01) !=
        ((g_CPU_reg[rs(instr)].flags & VALID_01) != VALID_01)) {
        MakeValid(&g_CPU_reg[rs(instr)], rsVal);
        MakeValid(&g_CPU_reg[rt(instr)], rtVal);
    }

    ret = g_CPU_reg[rs(instr)];
    ret.y = 0.f;
    ret.compFlags[1] = VALID;

    ret.x = (f16Unsign(g_CPU_reg[rs(instr)].y) < f16Unsign(g_CPU_reg[rt(instr)].y))
                ? 1.f
                : (f16Unsign(g_CPU_reg[rs(instr)].x) < f16Unsign(g_CPU_reg[rt(instr)].x)) ? 1.f : 0.f;

    ret.value = rdVal;
    g_CPU_reg[rd(instr)] = ret;
}

////////////////////////////////////
// Register mult/div
////////////////////////////////////

void PGXP_CPU_MULT(uint32_t instr, uint32_t hiVal, uint32_t loVal, uint32_t rsVal, uint32_t rtVal) {
    // Hi/Lo = Rs * Rt (signed)
    Validate(&g_CPU_reg[rs(instr)], rsVal);
    Validate(&g_CPU_reg[rt(instr)], rtVal);

    // iCB: Only require one valid input
    if (((g_CPU_reg[rt(instr)].flags & VALID_01) != VALID_01) !=
        ((g_CPU_reg[rs(instr)].flags & VALID_01) != VALID_01)) {
        MakeValid(&g_CPU_reg[rs(instr)], rsVal);
        MakeValid(&g_CPU_reg[rt(instr)], rtVal);
    }

    CPU_Lo = CPU_Hi = g_CPU_reg[rs(instr)];

    CPU_Lo.halfFlags[0] = CPU_Hi.halfFlags[0] = (g_CPU_reg[rs(instr)].halfFlags[0] & g_CPU_reg[rt(instr)].halfFlags[0]);

    double xx, xy, yx, yy;
    double lx = 0, ly = 0, hx = 0, hy = 0;
    int64_t of = 0;

    // Multiply out components
    xx = f16Unsign(g_CPU_reg[rs(instr)].x) * f16Unsign(g_CPU_reg[rt(instr)].x);
    xy = f16Unsign(g_CPU_reg[rs(instr)].x) * (g_CPU_reg[rt(instr)].y);
    yx = (g_CPU_reg[rs(instr)].y) * f16Unsign(g_CPU_reg[rt(instr)].x);
    yy = (g_CPU_reg[rs(instr)].y) * (g_CPU_reg[rt(instr)].y);

    // Split values into outputs
    lx = xx;

    ly = f16Overflow(xx);
    ly += xy + yx;

    hx = f16Overflow(ly);
    hx += yy;

    hy = f16Overflow(hx);

    CPU_Lo.x = f16Sign(lx);
    CPU_Lo.y = f16Sign(ly);
    CPU_Hi.x = f16Sign(hx);
    CPU_Hi.y = f16Sign(hy);

    CPU_Lo.value = loVal;
    CPU_Hi.value = hiVal;
}

void PGXP_CPU_MULTU(uint32_t instr, uint32_t hiVal, uint32_t loVal, uint32_t rsVal, uint32_t rtVal) {
    // Hi/Lo = Rs * Rt (unsigned)
    Validate(&g_CPU_reg[rs(instr)], rsVal);
    Validate(&g_CPU_reg[rt(instr)], rtVal);

    // iCB: Only require one valid input
    if (((g_CPU_reg[rt(instr)].flags & VALID_01) != VALID_01) !=
        ((g_CPU_reg[rs(instr)].flags & VALID_01) != VALID_01)) {
        MakeValid(&g_CPU_reg[rs(instr)], rsVal);
        MakeValid(&g_CPU_reg[rt(instr)], rtVal);
    }

    CPU_Lo = CPU_Hi = g_CPU_reg[rs(instr)];

    CPU_Lo.halfFlags[0] = CPU_Hi.halfFlags[0] = (g_CPU_reg[rs(instr)].halfFlags[0] & g_CPU_reg[rt(instr)].halfFlags[0]);

    double xx, xy, yx, yy;
    double lx = 0, ly = 0, hx = 0, hy = 0;
    int64_t of = 0;

    // Multiply out components
    xx = f16Unsign(g_CPU_reg[rs(instr)].x) * f16Unsign(g_CPU_reg[rt(instr)].x);
    xy = f16Unsign(g_CPU_reg[rs(instr)].x) * f16Unsign(g_CPU_reg[rt(instr)].y);
    yx = f16Unsign(g_CPU_reg[rs(instr)].y) * f16Unsign(g_CPU_reg[rt(instr)].x);
    yy = f16Unsign(g_CPU_reg[rs(instr)].y) * f16Unsign(g_CPU_reg[rt(instr)].y);

    // Split values into outputs
    lx = xx;

    ly = f16Overflow(xx);
    ly += xy + yx;

    hx = f16Overflow(ly);
    hx += yy;

    hy = f16Overflow(hx);

    CPU_Lo.x = f16Sign(lx);
    CPU_Lo.y = f16Sign(ly);
    CPU_Hi.x = f16Sign(hx);
    CPU_Hi.y = f16Sign(hy);

    CPU_Lo.value = loVal;
    CPU_Hi.value = hiVal;
}

void PGXP_CPU_DIV(uint32_t instr, uint32_t hiVal, uint32_t loVal, uint32_t rsVal, uint32_t rtVal) {
    // Lo = Rs / Rt (signed)
    // Hi = Rs % Rt (signed)
    Validate(&g_CPU_reg[rs(instr)], rsVal);
    Validate(&g_CPU_reg[rt(instr)], rtVal);

    //// iCB: Only require one valid input
    if (((g_CPU_reg[rt(instr)].flags & VALID_01) != VALID_01) !=
        ((g_CPU_reg[rs(instr)].flags & VALID_01) != VALID_01)) {
        MakeValid(&g_CPU_reg[rs(instr)], rsVal);
        MakeValid(&g_CPU_reg[rt(instr)], rtVal);
    }

    CPU_Lo = CPU_Hi = g_CPU_reg[rs(instr)];

    CPU_Lo.halfFlags[0] = CPU_Hi.halfFlags[0] = (g_CPU_reg[rs(instr)].halfFlags[0] & g_CPU_reg[rt(instr)].halfFlags[0]);

    double vs = f16Unsign(g_CPU_reg[rs(instr)].x) + (g_CPU_reg[rs(instr)].y) * (double)(1 << 16);
    double vt = f16Unsign(g_CPU_reg[rt(instr)].x) + (g_CPU_reg[rt(instr)].y) * (double)(1 << 16);

    double lo = vs / vt;
    CPU_Lo.y = f16Sign(f16Overflow(lo));
    CPU_Lo.x = f16Sign(lo);

    double hi = fmod(vs, vt);
    CPU_Hi.y = f16Sign(f16Overflow(hi));
    CPU_Hi.x = f16Sign(hi);

    CPU_Lo.value = loVal;
    CPU_Hi.value = hiVal;
}

void PGXP_CPU_DIVU(uint32_t instr, uint32_t hiVal, uint32_t loVal, uint32_t rsVal, uint32_t rtVal) {
    // Lo = Rs / Rt (unsigned)
    // Hi = Rs % Rt (unsigned)
    Validate(&g_CPU_reg[rs(instr)], rsVal);
    Validate(&g_CPU_reg[rt(instr)], rtVal);

    //// iCB: Only require one valid input
    if (((g_CPU_reg[rt(instr)].flags & VALID_01) != VALID_01) !=
        ((g_CPU_reg[rs(instr)].flags & VALID_01) != VALID_01)) {
        MakeValid(&g_CPU_reg[rs(instr)], rsVal);
        MakeValid(&g_CPU_reg[rt(instr)], rtVal);
    }

    CPU_Lo = CPU_Hi = g_CPU_reg[rs(instr)];

    CPU_Lo.halfFlags[0] = CPU_Hi.halfFlags[0] = (g_CPU_reg[rs(instr)].halfFlags[0] & g_CPU_reg[rt(instr)].halfFlags[0]);

    double vs = f16Unsign(g_CPU_reg[rs(instr)].x) + f16Unsign(g_CPU_reg[rs(instr)].y) * (double)(1 << 16);
    double vt = f16Unsign(g_CPU_reg[rt(instr)].x) + f16Unsign(g_CPU_reg[rt(instr)].y) * (double)(1 << 16);

    double lo = vs / vt;
    CPU_Lo.y = f16Sign(f16Overflow(lo));
    CPU_Lo.x = f16Sign(lo);

    double hi = fmod(vs, vt);
    CPU_Hi.y = f16Sign(f16Overflow(hi));
    CPU_Hi.x = f16Sign(hi);

    CPU_Lo.value = loVal;
    CPU_Hi.value = hiVal;
}

////////////////////////////////////
// Shift operations (sa)
////////////////////////////////////
void PGXP_CPU_SLL(uint32_t instr, uint32_t rdVal, uint32_t rtVal) {
    // Rd = Rt << Sa
    PGXP_value ret;
    uint32_t sh = sa(instr);
    Validate(&g_CPU_reg[rt(instr)], rtVal);

    ret = g_CPU_reg[rt(instr)];

    // TODO: Shift flags
#if 1
    double x = f16Unsign(g_CPU_reg[rt(instr)].x);
    double y = f16Unsign(g_CPU_reg[rt(instr)].y);
    if (sh >= 32) {
        x = 0.f;
        y = 0.f;
    } else if (sh == 16) {
        y = f16Sign(x);
        x = 0.f;
    } else if (sh >= 16) {
        y = x * (1 << (sh - 16));
        y = f16Sign(y);
        x = 0.f;
    } else {
        x = x * (1 << sh);
        y = y * (1 << sh);
        y += f16Overflow(x);
        x = f16Sign(x);
        y = f16Sign(y);
    }
#else
    double x = g_CPU_reg[rt(instr)].x, y = f16Unsign(g_CPU_reg[rt(instr)].y);

    psx_value iX;
    iX.d = rtVal;
    psx_value iY;
    iY.d = rtVal;

    iX.w.h = 0;  // remove Y
    iY.w.l = 0;  // remove X

    // Shift test values
    psx_value dX;
    dX.d = iX.d << sh;
    psx_value dY;
    dY.d = iY.d << sh;

    if ((dY.sw.h == 0) || (dY.sw.h == -1))
        y = dY.sw.h;
    else
        y = y * (1 << sh);

    if (dX.sw.h != 0.f) {
        if (sh == 16) {
            y = x;
        } else if (sh < 16) {
            y += f16Unsign(x) / (1 << (16 - sh));
            // if (in.x < 0)
            //  y += 1 << (16 - sh);
        } else {
            y += x * (1 << (sh - 16));
        }
    }

    // if there's anything left of X write it in
    if (dX.w.l != 0.f)
        x = x * (1 << sh);
    else
        x = 0;

    x = f16Sign(x);
    y = f16Sign(y);

#endif

    ret.x = x;
    ret.y = y;

    ret.value = rdVal;
    g_CPU_reg[rd(instr)] = ret;
}

void PGXP_CPU_SRL(uint32_t instr, uint32_t rdVal, uint32_t rtVal) {
    // Rd = Rt >> Sa
    PGXP_value ret;
    uint32_t sh = sa(instr);
    Validate(&g_CPU_reg[rt(instr)], rtVal);

    ret = g_CPU_reg[rt(instr)];

#if 0
    double x = f16Unsign(g_CPU_reg[rt(instr)].x);
    double y = f16Unsign(g_CPU_reg[rt(instr)].y);
    if (sh >= 32)
    {
        x = y = 0.f;
    }
    else if (sh >= 16)
    {
        x = y / (1 << (sh - 16));
        x = f16Sign(x);
        y = (y < 0) ? -1.f : 0.f;   // sign extend
    }
    else
    {
        x = x / (1 << sh);

        // check for potential sign extension in overflow
        psx_value valt;
        valt.d = rtVal;
        uint16_t mask = 0xFFFF >> (16 - sh);
        if ((valt.w.h & mask) == mask)
            x += mask << (16 - sh);
        else if ((valt.w.h & mask) == 0)
            x = x;
        else
            x += y * (1 << (16 - sh));//f16Overflow(y);

        y = y / (1 << sh);
        x = f16Sign(x);
        y = f16Sign(y);
    }
#else
    double x = g_CPU_reg[rt(instr)].x, y = f16Unsign(g_CPU_reg[rt(instr)].y);

    psx_value iX;
    iX.d = rtVal;
    psx_value iY;
    iY.d = rtVal;

    iX.sd = (iX.sd << 16) >> 16;  // remove Y
    iY.sw.l = iX.sw.h;            // overwrite x with sign(x)

    // Shift test values
    psx_value dX;
    dX.sd = iX.sd >> sh;
    psx_value dY;
    dY.d = iY.d >> sh;

    if (dX.sw.l != iX.sw.h)
        x = x / (1 << sh);
    else
        x = dX.sw.l;  // only sign bits left

    if (dY.sw.l != iX.sw.h) {
        if (sh == 16) {
            x = y;
        } else if (sh < 16) {
            x += y * (1 << (16 - sh));
            if (g_CPU_reg[rt(instr)].x < 0) x += 1 << (16 - sh);
        } else {
            x += y / (1 << (sh - 16));
        }
    }

    if ((dY.sw.h == 0) || (dY.sw.h == -1))
        y = dY.sw.h;
    else
        y = y / (1 << sh);

    x = f16Sign(x);
    y = f16Sign(y);

#endif
    ret.x = x;
    ret.y = y;

    ret.value = rdVal;
    g_CPU_reg[rd(instr)] = ret;
}

void PGXP_CPU_SRA(uint32_t instr, uint32_t rdVal, uint32_t rtVal) {
    // Rd = Rt >> Sa
    PGXP_value ret;
    uint32_t sh = sa(instr);
    Validate(&g_CPU_reg[rt(instr)], rtVal);
    ret = g_CPU_reg[rt(instr)];

#if 0
    double x = f16Unsign(g_CPU_reg[rt(instr)].x);
    double y = (g_CPU_reg[rt(instr)].y);
    if (sh >= 32)
    {
        // sign extend
        x = y = (y < 0) ? -1.f : 0.f;
    }
    else if (sh >= 16)
    {
        x = y / (1 << (sh - 16));
        x = f16Sign(x);
        y = (y < 0) ? -1.f : 0.f;   // sign extend
    }
    else
    {
        x = x / (1 << sh);

        // check for potential sign extension in overflow
        psx_value valt;
        valt.d = rtVal;
        uint16_t mask = 0xFFFF >> (16 - sh);
        if ((valt.w.h & mask) == mask)
            x += mask << (16 - sh);
        else if ((valt.w.h & mask) == 0)
            x = x;
        else
            x += y * (1 << (16 - sh));//f16Overflow(y);

        y = y / (1 << sh);
        x = f16Sign(x);
        y = f16Sign(y);
    }

#else
    double x = g_CPU_reg[rt(instr)].x, y = g_CPU_reg[rt(instr)].y;

    psx_value iX;
    iX.d = rtVal;
    psx_value iY;
    iY.d = rtVal;

    iX.sd = (iX.sd << 16) >> 16;  // remove Y
    iY.sw.l = iX.sw.h;            // overwrite x with sign(x)

    // Shift test values
    psx_value dX;
    dX.sd = iX.sd >> sh;
    psx_value dY;
    dY.sd = iY.sd >> sh;

    if (dX.sw.l != iX.sw.h)
        x = x / (1 << sh);
    else
        x = dX.sw.l;  // only sign bits left

    if (dY.sw.l != iX.sw.h) {
        if (sh == 16) {
            x = y;
        } else if (sh < 16) {
            x += y * (1 << (16 - sh));
            if (g_CPU_reg[rt(instr)].x < 0) x += 1 << (16 - sh);
        } else {
            x += y / (1 << (sh - 16));
        }
    }

    if ((dY.sw.h == 0) || (dY.sw.h == -1))
        y = dY.sw.h;
    else
        y = y / (1 << sh);

    x = f16Sign(x);
    y = f16Sign(y);

#endif

    ret.x = x;
    ret.y = y;

    ret.value = rdVal;
    g_CPU_reg[rd(instr)] = ret;
}

////////////////////////////////////
// Shift operations variable
////////////////////////////////////
void PGXP_CPU_SLLV(uint32_t instr, uint32_t rdVal, uint32_t rtVal, uint32_t rsVal) {
    // Rd = Rt << Rs
    PGXP_value ret;
    uint32_t sh = rsVal & 0x1F;
    Validate(&g_CPU_reg[rt(instr)], rtVal);
    Validate(&g_CPU_reg[rs(instr)], rsVal);

    ret = g_CPU_reg[rt(instr)];

#if 1
    double x = f16Unsign(g_CPU_reg[rt(instr)].x);
    double y = f16Unsign(g_CPU_reg[rt(instr)].y);
    if (sh >= 32) {
        x = 0.f;
        y = 0.f;
    } else if (sh == 16) {
        y = f16Sign(x);
        x = 0.f;
    } else if (sh >= 16) {
        y = x * (1 << (sh - 16));
        y = f16Sign(y);
        x = 0.f;
    } else {
        x = x * (1 << sh);
        y = y * (1 << sh);
        y += f16Overflow(x);
        x = f16Sign(x);
        y = f16Sign(y);
    }
#else
    double x = g_CPU_reg[rt(instr)].x, y = f16Unsign(g_CPU_reg[rt(instr)].y);

    psx_value iX;
    iX.d = rtVal;
    psx_value iY;
    iY.d = rtVal;

    iX.w.h = 0;  // remove Y
    iY.w.l = 0;  // remove X

    // Shift test values
    psx_value dX;
    dX.d = iX.d << sh;
    psx_value dY;
    dY.d = iY.d << sh;

    if ((dY.sw.h == 0) || (dY.sw.h == -1))
        y = dY.sw.h;
    else
        y = y * (1 << sh);

    if (dX.sw.h != 0.f) {
        if (sh == 16) {
            y = x;
        } else if (sh < 16) {
            y += f16Unsign(x) / (1 << (16 - sh));
            // if (in.x < 0)
            //  y += 1 << (16 - sh);
        } else {
            y += x * (1 << (sh - 16));
        }
    }

    // if there's anything left of X write it in
    if (dX.w.l != 0.f)
        x = x * (1 << sh);
    else
        x = 0;

    x = f16Sign(x);
    y = f16Sign(y);

#endif
    ret.x = x;
    ret.y = y;

    ret.value = rdVal;
    g_CPU_reg[rd(instr)] = ret;
}

void PGXP_CPU_SRLV(uint32_t instr, uint32_t rdVal, uint32_t rtVal, uint32_t rsVal) {
    // Rd = Rt >> Sa
    PGXP_value ret;
    uint32_t sh = rsVal & 0x1F;
    Validate(&g_CPU_reg[rt(instr)], rtVal);
    Validate(&g_CPU_reg[rs(instr)], rsVal);

    ret = g_CPU_reg[rt(instr)];

#if 0
    double x = f16Unsign(g_CPU_reg[rt(instr)].x);
    double y = f16Unsign(g_CPU_reg[rt(instr)].y);
    if (sh >= 32)
    {
        x = y = 0.f;
    }
    else if (sh >= 16)
    {
        x = y / (1 << (sh - 16));
        x = f16Sign(x);
        y = (y < 0) ? -1.f : 0.f;   // sign extend
    }
    else
    {
        x = x / (1 << sh);

        // check for potential sign extension in overflow
        psx_value valt;
        valt.d = rtVal;
        uint16_t mask = 0xFFFF >> (16 - sh);
        if ((valt.w.h & mask) == mask)
            x += mask << (16 - sh);
        else if ((valt.w.h & mask) == 0)
            x = x;
        else
            x += y * (1 << (16 - sh));//f16Overflow(y);

        y = y / (1 << sh);
        x = f16Sign(x);
        y = f16Sign(y);
    }

#else
    double x = g_CPU_reg[rt(instr)].x, y = f16Unsign(g_CPU_reg[rt(instr)].y);

    psx_value iX;
    iX.d = rtVal;
    psx_value iY;
    iY.d = rtVal;

    iX.sd = (iX.sd << 16) >> 16;  // remove Y
    iY.sw.l = iX.sw.h;            // overwrite x with sign(x)

    // Shift test values
    psx_value dX;
    dX.sd = iX.sd >> sh;
    psx_value dY;
    dY.d = iY.d >> sh;

    if (dX.sw.l != iX.sw.h)
        x = x / (1 << sh);
    else
        x = dX.sw.l;  // only sign bits left

    if (dY.sw.l != iX.sw.h) {
        if (sh == 16) {
            x = y;
        } else if (sh < 16) {
            x += y * (1 << (16 - sh));
            if (g_CPU_reg[rt(instr)].x < 0) x += 1 << (16 - sh);
        } else {
            x += y / (1 << (sh - 16));
        }
    }

    if ((dY.sw.h == 0) || (dY.sw.h == -1))
        y = dY.sw.h;
    else
        y = y / (1 << sh);

    x = f16Sign(x);
    y = f16Sign(y);

#endif

    ret.x = x;
    ret.y = y;

    ret.value = rdVal;
    g_CPU_reg[rd(instr)] = ret;
}

void PGXP_CPU_SRAV(uint32_t instr, uint32_t rdVal, uint32_t rtVal, uint32_t rsVal) {
    // Rd = Rt >> Sa
    PGXP_value ret;
    uint32_t sh = rsVal & 0x1F;
    Validate(&g_CPU_reg[rt(instr)], rtVal);
    Validate(&g_CPU_reg[rs(instr)], rsVal);

    ret = g_CPU_reg[rt(instr)];
#if 0
    double x = f16Unsign(g_CPU_reg[rt(instr)].x);
    double y = f16Unsign(g_CPU_reg[rt(instr)].y);
    if (sh >= 32)
    {
        x = y = 0.f;
    }
    else if (sh >= 16)
    {
        x = y / (1 << (sh - 16));
        x = f16Sign(x);
        y = (y < 0) ? -1.f : 0.f;   // sign extend
    }
    else
    {
        x = x / (1 << sh);

        // check for potential sign extension in overflow
        psx_value valt;
        valt.d = rtVal;
        uint16_t mask = 0xFFFF >> (16 - sh);
        if ((valt.w.h & mask) == mask)
            x += mask << (16 - sh);
        else if ((valt.w.h & mask) == 0)
            x = x;
        else
            x += y * (1 << (16 - sh));//f16Overflow(y);

        y = y / (1 << sh);
        x = f16Sign(x);
        y = f16Sign(y);
    }

#else
    double x = g_CPU_reg[rt(instr)].x, y = g_CPU_reg[rt(instr)].y;

    psx_value iX;
    iX.d = rtVal;
    psx_value iY;
    iY.d = rtVal;

    iX.sd = (iX.sd << 16) >> 16;  // remove Y
    iY.sw.l = iX.sw.h;            // overwrite x with sign(x)

    // Shift test values
    psx_value dX;
    dX.sd = iX.sd >> sh;
    psx_value dY;
    dY.sd = iY.sd >> sh;

    if (dX.sw.l != iX.sw.h)
        x = x / (1 << sh);
    else
        x = dX.sw.l;  // only sign bits left

    if (dY.sw.l != iX.sw.h) {
        if (sh == 16) {
            x = y;
        } else if (sh < 16) {
            x += y * (1 << (16 - sh));
            if (g_CPU_reg[rt(instr)].x < 0) x += 1 << (16 - sh);
        } else {
            x += y / (1 << (sh - 16));
        }
    }

    if ((dY.sw.h == 0) || (dY.sw.h == -1))
        y = dY.sw.h;
    else
        y = y / (1 << sh);

    x = f16Sign(x);
    y = f16Sign(y);

#endif

    ret.x = x;
    ret.y = y;

    ret.value = rdVal;
    g_CPU_reg[rd(instr)] = ret;
}

////////////////////////////////////
// Move registers
////////////////////////////////////
void PGXP_CPU_MFHI(uint32_t instr, uint32_t rdVal, uint32_t hiVal) {
    // Rd = Hi
    Validate(&CPU_Hi, hiVal);

    g_CPU_reg[rd(instr)] = CPU_Hi;
}

void PGXP_CPU_MTHI(uint32_t instr, uint32_t hiVal, uint32_t rdVal) {
    // Hi = Rd
    Validate(&g_CPU_reg[rd(instr)], rdVal);

    CPU_Hi = g_CPU_reg[rd(instr)];
}

void PGXP_CPU_MFLO(uint32_t instr, uint32_t rdVal, uint32_t loVal) {
    // Rd = Lo
    Validate(&CPU_Lo, loVal);

    g_CPU_reg[rd(instr)] = CPU_Lo;
}

void PGXP_CPU_MTLO(uint32_t instr, uint32_t loVal, uint32_t rdVal) {
    // Lo = Rd
    Validate(&g_CPU_reg[rd(instr)], rdVal);

    CPU_Lo = g_CPU_reg[rd(instr)];
}

////////////////////////////////////
// Memory Access
////////////////////////////////////

// Load 32-bit word
void PGXP_CPU_LWL(uint32_t instr, uint32_t rtVal, uint32_t addr) {
    // Rt = Mem[Rs + Im]
    PGXP_CPU_LW(instr, rtVal, addr);
}

void PGXP_CPU_LW(uint32_t instr, uint32_t rtVal, uint32_t addr) {
    // Rt = Mem[Rs + Im]
    ValidateAndCopyMem(&g_CPU_reg[rt(instr)], addr, rtVal);
}

void PGXP_CPU_LWR(uint32_t instr, uint32_t rtVal, uint32_t addr) {
    // Rt = Mem[Rs + Im]
    PGXP_CPU_LW(instr, rtVal, addr);
}

// Load 16-bit
void PGXP_CPU_LH(uint32_t instr, uint16_t rtVal, uint32_t addr) {
    // Rt = Mem[Rs + Im] (sign extended)
    psx_value val;
    val.sd = (int32_t)(int16_t)rtVal;
    ValidateAndCopyMem16(&g_CPU_reg[rt(instr)], addr, val.d, 1);
}

void PGXP_CPU_LHU(uint32_t instr, uint16_t rtVal, uint32_t addr) {
    // Rt = Mem[Rs + Im] (zero extended)
    psx_value val;
    val.d = rtVal;
    val.w.h = 0;
    ValidateAndCopyMem16(&g_CPU_reg[rt(instr)], addr, val.d, 0);
}

// Load 8-bit
void PGXP_CPU_LB(uint32_t instr, uint8_t rtVal, uint32_t addr) { InvalidLoad(addr, instr, 116); }

void PGXP_CPU_LBU(uint32_t instr, uint8_t rtVal, uint32_t addr) { InvalidLoad(addr, instr, 116); }

// Store 32-bit word
void PGXP_CPU_SWL(uint32_t instr, uint32_t rtVal, uint32_t addr) {
    // Mem[Rs + Im] = Rt
    PGXP_CPU_SW(instr, rtVal, addr);
}

void PGXP_CPU_SW(uint32_t instr, uint32_t rtVal, uint32_t addr) {
    // Mem[Rs + Im] = Rt
    Validate(&g_CPU_reg[rt(instr)], rtVal);
    WriteMem(&g_CPU_reg[rt(instr)], addr);
}

void PGXP_CPU_SWR(uint32_t instr, uint32_t rtVal, uint32_t addr) {
    // Mem[Rs + Im] = Rt
    PGXP_CPU_SW(instr, rtVal, addr);
}

// Store 16-bit
void PGXP_CPU_SH(uint32_t instr, uint16_t rtVal, uint32_t addr) {
    // validate and copy half value
    MaskValidate(&g_CPU_reg[rt(instr)], rtVal, 0xFFFF, VALID_0);
    WriteMem16(&g_CPU_reg[rt(instr)], addr);
}

// Store 8-bit
void PGXP_CPU_SB(uint32_t instr, uint8_t rtVal, uint32_t addr) { InvalidStore(addr, instr, 208); }

////////////////////////////////////
// Data transfer tracking
////////////////////////////////////
void PGXP_CP0_MFC0(uint32_t instr, uint32_t rtVal, uint32_t rdVal) {
    // CPU[Rt] = CP0[Rd]
    Validate(&g_CP0_reg[rd(instr)], rdVal);
    g_CPU_reg[rt(instr)] = g_CP0_reg[rd(instr)];
    g_CPU_reg[rt(instr)].value = rtVal;
}

void PGXP_CP0_MTC0(uint32_t instr, uint32_t rdVal, uint32_t rtVal) {
    // CP0[Rd] = CPU[Rt]
    Validate(&g_CPU_reg[rt(instr)], rtVal);
    g_CP0_reg[rd(instr)] = g_CPU_reg[rt(instr)];
    g_CP0_reg[rd(instr)].value = rdVal;
}

void PGXP_CP0_CFC0(uint32_t instr, uint32_t rtVal, uint32_t rdVal) {
    // CPU[Rt] = CP0[Rd]
    Validate(&g_CP0_reg[rd(instr)], rdVal);
    g_CPU_reg[rt(instr)] = g_CP0_reg[rd(instr)];
    g_CPU_reg[rt(instr)].value = rtVal;
}

void PGXP_CP0_CTC0(uint32_t instr, uint32_t rdVal, uint32_t rtVal) {
    // CP0[Rd] = CPU[Rt]
    Validate(&g_CPU_reg[rt(instr)], rtVal);
    g_CP0_reg[rd(instr)] = g_CPU_reg[rt(instr)];
    g_CP0_reg[rd(instr)].value = rdVal;
}

void PGXP_CP0_RFE(uint32_t instr) {}
