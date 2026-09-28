/*

MIT License

Copyright (c) 2025 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#pragma once

#include <stdint.h>

#include "mips.hh"

namespace Mips {
namespace Decoder {

struct Instruction {
    Instruction(uint32_t opcode) : code(opcode) {}

    // clang-format off
    // MIPS I instruction set mnemonics
    enum Mnemonic {
        // Arithmetic Instructions
        ADD, ADDU, ADDI, ADDIU, SUB, SUBU, SLT, SLTU, SLTI, SLTIU, DIV, DIVU, MULT, MULTU,

        // Logical Instructions
        AND, ANDI, OR, ORI, XOR, XORI, NOR,

        // Shift Instructions
        SLL, SRL, SRA, SLLV, SRLV, SRAV,

        // Load Instructions
        LB, LBU, LH, LHU, LUI, LW, LWL, LWR,

        // Store Instructions
        SB, SH, SW, SWL, SWR,

        // Branch Instructions
        BEQ, BNE, BGEZ, BGTZ, BLEZ, BLTZ, BGEZAL, BLTZAL,

        // Jump Instructions
        J, JAL, JR, JALR,

        // Move Instructions
        MFHI, MTHI, MFLO, MTLO,

        // System Instructions
        BREAK, SYSCALL,

        // Coprocessor Instructions
        MFC0, MTC0, CFC0, CTC0, MFC2, MTC2, CFC2, CTC2, SWC2, LWC2,

        // Invalid Instruction
        INVALID,
    };
    // clang-format on

    uint32_t opcode() const { return code >> 26; }
    uint32_t funct() const { return code & 0x3f; }
    uint32_t rs() const { return (code >> 21) & 0x1f; }
    uint32_t rt() const { return (code >> 16) & 0x1f; }
    uint32_t rd() const { return (code >> 11) & 0x1f; }
    uint32_t sa() const { return (code >> 6) & 0x1f; }
    int32_t imm() const { return static_cast<int16_t>(code & 0xffff); }
    uint32_t target() const { return code & 0x3ffffff; }
    int32_t offset() const { return code & 0x3ffffff; }
    uint32_t cop() const { return (code >> 26) & 0x1f; }
    uint32_t copFunc() const { return code & 0x3f; }

    Mnemonic mnemonic() const {
        switch (opcode()) {
            case 0b000000:  // special
                switch (funct()) {
                    case 0b100000:
                        return ADD;
                    case 0b100001:
                        return ADDU;
                    case 0b100010:
                        return SUB;
                    case 0b100011:
                        return SUBU;
                    case 0b101010:
                        return SLT;
                    case 0b101011:
                        return SLTU;
                    case 0b011010:
                        return DIV;
                    case 0b011011:
                        return DIVU;
                    case 0b011000:
                        return MULT;
                    case 0b011001:
                        return MULTU;
                    case 0b010000:
                        return MFHI;
                    case 0b010001:
                        return MTHI;
                    case 0b010010:
                        return MFLO;
                    case 0b010011:
                        return MTLO;
                    case 0b000000:
                        return SLL;
                    case 0b000010:
                        return SRL;
                    case 0b000011:
                        return SRA;
                    case 0b000100:
                        return SLLV;
                    case 0b000110:
                        return SRLV;
                    case 0b000111:
                        return SRAV;
                    case 0b100111:
                        return NOR;
                    case 0b001000:
                        return JR;
                    case 0b001001:
                        return JALR;
                    case 0b001101:
                        return BREAK;
                    case 0b001100:
                        return SYSCALL;
                }
                break;
            case 0b000001:  // REGIMM
                switch (rt()) {
                    case 0b00001:
                        return BGEZ;
                    case 0b10001:
                        return BGEZAL;
                    case 0b00000:
                        return BLTZ;
                    case 0b10000:
                        return BLTZAL;
                }
                break;
            case 0b001000:
                return ADDI;
            case 0b001001:
                return ADDIU;
            case 0b001010:
                return SLTI;
            case 0b001011:
                return SLTIU;
            case 0b001100:
                return ANDI;
            case 0b001101:
                return ORI;
            case 0b001110:
                return XORI;
            case 0b000010:
                return J;
            case 0b000011:
                return JAL;
            case 0b000100:
                return BEQ;
            case 0b000101:
                return BNE;
            case 0b000111:
                return BGTZ;
            case 0b000110:
                return BLEZ;
            case 0b100000:
                return LB;
            case 0b100100:
                return LBU;
            case 0b100001:
                return LH;
            case 0b100101:
                return LHU;
            case 0b001111:
                return LUI;
            case 0b100011:
                return LW;
            case 0b100010:
                return LWL;
            case 0b100110:
                return LWR;
            case 0b101000:
                return SB;
            case 0b101001:
                return SH;
            case 0b101011:
                return SW;
            case 0b101010:
                return SWL;
            case 0b101110:
                return SWR;
            case 0b010000:  // COP0
                switch (rs()) {
                    case 0b00000:
                        return MFC0;
                    case 0b00100:
                        return MTC0;
                    case 0b00010:
                        return CFC0;
                    case 0b00110:
                        return CTC0;
                }
                break;
            case 0b010010:  // COP2
                switch (rs()) {
                    case 0b00000:
                        return MFC2;
                    case 0b00100:
                        return MTC2;
                    case 0b00010:
                        return CFC2;
                    case 0b00110:
                        return CTC2;
                }
                break;
            case 0b111010:
                return SWC2;
            case 0b110010:
                return LWC2;
        }
        return INVALID;
    }

    bool isLoad() const {
        switch (mnemonic()) {
            case LB:
            case LBU:
            case LH:
            case LHU:
            case LUI:
            case LW:
            case LWL:
            case LWR:
            case LWC2:
                return true;
            default:
                return false;
        }
    }

    bool isStore() const {
        switch (mnemonic()) {
            case SB:
            case SH:
            case SW:
            case SWL:
            case SWR:
            case SWC2:
                return true;
            default:
                return false;
        }
    }

    uint32_t getLoadAddress(GPRRegs& gpr) const {
        switch (mnemonic()) {
            case LB:
            case LBU:
            case LH:
            case LHU:
            case LW:
            case LWL:
            case LWR:
            case LWC2:
                return gpr.r[rs()] + imm();
            default:
                return 0;
        }
    }

    uint32_t getStoreAddress(GPRRegs& gpr) const {
        switch (mnemonic()) {
            case SB:
            case SH:
            case SW:
            case SWL:
            case SWR:
            case SWC2:
                return gpr.r[rs()] + imm();
            default:
                return 0;
        }
    }

    uint32_t getLoadMask(GPRRegs& gpr) const {
        switch (mnemonic()) {
            case LB:
            case LBU:
                return 0xff;
            case LH:
            case LHU:
                return 0xffff;
            case LWL: {
                uint32_t address = gpr.r[rs()] + imm();
                switch (address & 0x3) {
                    case 0:
                        return 0x000000ff;
                    case 1:
                        return 0x0000ffff;
                    case 2:
                        return 0x00ffffff;
                    case 3:
                        return 0xffffffff;
                }
                return 0xffffffff;
            }
            case LWR: {
                uint32_t address = gpr.r[rs()] + imm();
                switch (address & 0x3) {
                    case 0:
                        return 0xffffffff;
                    case 1:
                        return 0xffffff00;
                    case 2:
                        return 0xffff0000;
                    case 3:
                        return 0xff000000;
                }
                return 0xffffffff;
            }
            default:
                return 0xffffffff;
        }
    }

    uint32_t getValueToStore(GPRRegs& gpr, uint32_t cop2regs[32]) const {
        switch (mnemonic()) {
            case SB:
                return gpr.r[rt()] & 0xff;
            case SH:
                return gpr.r[rt()] & 0xffff;
            case SWL: {
                uint32_t address = gpr.r[rs()] + imm();
                switch (address & 0x3) {
                    case 0:
                        return gpr.r[rt()] << 24;
                    case 1:
                        return gpr.r[rt()] << 16;
                    case 2:
                        return gpr.r[rt()] << 8;
                    case 3:
                        return gpr.r[rt()];
                }
                return gpr.r[rt()];
            }
            case SWR: {
                uint32_t address = gpr.r[rs()] + imm();
                switch (address & 0x3) {
                    case 0:
                        return gpr.r[rt()];
                    case 1:
                        return gpr.r[rt()] >> 8;
                    case 2:
                        return gpr.r[rt()] >> 16;
                    case 3:
                        return gpr.r[rt()] >> 24;
                }
                return gpr.r[rt()];
            }
            case SWC2:
                return cop2regs[rt()];
            default:
                return gpr.r[rt()];
        }
    }

    uint32_t getStoreMask(GPRRegs& gpr) const {
        switch (mnemonic()) {
            case SB:
                return 0xff;
            case SH:
                return 0xffff;
            case SWL: {
                uint32_t address = gpr.r[rs()] + imm();
                switch (address & 0x3) {
                    case 0:
                        return 0xff000000;
                    case 1:
                        return 0xffff0000;
                    case 2:
                        return 0xffffff00;
                    case 3:
                        return 0xffffffff;
                }
                return 0xffffffff;
            }
            case SWR: {
                uint32_t address = gpr.r[rs()] + imm();
                switch (address & 0x3) {
                    case 0:
                        return 0x000000ff;
                    case 1:
                        return 0x0000ffff;
                    case 2:
                        return 0x00ffffff;
                    case 3:
                        return 0xffffffff;
                }
                return 0xffffffff;
            }
            default:
                return 0xffffffff;
        }
    }

    uint32_t getBranchAddress(uint32_t pc) const {
        switch (mnemonic()) {
            case BEQ:
            case BNE:
            case BGEZ:
            case BGTZ:
            case BLEZ:
            case BLTZ:
            case BGEZAL:
            case BLTZAL:
                return pc + (imm() << 2) + 4;
            default:
                return 0;
        }
    }

    uint32_t getJumpAddress(uint32_t pc) const {
        switch (mnemonic()) {
            case J:
            case JAL:
                return (pc & 0xf0000000) | (target() << 2);
            default:
                return 0;
        }
    }

    uint32_t getJumpRegisterAddress(GPRRegs& gpr) const {
        switch (mnemonic()) {
            case JR:
            case JALR:
                return gpr.r[rs()];
            default:
                return 0;
        }
    }

    uint32_t code;
};
}  // namespace Decoder
}  // namespace Mips
