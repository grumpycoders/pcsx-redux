/*

MIT License

Copyright (c) 2021 PCSX-Redux authors

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
namespace Encoder {

using Reg = Mips::Reg;

constexpr uint32_t iclass(uint32_t v) { return v << 26; }
constexpr uint32_t dstVal(Reg r) { return uint32_t(r) << 11; }
constexpr uint32_t tgtVal(Reg r) { return uint32_t(r) << 16; }
constexpr uint32_t srcVal(Reg r) { return uint32_t(r) << 21; }

// ALU
constexpr uint32_t add(Reg dst, Reg src, Reg tgt) { return dstVal(dst) | tgtVal(tgt) | srcVal(src) | 0b100000; }
constexpr uint32_t add(Reg dst, Reg tgt) { return add(dst, dst, tgt); }
constexpr uint32_t addu(Reg dst, Reg src, Reg tgt) { return dstVal(dst) | tgtVal(tgt) | srcVal(src) | 0b100001; }
constexpr uint32_t addu(Reg dst, Reg tgt) { return addu(dst, dst, tgt); }
constexpr uint32_t addi(Reg tgt, Reg src, int16_t value) {
    uint32_t v = value;
    v &= 0xffff;
    return iclass(0b001000) | srcVal(src) | tgtVal(tgt) | v;
}
constexpr uint32_t addi(Reg tgt, int16_t value) { return addi(tgt, tgt, value); }
constexpr uint32_t addiu(Reg tgt, Reg src, int16_t value) {
    uint32_t v = value;
    v &= 0xffff;
    return iclass(0b001001) | srcVal(src) | tgtVal(tgt) | v;
}
constexpr uint32_t addiu(Reg tgt, int16_t value) { return addiu(tgt, tgt, value); }
constexpr uint32_t andd(Reg dst, Reg src, Reg tgt) { return dstVal(dst) | tgtVal(tgt) | srcVal(src) | 0b100100; }
constexpr uint32_t andd(Reg dst, Reg tgt) { return andd(dst, dst, tgt); }
constexpr uint32_t andi(Reg tgt, Reg src, uint16_t value) {
    return iclass(0b001100) | srcVal(src) | tgtVal(tgt) | value;
}
constexpr uint32_t andi(Reg tgt, uint16_t value) { return andi(tgt, tgt, value); }
constexpr uint32_t lui(Reg tgt, uint16_t value) { return iclass(0b001111) | tgtVal(tgt) | value; }
constexpr uint32_t nor(Reg dst, Reg src, Reg tgt) { return dstVal(dst) | tgtVal(tgt) | srcVal(src) | 0b100111; }
constexpr uint32_t nor(Reg dst, Reg tgt) { return nor(dst, dst, tgt); }
constexpr uint32_t orr(Reg dst, Reg src, Reg tgt) { return dstVal(dst) | tgtVal(tgt) | srcVal(src) | 0b100101; }
constexpr uint32_t orr(Reg dst, Reg tgt) { return orr(dst, dst, tgt); }
constexpr uint32_t ori(Reg tgt, Reg src, uint16_t value) {
    return iclass(0b001101) | srcVal(src) | tgtVal(tgt) | value;
}
constexpr uint32_t ori(Reg tgt, uint16_t value) { return ori(tgt, tgt, value); }
constexpr uint32_t slt(Reg dst, Reg src, Reg tgt) { return dstVal(dst) | tgtVal(tgt) | srcVal(src) | 0b101010; }
constexpr uint32_t slt(Reg dst, Reg tgt) { return slt(dst, dst, tgt); }
constexpr uint32_t sltu(Reg dst, Reg src, Reg tgt) { return dstVal(dst) | tgtVal(tgt) | srcVal(src) | 0b101011; }
constexpr uint32_t sltu(Reg dst, Reg tgt) { return sltu(dst, dst, tgt); }
constexpr uint32_t slti(Reg tgt, Reg src, int16_t value) {
    uint32_t v = value;
    v &= 0xffff;
    return iclass(0b001010) | srcVal(src) | tgtVal(tgt) | v;
}
constexpr uint32_t slti(Reg tgt, int16_t value) { return slti(tgt, tgt, value); }
constexpr uint32_t sltiu(Reg tgt, Reg src, uint16_t value) {
    return iclass(0b001011) | srcVal(src) | tgtVal(tgt) | value;
}
constexpr uint32_t sltiu(Reg tgt, uint16_t value) { return sltiu(tgt, tgt, value); }
constexpr uint32_t sub(Reg dst, Reg src, Reg tgt) { return dstVal(dst) | tgtVal(tgt) | srcVal(src) | 0b100010; }
constexpr uint32_t sub(Reg dst, Reg tgt) { return sub(dst, dst, tgt); }
constexpr uint32_t subu(Reg dst, Reg src, Reg tgt) { return dstVal(dst) | tgtVal(tgt) | srcVal(src) | 0b100011; }
constexpr uint32_t subu(Reg dst, Reg tgt) { return subu(dst, dst, tgt); }
constexpr uint32_t xorr(Reg dst, Reg src, Reg tgt) { return dstVal(dst) | tgtVal(tgt) | srcVal(src) | 0b100110; }
constexpr uint32_t xorr(Reg dst, Reg tgt) { return xorr(dst, dst, tgt); }
constexpr uint32_t xori(Reg tgt, Reg src, uint16_t value) {
    return iclass(0b001110) | srcVal(src) | tgtVal(tgt) | value;
}
constexpr uint32_t xori(Reg tgt, uint16_t value) { return xori(tgt, tgt, value); }

// shifts
constexpr uint32_t sll(Reg dst, Reg tgt, uint16_t sa) { return dstVal(dst) | tgtVal(tgt) | (sa << 6) | 0b000000; }
constexpr uint32_t sll(Reg dst, uint16_t sa) { return sll(dst, dst, sa); }
constexpr uint32_t sllv(Reg dst, Reg tgt, Reg src) { return dstVal(dst) | tgtVal(tgt) | srcVal(src) | 0b000100; }
constexpr uint32_t sllv(Reg dst, Reg src) { return sllv(dst, dst, src); }
constexpr uint32_t sra(Reg dst, Reg tgt, uint16_t sa) { return dstVal(dst) | tgtVal(tgt) | (sa << 6) | 0b000011; }
constexpr uint32_t sra(Reg dst, uint16_t sa) { return sra(dst, dst, sa); }
constexpr uint32_t srav(Reg dst, Reg tgt, Reg src) { return dstVal(dst) | tgtVal(tgt) | srcVal(src) | 0b000111; }
constexpr uint32_t srav(Reg dst, Reg src) { return srav(dst, dst, src); }
constexpr uint32_t srl(Reg dst, Reg tgt, uint16_t sa) { return dstVal(dst) | tgtVal(tgt) | (sa << 6) | 0b000010; }
constexpr uint32_t srl(Reg dst, uint16_t sa) { return srl(dst, dst, sa); }
constexpr uint32_t srlv(Reg dst, Reg tgt, Reg src) { return dstVal(dst) | tgtVal(tgt) | srcVal(src) | 0b000110; }
constexpr uint32_t srlv(Reg dst, Reg src) { return srlv(dst, dst, src); }

// mults
constexpr uint32_t div(Reg src, Reg tgt) { return tgtVal(tgt) | srcVal(src) | 0b011010; }
constexpr uint32_t divu(Reg src, Reg tgt) { return tgtVal(tgt) | srcVal(src) | 0b011011; }
constexpr uint32_t mfhi(Reg dst) { return dstVal(dst) | 0b010000; }
constexpr uint32_t mflo(Reg dst) { return dstVal(dst) | 0b010010; }
constexpr uint32_t mthi(Reg dst) { return dstVal(dst) | 0b010001; }
constexpr uint32_t mtlo(Reg dst) { return dstVal(dst) | 0b010011; }
constexpr uint32_t mult(Reg src, Reg tgt) { return tgtVal(tgt) | srcVal(src) | 0b011000; }
constexpr uint32_t multu(Reg src, Reg tgt) { return tgtVal(tgt) | srcVal(src) | 0b011001; }

// branches
constexpr uint32_t beq(Reg src, Reg tgt, int16_t offset) {
    uint32_t o = offset >> 2;
    o &= 0xffff;
    return iclass(0b000100) | tgtVal(tgt) | srcVal(src) | o;
}
constexpr uint32_t bgez(Reg src, int16_t offset) {
    uint32_t o = offset >> 2;
    o &= 0xffff;
    return iclass(0b000001) | tgtVal(Reg(0b00001)) | srcVal(src) | o;
}
constexpr uint32_t bgezal(Reg src, int16_t offset) {
    uint32_t o = offset >> 2;
    o &= 0xffff;
    return iclass(0b000001) | tgtVal(Reg(0b10001)) | srcVal(src) | o;
}
constexpr uint32_t bgtz(Reg src, int16_t offset) {
    uint32_t o = offset >> 2;
    o &= 0xffff;
    return iclass(0b000111) | tgtVal(Reg(0b00000)) | srcVal(src) | o;
}
constexpr uint32_t blez(Reg src, int16_t offset) {
    uint32_t o = offset >> 2;
    o &= 0xffff;
    return iclass(0b000110) | tgtVal(Reg(0b00000)) | srcVal(src) | o;
}
constexpr uint32_t bltz(Reg src, int16_t offset) {
    uint32_t o = offset >> 2;
    o &= 0xffff;
    return iclass(0b000001) | tgtVal(Reg(0b00000)) | srcVal(src) | o;
}
constexpr uint32_t bltzal(Reg src, int16_t offset) {
    uint32_t o = offset >> 2;
    o &= 0xffff;
    return iclass(0b000001) | tgtVal(Reg(0b10000)) | srcVal(src) | o;
}
constexpr uint32_t bne(Reg src, Reg tgt, int16_t offset) {
    uint32_t o = offset >> 2;
    o &= 0xffff;
    return iclass(0b000101) | tgtVal(tgt) | srcVal(src) | o;
}
constexpr uint32_t brk(uint32_t code) { return (code << 6) | 0b001101; }
constexpr uint32_t j(uint32_t addr) { return iclass(0b000010) | ((addr >> 2) & 0x03ffffff); }
constexpr uint32_t jal(uint32_t addr) { return iclass(0b000011) | ((addr >> 2) & 0x03ffffff); }
constexpr uint32_t jalr(Reg src, Reg dst = Reg::RA) { return dstVal(dst) | srcVal(src) | 0b001001; }
constexpr uint32_t jr(Reg src) { return srcVal(src) | 0b001000; }
constexpr uint32_t syscall() { return 0b001100; }

// memory
constexpr uint32_t lb(Reg tgt, int16_t offset, Reg src) {
    uint32_t o = offset;
    o &= 0xffff;
    return iclass(0b100000) | tgtVal(tgt) | srcVal(src) | o;
}
constexpr uint32_t lbu(Reg tgt, int16_t offset, Reg src) {
    uint32_t o = offset;
    o &= 0xffff;
    return iclass(0b100100) | tgtVal(tgt) | srcVal(src) | o;
}
constexpr uint32_t lh(Reg tgt, int16_t offset, Reg src) {
    uint32_t o = offset;
    o &= 0xffff;
    return iclass(0b100001) | tgtVal(tgt) | srcVal(src) | o;
}
constexpr uint32_t lhu(Reg tgt, int16_t offset, Reg src) {
    uint32_t o = offset;
    o &= 0xffff;
    return iclass(0b100101) | tgtVal(tgt) | srcVal(src) | o;
}
constexpr uint32_t lw(Reg tgt, int16_t offset, Reg src) {
    uint32_t o = offset;
    o &= 0xffff;
    return iclass(0b100011) | tgtVal(tgt) | srcVal(src) | o;
}
constexpr uint32_t lwl(Reg tgt, int16_t offset, Reg src) {
    uint32_t o = offset;
    o &= 0xffff;
    return iclass(0b100010) | tgtVal(tgt) | srcVal(src) | o;
}
constexpr uint32_t lwr(Reg tgt, int16_t offset, Reg src) {
    uint32_t o = offset;
    o &= 0xffff;
    return iclass(0b100110) | tgtVal(tgt) | srcVal(src) | o;
}
constexpr uint32_t sb(Reg tgt, int16_t offset, Reg src) {
    uint32_t o = offset;
    o &= 0xffff;
    return iclass(0b101000) | tgtVal(tgt) | srcVal(src) | o;
}
constexpr uint32_t sh(Reg tgt, int16_t offset, Reg src) {
    uint32_t o = offset;
    o &= 0xffff;
    return iclass(0b101001) | tgtVal(tgt) | srcVal(src) | o;
}
constexpr uint32_t sw(Reg tgt, int16_t offset, Reg src) {
    uint32_t o = offset;
    o &= 0xffff;
    return iclass(0b101011) | tgtVal(tgt) | srcVal(src) | o;
}
constexpr uint32_t swl(Reg tgt, int16_t offset, Reg src) {
    uint32_t o = offset;
    o &= 0xffff;
    return iclass(0b101010) | tgtVal(tgt) | srcVal(src) | o;
}
constexpr uint32_t swr(Reg tgt, int16_t offset, Reg src) {
    uint32_t o = offset;
    o &= 0xffff;
    return iclass(0b101110) | tgtVal(tgt) | srcVal(src) | o;
}

// cop0
constexpr uint32_t mfc0(Reg tgt, uint8_t dst) { return iclass(0b010000) | tgtVal(tgt) | (dst << 11); }
constexpr uint32_t mtc0(Reg tgt, uint8_t dst) { return iclass(0b010000) | (4 << 21) | tgtVal(tgt) | (dst << 11); }
constexpr uint32_t rfe() { return 0x42000010; }

// pseudo
constexpr uint32_t nop() { return 0; }
constexpr uint32_t li(Reg tgt, int16_t value) { return addiu(tgt, Reg::R0, value); }
constexpr uint32_t liu(Reg tgt, uint16_t value) { return ori(tgt, Reg::R0, value); }
constexpr uint32_t move(Reg tgt, Reg src) { return addu(tgt, Reg::R0, src); }
constexpr uint32_t nott(Reg tgt, Reg src) { return nor(tgt, src, Reg::R0); }
constexpr uint32_t nott(Reg tgt) { return nott(tgt, tgt); }
constexpr uint32_t neg(Reg tgt, Reg src) { return subu(tgt, Reg::R0, src); }
constexpr uint32_t neg(Reg tgt) { return neg(tgt, tgt); }
constexpr uint32_t b(int16_t offset) { return bgez(Reg::R0, offset); }
constexpr uint32_t beqz(Reg tgt, int16_t offset) { return beq(tgt, Reg::R0, offset); }
constexpr uint32_t bnez(Reg tgt, int16_t offset) { return bne(tgt, Reg::R0, offset); }
constexpr uint32_t bal(int16_t offset) { return bgezal(Reg::R0, offset); }

}  // namespace Encoder
}  // namespace Mips
