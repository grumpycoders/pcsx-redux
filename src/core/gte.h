/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                *
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

#include <bit>
#include <cstdint>

#include "core/psxemulator.h"
#include "core/r3000a.h"

// termios defines NCCS which collides with our method name
#undef NCCS

namespace PCSX {

class GTE {
  public:
    // COP2 data transfer operations
    uint32_t MFC2(uint32_t code);
    uint32_t MFC2(int reg);
    uint32_t CFC2(uint32_t code);
    void MTC2(uint32_t value, int reg);
    void MTC2(uint32_t code);
    void CTC2(uint32_t value, int reg);
    void CTC2(uint32_t code);
    void LWC2(uint32_t code);
    void SWC2(uint32_t code);

    // GTE function instructions (COP2 imm25)
    void RTPS(uint32_t code);
    void NCLIP(uint32_t code);
    void OP(uint32_t code);
    void DPCS(uint32_t code);
    void INTPL(uint32_t code);
    void MVMVA(uint32_t code);
    void NCDS(uint32_t code);
    void CDP(uint32_t code);
    void NCDT(uint32_t code);
    void NCCS(uint32_t code);
    void CC(uint32_t code);
    void NCS(uint32_t code);
    void NCT(uint32_t code);
    void SQR(uint32_t code);
    void DCPL(uint32_t code);
    void DPCT(uint32_t code);
    void AVSZ3(uint32_t code);
    void AVSZ4(uint32_t code);
    void RTPT(uint32_t code);
    void GPF(uint32_t code);
    void GPL(uint32_t code);
    void NCCT(uint32_t code);

    // Count leading redundant sign bits. For positive: leading zeros. For negative: leading ones.
    // Returns 32 for input of 0 or 0xffffffff.
    static uint32_t countLeadingBits(uint32_t value) {
        if (value & 0x80000000) value = ~value;
        return std::countl_zero<uint32_t>(value);
    }

    // Count leading zeros of a 16-bit value. Returns 16 for input of 0.
    static uint32_t countLeadingZeros16(uint16_t value) {
        return std::countl_zero<uint32_t>(static_cast<uint32_t>(value)) - 16;
    }

  private:
    // Template instruction implementations, parameterized on sf (shift factor) and lm (limit mode).
    // Defined in gte-instructions.cc. The public methods dispatch to these based on the encoding.
    template <bool sf, bool lm>
    void op(uint32_t op);
    template <bool sf, bool lm>
    void dpcs(uint32_t op);
    template <bool sf, bool lm>
    void intpl(uint32_t op);
    template <bool sf, bool lm>
    void cdp(uint32_t op);
    template <bool sf, bool lm>
    void cc(uint32_t op);
    template <bool sf, bool lm>
    void sqr(uint32_t op);
    template <bool sf, bool lm>
    void dcpl(uint32_t op);
    template <bool sf, bool lm>
    void dpct(uint32_t op);
    template <bool sf, bool lm>
    void gpf(uint32_t op);
    template <bool sf, bool lm>
    void gpl(uint32_t op);
};

}  // namespace PCSX
