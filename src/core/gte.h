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

#pragma once
#include <bit>

#include "core/psxemulator.h"
#include "core/r3000a.h"

// WTF termios
#undef NCCS

#define gteoB (PCSX::g_emulator->m_cpu->m_regs.GPR.r[_Rs_] + _Imm_)
#define gteop(instruction) ((instruction)&0x1ffffff)

namespace PCSX {

class GTE {
  public:
    uint32_t MFC2() {
        // CPU[Rt] = GTE_D[Rd]
        return MFC2_internal(_Rd_);
    }

    uint32_t MFC2(int reg) { return MFC2_internal(reg); }

    uint32_t CFC2() {
        // CPU[Rt] = GTE_C[Rd]
        return PCSX::g_emulator->m_cpu->m_regs.CP2C.p[_Rd_].d;
    }

    void CTC2(uint32_t value, int reg) { CTC2_internal(value, reg); }

    void MTC2(uint32_t value, int reg) { MTC2_internal(value, reg); }

    void MTC2(uint32_t code) { MTC2_internal(PCSX::g_emulator->m_cpu->m_regs.GPR.r[_Rt_], _Rd_); }
    void CTC2(uint32_t code) { CTC2_internal(PCSX::g_emulator->m_cpu->m_regs.GPR.r[_Rt_], _Rd_); }
    void LWC2(uint32_t code) { MTC2_internal(PCSX::g_emulator->m_mem->read32(gteoB), _Rt_); }
    void SWC2(uint32_t code) { PCSX::g_emulator->m_mem->write32(gteoB, MFC2_internal(_Rt_)); }

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

    // If MSB is set, return the number of leading ones, else return the number of leading zeroes
    // For an input of 0, 32 is returned
    static uint32_t countLeadingBits(uint32_t value) {
        if (value & 0x80000000) {
            value = ~value;
        }
        return std::countl_zero<uint32_t>(value);
    }

    // Count leading zeroes of a 16-bit value. For an input of 0, 16 is returned
    static uint32_t countLeadingZeros16(uint16_t value) {
        // Use a 32-bit CLZ as it's what's most commonly available and Clang/GCC fail to optimize 16-bit CLZ
        const auto count = std::countl_zero<uint32_t>((uint32_t)value);
        return count - 16;
    }

  private:
    class int44 {
      public:
        int44(int64_t value)
            : m_value(value), m_positive_overflow(value > 0x7ffffffffff), m_negative_overflow(value < -0x80000000000) {}

        int44(int64_t value, bool positive_overflow, bool negative_overflow)
            : m_value(value), m_positive_overflow(positive_overflow), m_negative_overflow(negative_overflow) {}

        int44 operator+(int64_t rhs) {
            int64_t value = ((m_value + rhs) << 20) >> 20;
            return int44(value, m_positive_overflow || (value < 0 && m_value >= 0 && rhs >= 0),
                         m_negative_overflow || (value >= 0 && m_value < 0 && rhs < 0));
        }

        bool positiveOverflow() { return m_positive_overflow; }
        bool negativeOverflow() { return m_negative_overflow; }
        int64_t value() { return m_value; }

      private:
        int64_t m_value;
        bool m_positive_overflow;
        bool m_negative_overflow;
    };

    int s_sf;
    int64_t s_mac0;
    int64_t s_mac3;

    int32_t BOUNDS(int44 value, int max_flag, int min_flag);
    int32_t A1(int44 a);
    int32_t A2(int44 a);
    int32_t A3(int44 a);
    int64_t F(int64_t a);

    uint32_t MFC2_internal(int reg);
    void MTC2_internal(uint32_t value, int reg);
    void CTC2_internal(uint32_t value, int reg);
    void pushZ(uint16_t z);
};

}  // namespace PCSX
