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

#include "core/psxemulator.h"
#include "core/r3000a.h"

// WTF termios
#undef NCCS

#define gteoB (PCSX::g_emulator->m_psxCpu->m_psxRegs.GPR.r[_Rs_] + _Imm_)
#define gteop(instruction) ((instruction) & 0x1ffffff)

namespace PCSX {

class GTE {
  public:
    uint32_t MFC2() {
        // CPU[Rt] = GTE_D[Rd]
        return MFC2_internal(_Rd_);
    }

    uint32_t MFC2(int reg) {
        return MFC2_internal(reg);
    }

    uint32_t CFC2() {
        // CPU[Rt] = GTE_C[Rd]
        return PCSX::g_emulator->m_psxCpu->m_psxRegs.CP2C.p[_Rd_].d;
    }

    void CTC2(uint32_t value, int reg) {
        CTC2_internal(value, reg);
    }

    void MTC2(uint32_t value, int reg) { 
        MTC2_internal(value, reg);
    }

    void MTC2(uint32_t code) { MTC2_internal(PCSX::g_emulator->m_psxCpu->m_psxRegs.GPR.r[_Rt_], _Rd_); }
    void CTC2(uint32_t code) { CTC2_internal(PCSX::g_emulator->m_psxCpu->m_psxRegs.GPR.r[_Rt_], _Rd_); }
    void LWC2(uint32_t code) { MTC2_internal(PCSX::g_emulator->m_psxMem->psxMemRead32(gteoB), _Rt_); }
    void SWC2(uint32_t code) { PCSX::g_emulator->m_psxMem->psxMemWrite32(gteoB, MFC2_internal(_Rt_)); }

    void RTPS(uint32_t code) { docop2(gteop(code)); }
    void NCLIP(uint32_t code) { docop2(gteop(code)); }
    void OP(uint32_t code) { docop2(gteop(code)); }
    void DPCS(uint32_t code) { docop2(gteop(code)); }
    void INTPL(uint32_t code) { docop2(gteop(code)); }
    void MVMVA(uint32_t code) { docop2(gteop(code)); }
    void NCDS(uint32_t code) { docop2(gteop(code)); }
    void CDP(uint32_t code) { docop2(gteop(code)); }
    void NCDT(uint32_t code) { docop2(gteop(code)); }
    void NCCS(uint32_t code) { docop2(gteop(code)); }
    void CC(uint32_t code) { docop2(gteop(code)); }
    void NCS(uint32_t code) { docop2(gteop(code)); }
    void NCT(uint32_t code) { docop2(gteop(code)); }
    void SQR(uint32_t code) { docop2(gteop(code)); }
    void DCPL(uint32_t code) { docop2(gteop(code)); }
    void DPCT(uint32_t code) { docop2(gteop(code)); }
    void AVSZ3(uint32_t code) { docop2(gteop(code)); }
    void AVSZ4(uint32_t code) { docop2(gteop(code)); }
    void RTPT(uint32_t code) { docop2(gteop(code)); }
    void GPF(uint32_t code) { docop2(gteop(code)); }
    void GPL(uint32_t code) { docop2(gteop(code)); }
    void NCCT(uint32_t code) { docop2(gteop(code)); }

  private:
    int s_sf;
    int64_t s_mac0;
    int64_t s_mac3;

    int32_t BOUNDS(/*int44*/ int64_t value, int max_flag, int min_flag);
    int32_t A1(/*int44*/ int64_t a);
    int32_t A2(/*int44*/ int64_t a);
    int32_t A3(/*int44*/ int64_t a);
    int64_t F(int64_t a);
    int docop2(int op);

    uint32_t MFC2_internal(int reg);
    void MTC2_internal(uint32_t value, int reg);
    void CTC2_internal(uint32_t value, int reg);
};

}  // namespace PCSX
