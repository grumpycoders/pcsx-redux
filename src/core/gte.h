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

#define gteoB (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_] + _Imm_)
#define gteop (PCSX::g_emulator.m_psxCpu->m_psxRegs.code & 0x1ffffff)

namespace PCSX {

class GTE {
  public:
    uint32_t MFC2() {
        // CPU[Rt] = GTE_D[Rd]
        return MFC2_internal(_Rd_);
    }
    uint32_t CFC2() {
        // CPU[Rt] = GTE_C[Rd]
        return PCSX::g_emulator.m_psxCpu->m_psxRegs.CP2C.p[_Rd_].d;
    }
    void MTC2() { MTC2_internal(PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_], _Rd_); }
    void CTC2() { CTC2_internal(PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_], _Rd_); }
    void LWC2() { MTC2_internal(PCSX::g_emulator.m_psxMem->psxMemRead32(gteoB), _Rt_); }
    void SWC2() { PCSX::g_emulator.m_psxMem->psxMemWrite32(gteoB, MFC2_internal(_Rt_)); }

    void RTPS() { docop2(gteop); }
    void NCLIP() { docop2(gteop); }
    void OP() { docop2(gteop); }
    void DPCS() { docop2(gteop); }
    void INTPL() { docop2(gteop); }
    void MVMVA() { docop2(gteop); }
    void NCDS() { docop2(gteop); }
    void CDP() { docop2(gteop); }
    void NCDT() { docop2(gteop); }
    void NCCS() { docop2(gteop); }
    void CC() { docop2(gteop); }
    void NCS() { docop2(gteop); }
    void NCT() { docop2(gteop); }
    void SQR() { docop2(gteop); }
    void DCPL() { docop2(gteop); }
    void DPCT() { docop2(gteop); }
    void AVSZ3() { docop2(gteop); }
    void AVSZ4() { docop2(gteop); }
    void RTPT() { docop2(gteop); }
    void GPF() { docop2(gteop); }
    void GPL() { docop2(gteop); }
    void NCCT() { docop2(gteop); }

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
