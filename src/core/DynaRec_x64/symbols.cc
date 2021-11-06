/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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

#include "recompiler.h"

#if defined(DYNAREC_X86_64)
#include <array>
#include "fmt/format.h"

#define REGISTER_VARIABLE(variable, name, size) \
m_symbols += fmt::format("{} {} {}\n", (void*) &(variable), (name), (size))

#define REGISTER_FUNCTION(function, name) \
m_symbols += fmt::format("{} {}\n", (void*) &(function), (name));

void DynaRecCPU::makeSymbols() {
    static constexpr std::array<const char*, 34> GPRs = {
        "r_zero", "r_at", "r_v0", "r_v1", "r_a0", "r_a1", "r_a2", "r_a3",  // 00
        "r_t0", "r_t1", "r_t2", "r_t3", "r_t4", "r_t5", "r_t6", "r_t7",  // 08
        "r_s0", "r_s1", "r_s2", "r_s3", "r_s4", "r_s5", "r_s6", "r_s7",  // 10
        "r_t8", "r_t9", "r_k0", "r_k1", "r_gp", "r_sp", "r_fp", "r_ra",  // 18
        "r_lo", "r_hi"
    };

    static constexpr std::array<const char*, 32> COP2_dataRegs = {
        "GTE_vxy0", "GTE_vz0",  "GTE_vxy1", "GTE_vz1",  "GTE_vxy2", "GTE_vz2",  "GTE_rgb",  "GTE_otz",   // 00
        "GTE_ir0",  "GTE_ir1",  "ir2",  "ir3",  "GTE_sxy0", "GTE_sxy1", "GTE_sxy2", "GTE_sxyp",  // 08
        "GTE_sz0",  "GTE_sz1",  "sz2",  "sz3",  "GTE_rgb0", "GTE_rgb1", "GTE_rgb2", "GTE_res1",  // 10
        "GTE_mac0", "GTE_mac1", "GTE_mac2", "GTE_mac3", "GTE_irgb", "GTE_orgb", "GTE_lzcs", "GTE_lzcr",  // 18
    };

    static constexpr std::array<const char*, 32> COP2_controlRegs = {
        "GTE_r11r12", "GTE_r13r21", "GTE_r22r23", "GTE_r31r32", "GTE_r33", "GTE_trx",  "GTE_try",  "GTE_trz",   // 00
        "GTE_l11l12", "GTE_l13l21", "GTE_l22l23", "GTE_l31l32", "GTE_l33", "GTE_rbk",  "GTE_gbk",  "GTE_bbk",   // 08
        "GTE_lr1lr2", "GTE_lr3lg1", "GTE_lg2lg3", "GTE_lb1lb2", "GTE_lb3", "GTE_rfc",  "GTE_gfc",  "GTE_bfc",   // 10
        "GTE_ofx",    "GTE_ofy",    "GTE_h",      "GTE_dqa",    "GTE_dqb", "GTE_zsf3", "GTE_zsf4", "GTE_flag",  // 18
    };

    static constexpr std::array<const char*, 32> COP0_regs = {
        "COP0_Index",    "COP0_Random",   "COP0_EntryLo0", "COP0_EntryLo1",  // 00
        "COP0_Context",  "COP0_PageMask", "COP0_Wired",    "COP0_Checkme",  // 04
        "COP0_BadVAddr", "COP0_Count",    "COP0_EntryHi",  "COP0_Compare",   // 08
        "COP0_Status",   "COP0_Cause",    "COP0_ExceptPC", "COP0_PRevID",    // 0c
        "COP0_Config",   "COP0_LLAddr",   "COP0_WatchLo",  "COP0_WatchHi",   // 10
        "COP0_XContext", "COP0_Dunno1",    "COP0_Dunno2",    "COP0_Dunno3",     // 14
        "COP0_Dunno4",    "COP0_Dunno5",    "COP0_PErr",     "COP0_CacheErr",  // 18
        "COP0_TagLo",    "COP0_TagHi",    "COP0_ErrorEPC", "COP0_MissingAgain",     // 1c
    };

    m_symbols += fmt::format("{}\n", (void*) gen.getCode()); // Base of code buffer
    m_symbols += fmt::format("{} psxRegs 10000 .data\n", (void*) &m_psxRegs); // Register register segment
    m_symbols += fmt::format("endsegs()\n"); // Stop registering segments

    for (auto i = 0; i < 34; i++) {
        REGISTER_VARIABLE(m_psxRegs.GPR.r[i], GPRs[i], 4);
    }

    for (auto i = 0; i < 32; i++) {
        REGISTER_VARIABLE(m_psxRegs.CP0.r[i], COP0_regs[i], 4);
        REGISTER_VARIABLE(m_psxRegs.CP2D.r[i], COP2_dataRegs[i], 4);
        REGISTER_VARIABLE(m_psxRegs.CP2C.r[i], COP2_controlRegs[i], 4);
    }

    REGISTER_VARIABLE(m_psxRegs.cycle, "m_cycles", 4);
    REGISTER_VARIABLE(m_psxRegs.pc, "m_pc", 4);

    for (int i = 0; i < 16; i++) { // Register host register cache
        REGISTER_VARIABLE(m_psxRegs.hostRegisterCache[i], fmt::format("cached_host_reg_{}", i), 8);
    }

    REGISTER_FUNCTION(psxMemRead8Wrapper, "read8");
    REGISTER_FUNCTION(psxMemRead16Wrapper, "read16");
    REGISTER_FUNCTION(psxMemRead32Wrapper, "read32");
    REGISTER_FUNCTION(psxMemWrite8Wrapper, "write8");
    REGISTER_FUNCTION(psxMemWrite16Wrapper, "write16");
    REGISTER_FUNCTION(psxMemWrite32Wrapper, "write32");

    REGISTER_FUNCTION(psxExceptionWrapper, "fire_exception");
    REGISTER_FUNCTION(recClearWrapper, "recompiler_clear");
    REGISTER_FUNCTION(signalShellReached, "signal_shell_reached");
    REGISTER_FUNCTION(SPU_writeRegisterWrapper, "spu_write_register");
    REGISTER_FUNCTION(recBranchTestWrapper, "branch_test_wrapper");

    m_symbols += fmt::format("{} dispatcher\n", (void*)m_dispatcher);
    m_symbols += fmt::format("{} return_from_block\n", (void*)m_returnFromBlock);
    m_symbols += fmt::format("{} uncompiled_block\n", (void*)m_uncompiledBlock);
}

#undef REGISTER_VARIABLE
#undef REGISTER_FUNCTION
#endif // DYNAREC_X86_64
