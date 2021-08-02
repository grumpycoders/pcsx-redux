#include "recompiler.h"
#if defined(DYNAREC_X86_64)

void DynaRecCPU::recUnknown() {
    fmt::print("Unknown instruction for dynarec - address %08x, instruction %08x\n");
    abort();
    PCSX::g_system->message("Unknown instruction for dynarec - address %08x, instruction %08x\n", m_pc, m_psxRegs.code);
    error();
}

void DynaRecCPU::recLUI() {
    if (_Rt_) return;

    maybeCancelDelayedLoad(_Rt_);
    m_registers[_Rt_].markConst(m_psxRegs.code << 16);
}

#endif DYNAREC_X86_64
