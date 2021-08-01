#include "recompiler.h"
#include "regAllocation.h"

#if defined(DYNAREC_X86_64)

void DynaRecCPU::allocateReg(int reg) {
    if (m_registers[reg].isAllocated) return;

    reserveRegs(1);
}
#endif // DYNAREC_X86_64