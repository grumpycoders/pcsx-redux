#include "recompiler.h"

#if defined(DYNAREC_X86_64)

void DynaRecCPU::recCOP2() {
    Label end;
    gen.test(dword[contextPointer + COP0_OFFSET(12)], 0x40000000); // Check SR to see if COP2 (GTE) is enabled
    gen.jz(end); // Skip the opcode if not
    
    const auto func = m_recGTE[m_psxRegs.code & 0x3F];  // Look up the opcode in our decoding LUT
    (*this.*func)(); // Jump into the handler to recompile it

    gen.L(end);
}

void DynaRecCPU::recGTEMove() {
    fmt::print("Woops, guess we've got to implement GTE moves\n");
    abort();
}

#endif  // DYNAREC_X86_64
