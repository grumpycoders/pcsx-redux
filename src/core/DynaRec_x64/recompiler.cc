#include "recompiler.h"

#if defined(DYNAREC_X86_64)

std::unique_ptr<PCSX::R3000Acpu> PCSX::Cpus::getDynaRec() {
    return std::unique_ptr<PCSX::R3000Acpu>(new DynaRecCPU());
}

void DynaRecCPU::execute() {
    fmt::print ("Add stuff here\n");
}

#endif // DYNAREC_X86_64