#include "recompiler.h"

#if defined(DYNAREC_X86_64)

std::unique_ptr<PCSX::R3000Acpu> PCSX::Cpus::getDynaRec() {
    return std::unique_ptr<PCSX::R3000Acpu>(new DynaRecCPU());
}

/// Params: A program counter value
/// Returns: A pointer to the host x64 code that points to the block that starts from the given PC
DynarecCallback* DynaRecCPU::getBlockPointer (uint32_t pc) {
	const auto base = m_recompilerLUT[pc >> 16];
	const auto offset = (pc & 0xFFFF) >> 2; // Remove the 2 lower bits, they're guaranteed to be 0

	return &base[offset];
}

void DynaRecCPU::execute() {
    m_pc = m_psxRegs.pc;
    if (!isPcValid(m_pc)) error();

    const auto recompilerFunc = getBlockPointer(m_pc);
    if (*recompilerFunc == nullptr) fmt::print("Need to compile block at {:08X}\n", m_pc);
}

void DynaRecCPU::error() {
    PCSX::g_system->hardReset();
    PCSX::g_system->stop();
    PCSX::g_system->message("Unrecoverable error while running recompiler\nProgram counter: %08X\n", m_pc);
}

void DynaRecCPU::flushCache() {
    gen.reset();    // Reset the emitter's code pointer and code size variables
    gen.align(32);  // Align next block
    std::memset(m_recROM, 0, 0x080000 / 4 * sizeof(DynarecCallback*));  // Delete all BIOS blocks
    std::memset(m_recRAM, 0, m_ramSize / 4 * sizeof(DynarecCallback*)); // Delete all RAM blocks
}

#endif // DYNAREC_X86_64