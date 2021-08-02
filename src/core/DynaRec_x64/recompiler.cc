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
    if (!isPcValid(m_pc)) {
        error();
    }

    auto ptr = (uint8_t*) gen.getCurr();
    auto recompilerFunc = getBlockPointer(m_pc);
    if (*recompilerFunc == nullptr) { // Check if this block has been compiled, compile it if not
        recompile(recompilerFunc);
    }

    while (ptr != gen.getCurr()) {
        fmt::print("{:02X} ", *ptr++);
    }

    fmt::print("OK done\n");
    abort();
    (*recompilerFunc)(); // Jump to emitted code
    psxBranchTest(); // Check scheduler events
}

void DynaRecCPU::error() {
    PCSX::g_system->hardReset();
    PCSX::g_system->stop();
    PCSX::g_system->message("Unrecoverable error while running recompiler\nProgram counter: %08X\n", m_pc);
}

void DynaRecCPU::flushCache() {
    gen.reset();    // Reset the emitter's code pointer and code size variables
    gen.align(16);  // Align next block
    std::memset(m_biosBlocks, 0, 0x080000 / 4 * sizeof(DynarecCallback));  // Delete all BIOS blocks
    std::memset(m_ramBlocks, 0, m_ramSize / 4 * sizeof(DynarecCallback)); // Delete all RAM blocks
}

void DynaRecCPU::recompile(DynarecCallback*& callback) {
    m_stopCompiling = false;
    m_inDelaySlot = false;
    m_nextIsDelaySlot = false;
    m_delayedLoadInfo[0].active = false;
    m_delayedLoadInfo[1].active = false;
    m_needsStackFrame = false;

    int count = 0; // How many instructions have we compiled?
    gen.align(16);  // Align next block

    if (gen.getSize() > codeCacheSize) {  // Flush JIT cache if we've gone above the acceptable size
        flushCache();
    }

    loadContext(); // Load a pointer to our CPU context
    if constexpr (isWindows()) {
        gen.sub(rsp, 32); // Allocate shadow stack space on Windows
    }

    auto shouldContinue = [&]() {
        if (m_nextIsDelaySlot) {
            return true;
        }
        if (m_stopCompiling) {
            return false;
        }
        if (count >= MAX_BLOCK_SIZE && !m_delayedLoadInfo[0].active && !m_delayedLoadInfo[1].active) {
            return false;
        }
        return true;
    };

    while (shouldContinue()) {
        m_inDelaySlot = m_nextIsDelaySlot;
        m_nextIsDelaySlot = false;

        fmt::print("Instruction\n");
        const auto p = (uint8_t*)PSXM(m_pc); // Fetch instruction
        if (p == nullptr) { // Error if it can't be fetched
            error();
            return;
        }

        m_psxRegs.code = *(uint32_t*)p; // Actually read the instruction
        m_pc += 4; // Increment recompiler PC
        count++;   // Increment instruction count

        auto func = m_recBSC[m_psxRegs.code >> 26];  // Look up the opcode in our decoding LUT
        (*this.*func)(); // Jump into the handler to recompile it

        //const bool isOtherActive = m_delayedLoadInfo[m_currentDelayedLoad].active;
        //processDelayedLoad();
        //if (isOtherActive) {
        //    gen.mov(esi, edi);
        //    gen.shr(ebx, 16);
        //}
    }
    
    flushRegs();
    if constexpr (isWindows()) {
        gen.add(rsp, 32); // Deallocate shadow stack space on Windows
    }
    gen.pop(contextPointer); // Restore our context pointer register
}
#endif // DYNAREC_X86_64
