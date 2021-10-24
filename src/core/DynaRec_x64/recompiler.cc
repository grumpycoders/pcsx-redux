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
#include <cassert>

std::unique_ptr<PCSX::R3000Acpu> PCSX::Cpus::getDynaRec() {
    return std::unique_ptr<PCSX::R3000Acpu>(new DynaRecCPU());
}

/// Params: A program counter value
/// Returns: A pointer to the host x64 code that points to the block that starts from the given PC
DynarecCallback* DynaRecCPU::getBlockPointer(uint32_t pc) {
	const auto base = m_recompilerLUT[pc >> 16];
	const auto offset = (pc & 0xFFFF) >> 2; // Remove the 2 lower bits, they're guaranteed to be 0

	return &base[offset];
}

void DynaRecCPU::execute() {
    if (!isPcValid(m_psxRegs.pc)) {
        error();
        return;
    }

    (*m_dispatcher)(); // Jump to emitted code
}

void DynaRecCPU::signalShellReached(DynaRecCPU* that) {
    if (!that->m_shellStarted) {
        that->m_shellStarted = true;
        PCSX::g_system->m_eventBus->signal(PCSX::Events::ExecutionFlow::ShellReached{});
    }
}

void DynaRecCPU::error() {
    PCSX::g_system->hardReset();
    PCSX::g_system->stop();
    PCSX::g_system->message("Unrecoverable error while running recompiler\nProgram counter: %08X\n", m_pc);
}

void DynaRecCPU::flushCache() {
    gen.reset();    // Reset the emitter's code pointer and code size variables
    gen.align(16);  // Align next block
    std::memset(m_biosBlocks, 0, 0x80000 / 4 * sizeof(DynarecCallback));  // Delete all BIOS blocks
    std::memset(m_ramBlocks, 0, m_ramSize / 4 * sizeof(DynarecCallback)); // Delete all RAM blocks
}

void DynaRecCPU::emitDispatcher() {
    Xbyak::Label mainLoop, done, compile;

    // (Address of CPU state) - (address of recompiler object)
    const uintptr_t offsetToRecompiler = (uintptr_t)&m_psxRegs - (uintptr_t)this;
    // Offset of m_recompilerLUT in the dynarec object
    const uintptr_t offsetToRecompilerLUT = (uintptr_t)&m_recompilerLUT[0] - (uintptr_t) this;

    gen.align(16);

    m_dispatcher = (DynarecCallback)gen.getCurr();
    gen.push(contextPointer); // Save context pointer register in stack (also align stack pointer)
    gen.mov(contextPointer, (uint64_t)&m_psxRegs);  // Load context pointer
    
    // Back up all our allocateable volatile regs
    static_assert((ALLOCATEABLE_NON_VOLATILE_COUNT & 1) == 0); // Make sure we've got an even number of regs
    for (auto i = 0; i < ALLOCATEABLE_NON_VOLATILE_COUNT; i++) {
        const auto reg = allocateableNonVolatiles[i];
        gen.push(reg.cvt64());
    }
    gen.mov(qword[contextPointer + HOST_REG_CACHE_OFFSET(ALLOCATEABLE_NON_VOLATILE_COUNT)], runningPointer); // Backup running pointer
    gen.mov(runningPointer, (uintptr_t)PCSX::g_system->runningPtr()); // Load pointer to "running" variable

    // Allocate shadow stack space on Windows
    if constexpr (isWindows()) {
        gen.sub(rsp, 32);
    }

    // This is the "execute until we're not running anymore" loop
    gen.L(mainLoop);
    gen.mov(ecx, dword[contextPointer + PC_OFFSET]); // eax = pc >> 16
    gen.mov(edx, ecx); // edx = (pc & 0xFFFF) >> 2
    gen.shr(ecx, 16);
    gen.shr(edx, 2);
    gen.and_(edx, 0x3fff);

    // Load the base pointer of the recompiler LUT to rax
    gen.mov(rax, (uintptr_t) m_recompilerLUT);
    gen.mov(rax, qword[rax + rcx * 8]); // Load base pointer to recompiler LUT page in rax
    gen.test(rax, rax); // Make sure this is a valid page for the PC to be in. Error if not
    gen.jz(done); // If it is not, we instantly stop execution and return
    gen.mov(rcx, qword[rax + rdx * 8]); // Pointer to block in rcx

    gen.test(rcx, rcx); // Check if block needs to be compiled
    gen.jz(compile);
    gen.jmp(rcx); // Jump to compiled block

    // Code to be executed after each block
    // Blocks will jmp to here
    gen.align(16);
    m_returnFromBlock = (DynarecCallback)gen.getCurr();

    loadThisPointer(arg1.cvt64()); // Poll events
    gen.call(recBranchTestWrapper);
    gen.test(Xbyak::util::byte[runningPointer], 1); // Check if PCSX::g_system->running is true
    gen.jnz(mainLoop); // Go back to the start of main loop if it is, otherwise return

    // Code for when the block is done
    // Restore all non-volatiles
    gen.L(done);
    for (int i = ALLOCATEABLE_NON_VOLATILE_COUNT-1; i >= 0; i--) {
        const auto reg = allocateableNonVolatiles[i];
        gen.pop(reg.cvt64());
    }
    gen.mov(runningPointer, qword[contextPointer + HOST_REG_CACHE_OFFSET(ALLOCATEABLE_NON_VOLATILE_COUNT)]);

    // Deallocate shadow stack space on Windows
    if constexpr (isWindows()) {
        gen.add(rsp, 32);
    }
    gen.pop(contextPointer); // Restore our context pointer
    gen.ret(); // Return

    // Code for when the block to be executed needs to be compiled
    gen.L(compile);
    loadThisPointer(arg1.cvt64());
    gen.lea(arg2.cvt64(), qword[rax + rdx * 8]); // Pointer to callback
    gen.callFunc(recRecompileWrapper); // Call recompilation function, pointer to new block in rax
    gen.jmp(rax); // Jump to compiled block
}


void DynaRecCPU::recompile(DynarecCallback* callback) {
    m_stopCompiling = false;
    m_inDelaySlot = false;
    m_nextIsDelaySlot = false;
    m_delayedLoadInfo[0].active = false;
    m_delayedLoadInfo[1].active = false;
    m_pcWrittenBack = false;
    m_pc = m_psxRegs.pc;

    const auto startingPC = m_pc;

    int count = 0; // How many instructions have we compiled?
    gen.align(16);  // Align next block

    if (gen.getSize() > codeCacheSize) {  // Flush JIT cache if we've gone above the acceptable size
        flushCache();
    }

    *callback = (DynarecCallback) gen.getCurr();
    handleKernelCall(); // Check if this is a kernel call vector, emit some extra code in that case.

    auto shouldContinue = [&]() {
        if (m_nextIsDelaySlot) {
            return true;
        }
        if (m_stopCompiling) {
            return false;
        }
        if (count >= MAX_BLOCK_SIZE) { // TODO: Check delay slots here
            return false;
        }
        return true;
    };

    while (shouldContinue()) {
        m_inDelaySlot = m_nextIsDelaySlot;
        m_nextIsDelaySlot = false;

        const auto p = (uint8_t*) PSXM(m_pc); // Fetch instruction
        if (p == nullptr) { // Error if it can't be fetched
            error();
            return;
        }

        m_psxRegs.code = *(uint32_t*)p; // Actually read the instruction
        m_pc += 4; // Increment recompiler PC
        count++;   // Increment instruction count

        const auto func = m_recBSC[m_psxRegs.code >> 26];  // Look up the opcode in our decoding LUT
        (*this.*func)(); // Jump into the handler to recompile it
    }
    
    flushRegs();
    if (!m_pcWrittenBack) {
        gen.mov(dword[contextPointer + PC_OFFSET], m_pc);
    }

     // If this was the block at 0x8003'0000 (Start of shell) send the GUI a "shell reached" signal
     // This must happen after the PC is written back, otherwise our PC after sideloading will be overriden.
    if (startingPC == 0x80030000) {
        loadThisPointer(arg1.cvt64());
        call(signalShellReached);
    }
    
    gen.add(dword[contextPointer + CYCLE_OFFSET], count * PCSX::Emulator::BIAS);  // Add block cycles
    gen.jmp(m_returnFromBlock);
}

void DynaRecCPU::recSpecial() {
    const auto func = m_recSPC[m_psxRegs.code & 0x3F];  // Look up the opcode in our decoding LUT
    (*this.*func)(); // Jump into the handler to recompile it
}

// Checks if the block being compiled is one of the kernel call vectors
// If so, emit a call to "InterceptBIOS", which handles the kernel call debugger features
void DynaRecCPU::handleKernelCall() {
    const uint32_t pc = m_pc & 0x1fffff;
    const uint32_t base = (m_pc >> 20) & 0xffc;
    if ((base != 0x000) && (base != 0x800) && (base != 0xa00))
        return;  // Mask out the segment, return if not a kernel call vector

    switch (pc) {  // Handle the A0/B0/C0 vectors
        case 0xA0:
            loadThisPointer(arg1.cvt64());
            call(interceptKernelCallWrapper<0xA0>);
            break;

        case 0xB0:
            loadThisPointer(arg1.cvt64());
            call(interceptKernelCallWrapper<0xB0>);
            break;

        case 0xC0:
            loadThisPointer(arg1.cvt64());
            call(interceptKernelCallWrapper<0xC0>);
            break;
    }
}
#endif // DYNAREC_X86_64
