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

bool DynaRecCPU::Init() {
    // Initialize recompiler memory
    // Check for 8MB RAM expansion
    const bool ramExpansion = PCSX::g_emulator->settings.get<PCSX::Emulator::Setting8MB>();
    m_ramSize = ramExpansion ? 0x800000 : 0x200000;
    const auto biosSize = 0x80000;

    // The amount of 64KB RAM pages. 0x80 with the ram expansion, 0x20 otherwise
    const int ramPages = m_ramSize >> 16;

    // Split the 32-bit address space into 64KB pages, so 0x10000 pages in total
    m_recompilerLUT = new DynarecCallback*[0x10000]();

    // Instructions need to be on 4-byte boundaries. So the amount of valid block entrypoints
    // in a region of memory is REGION_SIZE / 4
    m_ramBlocks = new DynarecCallback[m_ramSize / 4];
    m_biosBlocks = new DynarecCallback[biosSize / 4];
    m_dummyBlocks = new DynarecCallback[0x10000 / 4];  // Allocate one page worth of dummy blocks

    gen.reset();

    for (int page = 0; page < 0x10000; page++) {  // Default all pages to dummy blocks
        m_recompilerLUT[page] = &m_dummyBlocks[0];
    }

    // For every 64KB page of memory, we can have 64*1024/4 unique blocks = 0x4000
    // Hence the multiplications below
    for (int page = 0; page < ramPages; page++) {          // Map RAM to the recompiler LUT
        const auto pointer = &m_ramBlocks[page * 0x4000];  // Get a pointer to the page of RAM blocks
        m_recompilerLUT[page + 0x0000] = pointer;          // Map KUSEG, KSEG0 and KSEG1 RAM respectively
        m_recompilerLUT[page + 0x8000] = pointer;
        m_recompilerLUT[page + 0xA000] = pointer;
    }

    for (int page = 0; page < 8; page++) {  // Map BIOS to recompiler LUT
        const auto pointer = &m_biosBlocks[page * 0x4000];
        m_recompilerLUT[page + 0x1FC0] = pointer;  // Map KUSEG, KSEG0 and KSEG1 BIOS respectively
        m_recompilerLUT[page + 0x9FC0] = pointer;
        m_recompilerLUT[page + 0xBFC0] = pointer;
    }

    if (!gen.setRWX()) {
        PCSX::g_system->message("[Dynarec] Failed to allocate executable memory.\nTry disabling the Dynarec CPU.");
        return false;
    }
    emitDispatcher();  // Emit our assembly dispatcher
    uncompileAll();    // Mark all blocks as uncompiled

    for (int i = 0; i < 0x10000 / 4; i++) {  // Mark all dummy blocks as invalid
        m_dummyBlocks[i] = m_invalidBlock;
    }

    if constexpr (ENABLE_SYMBOLS) {
        makeSymbols();
    }

    if constexpr (ENABLE_PROFILER) {
        m_profiler.init();
    }

    m_regs[0].markConst(0);  // $zero is always zero
    return true;
}

void DynaRecCPU::Shutdown() {
    delete[] m_recompilerLUT;
    delete[] m_ramBlocks;
    delete[] m_biosBlocks;
    delete[] m_dummyBlocks;

    if constexpr (ENABLE_SYMBOLS) {
        std::ofstream out("DynarecOutput.map");
        out << m_symbols;
        m_symbols.clear();
        dumpBuffer();
    }

    if constexpr (ENABLE_PROFILER) {
        dumpProfileData();
    }
}

void DynaRecCPU::Reset() {
    R3000Acpu::Reset();  // Reset CPU registers
    Shutdown();          // Deinit and re-init dynarec
    Init();
}

std::unique_ptr<PCSX::R3000Acpu> PCSX::Cpus::getDynaRec() { return std::unique_ptr<PCSX::R3000Acpu>(new DynaRecCPU()); }

/// Params: A program counter value
/// Returns: A pointer to the host x64 code that points to the block that starts from the given PC
DynarecCallback* DynaRecCPU::getBlockPointer(uint32_t pc) {
    const auto base = m_recompilerLUT[pc >> 16];
    const auto offset = (pc & 0xFFFF) >> 2;  // Remove the 2 lower bits, they're guaranteed to be 0

    return &base[offset];
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

void DynaRecCPU::uncompileAll() {
    constexpr int biosSize = 0x80000;
    for (auto i = 0; i < m_ramSize / 4; i++) {  // Mark all RAM blocks as uncompiled
        m_ramBlocks[i] = m_uncompiledBlock;
    }
    for (auto i = 0; i < biosSize / 4; i++) {  // Mark all BIOS blocks as uncompiled
        m_biosBlocks[i] = m_uncompiledBlock;
    }
}

void DynaRecCPU::flushCache() {
    gen.reset();       // Reset the emitter's code pointer and code size variables
    emitDispatcher();  // Re-emit dispatcher
    uncompileAll();    // Mark all blocks as uncompiled
}

void DynaRecCPU::emitBlockLookup() {
    const auto lutOffset = (size_t)m_recompilerLUT - (size_t)this;

    gen.mov(ecx, dword[contextPointer + PC_OFFSET]);  // ecx = pc
    gen.mov(edx, ecx);      // edx = pc
    gen.shr(ecx, 16);       // ecx = pc >> 16
    gen.and_(edx, 0xfffc);  // edx = index into the recompiler LUT page, multiplied by 4

    // Load base pointer to recompiler LUT page in rax
    // Using a single mov if possible
    if (Xbyak::inner::IsInInt32(lutOffset)) {
        gen.mov(rax, qword[contextPointer + rcx * 8 + lutOffset]);
    } else {
        loadAddress(rax, m_recompilerLUT);
        gen.mov(rax, qword[rax + rcx * 8]);
    }
    gen.jmp(qword[rax + rdx * 2]);  // Jump to block
}

void DynaRecCPU::emitDispatcher() {
    Xbyak::Label done;

    gen.align(16);
    m_dispatcher = gen.getCurr<DynarecCallback>();
    gen.push(contextPointer);                  // Save context pointer register in stack (also align stack pointer)
    gen.mov(contextPointer, (uintptr_t)this);  // Load context pointer

    // Back up all our allocateable volatile regs
    static_assert((ALLOCATEABLE_NON_VOLATILE_COUNT & 1) == 0);  // Make sure we've got an even number of regs
    for (auto i = 0; i < ALLOCATEABLE_NON_VOLATILE_COUNT; i++) {
        const auto reg = allocateableNonVolatiles[i];
        gen.push(reg.cvt64());
    }
    gen.mov(qword[contextPointer + HOST_REG_CACHE_OFFSET(0)], runningPointer);  // Backup running pointer
    gen.mov(runningPointer, (uintptr_t)PCSX::g_system->runningPtr());           // Load pointer to "running" variable

    // Allocate shadow stack space on Windows
    if constexpr (isWindows()) {
        gen.sub(rsp, 32);
    }

    emitBlockLookup(); // Look up block

    // Code to be executed after each block
    // Blocks will jmp to here
    gen.align(16);
    m_returnFromBlock = gen.getCurr<DynarecCallback>();

    loadThisPointer(arg1.cvt64());  // Poll events
    gen.callFunc(recBranchTestWrapper);
    gen.test(Xbyak::util::byte[runningPointer], 1);  // Check if PCSX::g_system->running is true
    gen.jz(done);                                    // If it's not, return
    emitBlockLookup();                               // Otherwise, look up next block

    gen.align(16);
    // Code for exiting JIT context
    gen.L(done);

    // Deallocate shadow stack space on Windows
    if constexpr (isWindows()) {
        gen.add(rsp, 32);
    }

    // Restore all non-volatiles
    for (int i = ALLOCATEABLE_NON_VOLATILE_COUNT - 1; i >= 0; i--) {
        const auto reg = allocateableNonVolatiles[i];
        gen.pop(reg.cvt64());
    }
    gen.mov(runningPointer, qword[contextPointer + HOST_REG_CACHE_OFFSET(0)]);

    gen.pop(contextPointer);  // Restore our context pointer
    gen.ret();                // Return

    // Code for when the block to be executed needs to be compiled.
    gen.align(16);
    m_uncompiledBlock = gen.getCurr<DynarecCallback>();

    loadThisPointer(arg1.cvt64());
    gen.callFunc(recRecompileWrapper);            // Call recompilation function. Returns pointer to emitted code
    gen.jmp(rax);

    // Code for when the block we've jumped to is invalid. Throws an error and exits
    gen.align(16);
    m_invalidBlock = gen.getCurr<DynarecCallback>();

    loadThisPointer(arg1.cvt64());  // Throw recompiler error
    gen.callFunc(recErrorWrapper);
    gen.jmp(done);  // Exit
}

// Compile a block, write address of compiled code to *callback
// Returns the address of the compiled block
DynarecCallback DynaRecCPU::recompile(uint32_t pc, bool align) {
    m_stopCompiling = false;
    m_inDelaySlot = false;
    m_nextIsDelaySlot = false;
    m_delayedLoadInfo[0].active = false;
    m_delayedLoadInfo[1].active = false;
    m_pcWrittenBack = false;
    m_linkedPC = std::nullopt;
    m_pc = pc & ~3;

    int count = 0;  // How many instructions have we compiled?
    const auto startingPC = m_pc;
    DynarecCallback* const callback = getBlockPointer(pc); // Pointer to where we'll store the addr of the emitted code

    if (align) {
        gen.align(16);  // Align next block
    }

    if (gen.getSize() > codeCacheSize) {  // Flush JIT cache if we've gone above the acceptable size
        flushCache();
    }

    if constexpr (ENABLE_SYMBOLS) {
        m_symbols += fmt::format("{} recompile_{:08X}\n", gen.getCurr<void*>(), m_pc);
        // This is unnecessary, but it acts as a hint to the decompiler about the context pointer's value
        gen.mov(contextPointer, (uintptr_t)this);
    }

    *callback = gen.getCurr<DynarecCallback>();  // Pointer to emitted code
    if constexpr (ENABLE_PROFILER) {
        if (startProfiling(m_pc)) {  // Uncompile all blocks if the profiler data overflower
            uncompileAll();
        }
    }

    handleKernelCall();  // Check if this is a kernel call vector, emit some extra code in that case.
    auto shouldContinue = [&]() {
        if (m_nextIsDelaySlot) {
            return true;
        }
        if (m_stopCompiling) {
            return false;
        }
        if (count >= MAX_BLOCK_SIZE) {  // TODO: Check delay slots here
            return false;
        }
        return true;
    };

    while (shouldContinue()) {
        m_inDelaySlot = m_nextIsDelaySlot;
        m_nextIsDelaySlot = false;

        const auto p = (uint32_t*)PSXM(m_pc);  // Fetch instruction
        if (p == nullptr) {                    // Error if it can't be fetched
            return m_invalidBlock;
        }

        m_psxRegs.code = *p;  // Actually read the instruction
        m_pc += 4;            // Increment recompiler PC
        count++;              // Increment instruction count

        const auto func = m_recBSC[m_psxRegs.code >> 26];  // Look up the opcode in our decoding LUT
        (*this.*func)();                                   // Jump into the handler to recompile it
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
        m_linkedPC = std::nullopt;
    }
    if constexpr (ENABLE_PROFILER) {
        endProfiling();
    }

    gen.add(dword[contextPointer + CYCLE_OFFSET], count * PCSX::Emulator::BIAS);  // Add block cycles;
    if (m_linkedPC && ENABLE_BLOCK_LINKING && m_linkedPC.value() != startingPC) {
        handleLinking();
    } else {
        gen.jmp((void*)m_returnFromBlock);
    }

    // Block linking might have invalidated this block, so don't cache the pointer to the invalidated block.
    // Instead, read the callback address again
    return *callback;
}

void DynaRecCPU::recSpecial() {
    const auto func = m_recSPC[m_psxRegs.code & 0x3F];  // Look up the opcode in our decoding LUT
    (*this.*func)();                                    // Jump into the handler to recompile it
}

// Checks if the block being compiled is one of the kernel call vectors
// If so, emit a call to "InterceptBIOS", which handles the kernel call debugger features
// Also handles fast booting by intercepting the shell reached signal and setting pc to $ra if fastboot is on
void DynaRecCPU::handleKernelCall() {
    if (m_pc == 0x80030000) {
        handleFastboot();
        return;
    }

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

// Emits a jump to the dispatcher if there's no block to link to.
// Otherwise, handle linking blocks
void DynaRecCPU::handleLinking() {
    // Don't link unless the next PC is valid, and there's over 1MB of free space in the code cache
    if (isPcValid(m_linkedPC.value()) && gen.getRemainingSize() > 0x100000) {
        const auto nextPC = m_linkedPC.value();
        const auto nextBlockPointer = getBlockPointer(nextPC);
        const auto nextBlockOffset = (size_t)nextBlockPointer - (size_t)this;

        if (*nextBlockPointer == m_uncompiledBlock) {  // If the next block hasn't been compiled yet
            // Check that the block hasn't been invalidated/moved
            // The value will be patched later. Since all code is within the same 32MB segment,
            // We can get away with only checking the low 32 bits of the block pointer
            if (Xbyak::inner::IsInInt32(nextBlockOffset)) {
                gen.cmp(dword[contextPointer + nextBlockOffset], 0xcccccccc);
            } else {
                loadAddress(rax, nextBlockPointer);
                gen.cmp(dword[rax], 0xcccccccc);
            }

            const auto pointer = gen.getCurr<uint8_t*>();
            gen.jne((void*)m_returnFromBlock);    // Return if the block addr changed
            recompile(nextPC, false);  // Fallthrough to next block

            *(uint32_t*)(pointer - 4) = (uint32_t)(uintptr_t)*nextBlockPointer;  // Patch comparison value
        } else {  // If it has already been compiled, link by jumping to the compiled code
            if (Xbyak::inner::IsInInt32(nextBlockOffset)) {
                gen.cmp(dword[contextPointer + nextBlockOffset], (uint32_t)(uintptr_t)*nextBlockPointer);
            } else {
                loadAddress(rax, nextBlockPointer);
                gen.cmp(dword[rax], (uint32_t)(uintptr_t)*nextBlockPointer);
            }

            gen.jne((void*)m_returnFromBlock);  // Return if the block addr changed
            gen.jmp((void*)*nextBlockPointer);  // Jump to linked block otherwise
        }
    } else {  // Can't link, so return to dispatcher
        gen.jmp((void*)m_returnFromBlock);
    }
}

void DynaRecCPU::handleFastboot() {
    Xbyak::Label noFastBoot;

    loadAddress(rax, &m_shellStarted);  // Check if shell has already been reached
    gen.cmp(Xbyak::util::byte[rax], 0);
    gen.jnz(noFastBoot);  // Don't fastboot if so

    loadAddress(rax, &PCSX::g_emulator->settings.get<PCSX::Emulator::SettingFastBoot>());  // Check if fastboot is on
    gen.cmp(Xbyak::util::byte[rax], 0);
    gen.je(noFastBoot);

    loadThisPointer(arg1.cvt64());  // If fastbooting, call the signalShellReached function, set pc, and exit the block
    call(signalShellReached);
    gen.mov(eax, dword[contextPointer + GPR_OFFSET(31)]);
    gen.mov(dword[contextPointer + PC_OFFSET], eax);
    gen.jmp((void*)m_returnFromBlock);

    gen.L(noFastBoot);
}
#endif  // DYNAREC_X86_64
