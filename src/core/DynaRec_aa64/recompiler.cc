/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
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

#if defined(DYNAREC_AA64)

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

    gen.Reset();  // Reset code generator

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

#if !defined(__APPLE__)
    if (!gen.setRWX()) {  // Mark code cache as readable/writeable/executable
        PCSX::g_system->message("[Dynarec] Failed to allocate executable memory.\nTry disabling the Dynarec CPU.");
        return false;
    }
#endif
#if defined(__APPLE__)
    gen.setRW();  // M1 wants buffer marked as readable/writable with mprotect before emitting code
#endif
    emitDispatcher();  // Emit our assembly dispatcher
    uncompileAll();    // Mark all blocks as uncompiled

    for (int i = 0; i < 0x10000 / 4; i++) {  // Mark all dummy blocks as invalid
        m_dummyBlocks[i] = m_invalidBlock;
    }

    m_gprs[0].markConst(0);  // $zero is always zero

#if defined(__APPLE__)
    // Check to make sure code buffer memory was allocated
    if (gen.getCode<void*>() == nullptr) {
        PCSX::g_system->message("[Dynarec] Failed to allocate memory for Dynarec.\nTry disabling the Dynarec CPU.");
        return false;
    }
    gen.setRX();  // Mark code cache as readable/executable before jumping into dispatcher
#endif
    return true;
}

void DynaRecCPU::Reset() {
    R3000Acpu::Reset();  // Reset CPU registers
    Shutdown();          // Deinit and re-init dynarec
    Init();
}

void DynaRecCPU::Shutdown() {
    delete[] m_recompilerLUT;
    delete[] m_ramBlocks;
    delete[] m_biosBlocks;
    delete[] m_dummyBlocks;

    gen.dumpBuffer();  // dump buffer on shutdown/hard-reset for diagnostics
}

/// Params: A program counter value
/// Returns: A pointer to the host aa64 code that points to the block that starts from the given PC
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
    PCSX::g_system->pause();
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
    gen.Reset();       // Reset the emitter's code pointer and code size variables
    emitDispatcher();  // Re-emit dispatcher
    uncompileAll();    // Mark all blocks as uncompiled
}

void DynaRecCPU::emitBlockLookup() {
    gen.Ldr(w4, MemOperand(contextPointer, PC_OFFSET));  // w4 = pc
    // w3 = index into the recompiler LUT page. Calculated like ((pc >> 2) & 0x3fff)
    gen.Ubfx(w3, w4, 2, 14);
    gen.Lsr(w4, w4, 16);  // w4 = pc >> 16

    // Load base pointer to recompiler LUT page in x0
    gen.Mov(x0, (uintptr_t)m_recompilerLUT);
    gen.Ldr(x0, MemOperand(x0, x4, LSL, 3));

    // Load pointer to block in x5 and jump to it
    gen.Ldr(x5, MemOperand(x0, x3, LSL, 3));
    gen.Br(x5);
}

void DynaRecCPU::emitDispatcher() {
    Label done;
    gen.align();
    m_dispatcher = gen.getCurr<DynarecCallback>();

    gen.Str(x30, MemOperand(sp, -16, PreIndex));             // Backup link register
    gen.Str(runningPointer, MemOperand(sp, -16, PreIndex));  // Save runningPointer register in stack
    gen.Str(contextPointer,
            MemOperand(sp, -16, PreIndex));  // Save contextPointer register in stack (also align stack pointer)

    gen.Mov(runningPointer, (uintptr_t)PCSX::g_system->runningPtr());  // Move runningPtr to runningPointer register
    gen.Mov(contextPointer, (uintptr_t)this);                          // Load context pointer

    // Back up all our allocateable volatile regs
    static_assert((ALLOCATEABLE_NON_VOLATILE_COUNT & 1) == 0);  // Make sure we've got an even number of regs
    for (auto i = 0; i < ALLOCATEABLE_NON_VOLATILE_COUNT; i += 2) {
        const auto reg = allocateableNonVolatiles[i];
        const auto reg2 = allocateableNonVolatiles[i + 1];
        gen.Stp(reg2.X(), reg.X(), MemOperand(sp, -16, PreIndex));
    }

    emitBlockLookup();  // Look up block

    // Code to be executed after each block.
    gen.align();
    m_returnFromBlock = gen.getCurr<DynarecCallback>();

    loadThisPointer(arg1.X());  // Poll events
    call(recBranchTestWrapper);
    gen.Ldrb(w0, MemOperand(runningPointer));  // Check if PCSX::g_system->running is true
    gen.Cbz(w0, &done);                        // If it's not, return
    emitBlockLookup();                         // Otherwise, look up next block

    gen.align();

    // Code for exiting JIT context
    gen.L(done);

    // Restore all non-volatiles
    for (int i = ALLOCATEABLE_NON_VOLATILE_COUNT - 1; i >= 0; i -= 2) {
        const auto reg = allocateableNonVolatiles[i];
        const auto reg2 = allocateableNonVolatiles[i - 1];
        gen.Ldp(reg.X(), reg2.X(), MemOperand(sp, 16, PostIndex));
    }

    gen.Ldr(contextPointer, MemOperand(sp, 16, PostIndex));  // Restore contextPointer register from stack
    gen.Ldr(runningPointer, MemOperand(sp, 16, PostIndex));  // Restore runningPointer register from stack
    gen.Ldr(x30, MemOperand(sp, 16, PostIndex));             // Restore link register before returning
    gen.Ret();

    // Code for when the block to be executed needs to be compiled.
    // x0 = Base pointer to the page of m_recompilerLUT we're executing from
    // x3 = Index into the page
    // Doing x0 + (x3 << 3) gets us the pointer to where the block callback should be stored
    gen.align();
    m_uncompiledBlock = gen.getCurr<DynarecCallback>();

    // Do arg2 = x0 + (x3 << 3). Now arg2 points to the address we'll store the block callback to.
    gen.Add(arg2.X(), x0, Operand(x3, LSL, 3));
    loadThisPointer(arg1.X());
    call(recRecompileWrapper);
    gen.Br(x0);  // Jump to compiled block

    // Code for when the block we've jumped to is invalid. Throws an error and exits
    gen.align();
    m_invalidBlock = gen.getCurr<DynarecCallback>();

    loadThisPointer(arg1.X());  // Throw recompiler error
    call(recErrorWrapper);
    gen.B(&done);  // Exit
    gen.ready();   // Ready code buffer before emulator jumps into dispatcher for the first time
}

// Compile a block, write address of compiled code to *callback
// Returns the address of the compiled block
DynarecCallback DynaRecCPU::recompile(DynarecCallback* callback, uint32_t pc, bool align) {
    m_stopCompiling = false;
    m_inDelaySlot = false;
    m_nextIsDelaySlot = false;
    m_delayedLoadInfo[0].active = false;
    m_delayedLoadInfo[1].active = false;
    m_pcWrittenBack = false;
    m_linkedPC = std::nullopt;
    m_pc = pc & ~3;

    const auto startingPC = m_pc;
    int count = 0;  // How many instructions have we compiled?

#if defined(__APPLE__)
    gen.setRW();  // Mark code cache as readable/writeable before emitting code
#endif

    if (align) {
        gen.align();  // Align next block
    }

    if (gen.getSize() > codeCacheSize) {  // Flush JIT cache if we've gone above the acceptable size
        flushCache();
    }

    const auto blockStart = gen.getCurr<DynarecCallback>();
    *callback = blockStart;
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

        uint32_t* p = PCSX::g_emulator->m_mem->getPointer<uint32_t>(m_pc);
        if (p == nullptr) {  // Error if it can't be fetched
            return m_invalidBlock;
        }

        uint32_t code = m_regs.code = *p;  // Actually read the instruction
        m_pc += 4;                         // Increment recompiler PC
        count++;                           // Increment instruction count

        const auto func = m_recBSC[code >> 26];  // Look up the opcode in our decoding LUT
        (*this.*func)(code);                     // Jump into the handler to recompile it
    }

    flushRegs();
    if (!m_pcWrittenBack) {  // Write PC back if needed
        gen.Mov(w0, m_pc);
        gen.Str(w0, MemOperand(contextPointer, PC_OFFSET));
    }

    // If this was the block at 0x8003'0000 (Start of shell), don't link the PC in case we fastboot
    if (startingPC == 0x80030000) {
        m_linkedPC = std::nullopt;
    }

    gen.Ldr(x0, MemOperand(contextPointer, CYCLE_OFFSET));  // Fetch cycle count from memory
    gen.Add(x0, x0, count * PCSX::Emulator::BIAS);          // Add block cycles
    gen.Str(x0, MemOperand(contextPointer, CYCLE_OFFSET));  // Store cycles back to memory

    // Link block else return to dispatcher
    if (m_linkedPC && ENABLE_BLOCK_LINKING && m_linkedPC.value() != startingPC) {
        handleLinking();
    } else {
        jmp((void*)m_returnFromBlock);
    }

    // Clear stale instruction cache contents.
    __builtin___clear_cache(reinterpret_cast<char*>(blockStart), gen.getCurr<char*>());
    gen.ready();
#if defined(__APPLE__)
    gen.setRX();  // Mark code cache as readable/executable before returning to dispatcher
#endif
    // The block might have been invalidated by handleLinking, so re-read the pointer from *callback
    return *callback;
}

// Checks if the block being compiled is one of the kernel call vectors
// If so, emit a call to "InterceptBIOS", which handles the kernel call debugger features
// Also handles fast booting by intercepting the shell reached signal and setting pc to $ra if fastboot is on
void DynaRecCPU::handleKernelCall() {
    if (m_pc == 0x80030000) {
        handleShellReached();
        return;
    }

    const uint32_t pc = m_pc & 0x1fffff;
    const uint32_t base = (m_pc >> 20) & 0xffc;
    if ((base != 0x000) && (base != 0x800) && (base != 0xa00))
        return;  // Mask out the segment, return if not a kernel call vector

    switch (pc) {  // Handle the A0/B0/C0 vectors
        case 0xA0:
            loadThisPointer(arg1.X());
            call(interceptKernelCallWrapper<0xA0>);
            break;

        case 0xB0:
            loadThisPointer(arg1.X());
            call(interceptKernelCallWrapper<0xB0>);
            break;

        case 0xC0:
            loadThisPointer(arg1.X());
            call(interceptKernelCallWrapper<0xC0>);
            break;
    }
}

// Emits a jump to the dispatcher if there's no block to link to.
// Otherwise, handle linking blocks
void DynaRecCPU::handleLinking() {
    vixl::aarch64::Label returnFromBlock;
    // Don't link unless the next PC is valid, and there's over 1MB of free space in the code cache
    if (isPcValid(m_linkedPC.value()) && gen.getRemainingSize() > 0x100000) {
        const auto nextPC = m_linkedPC.value();
        const auto nextBlockPointer = getBlockPointer(nextPC);
        const auto nextBlockOffset = (size_t)nextBlockPointer - (size_t)this;

        if (*nextBlockPointer == m_uncompiledBlock) {  // If the next block hasn't been compiled yet
            // Check that the block hasn't been invalidated/moved
            // The value will be patched later. Since all code is within the same 32MB segment,
            // We can get away with only checking the low 32 bits of the block pointer
            gen.Mov(x0, (uintptr_t)nextBlockPointer);
            gen.Ldr(x0, MemOperand(x0));
            // Move value to compare against into w1
            gen.Mov(w1, 0xcccccccc);
            gen.Cmp(w0, w1);

            const auto pointer = gen.getCurr<uint8_t*>();
            gen.bne(returnFromBlock);  // Return if the block addr changed

            recompile(nextBlockPointer, nextPC, false);  // Fallthrough to next block

            *(uint32_t*)(pointer - 4) = (uint32_t)(uintptr_t)*nextBlockPointer;  // Patch comparison value
        } else {  // If it has already been compiled, link by jumping to the compiled code
            gen.Mov(x0, (uintptr_t)nextBlockPointer);
            gen.Ldr(x0, MemOperand(x0));
            // Move value to compare against into w1
            gen.Mov(w1, (uint32_t)(uintptr_t)*nextBlockPointer);
            gen.Cmp(w0, w1);

            gen.bne(returnFromBlock);       // Return if the block addr changed
            jmp((void*)*nextBlockPointer);  // Jump to linked block otherwise

            gen.L(returnFromBlock);
            jmp((void*)m_returnFromBlock);
        }
    } else {  // Can't link, so return to dispatcher
        jmp((void*)m_returnFromBlock);
    }
}

void DynaRecCPU::handleShellReached() {
    Label alreadyReached;

    gen.Mov(x0, (uintptr_t)&m_shellStarted);  // Check if shell has already been reached
    gen.Ldrb(w0, MemOperand(x0));
    gen.Cbnz(w0, &alreadyReached);  // Skip signalling that we've reached the shell if so

    loadThisPointer(arg1.X());  // Signal that we've reached the shell
    call(signalShellReached);
    jmp((void*)m_returnFromBlock);

    gen.L(alreadyReached);
}

std::unique_ptr<PCSX::R3000Acpu> PCSX::Cpus::getDynaRec() { return std::unique_ptr<PCSX::R3000Acpu>(new DynaRecCPU()); }

#endif  // DYNAREC_AA64
