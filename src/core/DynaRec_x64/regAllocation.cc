#include <cassert>
#include "recompiler.h"
#include "regAllocation.h"

#if defined(DYNAREC_X86_64)

// Map the guest register corresponding to the index to a host register
// Used internally by the allocateReg functions
void DynaRecCPU::reserveReg(int index) {
    static_assert(ALLOCATEABLE_REG_COUNT == 8);

    const auto regToAllocate = allocateableRegisters[m_allocatedRegisters]; // Fetch the next host reg to be allocated
    m_regs[index].markUnknown(); // If the reg was constant before, mark it as unknown
    m_regs[index].allocatedReg = regToAllocate;
    m_regs[index].allocated = true;

    // If the register was already allocated previously with writeback flush old value and unallocate it
    if (m_hostRegs[m_allocatedRegisters].mappedReg) {
        const auto previousReg = m_hostRegs[m_allocatedRegisters].mappedReg.value(); // The guest register this was previously allocated to
        if (m_regs[previousReg].writeback) {
            gen.mov(dword[contextPointer + GPR_OFFSET(previousReg)], regToAllocate);
            m_regs[previousReg].writeback = false;
        }

        m_regs[previousReg].allocated = false;  // rip, you're no longer allocated
    }

    // Check if the newly allocated register is non-volatile and back it up. Don't back it up if it was already allocated before
    else if (!IS_VOLATILE(m_allocatedRegisters) && !m_hostRegs[m_allocatedRegisters].restore) {
        gen.mov(qword[contextPointer + HOST_REG_CACHE_OFFSET(m_allocatedRegisters)],
                regToAllocate.cvt64());
        m_hostRegs[m_allocatedRegisters].restore = true; // Mark this register as "To be restored"
    }
    
    gen.mov(regToAllocate, dword[contextPointer + GPR_OFFSET(index)]); // Load reg
    m_hostRegs[m_allocatedRegisters].mappedReg = index;
    m_allocatedRegisters++; // Advance our register allcoator
}

// Flush constants and allocated registers to host regs at the end of a block
void DynaRecCPU::flushRegs() {
    for (auto i = 1; i < 32; i++) {
        if (m_regs[i].isConst()) { // If const: Write the value directly, mark as unknown
            gen.mov(dword[contextPointer + GPR_OFFSET(i)], m_regs[i].val);
            m_regs[i].markUnknown();
        }

        else if (m_regs[i].isAllocated()) { // If it's been allocated to a register, unallocate
            m_regs[i].allocated = false;
            if (m_regs[i].writeback) { // And if writeback was specified, write the value back
                gen.mov(dword[contextPointer + GPR_OFFSET(i)], m_regs[i].allocatedReg);
                m_regs[i].writeback = false; // And turn writeback off
            }
        }
    }

    for (auto i = 0; i < ALLOCATEABLE_REG_COUNT; i++) {  // Unallocate all regs
        m_hostRegs[i].mappedReg = std::nullopt;
    }

    for (auto i = 0; i < ALLOCATEABLE_NON_VOLATILE_COUNT; i++) { // Restore non volatiles
        if (m_hostRegs[i].restore) {
            gen.mov(allocateableRegisters[i].cvt64(), qword[contextPointer + HOST_REG_CACHE_OFFSET(i)]);
            m_hostRegs[i].restore = false;
        }
    }

    m_allocatedRegisters = 0;
}

// Save the contextPointer register to the stack (aligning the stack at the same time)
// And actually load the pointer to our context into it
void DynaRecCPU::loadContext() { 
    gen.push(contextPointer); // Save context pointer register in stack
    gen.mov(contextPointer, (uint64_t) &m_psxRegs); // Load context pointer
}

// Spill the volatile allocated registers into guest registers in preparation for a call to a C++ function
void DynaRecCPU::prepareForCall() {
    m_needsStackFrame = true;
    for (auto i = ALLOCATEABLE_NON_VOLATILE_COUNT; i < ALLOCATEABLE_REG_COUNT; i++) { // iterate volatile regs
        if (m_hostRegs[i].mappedReg) { // Unallocate and spill to guest regs as appropriate
            const auto previous = m_hostRegs[i].mappedReg.value(); // Get previously allocated register
            if (m_regs[previous].writeback) { // Spill to guest reg if writeback is enabled
                gen.mov(dword[contextPointer + GPR_OFFSET(previous)], allocateableRegisters[i]);
            }
            
            m_regs[previous].unallocate();  // Unallocate it
            m_hostRegs[i].mappedReg = std::nullopt;
        }
    }
}

// Used when our register cache overflows. Spill the entirety of it to host registers.
void DynaRecCPU::spillRegisterCache() {
    for (auto i = 0; i < ALLOCATEABLE_REG_COUNT; i++) {
        if (m_hostRegs[i].mappedReg) { // Check if the register is still allocated to a guest register
            const auto previous = m_hostRegs[i].mappedReg.value(); // Get the reg it's allocated to
            if (m_regs[previous].writeback) { // Spill to guest register if writeback is enabled and disable writeback
                gen.mov(dword[contextPointer + GPR_OFFSET(previous)], allocateableRegisters[i]); 
                m_regs[previous].writeback = false;
            }

            m_hostRegs[i].mappedReg = std::nullopt;  // Unallocate it
            m_regs[previous].allocated = false;
        }
    }

    m_allocatedRegisters = 0; // Nothing is allocated anymore
}

void DynaRecCPU::allocateReg(int reg) {
    if (!m_regs[reg].isAllocated()) {
        if (m_allocatedRegisters == ALLOCATEABLE_REG_COUNT) {
            spillRegisterCache();
        }
        reserveReg(reg);
    }
}

void DynaRecCPU::allocateReg(int reg1, int reg2) {
    if (reg1 == reg2) {
        if (!m_regs[reg1].isAllocated()) {
            if (m_allocatedRegisters == ALLOCATEABLE_REG_COUNT) {
                spillRegisterCache();
            }
            reserveReg(reg1);
        }
    } else {
        if (m_allocatedRegisters == ALLOCATEABLE_REG_COUNT - 1) { spillRegisterCache(); }

        if (!m_regs[reg1].isAllocated()) {
            reserveReg(reg1);
        }

        if (!m_regs[reg2].isAllocated()) {
            reserveReg(reg2);
        }
    }
}

void DynaRecCPU::allocateReg(int reg1, int reg2, int reg3) {
    if (reg1 == reg2 && reg1 == reg3) { // All 3 regs are the same
        if (m_allocatedRegisters == ALLOCATEABLE_REG_COUNT) {
            spillRegisterCache();
        }
        if (!m_regs[reg1].isAllocated()) {
            reserveReg(reg1);
        }
    }

    else if (reg1 == reg2) { // Reg1 and 2 are the same, 3 is different
        if (m_allocatedRegisters == ALLOCATEABLE_REG_COUNT - 1) {
            spillRegisterCache();
        }
        if (!m_regs[reg1].isAllocated()) {
            reserveReg(reg1);
        }

        if (!m_regs[reg3].isAllocated()) {
            reserveReg(reg3);
        }
    }

    else if (reg1 == reg3) { // Reg1 and 3 are the same, 2 is different
        if (m_allocatedRegisters == ALLOCATEABLE_REG_COUNT - 1) {
            spillRegisterCache();
        }
        if (!m_regs[reg1].isAllocated()) {
            reserveReg(reg1);
        }

        if (!m_regs[reg2].isAllocated()) {
            reserveReg(reg2);
        }
    }

    else if (reg2 == reg3) { // Reg2 and 3 are the same, 1 is different
        if (m_allocatedRegisters == ALLOCATEABLE_REG_COUNT - 1) {
            spillRegisterCache();
        }
        if (!m_regs[reg1].isAllocated()) {
            reserveReg(reg1);
        }

        if (!m_regs[reg2].isAllocated()) {
            reserveReg(reg2);
        }
    }

    else { // All regs are different
        if (m_allocatedRegisters == ALLOCATEABLE_REG_COUNT - 2) {
            spillRegisterCache();
        }
        if (!m_regs[reg1].isAllocated()) {
            reserveReg(reg1);
        }

        if (!m_regs[reg2].isAllocated()) {
            reserveReg(reg2);
        }

        if (!m_regs[reg3].isAllocated()) {
            reserveReg(reg3);
        }
    }
}

#endif // DYNAREC_X86_64
