#include <cassert>
#include <cstddef>
#include "recompiler.h"
#include "regAllocation.h"

#if defined(DYNAREC_X86_64)

void DynaRecCPU::reserveReg(int index) {
    static_assert(ALLOCATEABLE_REG_COUNT == 8);

    const auto regToAllocate = allocateableRegisters[m_allocatedRegisters]; // Fetch the next host reg to be allocated
    m_registers[index].markUnknown(); // If the reg was constant before, mark it as unknown
    m_registers[index].allocatedReg = regToAllocate;
    m_registers[index].isAllocated = true;

    // If the register was already allocated previously with writeback flush old value and unallocate it
    if (m_hostRegMappings[m_allocatedRegisters]) {
        const auto previousReg = m_hostRegMappings[m_allocatedRegisters].value(); // The guest register this was previously allocated to
        if (m_registers[previousReg].writeback) {
            gen.mov(dword[contextPointer + GPR_OFFSET(previousReg)], regToAllocate);
            m_registers[previousReg].writeback = false;
        }

        m_registers[previousReg].isAllocated = false;  // rip, you're no longer allocated
    }

    // Check if the newly allocated register is non-volatile and back it up. Don't back it up if it was already allocated before
    else if (!IS_VOLATILE(m_allocatedRegisters)) {
        gen.mov(qword[contextPointer + HOST_REG_CACHE_OFFSET(m_allocatedRegisters)],
                regToAllocate.cvt64());
    }
    
    gen.mov(regToAllocate, dword[contextPointer + GPR_OFFSET(index)]); // Load reg

    m_hostRegMappings[m_allocatedRegisters] = index;
    m_allocatedRegisters = (m_allocatedRegisters + 1) & 7; // Advance our register ring buffer
}

void DynaRecCPU::flushRegs() {
    for (auto i = 1; i < 32; i++) {
        if (m_registers[i].isConst()) { // If const: Write the value directly, mark as unknown
            gen.mov(dword[contextPointer + GPR_OFFSET(i)], m_registers[i].val);
            m_registers[i].markUnknown();
        }

        else if (m_registers[i].isAllocated) { // If it's been allocated to a register, unallocate
            m_registers[i].isAllocated = false;
            if (m_registers[i].writeback) { // And if writeback was specified, write the value back
                gen.mov(dword[contextPointer + GPR_OFFSET(i)], m_registers[i].allocatedReg);
                m_registers[i].writeback = false; // And turn writeback off
            }
        }
    }

    for (auto i = 0; i < ALLOCATEABLE_REG_COUNT; i++) {  // Restore our non volatiles
        if (m_hostRegMappings[i]) {
            m_hostRegMappings[i] = std::nullopt; // Unallocate host registers
            if (!IS_VOLATILE(i)) {                // Restore allocated non-volatile regs
                gen.mov(allocateableRegisters[i].cvt64(), qword[contextPointer + HOST_REG_CACHE_OFFSET(i)]);
            }
        }
    }
}

void DynaRecCPU::loadContext() { 
    gen.mov(rbp, (uint64_t) &m_psxRegs); 
}

void DynaRecCPU::allocateReg(int reg) {
    if (!m_registers[reg].isAllocated) {
        reserveReg(reg);
    }
}

void DynaRecCPU::allocateReg(int reg1, int reg2) {
    if (reg1 == reg2) {
        if (!m_registers[reg1].isAllocated) {
            reserveReg(reg1);
        }
    } else {
        if (!m_registers[reg1].isAllocated) {
            reserveReg(reg1);
        }

        if (!m_registers[reg2].isAllocated) {
            reserveReg(reg2);
        }
    }
}

void DynaRecCPU::allocateReg(int reg1, int reg2, int reg3) {
    if (reg1 == reg2 && reg1 == reg3) { // All 3 regs are the same
        if (!m_registers[reg1].isAllocated) {
            reserveReg(reg1);
        }
    }

    else if (reg1 == reg2) { // Reg1 and 2 are the same, 3 is different
        if (!m_registers[reg1].isAllocated) {
            reserveReg(reg1);
        }

        if (!m_registers[reg3].isAllocated) {
            reserveReg(reg3);
        }
    }

    else if (reg1 == reg3) { // Reg1 and 3 are the same, 2 is different
        if (!m_registers[reg1].isAllocated) {
            reserveReg(reg1);
        }

        if (!m_registers[reg2].isAllocated) {
            reserveReg(reg2);
        }
    }

    else if (reg2 == reg3) { // Reg2 and 3 are the same, 1 is different
        if (!m_registers[reg1].isAllocated) {
            reserveReg(reg1);
        }

        if (!m_registers[reg2].isAllocated) {
            reserveReg(reg2);
        }
    }

    else { // All regs are different
        if (!m_registers[reg1].isAllocated) {
            reserveReg(reg1);
        }

        if (!m_registers[reg2].isAllocated) {
            reserveReg(reg2);
        }

        if (!m_registers[reg3].isAllocated) {
            reserveReg(reg3);
        }
    }
}

#endif // DYNAREC_X86_64
