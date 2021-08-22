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

#include <cassert>
#include "recompiler.h"
#include "regAllocation.h"

#if defined(DYNAREC_X86_64)

// Map the guest register corresponding to the index to a host register
// Used internally by the allocateReg functions
void DynaRecCPU::reserveReg(int index) {
    const auto regToAllocate = allocateableRegisters[m_allocatedRegisters];  // Fetch the next host reg to be allocated
    m_regs[index].allocatedReg = regToAllocate;
    m_regs[index].markUnknown(); // Mark the register's value as unknown if it were previously const propagated
    m_regs[index].allocated = true; // Mark register as allocated
    m_regs[index].allocatedRegIndex = m_allocatedRegisters;

    // If allocating a non-volatile that hasn't been allocated before, back it up in reg cache
    if (!IS_VOLATILE(m_allocatedRegisters) && !m_hostRegs[m_allocatedRegisters].restore) {
        gen.mov(qword[contextPointer + HOST_REG_CACHE_OFFSET(m_allocatedRegisters)], regToAllocate.cvt64());
        m_hostRegs[m_allocatedRegisters].restore = true;  // Mark this register as "To be restored"
    }

    gen.mov(regToAllocate, dword[contextPointer + GPR_OFFSET(index)]);  // Load reg
    m_hostRegs[m_allocatedRegisters].mappedReg = index;
    m_allocatedRegisters++;  // Advance our register allcoator
}

// Flush constants and allocated registers to host regs at the end of a block
void DynaRecCPU::flushRegs() {
    for (auto i = 1; i < 32; i++) {
        if (m_regs[i].isConst()) {  // If const: Write the value directly, mark as unknown
            gen.mov(dword[contextPointer + GPR_OFFSET(i)], m_regs[i].val);
            m_regs[i].markUnknown();
        }

        else if (m_regs[i].isAllocated()) {  // If it's been allocated to a register, unallocate
            m_regs[i].allocated = false;
            if (m_regs[i].writeback) {  // And if writeback was specified, write the value back
                gen.mov(dword[contextPointer + GPR_OFFSET(i)], m_regs[i].allocatedReg);
                m_regs[i].writeback = false;  // And turn writeback off
            }
        }
    }

    for (auto i = 0; i < ALLOCATEABLE_REG_COUNT; i++) {  // Unallocate all regs
        m_hostRegs[i].mappedReg = std::nullopt;
    }

    for (auto i = 0; i < ALLOCATEABLE_NON_VOLATILE_COUNT; i++) {  // Restore non volatiles
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
    gen.push(contextPointer);                       // Save context pointer register in stack
    gen.mov(contextPointer, (uint64_t)&m_psxRegs);  // Load context pointer
}

// Spill the volatile allocated registers into guest registers in preparation for a call to a C++ function
void DynaRecCPU::prepareForCall() {
    if (m_allocatedRegisters > ALLOCATEABLE_NON_VOLATILE_COUNT) {  // Check if there's any allocated volatiles to flush
        for (auto i = ALLOCATEABLE_NON_VOLATILE_COUNT; i < m_allocatedRegisters; i++) {  // iterate volatile regs
            if (m_hostRegs[i].mappedReg) {  // Unallocate and spill to guest regs as appropriate
                const auto previous = m_hostRegs[i].mappedReg.value();  // Get previously allocated register
                if (m_regs[previous].writeback) {                       // Spill to guest reg if writeback is enabled
                    gen.mov(dword[contextPointer + GPR_OFFSET(previous)], allocateableRegisters[i]);
                    m_regs[previous].writeback = false;
                }

                m_regs[previous].allocated = false;  // Unallocate it
                m_hostRegs[i].mappedReg = std::nullopt;
            }
        }

        // Since we just flushed all our volatiles, we can perform an optimization by making the allocator start
        // allocating from the first volatile again. This makes it so we have to flush less often, as we free up
        // regs every time we call a C++ function instead of letting them linger and go to waste.
        m_allocatedRegisters = ALLOCATEABLE_NON_VOLATILE_COUNT;
    }
}

// Used when our register cache overflows. Spill the entirety of it to host registers.
void DynaRecCPU::spillRegisterCache() {
    for (auto i = 0; i < m_allocatedRegisters; i++) {
        if (m_hostRegs[i].mappedReg) {  // Check if the register is still allocated to a guest register
            const auto previous = m_hostRegs[i].mappedReg.value();  // Get the reg it's allocated to

            if (m_regs[previous].writeback) {  // Spill to guest register if writeback is enabled and disable writeback
                gen.mov(dword[contextPointer + GPR_OFFSET(previous)], allocateableRegisters[i]);
                m_regs[previous].writeback = false;
            }

            m_hostRegs[i].mappedReg = std::nullopt;  // Unallocate it
            m_regs[previous].allocated = false;
        }
    }

    m_allocatedRegisters = 0;  // Nothing is allocated anymore
}

void DynaRecCPU::allocateReg(int reg) {
    if (!m_regs[reg].isAllocated()) {
        if (m_allocatedRegisters >= ALLOCATEABLE_REG_COUNT) {
            spillRegisterCache();
        }
        reserveReg(reg);
    }
}

void DynaRecCPU::allocateReg(int reg1, int reg2) {
start:
    if (reg1 == reg2) {
        if (!m_regs[reg1].isAllocated()) {
            if (m_allocatedRegisters >= ALLOCATEABLE_REG_COUNT) {
                spillRegisterCache();
            }
            reserveReg(reg1);
        }
    } else {
        if (!m_regs[reg1].isAllocated() && !m_regs[reg2].isAllocated()) {
            if (m_allocatedRegisters >= ALLOCATEABLE_REG_COUNT - 1) {
                spillRegisterCache();
                goto start;
            }

            reserveReg(reg1);
            reserveReg(reg2);
        }

        else if (!m_regs[reg1].isAllocated()) {
            if (m_allocatedRegisters >= ALLOCATEABLE_REG_COUNT) {
                spillRegisterCache();
                goto start;
            }

            reserveReg(reg1);
        }

        else if (!m_regs[reg2].isAllocated()) {
            if (m_allocatedRegisters >= ALLOCATEABLE_REG_COUNT) {
                spillRegisterCache();
                goto start;
            }

            reserveReg(reg2);
        }
    }
}

void DynaRecCPU::allocateReg(int reg1, int reg2, int reg3) {
start:
    if (reg1 == reg2 && reg1 == reg3) {  // All 3 regs are the same
        if (!m_regs[reg1].isAllocated()) {
            if (m_allocatedRegisters >= ALLOCATEABLE_REG_COUNT) {
                spillRegisterCache();
            }

            reserveReg(reg1);
        }
    }

    else if (reg1 == reg2) {  // Reg1 and 2 are the same, 3 is different
        if (!m_regs[reg1].isAllocated() && !m_regs[reg3].isAllocated()) {
            if (m_allocatedRegisters >= ALLOCATEABLE_REG_COUNT - 1) {
                spillRegisterCache();
                goto start;
            }

            reserveReg(reg1);
            reserveReg(reg3);
        }

        else if (!m_regs[reg1].isAllocated()) {
            if (m_allocatedRegisters >= ALLOCATEABLE_REG_COUNT) {
                spillRegisterCache();
                goto start;
            }

            reserveReg(reg1);
        }

        else if (!m_regs[reg3].isAllocated()) {
            if (m_allocatedRegisters >= ALLOCATEABLE_REG_COUNT) {
                spillRegisterCache();
                goto start;
            }

            reserveReg(reg3);
        }
    }

    else if (reg1 == reg3) {  // Reg1 and 3 are the same, 2 is different
        if (!m_regs[reg1].isAllocated() && !m_regs[reg2].isAllocated()) {
            if (m_allocatedRegisters >= ALLOCATEABLE_REG_COUNT - 1) {
                spillRegisterCache();
                goto start;
            }

            reserveReg(reg1);
            reserveReg(reg2);
        }

        else if (!m_regs[reg1].isAllocated()) {
            if (m_allocatedRegisters >= ALLOCATEABLE_REG_COUNT) {
                spillRegisterCache();
                goto start;
            }

            reserveReg(reg1);
        }

        else if (!m_regs[reg2].isAllocated()) {
            if (m_allocatedRegisters >= ALLOCATEABLE_REG_COUNT) {
                spillRegisterCache();
                goto start;
            }

            reserveReg(reg2);
        }
    }

    else if (reg2 == reg3) {  // Reg2 and 3 are the same, 1 is different
        if (!m_regs[reg1].isAllocated() && !m_regs[reg2].isAllocated()) {
            if (m_allocatedRegisters >= ALLOCATEABLE_REG_COUNT - 1) {
                spillRegisterCache();
                goto start;
            }

            reserveReg(reg1);
            reserveReg(reg2);
        }

        else if (!m_regs[reg1].isAllocated()) {
            if (m_allocatedRegisters >= ALLOCATEABLE_REG_COUNT) {
                spillRegisterCache();
                goto start;
            }

            reserveReg(reg1);
        }

        else if (!m_regs[reg2].isAllocated()) {
            if (m_allocatedRegisters >= ALLOCATEABLE_REG_COUNT) {
                spillRegisterCache();
                goto start;
            }

            reserveReg(reg2);
        }
    }

    else {  // All regs are different
        if (!m_regs[reg1].isAllocated() && !m_regs[reg2].isAllocated() && !m_regs[reg3].isAllocated()) {
            if (m_allocatedRegisters >= ALLOCATEABLE_REG_COUNT - 2) {
                spillRegisterCache();
                goto start;
            }

            reserveReg(reg1);
            reserveReg(reg2);
            reserveReg(reg3);
        }

        else if (!m_regs[reg1].isAllocated() && !m_regs[reg2].isAllocated()) {
            if (m_allocatedRegisters >= ALLOCATEABLE_REG_COUNT - 1) {
                spillRegisterCache();
                goto start;
            }

            reserveReg(reg1);
            reserveReg(reg2);
        }

        else if (!m_regs[reg1].isAllocated() && !m_regs[reg3].isAllocated()) {
            if (m_allocatedRegisters >= ALLOCATEABLE_REG_COUNT - 1) {
                spillRegisterCache();
                goto start;
            }

            reserveReg(reg1);
            reserveReg(reg3);
        }

        else if (!m_regs[reg2].isAllocated() && !m_regs[reg3].isAllocated()) {
            if (m_allocatedRegisters >= ALLOCATEABLE_REG_COUNT - 1) {
                spillRegisterCache();
                goto start;
            }

            reserveReg(reg2);
            reserveReg(reg3);
        }

        else if (!m_regs[reg1].isAllocated()) {
            if (m_allocatedRegisters >= ALLOCATEABLE_REG_COUNT) {
                spillRegisterCache();
                goto start;
            }

            reserveReg(reg1);
        }

        else if (!m_regs[reg2].isAllocated()) {
            if (m_allocatedRegisters >= ALLOCATEABLE_REG_COUNT) {
                spillRegisterCache();
                goto start;
            }

            reserveReg(reg2);
        }

        else if (!m_regs[reg3].isAllocated()) {
            if (m_allocatedRegisters >= ALLOCATEABLE_REG_COUNT) {
                spillRegisterCache();
                goto start;
            }

            reserveReg(reg3);
        }
    }
}

#endif  // DYNAREC_X86_64
