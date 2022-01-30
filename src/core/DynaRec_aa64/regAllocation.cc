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

#include "regAllocation.h"
#include <cassert>
#include "recompiler.h"
#if defined(DYNAREC_AA64)

// Map the guest register corresponding to the index to a host register
// Used internally by the allocateReg functions. Don't use it directly
template <DynaRecCPU::LoadingMode mode>
void DynaRecCPU::reserveReg(int index) {
    const auto regToAllocate = allocateableRegisters[m_allocatedRegisters];  // Fetch the next host reg to be allocated
    m_regs[index].allocatedReg = regToAllocate;
    m_regs[index].markUnknown();     // Mark the register's value as unknown if it were previously const propagated
    m_regs[index].allocated = true;  // Mark register as allocated
    m_regs[index].allocatedRegIndex = m_allocatedRegisters;

    // For certain instructions like loads, we don't want to load the reg because it'll get instantly overwritten
    if constexpr (mode == LoadingMode::Load) {
        gen.Ldr(regToAllocate, MemOperand(contextPointer, GPR_OFFSET(index)));  // Load reg
    }
    m_hostRegs[m_allocatedRegisters].mappedReg = index;
    m_allocatedRegisters++;  // Advance our register allcoator
}

// Flush constants and allocated registers to host regs at the end of a block
void DynaRecCPU::flushRegs() {
    for (auto i = 1; i < 32; i++) {
        if (m_regs[i].isConst()) {  // If const: Write the value directly, mark as unknown. Possibly change when constants will be stored in host regs
            if (m_regs[i].val != 0) {
                gen.Mov(w4, m_regs[i].val);
                gen.Str(w4, MemOperand(contextPointer, GPR_OFFSET(i)));
            } else {
                gen.Str(wzr, MemOperand(contextPointer, GPR_OFFSET(i)));
            }

            m_regs[i].markUnknown();
        }

        else if (m_regs[i].isAllocated()) {  // If it's been allocated to a register, unallocate
            m_regs[i].allocated = false;
            if (m_regs[i].writeback) {  // And if writeback was specified, write the value back
                gen.Str(m_regs[i].allocatedReg, MemOperand(contextPointer, GPR_OFFSET(i)));
                m_regs[i].writeback = false;  // And turn writeback off
            }
        }
    }

    for (auto i = 0; i < ALLOCATEABLE_REG_COUNT; i++) {  // Unallocate all regs
        m_hostRegs[i].mappedReg = std::nullopt;
    }

    m_allocatedRegisters = 0;
}

// Spill the volatile allocated registers into guest registers in preparation for a call to a C++ function
void DynaRecCPU::prepareForCall() {
    if (m_allocatedRegisters > ALLOCATEABLE_NON_VOLATILE_COUNT) {  // Check if there's any allocated volatiles to flush
        for (auto i = ALLOCATEABLE_NON_VOLATILE_COUNT; i < m_allocatedRegisters; i++) {  // iterate volatile regs
            if (m_hostRegs[i].mappedReg) {  // Unallocate and spill to guest regs as appropriate
                const auto previous = m_hostRegs[i].mappedReg.value();  // Get previously allocated register
                if (m_regs[previous].writeback) {                       // Spill to guest reg if writeback is enabled
                    // TODO: Possibly optimize with Store pair
                    gen.Str(allocateableRegisters[i], MemOperand(contextPointer, GPR_OFFSET(previous)));
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
                // TODO: Possibly optimize with Store pair
                gen.Str(allocateableRegisters[i], MemOperand(contextPointer, GPR_OFFSET(previous)));
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
        reserveReg<LoadingMode::Load>(reg);
    }
}

void DynaRecCPU::allocateRegWithoutLoad(int reg) {
    if (!m_regs[reg].isAllocated()) {
        if (m_allocatedRegisters >= ALLOCATEABLE_REG_COUNT) {
            spillRegisterCache();
        }
        reserveReg<LoadingMode::DoNotLoad>(reg);
    }
}

// T: Number of regs without writeback we must allocate
// U: Number of regs with writeback we must allocate
// We want both of them to be compile-time constants for efficiency
template <int T, int U>
void DynaRecCPU::allocateRegisters(std::array<int, T> regsWithoutWb, std::array<int, U> regsWithWb) {
    static_assert(T + U < ALLOCATEABLE_REG_COUNT, "Trying to allocate too many registers");

start:
    // Which specific regs we need to load
    uint32_t regsToLoad = 0;
    // Which specific regs we need to allocate without loading, with writeback
    uint32_t regsToWriteback = 0;
    // How many registers we need to load
    int regsToAllocateCount = 0;

    for (int i = 0; i < T; i++) {
        const auto reg = regsWithoutWb[i];
        if (!m_regs[reg].allocated && (regsToLoad & (1 << reg)) == 0) {
            regsToLoad |= 1 << reg;
            regsToAllocateCount++;
        }
    }

    for (int i = 0; i < U; i++) {
        const auto reg = regsWithWb[i];
        if (!m_regs[reg].allocated && (regsToWriteback & (1 << reg)) == 0 && (regsToLoad & (1 << reg)) == 0) {
            regsToWriteback |= 1 << reg;
            regsToAllocateCount++;
        }
    }

    if (regsToAllocateCount != 0) {
        // Flush register cache if we're going to overflow it and restart alloc process
        if (m_allocatedRegisters + regsToAllocateCount >= ALLOCATEABLE_REG_COUNT) {
            flushRegs();
            goto start;
        }

        // Check which registers we need to load
        for (int i = 0; i < T; i++) {
            const auto reg = regsWithoutWb[i];
            if ((regsToLoad & (1 << reg)) != 0 && !m_regs[reg].allocated) {
                reserveReg<LoadingMode::Load>(reg);
            }
        }
    }

    // Specify writeback for whatever regs we need to
    for (int i = 0; i < U; i++) {
        const auto reg = regsWithWb[i];
        if (!m_regs[reg].allocated) {
            reserveReg<LoadingMode::DoNotLoad>(reg);
        }
        m_regs[reg].writeback = true;
    }
}

void DynaRecCPU::alloc_rt_rs() { allocateRegisters<2, 0>({(int) _Rt_, (int)_Rs_}, {}); }

void DynaRecCPU::alloc_rt_wb_rd() { allocateRegisters<1, 1>({(int)_Rt_}, {(int)_Rd_}); }

void DynaRecCPU::alloc_rs_wb_rd() { allocateRegisters<1, 1>({(int)_Rs_}, {(int)_Rd_}); }

void DynaRecCPU::alloc_rs_wb_rt() { allocateRegisters<1, 1>({(int)_Rs_}, {(int)_Rt_}); }

void DynaRecCPU::alloc_rt_rs_wb_rd() { allocateRegisters<2, 1>({(int)_Rt_, (int)_Rs_}, {(int)_Rd_}); }

#endif // DYNAREC_AA64
