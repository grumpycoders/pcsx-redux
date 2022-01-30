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

#pragma once
#include "core/r3000a.h"
#if defined(DYNAREC_AA64)

#include <array>

#include "vixl/src/aarch64/macro-assembler-aarch64.h"
using namespace vixl::aarch64;

// Volatile = caller-saved
// Non-Volatile = callee-saved

const Register contextPointer = x19; // Pointer to the JIT object
const Register runningPointer = x20; // Pointer to "running" variable
constexpr int ALLOCATEABLE_REG_COUNT = 15;
constexpr int ALLOCATEABLE_NON_VOLATILE_COUNT = 8;

// Our allocateable registers and the order they should be allocated
// We prefer using non-volatile regs first
const std::array<Register, ALLOCATEABLE_REG_COUNT> allocateableRegisters = {w21, w22, w23, w24, w25, w26, w27, w28,
                                                                            w9, w10, w11, w12, w13, w14, w15};
// Which of our allocateables are volatile?
const std::array<Register, 7> allocateableVolatiles = {w9, w10, w11, w12, w13, w14, w15};
// Which of them are not volatile?
const std::array<Register, 8> allocateableNonVolatiles = {w21, w22, w23, w24, w25, w26, w27, w28};

const Register arg1 = w0;  // register where first arg is stored
const Register arg2 = w1;  // register where second arg is stored
const Register arg3 = w2;  // register where third arg is stored
const Register arg4 = w3;  // register where fourth arg is stored
#define IS_VOLATILE(x) ((x) >= ALLOCATEABLE_NON_VOLATILE_COUNT)
#endif // DYNAREC_AA64
