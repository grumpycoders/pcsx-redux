#pragma once
#include "recompiler.h"
#if defined(DYNAREC_X86_64)

#include <array>
#include "xbyak.h"
using namespace Xbyak;
using namespace Xbyak::util;

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
	/* 
	   The register our JIT can allocate.
	   Starting by the available **non-volatile** regs, since those can be pushed and popped just once per block
	   Then follow the volatile regs, which can sadly be bonked by any C-interop, which is why they're not preferred
	*/
    constexpr Reg64 contextPointer = rbp; // Pointer to CPU context
    constexpr Reg64 memPointer = rbx; // Pointer to memory page table
    constexpr int ALLOCATEABLE_REG_COUNT = 8;

    // Our allocateable registers and the order they should be allocated
    // We prefer using non-volatile regs first
	constexpr std::array <Reg32, ALLOCATEABLE_REG_COUNT> allocateableRegisters = { edi, esi, r12d, r13d, r14d, r15d, r10d, r11d };
    // Which of our allocateables are volatile?
    constexpr std::array <Reg32, 2> allocateableVolatiles = { r10d, r11d };

	constexpr Reg32 arg1 = ecx; // register where first arg is stored
	constexpr Reg32 arg2 = edx; // register where second arg is stored
	constexpr Reg32 arg3 = r8d; // register where third arg is stored
	constexpr Reg32 arg4 = r9d; // register where fourth arg is stored
    #define IS_VOLATILE(x) ((x) >= 6) // Check if register "x" out of the allocateable regs is a volatile one

#else // System V calling convention
    constexpr Reg64 contextPointer = rbp;
    constexpr Reg64 memPointer = rbx;
    constexpr int ALLOCATEABLE_REG_COUNT = 8;
    constexpr std::array <Reg32, ALLOCATEABLE_REG_COUNT> allocateableRegisters = { r12d, r13d, r14d, r15d, r8d, r9d, r10d, r11d };
    constexpr std::array <Reg32, 4> allocateableVolatiles = { r8d, r9d, r10d, r11d };

    constexpr Reg32 arg1 = edi;
	constexpr Reg32 arg2 = esi;
	constexpr Reg32 arg3 = edx;
	constexpr Reg32 arg4 = ecx;
    #define IS_VOLATILE(x) ((x) >= 4)
#endif
#endif // DYNAREC_X86_64
