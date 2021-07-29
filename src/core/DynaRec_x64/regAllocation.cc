#include "recompiler.h"
#if defined(DYNAREC_X86_64)

#include <array>
#include "xbyak.h"
using namespace Xbyak;
using namespace Xbyak::util;

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
	const Reg64 registerPointer = rbp;  // rbp will be used as a pointer to the register array

	/* 
	   The register our JIT can allocate.
	   Starting by the available **non-volatile** regs, since those can be pushed and popped just once per block
	   Then follow the volatile regs, which can sadly be bonked by any C-interop, which is why they're not preferred
	*/
	const std::array <Reg32, 11> allocateableRegisters = { edi, esi, ebx, r12d, r13d, r14d, r15d, r8d, r9d, r10d, r11d};

	const Reg32 arg1 = ecx; // register where first arg is stored
	const Reg32 arg2 = edx; // register where second arg is stored
	const Reg32 arg3 = r8d; // register where third arg is stored
	const Reg32 arg4 = r9d; // register where fourth arg is stored
#else
#error "x64 JIT not supported outside of Windows"
#endif

void DynaRecCPU::allocateReg(int reg) {
    if (m_registers[reg].isAllocated) return;

    reserveRegs(1);
}

#endif // DYNAREC_X86_64