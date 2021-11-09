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

#pragma once
#include "core/r3000a.h"

#ifdef DYNAREC_X86_64
#include "xbyak.h"
#include "xbyak_util.h"
#ifdef __APPLE__
#include <sys/mman.h> // For mmap
#endif // __APPLE__

using namespace Xbyak;
using namespace Xbyak::util;

// Allocate 32MB for the code cache. This might be big, but better safe than sorry
constexpr uint32_t codeCacheSize = 32 * 1024 * 1024;

// Allocate a bit more memory to be safe.
// This has to be static so JIT code will be close enough to the executable to address stuff with rip-relative accesses
alignas(4096) static uint8_t s_codeCache[codeCacheSize + 0x1000];

struct Emitter final : public CodeGenerator {
    bool hasAVX = false;
    bool hasBMI2 = false;
    bool hasLZCNT = false;
    
    Emitter() : CodeGenerator(codeCacheSize, s_codeCache) {
        const auto cpu = Xbyak::util::Cpu();

        hasAVX = cpu.has(Xbyak::util::Cpu::tAVX);
        hasBMI2 = cpu.has(Xbyak::util::Cpu::tBMI2);
        hasLZCNT = cpu.has(Xbyak::util::Cpu::tLZCNT);
    }

    template <typename T>
    void callFunc(T& func) {
        call(reinterpret_cast<void*>(&func));
    }

    template <typename T>
    void jmpFunc(T& func) {
        jmp(reinterpret_cast<void*>(&func));
    }

    // Adds "value" to "source" and stores the result in dest
    // Uses lea if the value is non-zero, or mov otherwise
    void moveAndAdd(Xbyak::Reg32 dest, Xbyak::Reg32 source, uint32_t value) {
        if (value != 0) {
            lea(dest, dword[source.cvt64() + value]);
        } else {
            mov(dest, source);
        }
    }

    // Moves "value" into "dest". Optimizes the move to xor dest, dest if value is 0.
    // Thrashes EFLAGS
    void moveImm(Xbyak::Reg32 dest, uint32_t value) {
        if (value == 0) {
            xor_(dest, dest);
        } else {
            mov(dest, value);
        }
    }

    // Logical or dest by value (Skip the or if value == 0)
    void orImm(Xbyak::Reg32 dest, uint32_t value) {
        if (value != 0) {
            or_(dest, value);
        }
    }

    // Returns whether dest is equal to value via the zero flag
    void cmpEqImm(Xbyak::Reg32 dest, uint32_t value) {
        if (value == 0) {
            test(dest, dest);
        } else {
            cmp(dest, value);
        }
    }

    void moveReg(Xbyak::Reg32 dest, Xbyak::Reg32 source) {
        if (dest != source) {
            mov(dest, source);
        }
    }

    // Set dest to 1 if source < value (signed). Otherwise set dest to 0
    void setLess(Xbyak::Reg32 dest, Xbyak::Reg32 source, uint32_t value) {
        if (value == 0) {
            moveReg(dest, source);
            shr(dest, 31);
        } else {
            cmp(source, value);
            setl(al);
            movzx(dest, al);
        }
    }

    // dest = source & value
    // Optimizes to movzx or xor wherever possible
    void andImm(Xbyak::Reg32 dest, Xbyak::Reg32 source, uint32_t value) {
        switch (value) {
            case 0: 
                xor_(dest, dest);
                break;
            case 0xFF:
                movzx(dest, source.cvt8());
                break;
            case 0xFFFF:
                movzx(dest, source.cvt16());
                break;
            default:
                moveReg(dest, source);
                and_(dest, value);
                break;
        }
    }

    // dest <<= amount
    // Ignores shifts by 0, optimizes to add if possible
    void shlImm(Xbyak::Reg32 dest, int amount) {
        if (amount == 1) { // Optimize shift by 1 to add
            add(dest, dest);
        } else if (amount != 0) {
            shl(dest, amount);
        }
    }

    // dest = source << amount
    // Optimizes to lea if appropriate
    void shlImm(Xbyak::Reg32 dest, Xbyak::Reg32 source, int amount) {
        if (dest == source) {
            shlImm(dest, amount);
        } else {
            if (amount == 1 || amount == 2 || amount == 3) {
                lea(dest, dword[source.cvt64() * (1 << amount)]);
            } else {
                mov(dest, source);
                if (amount != 0) {
                    shl(dest, amount);
                }
            }
        }
    }

    // dest = value - source
    // Optimizes the value == 0 case, might thrash eax and EFLAGS
    void reverseSub(Xbyak::Reg32 dest, Xbyak::Reg32 source, uint32_t value) {
        if (value == 0) {
            moveReg(dest, source);
            neg(dest);
        } else {
            mov(eax, value);
            sub(eax, source);
            mov(dest, eax);
        }
    }

    // Like callFunc, except it checks whether the function can be called with a relative call
    // If it can't, it loads a pointer to the function in rax, then uses call rax
    // We don't really need it because we've guaranteed all calls can be relative, but it's
    // Nice to have
    template <typename T>
    void callFuncSafe(T& func) {
        const size_t distance = (size_t)func - (size_t)getCurr();

        if (Xbyak::inner::IsInInt32(distance)) {
            callFunc(func);
        } else {
            mov(rax, (uint64_t)func);
            call(rax);
        }
    }

    // Similar to callFuncSafe, except it does a jmp instead
    template <typename T>
    void jmpFuncSafe(T& func) {
        const size_t distance = (size_t)func - (size_t)getCurr();

        if (Xbyak::inner::IsInInt32(distance)) {
            jmpFunc(func);
        } else {
            mov(rax, (uint64_t)func);
            jmp(rax);
        }
    }

    // Returns a signed integer that shows how many bytes of free space are left in the code buffer
    int64_t getRemainingSize() {
        return (int64_t) codeCacheSize - (int64_t) getSize();
    }

    // Tries to mark the emitter memory as readable/writeable/executable without throwing an exception.
    // Returns whether or not it succeeded
    bool setRWX() {
        #ifdef __APPLE__ // MacOS doesn't like marking static memory as executable the way Xbyak does, so we do it ourselves
        return mmap(s_codeCache, codeCacheSize + 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1,
                    0) != MAP_FAILED;
        #endif

        return setProtectMode(PROTECT_RWE, false);
    }
};
#endif // DYNAREC_X86_64