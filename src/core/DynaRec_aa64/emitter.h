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
#ifdef DYNAREC_AA64
#include "support/windowswrapper.h"

#ifndef _WIN32
#include <sys/mman.h>  // For mmap/mprotect
#endif
#include "vixl/src/aarch64/macro-assembler-aarch64.h"

using namespace vixl::aarch64;

// Allocate 32MB for the code cache.
constexpr size_t codeCacheSize = 32 * 1024 * 1024;
constexpr size_t allocSize = codeCacheSize + 0x1000;

// Allocate a bit more memory to be safe.
// This has to be static so JIT code will be close enough to the executable to address stuff with pc-relative accesses
alignas(4096) static uint8_t s_codeCache[allocSize];

class Emitter : public MacroAssembler {
  public:
#ifdef __APPLE__
    Emitter() : MacroAssembler(reinterpret_cast<uint8_t*>(makeBuffer()), allocSize) {}

    static void* makeBuffer() {
        void* ptr = mmap(s_codeCache, allocSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        return (ptr == MAP_FAILED) ? nullptr : ptr;
    }
#else
    Emitter() : MacroAssembler(s_codeCache, allocSize) {}
#endif
    void L(Label& l) { Bind(&l); }

    template <typename T = void*>
    T getCurr() {
        return GetCursorAddress<T>();
    }

    template <typename T = void*>
    T getCode() {
        return GetBuffer()->GetStartAddress<T>();
    }

    size_t getSize() { return GetCursorOffset(); }

    void ready() { FinalizeCode(); }

    bool setRWX() {
#if defined(_WIN32)
        DWORD oldProtect;  // Unused, but VirtualProtect wants somewhere to store it anyways.
        return VirtualProtect(s_codeCache, allocSize, PAGE_EXECUTE_READWRITE, &oldProtect) != 0;
#elif !defined(__APPLE__)
        return mprotect(s_codeCache, allocSize, PROT_READ | PROT_WRITE | PROT_EXEC) != -1;
#else
        return false;
#endif
    }

    void setRW() { GetBuffer()->SetWritable(); }

    void setRX() { GetBuffer()->SetExecutable(); }

    void align() { GetBuffer()->Align(); }

#define MAKE_CONDITIONAL_BRANCH(properName, alias)      \
    void b##properName(Label& l) { b(&l, properName); } \
    void b##alias(Label& l) { b##properName(l); }

    MAKE_CONDITIONAL_BRANCH(ne, nz);
    MAKE_CONDITIONAL_BRANCH(eq, z);
    MAKE_CONDITIONAL_BRANCH(mi, s);
    MAKE_CONDITIONAL_BRANCH(pl, ns);
    MAKE_CONDITIONAL_BRANCH(cs, hs);
    MAKE_CONDITIONAL_BRANCH(cc, lo);
    void bvc(Label& l) { b(&l, vc); }
    void bvs(Label& l) { b(&l, vs); }
    void bhi(Label& l) { b(&l, hi); }
    void bls(Label& l) { b(&l, ls); }
    void bge(Label& l) { b(&l, ge); }
    void blt(Label& l) { b(&l, lt); }
    void bgt(Label& l) { b(&l, gt); }
    void ble(Label& l) { b(&l, le); }
    void bal(Label& l) { b(&l); }

#undef MAKE_CONDITIONAL_BRANCH

    void dumpBuffer() {
        std::ofstream file("DynarecOutput.dump", std::ios::binary);  // Make a file for our dump
        file.write(getCode<const char*>(), getSize());               // Write the code buffer to the dump
    }

    // Returns a signed integer that shows how many bytes of free space are left in the code buffer
    int64_t getRemainingSize() { return (int64_t)codeCacheSize - (int64_t)getSize(); }

    // Adds "value" to "source" and stores the result in dest
    // Uses add if the value is non-zero, or mov otherwise
    void moveAndAdd(Register dest, Register source, uint32_t value) {
        if (value != 0) {
            Add(dest, source, value);
        } else {
            Mov(dest, source);
        }
    }

    // dest = source & value
    // Optimizes to Uxt or xor wherever possible
    void andImm(Register dest, Register source, uint32_t value) {
        switch (value) {
            case 0:
                Mov(dest, 0);
                break;
            case 0xFF:
                Uxtb(dest, source);
                break;
            case 0xFFFF:
                Uxth(dest, source);
                break;
            default:
                And(dest, source, value);
                break;
        }
    }

    // Logical OR dest by value (Skip the OR if value == 0)
    void orImm(Register dest, uint32_t value) {
        if (value != 0) {
            Orr(dest, dest, value);
        }
    }

    // Logical OR source by value (
    void orImm(Register dest, Register source, uint32_t value) {
        if (value != 0) {
            Orr(dest, source, value);
        } else if (!dest.Is(source)) {
            Mov(dest, source);
        }
    }

    // dest = value - source
    // Optimizes the value == 0 case, thrases w0 but not FLAGs
    void reverseSub(Register dest, Register source, uint32_t value) {
        if (value == 0) {
            Neg(dest, source);
        } else {
            Mov(w0, value);
            Sub(dest, w0, source);
        }
    }

    // Emit a trap instruction that gdb/lldb/Visual Studio can interpret as a breakpoint
    void breakpoint() { Brk(0); }
};
#endif  // DYNAREC_AA64
