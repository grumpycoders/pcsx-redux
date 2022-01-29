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
    Emitter() : MacroAssembler(s_codeCache, allocSize) {}

    void L(Label& l) {
        bind(&l);
    }

    template <typename T = void*>
    T getCurr() {
        return GetCursorAddress<T>();
    }

    template <typename T = void*>
    T getCode() {
        return GetBuffer()->GetStartAddress<T>();
    }

    size_t getSize() {
        return GetCursorOffset();
    }

    void ready() { FinalizeCode(); }

    #define MAKE_CONDITIONAL_BRANCH(properName, alias) \
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
        file.write(getCode<const char*>(), getSize());       // Write the code buffer to the dump
    }
};