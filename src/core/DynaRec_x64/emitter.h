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
#include "xbyak.h"

using namespace Xbyak;
using namespace Xbyak::util;

// Allocate 32MB for the code cache. This might be big, but better safe than sorry
constexpr uint32_t codeCacheSize = 32 * 1024 * 1024;

// Allocate a bit more memory to be safe.
// This has to be static so JIT code will be able to call C++ functions without absolute calls
static uint8_t s_codeCache[codeCacheSize + 0x1000]; 

struct Emitter final : public CodeGenerator {                   
    Emitter() : CodeGenerator(codeCacheSize, s_codeCache) {}

    template <typename T>
    void callFunc (T& func) {
        call (reinterpret_cast<void*>(&func));
    }

    // Tries to mark the emitter memory as readable/writeable/executable without throwing an exception.
    // Returns whether or not it succeeded
    bool setRWX() { 
        return setProtectMode(PROTECT_RWE, false);
    }
};
