#pragma once
#include "xbyak.h"

using namespace Xbyak;
using namespace Xbyak::util;

// Allocate 32MB for the code cache. This might be big, but better safe than sorry
constexpr uint32_t codeCacheSize = 32 * 1024 * 1024;

// Allocate a bit more memory to be safe.
// This has to be static so JIT code will be able to call C++ functions without absolute calls
static uint8_t* s_codeCache[codeCacheSize + 0x1000]; 

struct Emitter final : public CodeGenerator {                   
    Emitter() : CodeGenerator(codeCacheSize, s_codeCache) { // Initialize emitter and memory
        setProtectMode(PROTECT_RWE); // Mark emitter memory as readadable/writeable/executable
    }

    template <typename T>
    void callFunc (T& func) {
        call ((void*) &func);
    }
};