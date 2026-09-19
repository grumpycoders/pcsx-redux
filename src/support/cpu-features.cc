/*

MIT License

Copyright (c) 2026 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#include "support/cpu-features.h"

#include <string.h>

#if defined(__i386__) || defined(_M_IX86) || defined(__x86_64) || defined(_M_AMD64)
#define CPU_FEATURES_X86
#if defined(_MSC_VER)
#include <immintrin.h>
#include <intrin.h>
#else
#include <cpuid.h>
#include <immintrin.h>
#endif
#endif

#if defined(__linux__) && (defined(__arm__) || defined(__aarch64__))
#include <sys/auxv.h>
#ifndef HWCAP_NEON
#define HWCAP_NEON (1 << 12)
#endif
#endif

namespace {

#ifdef CPU_FEATURES_X86
struct Regs {
    uint32_t eax, ebx, ecx, edx;
};

bool cpuidCount(uint32_t leaf, uint32_t subleaf, Regs &r) {
#if defined(_MSC_VER)
    int out[4];
    __cpuidex(out, static_cast<int>(leaf), static_cast<int>(subleaf));
    r = {static_cast<uint32_t>(out[0]), static_cast<uint32_t>(out[1]), static_cast<uint32_t>(out[2]),
         static_cast<uint32_t>(out[3])};
    return true;
#else
    return __get_cpuid_count(leaf, subleaf, &r.eax, &r.ebx, &r.ecx, &r.edx) != 0;
#endif
}

uint32_t maxLeaf() {
    Regs r{};
    if (!cpuidCount(0, 0, r)) return 0;
    return r.eax;
}

uint64_t xcr0() {
#if defined(_MSC_VER)
    return _xgetbv(0);
#elif defined(__GNUC__) || defined(__clang__)
    uint32_t lo, hi;
    __asm__ __volatile__("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
    return (static_cast<uint64_t>(hi) << 32) | lo;
#else
    return 0;
#endif
}
#endif  // CPU_FEATURES_X86

PCSX::CPUFeatures probe() {
    PCSX::CPUFeatures f;
#ifdef CPU_FEATURES_X86
    const uint32_t max = maxLeaf();
    if (max < 1) return f;

    Regs r1{};
    cpuidCount(1, 0, r1);
    f.sse2 = (r1.edx & (1u << 26)) != 0;
    f.ssse3 = (r1.ecx & (1u << 9)) != 0;
    f.sse41 = (r1.ecx & (1u << 19)) != 0;
    f.sse42 = (r1.ecx & (1u << 20)) != 0;

    const bool osxsave = (r1.ecx & (1u << 27)) != 0;
    const bool cpuAvx = (r1.ecx & (1u << 28)) != 0;
    const bool cpuFma = (r1.ecx & (1u << 12)) != 0;

    // XCR0 bit 1 = XMM state, bit 2 = YMM state. Both must be enabled by the OS
    // before any VEX-encoded 256-bit instruction is legal to execute.
    bool ymmOk = false;
    bool zmmOk = false;
    if (osxsave) {
        const uint64_t x = xcr0();
        ymmOk = (x & 0x6) == 0x6;
        // bits 5,6,7 = opmask, ZMM_Hi256, Hi16_ZMM
        zmmOk = ymmOk && ((x & 0xe0) == 0xe0);
    }

    f.avx = cpuAvx && ymmOk;
    f.fma = cpuFma && f.avx;

    if (max >= 7) {
        Regs r7{};
        cpuidCount(7, 0, r7);
        f.avx2 = ((r7.ebx & (1u << 5)) != 0) && f.avx;
        f.avx512f = ((r7.ebx & (1u << 16)) != 0) && zmmOk;
        f.avx512bw = ((r7.ebx & (1u << 30)) != 0) && f.avx512f;
    }
#endif

#if defined(__aarch64__) || defined(_M_ARM64)
    // Advanced SIMD is mandatory in the AArch64 base architecture.
    f.neon = true;
#elif defined(__linux__) && defined(__arm__)
    f.neon = (getauxval(AT_HWCAP) & HWCAP_NEON) != 0;
#endif
    return f;
}

}  // namespace

const PCSX::CPUFeatures &PCSX::CPUFeatures::get() {
    static const CPUFeatures s_features = probe();
    return s_features;
}

const char *PCSX::CPUFeatures::describe() {
    static char s_buffer[256];
    static bool s_built = false;
    if (s_built) return s_buffer;
    const auto &f = get();
    s_buffer[0] = 0;
    auto append = [](const char *s) {
        if (s_buffer[0]) strncat(s_buffer, " ", sizeof(s_buffer) - strlen(s_buffer) - 1);
        strncat(s_buffer, s, sizeof(s_buffer) - strlen(s_buffer) - 1);
    };
    if (f.sse2) append("sse2");
    if (f.ssse3) append("ssse3");
    if (f.sse41) append("sse4.1");
    if (f.sse42) append("sse4.2");
    if (f.avx) append("avx");
    if (f.fma) append("fma");
    if (f.avx2) append("avx2");
    if (f.avx512f) append("avx512f");
    if (f.avx512bw) append("avx512bw");
    if (f.neon) append("neon");
    if (!s_buffer[0]) strncpy(s_buffer, "none", sizeof(s_buffer));
    s_built = true;
    return s_buffer;
}
