/*

MIT License

Copyright (c) 2025 PCSX-Redux authors

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

// GTE (Geometry Transformation Engine) hardware validation test suite.
// All test expectations verified against SCPH-5501 silicon.
//
// Sub-test files are included into this single compilation unit
// because libcester requires a single TU via __BASE_FILE__ re-include.

#include "common/hardware/cop2.h"
#include "common/syscalls/syscalls.h"

// clang-format off

// ==========================================================================
// Helper functions (guarded against cester double-include)
// ==========================================================================

#ifndef GTE_HELPERS_DEFINED
#define GTE_HELPERS_DEFINED

static inline void gte_enable(void) {
    uint32_t sr;
    __asm__ volatile("mfc0 %0, $12" : "=r"(sr));
    sr |= 0x40000000;
    __asm__ volatile("mtc0 %0, $12; nop; nop" : : "r"(sr));
}

static inline void gte_clear_flag(void) {
    cop2_putc(31, 0);
}

static inline uint32_t gte_read_flag(void) {
    uint32_t flag;
    cop2_getc(31, flag);
    return flag;
}

static inline void gte_set_identity_rotation(void) {
    cop2_putc(0, 0x00001000);
    cop2_putc(1, 0x00000000);
    cop2_putc(2, 0x00001000);
    cop2_putc(3, 0x00000000);
    cop2_putc(4, 0x1000);
}

static inline void gte_set_simple_light(void) {
    cop2_putc(8, 0x00000000);
    cop2_putc(9, 0x00000000);
    cop2_putc(10, 0x00000000);
    cop2_putc(11, 0x00000000);
    cop2_putc(12, 0x1000);
}

static inline void gte_set_white_light_color(void) {
    cop2_putc(16, 0x00001000);
    cop2_putc(17, 0x00000000);
    cop2_putc(18, 0x00001000);
    cop2_putc(19, 0x00000000);
    cop2_putc(20, 0x1000);
}

static inline void gte_set_zero_bk(void) {
    cop2_putc(13, 0);
    cop2_putc(14, 0);
    cop2_putc(15, 0);
}

static inline void gte_set_far_color(int32_t r, int32_t g, int32_t b) {
    cop2_putc(21, r);
    cop2_putc(22, g);
    cop2_putc(23, b);
}

static inline void gte_set_translation(int32_t x, int32_t y, int32_t z) {
    cop2_putc(5, x);
    cop2_putc(6, y);
    cop2_putc(7, z);
}

static inline void gte_set_screen(int32_t ofx, int32_t ofy, uint16_t h) {
    cop2_putc(24, ofx);
    cop2_putc(25, ofy);
    cop2_putc(26, h);
    cop2_putc(27, 0);
    cop2_putc(28, 0);
}

#endif // GTE_HELPERS_DEFINED

#undef unix
#define CESTER_NO_SIGNAL
#define CESTER_NO_TIME
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#include "exotic/cester.h"

CESTER_BEFORE_ALL(gte_tests,
    gte_enable();
)

// Include sub-test files
#include "gte-regio.c"
#include "gte-nclip.c"
#include "gte-avsz.c"
#include "gte-sqr.c"
#include "gte-op.c"
#include "gte-gpf-gpl.c"
#include "gte-rtps.c"
#include "gte-mvmva.c"
#include "gte-depthcue.c"
#include "gte-lighting.c"
#include "gte-edgecase.c"
#include "gte-precision.c"
#include "gte-encoding.c"
