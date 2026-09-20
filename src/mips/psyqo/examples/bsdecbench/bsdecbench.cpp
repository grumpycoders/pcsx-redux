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

/*
 * Times the pieces of bsdec's AC symbol on the console, one at a time.
 *
 * The frame-level profile says where the decoder's time goes to within a block;
 * it cannot see inside one symbol, and the disassembly can only count
 * instructions, which on a machine with no data cache is not the same question.
 * So each candidate runs in its own loop against counter 2 and the empty loop is
 * subtracted.
 *
 * COUNTER 2 AT SYSTEM CLOCK / 8 is 4.2336 MHz against a 33.8688 MHz CPU, so one
 * tick is exactly eight cycles and the 16-bit counter wraps every 65536 of them.
 * ITERS is sized so the slowest arm stays inside one wrap; the raw tick count is
 * printed beside every derived figure so a wrap is visible rather than silent.
 *
 * Every arm runs the same LCG and the same subtraction, so what is left is the
 * body. The LCG's own output is the window under test: its leading-zero count is
 * geometric, 50/25/12.5/6.25, against the 43.8/23.6/15.2/5.0 the real stream
 * gives, which is close enough for comparing arms against each other.
 */

#include <stdint.h>

#include "common/hardware/counters.h"
#include "common/syscalls/syscalls.h"
#include "psyqo/application.hh"
#include "psyqo/gpu.hh"
#include "psyqo/scene.hh"

extern "C" {
#include "bsdec/bsdec-vlc.h"
}

namespace {

// 2048, not 8192. The first run put four arms past the counter's 65536-tick
// wrap, where a wrapped delta reads as a tiny one, and taking the MIN of the
// repeats then selected exactly the wrapped readings. Every raw tick count is
// printed and anything near the wrap is flagged, so the instrument says so
// rather than handing back a fast-looking number.
constexpr uint32_t ITERS = 2048;
constexpr uint16_t WRAP_WARN = 55000;
constexpr uint32_t REPEATS = 3;

// 1 KB of scratchpad lives here. Only the second half is touched, and it is
// saved and put back, because psyqo may be using the rest. 512 bytes is also
// exactly a 256-entry halfword primary table, which is why the arms below can
// ask what the scratchpad is worth without taking the half psyqo may hold.
volatile uint32_t *const SPM = (volatile uint32_t *)0x1f800200;
constexpr uint32_t SPM_WORDS = 128;

uint32_t s_ram[256];
uint32_t s_spmSave[SPM_WORDS];
uint8_t s_clz8[256];
// (offset << 8) | suffix width, so one load answers what two do today.
uint32_t s_disp[32];

// A synthetic payload for the whole-symbol arms. Declared as halfwords so the
// one-lhu refill is legal on it, which is the same alignment bsdecFrame already
// requires of its input. 8 KB is 2048 symbols at the book's 32-bit worst case,
// so no arm ever reaches the end and starts decoding synthetic zeros - which
// would end blocks on the cheap sentinel and quietly make every arm faster.
constexpr uint32_t BITS_BYTES = 8192;
uint16_t s_bits[BITS_BYTES / 2];

// The dispatch offsets with the marker bit folded in: index the group with the
// leading 1 still on top of the suffix, and subtract it back here once at
// build time. That is what lets the extraction drop its `width ? :` arm.
uint32_t s_off2[32];

// Top 9 bits -> (total code length << 9) | slot in c_bsdecVlc, or 0 when the
// prefix is longer than 9 bits. Groups 0..5 are all at most 9 bits long and are
// 92.4% of real symbols, so this retires the leading-zero count for nine
// symbols in ten.
uint16_t s_prim[512];

// The same on eight bits, which is 512 bytes and therefore fits the half of the
// scratchpad psyqo is not using. Eight bits cannot hold group 2 - its codes run
// to nine - so this trades 15.2% of the coverage for a 4.00 cycle load against
// 6.05. Which way that trade goes is the question the two arms answer.
uint16_t s_prim8[256];

// A sink the compiler cannot reason about, so no arm's body can be folded away.
volatile uint32_t g_sink;

uint16_t s_best[32];
uint16_t s_worst[32];
uint32_t s_check[32];
uint8_t s_baseIdx[32];
const char *s_name[32];
uint32_t s_arms = 0;
// Index of the baseline the whole-symbol arms subtract. They do not run the
// xorshift - their input is the payload - so the xorshift-carrying `empty` arm
// is the wrong zero for them.
uint32_t s_noxBase = 0;

#define ARM(label, body)                                          \
    do {                                                          \
        uint16_t best = 0xffff;                                   \
        uint16_t worst = 0;                                       \
        for (uint32_t r = 0; r < REPEATS; r++) {                  \
            uint32_t w = 0x12345678u + r;                         \
            uint32_t acc = 0;                                     \
            const uint16_t t0 = COUNTERS[2].value;                \
            for (uint32_t i = 0; i < ITERS; i++) {                \
                /* xorshift, not an LCG: the multiply was 18 cycles of  \
                 * baseline and swamped the arms it was meant to carry. */ \
                w ^= w << 13; w ^= w >> 17; w ^= w << 5;          \
                /* Opaque to the optimiser, so no body can be folded \
                 * against a known input. The msb arm was constant-folded \
                 * to nothing and reported zero ticks. */          \
                __asm__ volatile("" : "+r"(w));                   \
                body;                                             \
            }                                                     \
            const uint16_t t1 = COUNTERS[2].value;                \
            g_sink = acc;                                         \
            const uint16_t d = (uint16_t)(t1 - t0);               \
            if (d < best) best = d;                               \
            if (d > worst) worst = d;                             \
        }                                                         \
        s_name[s_arms] = label;                                   \
        s_best[s_arms] = best;                                    \
        s_worst[s_arms] = worst;                                  \
        s_check[s_arms] = 0;                                      \
        s_baseIdx[s_arms] = 0;                                    \
        s_arms++;                                                 \
    } while (0)

/*
 * A whole-symbol arm: refill, dispatch and window maintenance together, which
 * is what the AC loop actually executes and what the arms above deliberately
 * cut apart. No xorshift - the input is the payload, walked by `feed`, so
 * `init` resets the bit state and every repeat decodes the same bits.
 *
 * `check` is the positive control and it is the whole reason these are
 * comparable: every arm decodes the same stream, so every arm must accumulate
 * the same sum. An arm that is fast because it decodes something else prints a
 * different number instead of a better one.
 */
#define ARMB(label, init, body)                                   \
    do {                                                          \
        uint16_t best = 0xffff;                                   \
        uint16_t worst = 0;                                       \
        uint32_t check = 0;                                       \
        for (uint32_t r = 0; r < REPEATS; r++) {                  \
            uint32_t acc = 0;                                     \
            init;                                                 \
            const uint16_t t0 = COUNTERS[2].value;                \
            for (uint32_t i = 0; i < ITERS; i++) {                \
                body;                                             \
            }                                                     \
            const uint16_t t1 = COUNTERS[2].value;                \
            g_sink = acc;                                         \
            check = acc;                                          \
            const uint16_t d = (uint16_t)(t1 - t0);               \
            if (d < best) best = d;                               \
            if (d > worst) worst = d;                             \
        }                                                         \
        s_name[s_arms] = label;                                   \
        s_best[s_arms] = best;                                    \
        s_worst[s_arms] = worst;                                  \
        s_check[s_arms] = check;                                  \
        s_baseIdx[s_arms] = (uint8_t)s_noxBase;                   \
        s_arms++;                                                 \
    } while (0)

/* A leading-zero count with no call and no memory: five compare-and-shift
 * steps, constant time. This is the thing the GTE call is being priced
 * against. */
__attribute__((always_inline)) static inline uint32_t clzBsearch(uint32_t v) {
    uint32_t n = 0;
    if (v == 0) return 31;
    if (!(v & 0xffff0000u)) { n += 16; v <<= 16; }
    if (!(v & 0xff000000u)) { n += 8; v <<= 8; }
    if (!(v & 0xf0000000u)) { n += 4; v <<= 4; }
    if (!(v & 0xc0000000u)) { n += 2; v <<= 2; }
    if (!(v & 0x80000000u)) { n += 1; }
    return n;
}

/* One byte-table lookup covers a leading-zero count up to 7, which the real
 * stream hits 96.2% of the time. Anything longer falls through to the slow
 * arm, and the book only reaches 11. */
__attribute__((always_inline)) static inline uint32_t clzTable8(const uint8_t *tab, uint32_t v) {
    const uint32_t top = v >> 24;
    if (top) return tab[top];
    return 8 + clzBsearch(v << 8);
}

/* The same, capped at 31 the way bsdecClz32 caps, so an empty window lands on
 * the dispatch's sentinel row instead of indexing off the end of a 32-row
 * table. The cap costs nothing on the 96.2% path: it is inside the arm the
 * byte table already misses. */
__attribute__((always_inline)) static inline uint32_t clzTable8Sat(const uint8_t *tab, uint32_t v) {
    const uint32_t top = v >> 24;
    if (top) return tab[top];
    const uint32_t rest = v << 8;
    if (!rest) return 31;
    return 8 + clzBsearch(rest);
}

void runBench() {
    for (uint32_t i = 0; i < 256; i++) s_ram[i] = (i * 7u + 1u) & 0xffu;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t n = 0, v = i;
        while (n < 8 && !(v & 0x80u)) { n++; v <<= 1; }
        s_clz8[i] = (uint8_t)n;
    }
    for (uint32_t i = 0; i < 32; i++)
        s_disp[i] = ((uint32_t)c_bsdecVlcOffset[i] << 8) | c_bsdecVlcSuffixBits[i];
    // Unsigned wrap is load-bearing: row 0 has a 2-bit suffix, so its folded
    // offset is 0 - 4, and the index the extraction produces adds the 4 back.
    for (uint32_t i = 0; i < 32; i++)
        s_off2[i] = (uint32_t)c_bsdecVlcOffset[i] - (1u << c_bsdecVlcSuffixBits[i]);
    {
        uint32_t x = 0x1badd00du;
        for (uint32_t i = 0; i < BITS_BYTES / 2; i++) {
            x ^= x << 13; x ^= x >> 17; x ^= x << 5;
            s_bits[i] = (uint16_t)x;
        }
    }
    for (uint32_t i = 0; i < 512; i++) {
        const uint32_t v = i << 23;
        uint32_t n = 0;
        while (n < 9 && !(v & (0x80000000u >> n))) n++;
        s_prim[i] = 0;
        if (n <= 5) {
            const uint32_t sw = c_bsdecVlcSuffixBits[n];
            const uint32_t slot = (uint32_t)c_bsdecVlcOffset[n] + (sw ? (((v << n) << 1) >> (32 - sw)) : 0u);
            const uint32_t len = n + 1 + BSDEC_VLC_SUFFIXBITS(c_bsdecVlc[slot]);
            s_prim[i] = (uint16_t)((len << 9) | slot);
        }
    }
    for (uint32_t i = 0; i < 256; i++) {
        const uint32_t v = i << 24;
        uint32_t n = 0;
        while (n < 8 && !(v & (0x80000000u >> n))) n++;
        s_prim8[i] = 0;
        // The test is on the INDEX width, not on the code's own length: the
        // table has to read all of `sw` to pick the row, even where the row it
        // picks turns out to spend fewer bits than that.
        if (n <= 5 && n + 1 + c_bsdecVlcSuffixBits[n] <= 8) {
            const uint32_t sw = c_bsdecVlcSuffixBits[n];
            const uint32_t slot = (uint32_t)c_bsdecVlcOffset[n] + (sw ? (((v << n) << 1) >> (32 - sw)) : 0u);
            const uint32_t len = n + 1 + BSDEC_VLC_SUFFIXBITS(c_bsdecVlc[slot]);
            s_prim8[i] = (uint16_t)((len << 9) | slot);
        }
    }
    for (uint32_t i = 0; i < SPM_WORDS; i++) s_spmSave[i] = SPM[i];
    for (uint32_t i = 0; i < SPM_WORDS; i++) SPM[i] = (i * 7u + 1u) & (SPM_WORDS - 1);
    for (uint32_t i = 0; i < 32; i++) SPM[i] = s_disp[i];

    COUNTERS[2].mode = 0x0200;  // system clock / 8, free running

    const uint8_t *const clz8 = s_clz8;
    const uint32_t *const ram = s_ram;

    ARM("empty            ", acc += w);
    ARM("clz builtin  any ", acc += (uint32_t)__builtin_clz(w | 1u));
    ARM("clz builtin  msb ", {
        uint32_t x = w | 0x80000000u;
        __asm__ volatile("" : "+r"(x));
        acc += (uint32_t)__builtin_clz(x);
    });
    ARM("clz builtin  n>0 ", acc += (uint32_t)__builtin_clz((w >> 1) | 1u));
    ARM("clz bsearch  any ", acc += clzBsearch(w | 1u));
    ARM("clz table8   any ", acc += clzTable8(clz8, w | 1u));
    ARM("load ram  dep    ", acc = ram[acc & 0xffu]);
    ARM("load ram  indep  ", acc += ram[w & 0xffu]);
    ARM("load spm  dep    ", acc = SPM[acc & (SPM_WORDS - 1)]);
    ARM("load spm  indep  ", acc += SPM[w & (SPM_WORDS - 1)]);
    // The dispatch as the decoder spells it today: width, offset, entry.
    ARM("dispatch 3 loads ", {
        const uint32_t n = (uint32_t)__builtin_clz(w | 1u) & 31u;
        const uint32_t sw = c_bsdecVlcSuffixBits[n];
        const uint32_t off = c_bsdecVlcOffset[n];
        acc += c_bsdecVlc[off + (sw ? ((w << 1) >> (32 - sw)) : 0u)];
    });
    // Width and offset folded into one word ahead of time, so this is two loads.
    const uint32_t *const disp = s_disp;
    ARM("dispatch 2 loads ", {
        const uint32_t n = (uint32_t)__builtin_clz(w | 1u) & 31u;
        const uint32_t d = disp[n];
        const uint32_t sw = d & 0xffu;
        acc += c_bsdecVlc[(d >> 8) + (sw ? ((w << 1) >> (32 - sw)) : 0u)];
    });
    // The same two loads with the dispatch half living in scratchpad.
    ARM("dispatch 2 spm   ", {
        const uint32_t n = (uint32_t)__builtin_clz(w | 1u) & 31u;
        const uint32_t d = SPM[n];
        const uint32_t sw = d & 0xffu;
        acc += c_bsdecVlc[(d >> 8) + (sw ? ((w << 1) >> (32 - sw)) : 0u)];
    });
    // Dispatch with the leading-zero count inlined instead of called.
    ARM("dispatch 2 + bsrch", {
        const uint32_t n = clzBsearch(w | 1u) & 31u;
        const uint32_t d = disp[n];
        const uint32_t sw = d & 0xffu;
        acc += c_bsdecVlc[(d >> 8) + (sw ? ((w << 1) >> (32 - sw)) : 0u)];
    });
    // Three loads and an inlined count, which the 2-load arm above leaves
    // unmeasured: 76.42 vs 88.06 says the merge was the slower half, so pricing
    // the inline on top of the merge prices two changes at once.
    ARM("dispatch 3 + bsrch", {
        const uint32_t n = clzBsearch(w | 1u) & 31u;
        const uint32_t sw = c_bsdecVlcSuffixBits[n];
        const uint32_t off = c_bsdecVlcOffset[n];
        acc += c_bsdecVlc[off + (sw ? ((w << 1) >> (32 - sw)) : 0u)];
    });

    /*
     * WHOLE-SYMBOL ARMS. Everything above cuts the symbol apart to price one
     * piece; these run the piece the decoder runs - refill, count, dispatch,
     * window maintenance - so a change that moves work from one piece to
     * another shows up as a change rather than as two cancelling ones.
     */
    const uint8_t *const bitsB = (const uint8_t *)s_bits;
    const uint16_t *const bitsH = s_bits;
    const uint16_t *const prim = s_prim;
    const uint32_t *const off2 = s_off2;
    uint32_t win = 0, pos = 0, feed = 0;
    int32_t valid = 0, dctr = 0;

    s_noxBase = s_arms;
    // The loop and nothing else. `j` is made opaque because the compiler
    // otherwise closes the sum into a formula and deletes the loop, which
    // reports zero and silently leaves the loop's own cost inside every arm
    // below it.
    ARMB("empty nox        ", { }, {
        uint32_t j = i;
        __asm__ volatile("" : "+r"(j));
        acc += j;
    });

    // Exactly what bsdec.c spells today: two byte loads a refill, `valid` and
    // `pos` both maintained, and the width-zero arm on the extraction.
    ARMB("sym base         ", { win = 0; valid = 0; pos = 0; feed = 0; }, {
        while (valid <= 16) {
            uint32_t half = 0;
            if (feed < BITS_BYTES) half = (uint32_t)bitsB[feed] | ((uint32_t)bitsB[feed + 1] << 8);
            feed += 2;
            win |= half << (16 - valid);
            valid += 16;
        }
        const uint32_t n = win ? (uint32_t)__builtin_clz(win) : 31u;
        pos += n + 1;
        win = (win << n) << 1;
        valid -= (int32_t)n + 1;
        const uint32_t sw = c_bsdecVlcSuffixBits[n];
        const uint32_t e = c_bsdecVlc[c_bsdecVlcOffset[n] + (sw ? (win >> (32 - sw)) : 0u)];
        const uint32_t sb = BSDEC_VLC_SUFFIXBITS(e);
        pos += sb;
        win <<= sb;
        valid -= (int32_t)sb;
        acc += e;
    });
    g_sink = win + (uint32_t)valid + pos + feed;

    // One halfword load a refill instead of two bytes and a shift-or. `base` is
    // halfword aligned - bsdecFrame already requires that of `in`, and its
    // payload starts eight bytes in - and `feed` is even between pulls.
    ARMB("sym lhu          ", { win = 0; valid = 0; pos = 0; feed = 0; }, {
        while (valid <= 16) {
            uint32_t half = 0;
            if (feed < BITS_BYTES) half = bitsH[feed >> 1];
            feed += 2;
            win |= half << (16 - valid);
            valid += 16;
        }
        const uint32_t n = win ? (uint32_t)__builtin_clz(win) : 31u;
        pos += n + 1;
        win = (win << n) << 1;
        valid -= (int32_t)n + 1;
        const uint32_t sw = c_bsdecVlcSuffixBits[n];
        const uint32_t e = c_bsdecVlc[c_bsdecVlcOffset[n] + (sw ? (win >> (32 - sw)) : 0u)];
        const uint32_t sb = BSDEC_VLC_SUFFIXBITS(e);
        pos += sb;
        win <<= sb;
        valid -= (int32_t)sb;
        acc += e;
    });
    g_sink = win + (uint32_t)valid + pos + feed;

    // ONE COUNTER INSTEAD OF TWO. `pos` and `valid` are the same quantity read
    // from opposite ends - valid == 8 * feed - pos holds at every point - so
    // one of them is bookkeeping the other already did. Keeping 16 - valid
    // rather than valid is what makes the refill shift free: the amount it
    // needs IS the counter, so the subtract goes too.
    ARMB("sym d-ctr        ", { win = 0; dctr = 16; feed = 0; }, {
        while (dctr >= 0) {
            uint32_t half = 0;
            if (feed < BITS_BYTES) half = bitsH[feed >> 1];
            feed += 2;
            win |= half << dctr;
            dctr -= 16;
        }
        const uint32_t n = win ? (uint32_t)__builtin_clz(win) : 31u;
        win = (win << n) << 1;
        dctr += (int32_t)n + 1;
        const uint32_t sw = c_bsdecVlcSuffixBits[n];
        const uint32_t e = c_bsdecVlc[c_bsdecVlcOffset[n] + (sw ? (win >> (32 - sw)) : 0u)];
        const uint32_t sb = BSDEC_VLC_SUFFIXBITS(e);
        win <<= sb;
        dctr += (int32_t)sb;
        acc += e;
    });
    g_sink = win + (uint32_t)dctr + feed;

    // THE MARKER STAYS IN THE INDEX. Shifting the leading 1 off and then
    // extracting the suffix is two shifts and a width-zero arm; leaving it on
    // and folding its weight into the offset is one shift and no branch, and
    // the marker-and-suffix shift the window needs afterwards is the same
    // count either way.
    ARMB("sym d+mark       ", { win = 0; dctr = 16; feed = 0; }, {
        while (dctr >= 0) {
            uint32_t half = 0;
            if (feed < BITS_BYTES) half = bitsH[feed >> 1];
            feed += 2;
            win |= half << dctr;
            dctr -= 16;
        }
        const uint32_t n = win ? (uint32_t)__builtin_clz(win) : 31u;
        const uint32_t sw = c_bsdecVlcSuffixBits[n];
        const uint32_t t = win << n;
        const uint32_t e = c_bsdecVlc[off2[n] + (t >> (31 - sw))];
        const uint32_t sb = BSDEC_VLC_SUFFIXBITS(e);
        win = t << (sb + 1);
        dctr += (int32_t)(n + 1 + sb);
        acc += e;
    });
    g_sink = win + (uint32_t)dctr + feed;

    // The same without the end-of-payload test, to price splitting the AC loop
    // into a fast body that runs while the payload is known to have four bytes
    // left and a careful one for the tail. Safe here only because the buffer is
    // sized so `feed` never reaches it.
    ARMB("sym d+mk nobnd   ", { win = 0; dctr = 16; feed = 0; }, {
        while (dctr >= 0) {
            const uint32_t half = bitsH[feed >> 1];
            feed += 2;
            win |= half << dctr;
            dctr -= 16;
        }
        const uint32_t n = win ? (uint32_t)__builtin_clz(win) : 31u;
        const uint32_t sw = c_bsdecVlcSuffixBits[n];
        const uint32_t t = win << n;
        const uint32_t e = c_bsdecVlc[off2[n] + (t >> (31 - sw))];
        const uint32_t sb = BSDEC_VLC_SUFFIXBITS(e);
        win = t << (sb + 1);
        dctr += (int32_t)(n + 1 + sb);
        acc += e;
    });
    g_sink = win + (uint32_t)dctr + feed;

    ARMB("sym d+mk bsrch   ", { win = 0; dctr = 16; feed = 0; }, {
        while (dctr >= 0) {
            uint32_t half = 0;
            if (feed < BITS_BYTES) half = bitsH[feed >> 1];
            feed += 2;
            win |= half << dctr;
            dctr -= 16;
        }
        const uint32_t n = clzBsearch(win);
        const uint32_t sw = c_bsdecVlcSuffixBits[n];
        const uint32_t t = win << n;
        const uint32_t e = c_bsdecVlc[off2[n] + (t >> (31 - sw))];
        const uint32_t sb = BSDEC_VLC_SUFFIXBITS(e);
        win = t << (sb + 1);
        dctr += (int32_t)(n + 1 + sb);
        acc += e;
    });
    g_sink = win + (uint32_t)dctr + feed;

    /*
     * THE SAME LADDER WITH THE COUNT INLINED, AND IT IS THE ONLY ONE THAT
     * ISOLATES ANYTHING. With `jal __clzsi2` in the loop every arm's cost is
     * dominated by what it keeps live across the call - the marker arm above
     * spills eleven registers where the one before it spills seven - so those
     * four arms price register pressure and not the change that was made. With
     * no call there is nothing to spill around and each step is itself.
     */
    ARMB("sym base tab8    ", { win = 0; valid = 0; pos = 0; feed = 0; }, {
        while (valid <= 16) {
            uint32_t half = 0;
            if (feed < BITS_BYTES) half = (uint32_t)bitsB[feed] | ((uint32_t)bitsB[feed + 1] << 8);
            feed += 2;
            win |= half << (16 - valid);
            valid += 16;
        }
        const uint32_t n = clzTable8Sat(clz8, win);
        pos += n + 1;
        win = (win << n) << 1;
        valid -= (int32_t)n + 1;
        const uint32_t sw = c_bsdecVlcSuffixBits[n];
        const uint32_t e = c_bsdecVlc[c_bsdecVlcOffset[n] + (sw ? (win >> (32 - sw)) : 0u)];
        const uint32_t sb = BSDEC_VLC_SUFFIXBITS(e);
        pos += sb;
        win <<= sb;
        valid -= (int32_t)sb;
        acc += e;
    });
    g_sink = win + (uint32_t)valid + pos + feed;

    ARMB("sym lhu tab8     ", { win = 0; valid = 0; pos = 0; feed = 0; }, {
        while (valid <= 16) {
            uint32_t half = 0;
            if (feed < BITS_BYTES) half = bitsH[feed >> 1];
            feed += 2;
            win |= half << (16 - valid);
            valid += 16;
        }
        const uint32_t n = clzTable8Sat(clz8, win);
        pos += n + 1;
        win = (win << n) << 1;
        valid -= (int32_t)n + 1;
        const uint32_t sw = c_bsdecVlcSuffixBits[n];
        const uint32_t e = c_bsdecVlc[c_bsdecVlcOffset[n] + (sw ? (win >> (32 - sw)) : 0u)];
        const uint32_t sb = BSDEC_VLC_SUFFIXBITS(e);
        pos += sb;
        win <<= sb;
        valid -= (int32_t)sb;
        acc += e;
    });
    g_sink = win + (uint32_t)valid + pos + feed;

    ARMB("sym d-ctr tab8   ", { win = 0; dctr = 16; feed = 0; }, {
        while (dctr >= 0) {
            uint32_t half = 0;
            if (feed < BITS_BYTES) half = bitsH[feed >> 1];
            feed += 2;
            win |= half << dctr;
            dctr -= 16;
        }
        const uint32_t n = clzTable8Sat(clz8, win);
        win = (win << n) << 1;
        dctr += (int32_t)n + 1;
        const uint32_t sw = c_bsdecVlcSuffixBits[n];
        const uint32_t e = c_bsdecVlc[c_bsdecVlcOffset[n] + (sw ? (win >> (32 - sw)) : 0u)];
        const uint32_t sb = BSDEC_VLC_SUFFIXBITS(e);
        win <<= sb;
        dctr += (int32_t)sb;
        acc += e;
    });
    g_sink = win + (uint32_t)dctr + feed;

    ARMB("sym d+mk tab8    ", { win = 0; dctr = 16; feed = 0; }, {
        while (dctr >= 0) {
            uint32_t half = 0;
            if (feed < BITS_BYTES) half = bitsH[feed >> 1];
            feed += 2;
            win |= half << dctr;
            dctr -= 16;
        }
        const uint32_t n = clzTable8Sat(clz8, win);
        const uint32_t sw = c_bsdecVlcSuffixBits[n];
        const uint32_t t = win << n;
        const uint32_t e = c_bsdecVlc[off2[n] + (t >> (31 - sw))];
        const uint32_t sb = BSDEC_VLC_SUFFIXBITS(e);
        win = t << (sb + 1);
        dctr += (int32_t)(n + 1 + sb);
        acc += e;
    });
    g_sink = win + (uint32_t)dctr + feed;

    // No leading-zero count at all on the common path: the top nine bits of the
    // window index straight to a slot and a length. Groups 0..5 are every code
    // nine bits or shorter and 92.4% of real symbols; the rest fall through to
    // the arm above.
    ARMB("sym prim9        ", { win = 0; dctr = 16; feed = 0; }, {
        while (dctr >= 0) {
            uint32_t half = 0;
            if (feed < BITS_BYTES) half = bitsH[feed >> 1];
            feed += 2;
            win |= half << dctr;
            dctr -= 16;
        }
        const uint32_t p = prim[win >> 23];
        if (p) {
            const uint32_t len = p >> 9;
            acc += c_bsdecVlc[p & 0x1ffu];
            win <<= len;
            dctr += (int32_t)len;
        } else {
            const uint32_t n = clzTable8Sat(clz8, win);
            const uint32_t sw = c_bsdecVlcSuffixBits[n];
            const uint32_t t = win << n;
            const uint32_t e = c_bsdecVlc[off2[n] + (t >> (31 - sw))];
            const uint32_t sb = BSDEC_VLC_SUFFIXBITS(e);
            win = t << (sb + 1);
            dctr += (int32_t)(n + 1 + sb);
            acc += e;
        }
    });
    g_sink = win + (uint32_t)dctr + feed;
    // Eight bits from RAM, so the pair below separates the coverage loss from
    // the scratchpad gain instead of moving both at once.
    const uint16_t *const prim8 = s_prim8;
    ARMB("sym prim8 ram    ", { win = 0; dctr = 16; feed = 0; }, {
        while (dctr >= 0) {
            uint32_t half = 0;
            if (feed < BITS_BYTES) half = bitsH[feed >> 1];
            feed += 2;
            win |= half << dctr;
            dctr -= 16;
        }
        const uint32_t p = prim8[win >> 24];
        if (p) {
            const uint32_t len = p >> 9;
            acc += c_bsdecVlc[p & 0x1ffu];
            win <<= len;
            dctr += (int32_t)len;
        } else {
            const uint32_t n = clzTable8Sat(clz8, win);
            const uint32_t sw = c_bsdecVlcSuffixBits[n];
            const uint32_t t = win << n;
            const uint32_t e = c_bsdecVlc[off2[n] + (t >> (31 - sw))];
            const uint32_t sb = BSDEC_VLC_SUFFIXBITS(e);
            win = t << (sb + 1);
            dctr += (int32_t)(n + 1 + sb);
            acc += e;
        }
    });
    g_sink = win + (uint32_t)dctr + feed;

    // The identical table in the half of the scratchpad psyqo is not using.
    for (uint32_t i = 0; i < SPM_WORDS; i++)
        SPM[i] = (uint32_t)s_prim8[i * 2] | ((uint32_t)s_prim8[i * 2 + 1] << 16);
    const uint16_t *const prim8Spm = (const uint16_t *)0x1f800200;
    ARMB("sym prim8 spm    ", { win = 0; dctr = 16; feed = 0; }, {
        while (dctr >= 0) {
            uint32_t half = 0;
            if (feed < BITS_BYTES) half = bitsH[feed >> 1];
            feed += 2;
            win |= half << dctr;
            dctr -= 16;
        }
        const uint32_t p = prim8Spm[win >> 24];
        if (p) {
            const uint32_t len = p >> 9;
            acc += c_bsdecVlc[p & 0x1ffu];
            win <<= len;
            dctr += (int32_t)len;
        } else {
            const uint32_t n = clzTable8Sat(clz8, win);
            const uint32_t sw = c_bsdecVlcSuffixBits[n];
            const uint32_t t = win << n;
            const uint32_t e = c_bsdecVlc[off2[n] + (t >> (31 - sw))];
            const uint32_t sb = BSDEC_VLC_SUFFIXBITS(e);
            win = t << (sb + 1);
            dctr += (int32_t)(n + 1 + sb);
            acc += e;
        }
    });
    g_sink = win + (uint32_t)dctr + feed;

    const uint32_t bytesWalked = feed;

    for (uint32_t i = 0; i < SPM_WORDS; i++) SPM[i] = s_spmSave[i];

    ramsyscall_printf("BSB: iters %d, counter 2 at sysclk/8, 1 tick = 8 cycles\n", ITERS);
    // The whole-symbol arms all walk the same payload, so this is one number and
    // it has to be under the buffer. If it reaches it, the tail of every arm
    // decoded synthetic zeros onto the cheap sentinel and every figure below is
    // faster than the thing it claims to measure.
    ramsyscall_printf("BSB: payload walked %d of %d bytes%s\n", bytesWalked, BITS_BYTES,
                      bytesWalked >= BITS_BYTES ? "  ** EXHAUSTED **" : "");
    const uint32_t firstSym = s_noxBase + 1;
    for (uint32_t i = 0; i < s_arms; i++) {
        const int32_t net = (int32_t)s_best[i] - (int32_t)s_best[s_baseIdx[i]];
        // cycles per iteration, x100 so the fraction survives an integer printf
        const int32_t cyc100 = (net * 8 * 100) / (int32_t)ITERS;
        // A whole-symbol arm that does not accumulate what the first one did
        // decoded a different stream, so its timing is about something else.
        const int mismatch = s_baseIdx[i] != 0 && i > s_noxBase && s_check[i] != s_check[firstSym];
        ramsyscall_printf("BSB: %s lo %5d hi %5d  net %5d  %3d.%02d cyc/iter%s%s\n", s_name[i], s_best[i],
                          s_worst[i], net, cyc100 / 100, (cyc100 < 0 ? -cyc100 : cyc100) % 100,
                          (s_worst[i] > WRAP_WARN || net < 0) ? "  ** SUSPECT **" : "",
                          mismatch ? "  ** CHECK MISMATCH **" : "");
    }
    ramsyscall_printf("BSB: check %08x over %d symbols\n", s_check[firstSym], ITERS);
    ramsyscall_printf("BSB: end\n");
}

class Bench final : public psyqo::Application {
    void prepare() override;
    void createScene() override;
};

class BenchScene final : public psyqo::Scene {
    void frame() override;
    bool m_done = false;
};

Bench g_app;
BenchScene g_scene;

}  // namespace

void Bench::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
}

void Bench::createScene() { pushScene(&g_scene); }

void BenchScene::frame() {
    if (m_done) return;
    m_done = true;
    runBench();
}

int main() { return g_app.run(); }
