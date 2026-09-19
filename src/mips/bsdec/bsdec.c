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

#include "bsdec.h"

#include "bsdec-vlc.h"

/*
 * Every code in Sony's AC book is N zeros, a marker 1, then a suffix whose width
 * depends only on N - so the decode is a count-leading-zeros, a shift past the
 * marker, and one indexed load. That is worth arranging for on this machine
 * specifically: the R3000A has no CLZ opcode, since that is MIPS32 and the
 * console predates it, and GTE LZCS/LZCR is the only count-leading hardware
 * there is. The alternative is a bit-at-a-time walk, which on a 17-bit code
 * costs seventeen branches.
 *
 * The rearranged book is in bsdec-vlc.h, generated from the same table the host
 * encoder uses. It came out with 269 slots and no holes, which is a stronger
 * property than prefix-free: the book saturates, so any window whose leading-zero
 * count is within range decodes to a symbol and the dispatch has no error arm.
 *
 * __builtin_clz lowers to __clzsi2, which common/crt0/clz.c implements on the
 * GTE. Only the zero case is handled here, because the builtin leaves it
 * undefined and this decoder relies on 32 to detect a run of zeros past the end
 * of the payload.
 */

static inline uint32_t bsdecClz32(uint32_t v) { return v ? (uint32_t)__builtin_clz(v) : 32u; }

#ifdef BSDEC_PROFILE
/* Counter 2 on the system clock over 8 is 4.23 MHz, so one tick is 236 ns and a
 * 16-bit counter wraps every 15.5 ms. Every phase timed below is one block, far
 * under that, so a 16-bit delta never aliases. Counter 1 on hblanks is 64 us and
 * cannot see inside a block at all, which is why this uses a different one from
 * the frame-level harness. */
#include "common/hardware/counters.h"
struct BsdecProf g_bsdecProf;
#define PROF2() (COUNTERS[2].value)
#define PROF2_ACC(t0, acc) (acc) += (uint16_t)(COUNTERS[2].value - (t0))
#define PROF_COUNT(f) (g_bsdecProf.f++)
#define PROF_ADD(f, n) (g_bsdecProf.f += (n))
struct BsdecProf *bsdecProfile(void) { return &g_bsdecProf; }
void bsdecProfileReset(void) {
    COUNTERS[2].mode = 0x0200; /* system clock / 8, free running */
    __builtin_memset(&g_bsdecProf, 0, sizeof(g_bsdecProf));
}
#else
#define PROF2() 0
#define PROF2_ACC(t0, acc) ((void)0)
#define PROF_COUNT(f) ((void)0)
#define PROF_ADD(f, n) ((void)0)
#endif

struct BsdecBits {
    const uint8_t *base; /* payload, i.e. the frame past its 8-byte header */
    uint32_t bytes;      /* payload bytes; always even, the writer flushes halfwords */
    uint32_t availBits;  /* bits the payload actually carries */
    uint32_t pos;        /* bits consumed */
    uint32_t feed;       /* bytes shifted into the window, synthetic zeros included */
    uint32_t window;     /* next bit at bit 31 */
    int32_t valid;       /* bits in the window, including zeros past the payload */
    uint32_t overrun;    /* sticky: a consumed bit came from past the payload */
};

/*
 * Top the window up to at least 25 bits, which covers the longest thing anything
 * below peeks at: an escape is 6 bits of marker and 16 of payload, and the
 * longest code is 17.
 *
 * Bytes leave the payload in the order b1, b0, b3, b2, ... - the index XOR 1 -
 * because codes are MSB-first inside little-endian halfwords. Past the end the
 * window takes zeros and says nothing: no code is all zeros, so a run of them
 * pushes the leading-zero count out of range and the block truncates. Feeding
 * zeros is deliberately NOT an overrun on its own, because peeking past the end
 * is normal for a short code near the last halfword; only consuming is.
 */
static void bsdecRefill(struct BsdecBits *b) {
    PROF_COUNT(refillCalls);
    while (b->valid <= 24) {
        PROF_COUNT(refillBytes);
        uint32_t byte = 0;
        if (b->feed < b->bytes) byte = b->base[b->feed ^ 1];
        b->feed++;
        b->window |= byte << (24 - b->valid);
        b->valid += 8;
    }
}

static uint32_t bsdecPeek(const struct BsdecBits *b, unsigned bits) { return b->window >> (32 - bits); }

/* NO OVERRUN TEST HERE ON PURPOSE. It used to run on every consume, two or three
 * times per AC symbol, and a compare-and-branch was all it did to maintain a flag
 * that `pos > availBits` already answers from state this keeps anyway. The tests
 * that used to read the flag ask that question directly instead, which is the
 * same answer at every point that reads it and costs nothing per symbol. */
static void bsdecConsume(struct BsdecBits *b, unsigned bits) {
    b->pos += bits;
    b->window <<= bits;
    b->valid -= bits;
}

/* A consumed bit came from past the payload. Peeking past the end is normal near
 * the last halfword, which is why this asks about `pos` and not about `feed`. */
static int bsdecPastEnd(const struct BsdecBits *b) { return b->pos > b->availBits; }

uint32_t bsdecRlHalfwords(const void *in, uint32_t inBytes) {
    const uint8_t *p = (const uint8_t *)in;
    if (inBytes < 8) return 0;
    return ((uint32_t)p[0] | ((uint32_t)p[1] << 8)) * 2;
}

struct BsdecResult bsdecFrame(const void *in, uint32_t inBytes, uint16_t *out, uint32_t outHalfwords) {
    struct BsdecResult r;
    const uint8_t *p = (const uint8_t *)in;
    struct BsdecBits b;
    uint32_t target, count = 0, dc;
    int32_t lastDc[3];
    unsigned blockInMb = 0, version, qScale, magic;

    r.mdecCommand = 0;
    r.halfwords = 0;
    r.blocks = 0;
    r.qScale = 0;
    r.version = 0;
    r.error = BSDEC_OK;

    if (inBytes < 8) {
        r.error = BSDEC_SHORT;
        return r;
    }
    magic = (unsigned)p[2] | ((unsigned)p[3] << 8);
    if (magic != 0x3800) {
        r.error = BSDEC_NOT_BS;
        return r;
    }
    qScale = (unsigned)p[4] | ((unsigned)p[5] << 8);
    version = (unsigned)p[6] | ((unsigned)p[7] << 8);
    if (version == 0 || version > 3) {
        r.error = BSDEC_BAD_VERSION;
        return r;
    }
    r.mdecCommand = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    r.qScale = (uint16_t)qScale;
    r.version = (uint8_t)version;

    /* The only use of outHalfwords: past this point every write is bounded by
       target instead, so the output length is exactly what the MDEC command
       declares whether or not the caller left slack. */
    target = ((uint32_t)p[0] | ((uint32_t)p[1] << 8)) * 2;
    if (outHalfwords < target) {
        r.error = BSDEC_OUTPUT_TOO_SMALL;
        return r;
    }

    b.base = p + 8;
    b.bytes = (inBytes - 8) & ~1u;
    b.availBits = b.bytes * 8;
    b.pos = 0;
    b.feed = 0;
    b.window = 0;
    b.valid = 0;
    b.overrun = 0;

    lastDc[0] = lastDc[1] = lastDc[2] = 0;

    /*
     * Stop at the last block that FITS and pad the rest, rather than decoding
     * into exhausted bits. Sony's DecDCTvlc loops on the padded length and so
     * reads one more block header out of nothing, writing a spurious DC word
     * into the first pad slot; measured on retail streams, one halfword each
     * time. The padding is beyond the picture's block count, so nothing reads
     * it, and the documentation says the decoder ADDS footers to reach the
     * 32-word boundary, which is what this does.
     */
    while (count < target) {
        const uint32_t blockStart = count;
        const uint16_t tDc = PROF2();
        if (b.overrun) break;

        if (version != 3) {
            /* v1 and v2 both carry the DC raw. Only v3 delta-codes it, whatever
             * DecDCTvlc's `type == 2` test implies. */
            bsdecRefill(&b);
            dc = bsdecPeek(&b, 10);
            bsdecConsume(&b, 10);
        } else {
            const unsigned luma = blockInMb >= 2;
            const uint8_t *code = luma ? c_bsdecDcLumaCode : c_bsdecDcChromaCode;
            const uint8_t *bits = luma ? c_bsdecDcLumaBits : c_bsdecDcChromaBits;
            unsigned pred, size = 9, s;
            int32_t delta = 0;
            bsdecRefill(&b);
            for (s = 0; s < 9; s++) {
                PROF_COUNT(dcScanIters);
                if (bsdecPeek(&b, bits[s]) == code[s]) {
                    size = s;
                    break;
                }
            }
            if (size == 9) {
                count = blockStart;
                b.overrun = 1;
                break;
            }
            bsdecConsume(&b, bits[size]);
            if (size > 0) {
                const uint32_t raw = bsdecPeek(&b, size);
                bsdecConsume(&b, size);
                /* Top bit set means the value is positive as stored; clear means
                 * it was stored as an offset from -(2^size - 1). */
                delta = (raw & (1u << (size - 1))) ? (int32_t)raw : (int32_t)raw - (int32_t)((1u << size) - 1);
            }
            pred = luma ? 2u : blockInMb;
            /* The predictor is NOT clamped to ten bits between blocks - some Sony
             * decoders let it run and wrap only at use, and psxavenc's encoder
             * exploits exactly that to turn a large jump into a small delta. */
            lastDc[pred] += delta * 4;
            dc = (uint32_t)lastDc[pred] & 0x3ff;
            if (++blockInMb == 6) blockInMb = 0;
        }
        if (bsdecPastEnd(&b)) b.overrun = 1;
        if (b.overrun) break;
        if (count >= target) {
            count = blockStart;
            r.error = BSDEC_OVERLONG;
            break;
        }
        out[count++] = (uint16_t)(((qScale & 0x3f) << 10) | (dc & 0x3ff));
        PROF2_ACC(tDc, g_bsdecProf.tDc);
        PROF_COUNT(blocks);

        {
        const uint16_t tAc = PROF2();
        for (;;) {
            uint32_t n, e;
            PROF_COUNT(acSymbols);
            unsigned w, kind;
            bsdecRefill(&b);
            /* bsdecClz32's own sign-bit branch does double duty here: the
             * MSB-set group is where the end-of-block code lives, so every
             * block exits through it and it is the hot path as well as the
             * correction. */
            /* n is 0..32 and both dispatch tables are 33 long, the rows past
             * the book pointing at an EOB sentinel, so an impossible prefix ends
             * the block through the ordinary path instead of through a range
             * test. The VALID test that used to follow could not fire either -
             * the book saturates its slots. What is NOT dead, and is the one
             * test left here, is the bound on `out`: a block writes one halfword
             * per code and nothing in the loop limits how many codes a malformed
             * stream can spell, so this is the only thing standing between it
             * and the caller's buffer. The end-of-stream test is gone from here
             * because running past the payload discards the whole block anyway,
             * which the check after the loop does once instead of per symbol. */
            n = bsdecClz32(b.window);
            bsdecConsume(&b, n + 1);
            w = c_bsdecVlcSuffixBits[n];
            e = c_bsdecVlc[c_bsdecVlcOffset[n] + (w ? bsdecPeek(&b, w) : 0u)];
            bsdecConsume(&b, BSDEC_VLC_SUFFIXBITS(e));
            if (count >= target) {
                count = blockStart;
                r.error = BSDEC_OVERLONG;
                break;
            }
            kind = BSDEC_VLC_KIND(e);
            if (kind == BSDEC_VLC_ESCAPE) {
                /* 16 bits total after the marker: a 6-bit run then a 10-bit
                 * signed level, which is the run-level halfword verbatim. The
                 * doc's Table 1-9 lists 16-bit patterns for the LEVEL alone;
                 * reading it that way costs 28 bits and desyncs at the first
                 * escape. An escape running off the end is left for the next
                 * code fetch to catch, which discards the block. */
                bsdecRefill(&b);
                out[count++] = (uint16_t)bsdecPeek(&b, 16);
                bsdecConsume(&b, 16);
            } else {
                out[count++] = BSDEC_VLC_HALFWORD(e);
                if (kind == BSDEC_VLC_EOB) break;
            }
        }
        PROF2_ACC(tAc, g_bsdecProf.tAc);
        }
        /* A block is only sound if every bit in it came from the payload, and a
         * block that ran off the end is discarded whole. Asking once here is what
         * pays for the loop above having no end-of-stream test in it: the per
         * symbol version discovered the same thing a few symbols earlier and
         * threw away exactly the same block. */
        if (bsdecPastEnd(&b)) {
            b.overrun = 1;
            count = blockStart;
        }
        if (b.overrun || r.error != BSDEC_OK) break;
        r.blocks++;
    }

    /*
     * Running out of bits is the NORMAL end of a frame, not a fault: the header's
     * length counts a DMA pad the bitstream does not carry, so the last block is
     * always followed by a reach into nothing. What separates that from real
     * damage is how big the shortfall is. The length is ceil(real/64)*64 by
     * construction - psxavenc rounds the halfword count up to a 32-word boundary
     * and only then halves it - so a sound frame lands within 63 halfwords of it,
     * and anything further short means the bitstream ended early.
     *
     * That is the strongest completeness test the header alone supports: a frame
     * that lost only its last few halfwords reads as sound here. A caller that
     * knows the picture size knows the block count too - six per macroblock - and
     * `blocks` is there to be checked against it.
     */
    if (r.error == BSDEC_OK && b.overrun && count < target && (target - count) >= 64) r.error = BSDEC_TRUNCATED;
    /* The footers the header's length implies and the bitstream does not carry. */
    while (count < target) out[count++] = 0xfe00;
    r.halfwords = count;
    return r;
}
