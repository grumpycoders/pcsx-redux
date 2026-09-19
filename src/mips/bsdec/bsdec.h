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

#pragma once

/*
 * A BS frame decoder. Takes the compressed frame a .STR video sector chain
 * carries and produces the run-level halfwords the MDEC wants, which the caller
 * then DMAs to MDEC0. Plain C, no dependencies beyond stdint, no allocation, no
 * hardware access - it is pure bitstream work, so it builds and runs on a host
 * as well as on the console.
 *
 * BS is Sony's own STR video format, described in FileFormat47 pp.1-20..1-21
 * with the code book at pp.29-31. Three things about it that its documentation
 * does not make easy, all measured against retail discs:
 *
 *  - Versions 1 and 2 carry a raw 10-bit DC per block. ONLY version 3
 *    delta-codes it. Sony's own DecDCTvlc tests `type == 2` and sends version 1
 *    down the delta path, where it decodes 149 of 4416 halfwords and then fills
 *    the rest with end-of-block markers - while returning success. All three
 *    versions ship: Suikoden II's _KONAMIC.STR is v1, Castlevania SOTN's
 *    LOGO15XA.STR is v3, and everything else measured is v2.
 *
 *  - Word 0 of the header is not a magic number, it is the MDEC(1) decode
 *    command, ready to write to MDEC0 before the DMA. mdecCommand below hands it
 *    back rather than making the caller rebuild it.
 *
 *  - The header's length counts the DMA padding that the bitstream does not
 *    carry, because it describes what DMA0 will receive rather than what was
 *    encoded. bsdecRlHalfwords() returns that padded count, which is the buffer
 *    size to allocate; the decoder fills the tail with 0xfe00 itself.
 *
 * Bit order: codes are MSB-first inside little-endian halfwords. Sony's "coded
 * bit sequences are ordered starting with low-order bits" is about the byte
 * order, not the bits inside a code, and reading it the other way gives a
 * well-formed stream that decodes to garbage.
 */

#include <stdint.h>

#ifdef __mips__
#include "common/hardware/cop2.h"
#endif

/*
 * Leading zeros of a 32-bit word, 0 to 32. Here in the header rather than hidden
 * in the decoder because the decoder's hot path and any test of that path have to
 * be the same code - a self-test that builds its own copy of this measures the
 * copy.
 *
 * The R3000A has no CLZ opcode; that is MIPS32 and the console predates it. GTE
 * LZCS/LZCR is the only count-leading hardware on the machine, which is what
 * makes it worth shaping a bitstream decoder around. Two things about it:
 *
 *  - It counts leading bits EQUAL TO THE SIGN BIT, so on a negative input it
 *    returns the leading-ONES count and answers 1 for both 0x80000000 and
 *    0x40000000-with-the-top-bit-set. The branch below is that correction, not
 *    an optimisation. LZCR(0) is 32, which is already what this wants.
 *  - It is the one corner of the GTE that does not interlock, so the write and
 *    the read each need two dummy opcodes after them; cop2_put and cop2_get
 *    carry those. One nop is NOT enough - the read comes back with the previous
 *    write's answer about a third of the time, and a single isolated call passes
 *    by luck, so only a loop self-test on real silicon exposes it.
 */
static inline uint32_t bsdecClz32(uint32_t v) {
#ifdef __mips__
    uint32_t r;
    if ((int32_t)v < 0) return 0;
    cop2_put(30, v);
    cop2_get(31, r);
    return r;
#else
    return v ? (uint32_t)__builtin_clz(v) : 32u;
#endif
}

enum BsdecError {
    BSDEC_OK = 0,
    BSDEC_SHORT,          /* fewer than 8 bytes, so not even a header */
    BSDEC_NOT_BS,         /* word 0 is not the MDEC decode command */
    BSDEC_BAD_VERSION,    /* version field outside 1..3 */
    BSDEC_OUTPUT_TOO_SMALL, /* out holds fewer than bsdecRlHalfwords() entries */
    BSDEC_TRUNCATED,      /* the bitstream ended more than a pad block early */
};

struct BsdecResult {
    uint32_t mdecCommand; /* write this to MDEC0 before the DMA */
    uint32_t halfwords;   /* run-level halfwords written, padding included */
    uint32_t blocks;      /* blocks the bitstream actually carried; check this against
                           * the count the picture size implies, six per macroblock,
                           * which the caller knows and a BS header does not */
    uint16_t qScale;      /* the one quantization scale the whole frame uses */
    uint8_t version;      /* 1, 2 or 3 */
    uint8_t error;        /* enum BsdecError */
};

/*
 * How many run-level halfwords a frame decodes to, read straight out of the
 * header. Returns 0 if the buffer is too short to hold a header. Cheap enough
 * to call before every decode; it reads two bytes.
 */
uint32_t bsdecRlHalfwords(const void *in, uint32_t inBytes);

/*
 * Decode one frame. `in` must be halfword aligned - the bit reader walks the
 * payload in halfword pairs - and in practice it is, since a frame arrives in
 * sector payloads. `out` needs bsdecRlHalfwords(in, inBytes) entries.
 *
 * On a truncated or malformed bitstream the result reports BSDEC_TRUNCATED and
 * `blocks` says how far it got: the partially decoded block is discarded and the
 * remainder is padded with end-of-block markers, so the output is always a
 * complete, DMA-able buffer that renders as much of the frame as arrived. That
 * is deliberate - a video decoder that refuses a damaged frame outright drops a
 * frame where it could have shown most of one.
 */
struct BsdecResult bsdecFrame(const void *in, uint32_t inBytes, uint16_t *out, uint32_t outHalfwords);
