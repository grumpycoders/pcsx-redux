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

enum BsdecError {
    BSDEC_OK = 0,
    /* Refusals. Nothing is written to out. */
    BSDEC_SHORT,            /* fewer than 8 bytes, so not even a header */
    BSDEC_NOT_BS,           /* word 0 is not the MDEC decode command */
    BSDEC_BAD_VERSION,      /* version field outside 1..3 */
    BSDEC_OUTPUT_TOO_SMALL, /* out holds fewer than bsdecRlHalfwords() entries */
    /* Malformed bitstreams. out still holds a complete, DMA-able frame. */
    BSDEC_TRUNCATED,        /* ended more than a pad block early; rest padded */
    BSDEC_OVERLONG,         /* carried more than the header's length; excess dropped */
};

/**
 * @brief Whether a result's output buffer is usable.
 *
 * @details True for success and for both malformed-bitstream statuses, which
 * still produce a complete frame of the length the header declares. A caller
 * that treats every non-zero status as fatal throws away frames it could have
 * displayed, so prefer this over comparing against BSDEC_OK.
 */
static inline int bsdecUsable(uint8_t error) {
    return error == BSDEC_OK || error == BSDEC_TRUNCATED || error == BSDEC_OVERLONG;
}

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

/**
 * @brief How many run-level halfwords a frame decodes to.
 *
 * @details Read straight out of the header, so it costs two bytes and can be
 * called before every decode. This is the size out must have. Returns 0 if the
 * buffer is too short to hold a header.
 */
uint32_t bsdecRlHalfwords(const void *in, uint32_t inBytes);

/**
 * @brief Decode one BS frame into MDEC run-level halfwords.
 *
 * @details in must be halfword aligned - the bit reader walks the payload in
 * halfword pairs - and in practice it is, since a frame arrives in sector
 * payloads. out needs bsdecRlHalfwords(in, inBytes) entries.
 *
 * The output is always a complete frame of exactly that many halfwords whenever
 * bsdecUsable() holds, whatever the bitstream did: a partially decoded block is
 * discarded, a short bitstream is padded with end-of-block markers, and a
 * bitstream carrying more than its header declares is cut at the declared
 * length. That is deliberate - a video decoder that refuses a damaged frame
 * outright drops a frame where it could have shown most of one.
 */struct BsdecResult bsdecFrame(const void *in, uint32_t inBytes, uint16_t *out, uint32_t outHalfwords);
