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
 * Host-side adversarial harness for the BS decoder. bsdec is plain C with no
 * dependencies beyond stdint, which is the property that makes this possible:
 * the same translation unit the console runs compiles and runs here, so the
 * cases that need thousands of decodes do not need a console at all.
 *
 *   cc -O2 -fno-strict-aliasing -I. -o hostfuzz hostfuzz.c bsdec.c
 *   ./hostfuzz frame.bs [expected-blocks]
 *
 * PASS THE BLOCK COUNT. Six blocks per macroblock and the picture size is the
 * caller's to know, so a BS header cannot check it and neither can this without
 * being told: 320x240 is 300 macroblocks, so 1800. Without it the only thing
 * asserted about a sound decode is that it filled the buffer, and a desynced
 * decoder fills it too. One did - a refill that left `feed` odd returned 1861
 * blocks of confident garbage and this harness said ok.
 *
 * A frame is one entry of a packstream blob, not the blob: the offset table
 * starts at 0x118 and holds one 32-bit absolute offset per frame, so frame i
 * runs from offsets[i] to offsets[i+1]. A frame starts with its halfword count
 * and 0x3800.
 *
 * WHAT IT IS FOR. The AC loop has one bounds test in it, `count >= target`, and
 * a dispatch whose rows past the code book are an end-of-block sentinel. A sound
 * frame indexes that sentinel about once, at the end of the payload, in the block
 * the past-end check then discards - so its contents never reach `out` and a
 * corrupted sentinel leaves every decode of a real frame byte-identical. The
 * bounds test is not reached at all. Both need input built to reach them with an
 * observable result, which is what this makes.
 *
 * The three properties it asserts, and why each one is here:
 *
 *  - NOTHING IS WRITTEN OUTSIDE THE BUFFER THE CALLER PASSED, at any truncation
 *    length. A block emits one halfword per code and nothing caps how many codes
 *    a malformed stream can spell, so the bound is the only thing between such a
 *    stream and the caller's memory. Canaries either side catch a write the
 *    returned halfword count would not report.
 *  - A SOUND FRAME DECODES TO ITS DECLARED LENGTH, which is the control: without
 *    it a harness that broke the decoder outright would pass the other two.
 *  - A FRAME CARRYING A RUN OF ZERO BITS KEEPS GOING. That run is the only thing
 *    that drives the leading-zero count past the book, so it is the sentinel's
 *    reachability test. A decoder that aborts the frame there decodes a fraction
 *    of the blocks, which is what this compares against.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bsdec.h"

#define CANARY 0xa5a5
#define SLACK 256   /* halfwords of canary either side of the output window */
#define MAX_IN (1 << 20)
#define MAX_HW 65536

static uint8_t s_in[MAX_IN];
static uint8_t s_mut[MAX_IN];
static uint16_t s_buf[MAX_HW + 2 * SLACK];

struct Outcome {
    uint32_t blocks;
    uint32_t halfwords;
    uint32_t sum;
    uint8_t error;
    int outOfBounds;
};

/* Decode `bytes` of `in` into a canaried window and report what came back. The
 * canary either side is the point: `halfwords` is the decoder's own account of
 * what it wrote, and a bound that failed would not appear in it. */
static struct Outcome run(const uint8_t *in, uint32_t bytes, uint32_t target) {
    struct Outcome o;
    struct BsdecResult r;
    uint16_t *out = s_buf + SLACK;
    uint32_t i;

    for (i = 0; i < MAX_HW + 2 * SLACK; i++) s_buf[i] = CANARY;
    r = bsdecFrame(in, bytes, out, target);

    o.error = r.error;
    o.blocks = r.blocks;
    o.halfwords = r.halfwords;
    o.outOfBounds = r.halfwords > target;
    for (i = 0; i < SLACK; i++)
        if (s_buf[i] != CANARY) o.outOfBounds = 1;
    for (i = target; i < MAX_HW + SLACK; i++)
        if (out[i] != CANARY) o.outOfBounds = 1;

    o.sum = 0;
    for (i = 0; i < (r.halfwords < target ? r.halfwords : target); i++) o.sum = o.sum * 31u + out[i];
    return o;
}

/* Every truncation length from a bare header to the whole frame. Returns the
 * number of lengths that wrote outside the window. */
static uint32_t sweep(const uint8_t *in, uint32_t bytes, uint32_t target, const char *what) {
    uint32_t len, bad = 0, truncated = 0, ok = 0;
    for (len = 8; len <= bytes; len++) {
        const struct Outcome o = run(in, len, target);
        if (o.outOfBounds) {
            if (bad == 0) printf("  OUT OF BOUNDS at %s length %u: halfwords %u against target %u\n", what, len,
                                 o.halfwords, target);
            bad++;
        }
        if (o.error == BSDEC_TRUNCATED) truncated++;
        if (o.error == BSDEC_OK) ok++;
    }
    printf("  %s: %u lengths swept, %u truncated, %u clean, %u out of bounds\n", what, bytes - 7, truncated, ok, bad);
    return bad;
}

int main(int argc, char **argv) {
    FILE *f;
    uint32_t bytes, target, bad = 0, zeroAt;
    struct Outcome clean, zeroRun;
    int fail = 0;

    uint32_t expectBlocks = 0;

    if (argc < 2) {
        fprintf(stderr, "usage: hostfuzz <frame.bs> [expected-blocks]\n");
        return 2;
    }
    if (argc > 2) expectBlocks = (uint32_t)strtoul(argv[2], NULL, 0);
    f = fopen(argv[1], "rb");
    if (!f) {
        perror(argv[1]);
        return 2;
    }
    bytes = (uint32_t)fread(s_in, 1, MAX_IN, f);
    fclose(f);

    target = bsdecRlHalfwords(s_in, bytes);
    if (bytes < 16 || target == 0 || target > MAX_HW) {
        fprintf(stderr, "%s: %u bytes declaring %u halfwords, which this harness cannot hold\n", argv[1], bytes,
                target);
        return 2;
    }
    printf("%s: %u bytes, %u halfwords declared\n", argv[1], bytes, target);

    /* The control. A harness that broke the decoder outright would pass every
     * bounds assertion below, so this one runs first and its failure is fatal. */
    clean = run(s_in, bytes, target);
    printf("  sound frame: err %u, %u blocks, %u halfwords\n", clean.error, clean.blocks, clean.halfwords);
    if (clean.error != BSDEC_OK || clean.halfwords != target || clean.blocks == 0) {
        printf("  FAIL: a sound frame did not decode to its declared length\n");
        fail = 1;
    }
    if (expectBlocks == 0) {
        printf("  NOTE: block count unchecked. Pass it as argv[2] - six per macroblock - or a\n");
        printf("        decoder that desyncs and fills the buffer with the wrong number of\n");
        printf("        short blocks passes everything below.\n");
    } else if (clean.blocks != expectBlocks) {
        printf("  FAIL: %u blocks against the %u the picture calls for\n", clean.blocks, expectBlocks);
        fail = 1;
    }

    /* Eight zero bytes mid-payload. No code in the book is all zeros, so this is
     * what pushes the leading-zero count past the last row the book fills. */
    memcpy(s_mut, s_in, bytes);
    zeroAt = 8 + (bytes - 8) / 2;
    memset(s_mut + zeroAt, 0, 8);
    zeroRun = run(s_mut, bytes, target);
    printf("  zero run at byte %u: err %u, %u blocks, %u halfwords\n", zeroAt, zeroRun.error, zeroRun.blocks,
           zeroRun.halfwords);
    if (zeroRun.halfwords != target) {
        printf("  FAIL: a frame carrying a zero run did not fill its declared length\n");
        fail = 1;
    }
    if (zeroRun.blocks * 10 < clean.blocks * 9) {
        printf("  FAIL: the zero run cost %u of %u blocks, so the sentinel did not carry it\n",
               clean.blocks - zeroRun.blocks, clean.blocks);
        fail = 1;
    }

    bad += sweep(s_in, bytes, target, "sound");
    bad += sweep(s_mut, bytes, target, "zero run");
    if (bad) {
        printf("FAIL: %u truncation lengths wrote outside the caller's buffer\n", bad);
        fail = 1;
    }
    printf("%s\n", fail ? "FAIL" : "ok");
    return fail;
}
