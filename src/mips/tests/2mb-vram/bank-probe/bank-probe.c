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

// Test 1: VRAM bank presence probe.
//
// Foundation test for the rest of the suite. Triangulates between three
// possible address-decode behaviors of GP1(0x09):
//
//   1. Real second bank: address bit 9 of Y is honored. (8, 0) and (8, 512)
//      are distinct physical pixels; sentinels written at one do not
//      interfere with the other.
//   2. Mirror: the upper-bank address bit is masked off. Writing to
//      (8, 512) actually lands at (8, 0); reading (8, 512) also reads
//      (8, 0). On retail hardware this is the documented behavior with
//      GP1(0x09) bit0 = 0.
//   3. Open bus: the upper-bank region is unmapped. Reads return garbage,
//      writes are dropped. On retail hardware this is the documented
//      behavior with GP1(0x09) bit0 = 1.
//
// A naive single-coordinate round-trip (write S to y=512, read y=512, check
// for S) cannot distinguish (1) from (2) - both round-trip the sentinel. We
// must use distinct sentinels at distinct addresses and check whether the
// address bit was actually honored.

#include "probe-common.h"

#define SENT_LOWER_0    0x5a5au
#define SENT_LOWER_511  0xa5a5u
#define SENT_UPPER_512  0x1234u
#define SENT_UPPER_1023 0xfedcu
#define PROBE_X         8

typedef enum {
    DECODE_REAL,     // address bit honored, distinct upper bank
    DECODE_MIRROR,   // upper address aliases to lower
    DECODE_OPENBUS,  // upper region returns garbage / drops writes
    DECODE_BROKEN,   // lower bank itself fails - suite is meaningless
} BankDecode;

static const char* decodeName(BankDecode d) {
    switch (d) {
        case DECODE_REAL:
            return "real";
        case DECODE_MIRROR:
            return "mirror";
        case DECODE_OPENBUS:
            return "open-bus";
        case DECODE_BROKEN:
            return "broken";
    }
    return "?";
}

// One probe pass under a given GP1(0x09) value. Writes four distinct
// sentinels at four distinct Y addresses, then reads them all back and
// classifies the upper-bank decode behavior. Upper writes come AFTER
// lower writes so that mirroring (upper aliasing to lower) is visible
// as a stomped lower bank on readback.
static BankDecode probePass(uint32_t gp1_09_value, int* lowerOk) {
    probeReset();
    gp1_09(gp1_09_value);

    writePixel(PROBE_X, 0, SENT_LOWER_0);
    writePixel(PROBE_X, 511, SENT_LOWER_511);
    writePixel(PROBE_X, 512, SENT_UPPER_512);
    writePixel(PROBE_X, 1023, SENT_UPPER_1023);

    uint16_t r0 = readPixel(PROBE_X, 0);
    uint16_t r511 = readPixel(PROBE_X, 511);
    uint16_t r512 = readPixel(PROBE_X, 512);
    uint16_t r1023 = readPixel(PROBE_X, 1023);

    PROBE_RESULT("bank-probe gate=%02x r0=%04x r511=%04x r512=%04x r1023=%04x",
                 gp1_09_value, r0, r511, r512, r1023);

    int lowerCleanRoundTrip = (r0 == SENT_LOWER_0) && (r511 == SENT_LOWER_511);
    int upperCleanRoundTrip = (r512 == SENT_UPPER_512) && (r1023 == SENT_UPPER_1023);
    int mirrorPattern = (r0 == SENT_UPPER_512) && (r511 == SENT_UPPER_1023) &&
                        (r512 == SENT_UPPER_512) && (r1023 == SENT_UPPER_1023);

    if (lowerCleanRoundTrip && upperCleanRoundTrip) {
        *lowerOk = 1;
        return DECODE_REAL;
    }
    if (mirrorPattern) {
        *lowerOk = 1;
        return DECODE_MIRROR;
    }
    if (lowerCleanRoundTrip && !upperCleanRoundTrip) {
        *lowerOk = 1;
        return DECODE_OPENBUS;
    }
    *lowerOk = 0;
    return DECODE_BROKEN;
}

int main(void) {
    ramsyscall_printf("\n=== 573 bank-probe ===\n");

    ProbeStats stats;
    probeStatsInit(&stats);

    int lowerOk0 = 0;
    int lowerOk1 = 0;
    BankDecode gate0 = probePass(0, &lowerOk0);
    BankDecode gate1 = probePass(1, &lowerOk1);

    // Reset gate to 0 before leaving so any subsequent code starts in a
    // retail-compatible state.
    gp1_09(0);

    PROBE_RESULT("bank-probe summary lower_ok=%d gate0=%s gate1=%s",
                 lowerOk0 && lowerOk1, decodeName(gate0), decodeName(gate1));

    if (lowerOk0 && lowerOk1) {
        PROBE_PASS(&stats, "lower-bank round-trips under both gate polarities");
    } else {
        PROBE_FAIL(&stats, "lower-bank round-trip failed (lowerOk0=%d lowerOk1=%d)",
                   lowerOk0, lowerOk1);
    }

    int gate0Real = (gate0 == DECODE_REAL);
    int gate1Real = (gate1 == DECODE_REAL);

    if (gate0Real || gate1Real) {
        if (gate0Real && !gate1Real) {
            PROBE_PASS(&stats, "verdict=arcade-gate0-opens-upper");
        } else if (!gate0Real && gate1Real) {
            PROBE_PASS(&stats, "verdict=arcade-gate1-opens-upper");
        } else {
            PROBE_PASS(&stats, "verdict=both-polarities-open-upper");
        }
    } else if (gate0 != DECODE_BROKEN && gate1 != DECODE_BROKEN) {
        PROBE_INFO(&stats, "verdict=retail-or-no-upper-bank gate0=%s gate1=%s",
                   decodeName(gate0), decodeName(gate1));
    } else {
        PROBE_FAIL(&stats, "verdict=broken gate0=%s gate1=%s", decodeName(gate0),
                   decodeName(gate1));
    }

    probeStatsSummary(&stats, "bank-probe");

    while (1) {
    }
    return 0;
}
