/*

MIT License

Copyright (c) 2026 Nicolas "Pixel" Noble

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

#include "correct.h"

#include "tables.h"

// This is the counterpart to edcecc.c: where that file generates the EDC and
// the P/Q ECC for a Mode 2 sector, this one verifies and repairs one. The
// layout, the geometry of the P and Q lines, and the Galois field are all
// exactly as described in edcecc.c, so this file assumes that file has been
// read first and does not repeat the derivations, only the parts specific to
// going backwards.

// --- Galois field helpers -------------------------------------------------

// Multiplication is, as in the encoder, addition of discrete logarithms. The
// log of either operand is at most 254, so their sum is at most 508, which is
// why gf_exp_table is 512 entries long: we never have to take a modulo.
static uint8_t gf_mul(uint8_t a, uint8_t b) {
    if (a == 0 || b == 0) return 0;
    return gf_exp_table[gf_log_table[a] + gf_log_table[b]];
}

// Division subtracts logs. The difference lands in [-254, 254]; adding 255
// before the lookup shifts it into [1, 509], still inside the doubled table, so
// again no modulo and, crucially, no negative index. (This is precisely the
// trap a naive implementation falls into: in a language whose % returns a
// negative remainder, expTable[(log(a) - log(b)) % 255] indexes out of range
// for every a/b with log(a) < log(b). The doubled table sidesteps it entirely.)
static uint8_t gf_div(uint8_t a, uint8_t b) {
    if (a == 0) return 0;
    return gf_exp_table[gf_log_table[a] - gf_log_table[b] + 255];
}

// --- Symbol addressing ----------------------------------------------------

// A P line is 26 symbols: 24 data then 2 parity, all on the 86 stride. Symbol k
// (0 = first data = highest polynomial degree, 25 = last parity = degree 0)
// lives at ecc_data[86 * k + line].
static unsigned p_index(unsigned line, unsigned k) { return 86 * k + line; }

// A Q line is 45 symbols: 43 data then 2 parity. The 43 data symbols follow the
// same straddle the encoder uses; the 2 parity symbols sit at the end of the
// sector. line runs 0..51, k runs 0..44.
static unsigned q_index(unsigned line, unsigned k) {
    if (k < 43) return ((44 * k + 43 * (line / 2)) % 1118) * 2 + (line & 1);
    if (k == 43) return 43 * 26 * 2 + line;
    return 44 * 26 * 2 + line;
}

// --- One Reed-Solomon line ------------------------------------------------

// Correct a single (n, n-2) line in place. ecc_data is the sector body starting
// at the header; index(line, k) maps symbol k of the line to a byte offset. The
// generator roots are alpha^0 and alpha^1, so the two syndromes are:
//    S0 = sum of all symbols                 (evaluate the codeword at alpha^0 = 1)
//    S1 = sum of symbol_k * 2^(n-1-k)        (evaluate at alpha^1 = 2)
// because symbol k sits at polynomial degree (n - 1 - k), and 2^m is gf_exp[m].
//
// With two parity symbols the line corrects exactly one error:
//    S0 == 0 && S1 == 0  -> the line is clean.
//    both non-zero       -> a single error of magnitude S0 at the position whose
//                           locator X = S1 / S0 = 2^(n-1-p); recover p from
//                           log(X) and, if it is a real position, fix it.
//    exactly one zero, or a locator that points outside the line -> two or more
//                           errors; this line cannot fix it alone (the partner
//                           channel must), so report no progress.
// Returns 1 if it changed a symbol, 0 otherwise.
static int correct_line(uint8_t* ecc_data, unsigned line, unsigned n, unsigned (*index)(unsigned, unsigned)) {
    uint8_t s0 = 0;
    uint8_t s1 = 0;
    for (unsigned k = 0; k < n; k++) {
        uint8_t sym = ecc_data[index(line, k)];
        s0 ^= sym;
        s1 ^= gf_mul(sym, gf_exp_table[n - 1 - k]);
    }

    if (s0 == 0 && s1 == 0) return 0;  // clean line
    if (s0 == 0 || s1 == 0) return 0;  // two or more errors, not ours to fix

    uint8_t locator = gf_div(s1, s0);    // X = 2^(n-1-p)
    unsigned m = gf_log_table[locator];  // m = n-1-p
    if (m > n - 1) return 0;             // locator outside the line: uncorrectable here
    unsigned p = (n - 1) - m;

    ecc_data[index(line, p)] ^= s0;  // magnitude is S0
    return 1;
}

// --- EDC ------------------------------------------------------------------

// Recompute the Yellow Book CRC32 over the same range the encoder covered (the
// subheader plus the user data) and compare with the stored EDC. The form is
// passed in rather than re-read from the sector, because correct_sector blanks
// the header (including the mode byte) while it works: re-reading the mode there
// would see a zero and wrongly conclude "not a Mode 2 sector, nothing to check"
// and report a false pass. The caller that knows the form supplies it.
static int edc_matches(const uint8_t* sector, unsigned form) {
    const uint8_t* subheader = sector + 16;
    unsigned len = ((form == 2) ? 2324 : 2048) + 8;

    uint32_t edc = 0;
    for (unsigned i = 0; i < len; i++) {
        edc = yellow_book_crctable[(edc ^ subheader[i]) & 0xff] ^ (edc >> 8);
    }

    const uint8_t* stored = subheader + len;
    uint32_t have =
        (uint32_t)stored[0] | ((uint32_t)stored[1] << 8) | ((uint32_t)stored[2] << 16) | ((uint32_t)stored[3] << 24);
    return edc == have;
}

int check_edc(const uint8_t* sector) {
    uint8_t mode = sector[15];
    if (mode != 2) return 1;  // not a Mode 2 sector; nothing to verify here
    unsigned form = (sector[18] & 0x20) ? 2 : 1;
    return edc_matches(sector, form);
}

// --- The corrector --------------------------------------------------------

int correct_sector(uint8_t* sector) {
    uint8_t* body = sector + 12;
    uint8_t mode = body[3];
    if (mode != 2) return 1;  // only Mode 2 carries the EDC/ECC we handle

    const uint8_t* subheader = body + 4;
    unsigned form = (subheader[2] & 0x20) ? 2 : 1;

    // A clean sector needs no work, and Form 2 has no ECC at all, so for Form 2
    // the EDC verdict is final either way.
    if (check_edc(sector)) return 1;
    if (form == 2) return 0;

    // As in the encoder, the P/Q ECC is defined with the four header bytes
    // (the address and mode) forced to zero. The address is positional and not
    // recoverable from the ECC, so we blank it for the duration of the repair
    // and restore it afterwards, exactly mirroring compute_edcecc.
    uint8_t* ecc_data = body;
    uint8_t saved[4];
    for (int i = 0; i < 4; i++) {
        saved[i] = ecc_data[i];
        ecc_data[i] = 0;
    }

    // Iterate the two channels. Each pass corrects every line it can; because P
    // and Q cross-cover each byte, a fix in one channel can unlock a line in the
    // other on the next pass. We stop as soon as the EDC validates (the only
    // real proof of success), or when a whole pass changes nothing (stuck). The
    // bound is generous: there are 86 + 52 lines, and any reachable error
    // pattern converges well before this.
    int result = 0;
    for (unsigned pass = 0; pass < 128; pass++) {
        int changed = 0;
        for (unsigned line = 0; line < 86; line++) {
            changed |= correct_line(ecc_data, line, 26, p_index);
        }
        for (unsigned line = 0; line < 52; line++) {
            changed |= correct_line(ecc_data, line, 45, q_index);
        }
        // The header blanking does not touch the EDC range (subheader onward),
        // so the EDC can be checked at any point during the repair, as long as
        // we use the form captured before blanking rather than re-reading the
        // now-zeroed mode byte.
        if (edc_matches(sector, form)) {
            result = 1;
            break;
        }
        if (!changed) break;
    }

    for (int i = 0; i < 4; i++) ecc_data[i] = saved[i];
    return result;
}
