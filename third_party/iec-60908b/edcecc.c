/*

MIT License

Copyright (c) 2022 Nicolas "Pixel" Noble

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

#include <stdint.h>

#include "tables.h"

void compute_edcecc(uint8_t* sector) {
    sector += 12;
    uint8_t* location = sector;
    sector += 3;
    uint8_t mode = *sector++;

    if (mode != 2) return;

    uint8_t* subheader = sector;
    // form1 or form2?
    unsigned form = subheader[2] & 0x20 ? 2 : 1;
    // in addition to user data, we're also computing the edc over
    // the subheader, which is 8 bytes long
    unsigned len = ((form == 2) ? 2324 : 2048) + 8;

    // advancing at the location of the EDC
    uint8_t* edc_data = subheader;
    uint8_t* edc_ptr = edc_data + len;

    uint32_t edc = 0;
    unsigned i, j;

    // this is the typical CRC32 formula, simply using the special
    // crc32 lookup table as specified by the yellow book
    for (i = 0; i < len; i++) {
        edc = yellow_book_crctable[(edc ^ *edc_data++) & 0xff] ^ (edc >> 8);
    }

    // done, write the edc
    *edc_ptr++ = edc & 0xff;
    edc >>= 8;
    *edc_ptr++ = edc & 0xff;
    edc >>= 8;
    *edc_ptr++ = edc & 0xff;
    edc >>= 8;
    *edc_ptr++ = edc & 0xff;

    // if the sector was form 2, then that's all we had to do
    // the edc doesn't cover the ecc, so this can be done in this order
    if (form == 2) return;

    // otherwise, we need to compute ECC's P and Q too
    uint8_t* ecc_data = location;

    // the fucked up part about MODE2 FORM1 ECC is that it needs to have
    // the location fields to be zeroes to work; luckily, we can rebuild it
    uint8_t actualLocation[3];
    actualLocation[0] = location[0];
    actualLocation[1] = location[1];
    actualLocation[2] = location[2];
    location[0] = 0;
    location[1] = 0;
    location[2] = 0;
    location[3] = 0;

    // for our P and Q ECC channels, Q is covering P, so we need to compute
    // P first, then Q, in order to have a consistent ECC overall

    // for reed solomon, we need to create a generator polynome by
    // computing the product:
    //    Π(x+2ⁿ, n, 1, r)
    // with r being the number of recovery symbols

    // we're doing (26, 24) and (45, 43) reed solomon computations,
    // which means we have r=2 recovery symbols, reducing to the polynome
    //   x² + 3·x + 2 (from (x+1)·(x+2))

    // the way reed solomon works is by transforming the message into a
    // polynome, and then dividing it by the generator polynome;
    // the remainder of the division form the recovery symbols

    // there are two ways to do polynome division, the slow one technically
    // being the long division, and the fast one, called expanded synthetic
    // division, that can be found at
    // https://en.wikipedia.org/wiki/Synthetic_division#Expanded_synthetic_division

    // the long story short of the expanded synthetic division is that
    // we only have to compute the following for each round:
    //   data[i + j] += divisor[j] * data[i]

    // also, using galois fields, addition is xor, and we can do a fast
    // multiplication by using discrete logarithms and powers of two, thus our
    // gf_exp_table and gf_log_table arrays, using the following formula:
    //   a·b = 2^((log2(a) + log2(b) % 255))
    // the only trouble being that we need an early out if a or be are 0
    // because log(0) is invalid

    // looking up the coefficients in the logarithm table, we can hardcode
    // these two values to:
    //   log(3) = 0x19
    //   log(2) = 0x01

    // which speeds up our math here a bit

    // however, considering our generator polynome, we can still use the
    // long division, and still be faster than using the expanded synthetic
    // division, because our only factors are 2 and 3, so if we precompute
    // the mul2 and div3 tables in our galois field, then we only have a
    // single lookup to do per round, instead of 3

    // we'll have both implementations for the sake of completeness,
    // but only one will be active at a time using compilation flags

    // the P channel is essentially 86 lines of ECC, despite the ECMA-130
    // claim it's rather 43 lines; the discrepancy is due to how each
    // line is 16-bits split into two 8-bits, which creates unnecessary
    // complexity in understanding the format

    // each line starts at byte i, and advances by 86 bytes
    // there are 24 bytes in each line

    // overall, the ecma-130 formula says 43 * j + i, which translates
    // to 86 * j + i for us
    for (i = 0; i < 86; i++) {
        uint16_t ecc = 0;
        // note that this jumps fairly high, so it's not going to make
        // a small d-cache happy; if having lots of local registers, it
        // might be more preferable to create a lot of ecc lines in
        // parallel, and read more than one column in parallel
        for (j = 0; j < 24; j++) {
            uint8_t coeff = ecc_data[86 * j + i];
#ifdef USE_EXPANDED_SYNTHETIC_DIVISION
            coeff ^= ecc & 0xff;
            ecc >>= 8;
            // as a special case, if the coefficient is 0, our multiplication
            // will result in 0, and no further processing needs to be done
            // this isn't an optimisation: the multiplication code can't
            // work with zero, because log(0) is invalid, but luckily, the
            // result with 0 is an easy way out to handle, as the shift
            // above already puts the correct value in our LFSR
            if (coeff == 0) continue;

            // otherwise, we need to first compute log(coeff ^ ecc[0])
            coeff = gf_log_table[coeff];
            // then we can mutate our ecc based on the hardcoded values
            // for our generator polynome, as explained before
            uint16_t adder = 0;
            adder = gf_exp_table[coeff + 0x01];
            adder <<= 8;
            adder |= gf_exp_table[coeff + 0x19];
            ecc ^= adder;
        }
#else
            // when doing the long division, the upper portion of our
            // ecc value will hold the sum of all bytes, while the lower
            // portion will hold the series S(n) = 2(S(n-1) + b)
            ecc = gf_mul2_table[(ecc & 0xff) ^ coeff] | ((ecc & 0xff00) ^ (((uint16_t)coeff) << 8));
        }
        // before we can store the ECC, we need to adjust both series,
        // and compute our final values; remember that xor means +
        uint8_t ecc_high = ecc >> 8;
        uint8_t ecc_low = gf_div3_table[gf_mul2_table[ecc & 0xff] ^ ecc_high];
        ecc_high ^= ecc_low;

        ecc = ecc_low | (ecc_high << 8);
#endif
        // if we're done with this ECC line, we can store its results
        // of course, since nothing is ever easy, each 8-bits part of the ecc
        // goes to its own location; luckily, it's on the same stride as the
        // data for it, which makes sense for reading it back as a single
        // polynome when doing the ecc correction
        ecc_data[24 * 86 + i] = ecc & 0xff;
        ecc >>= 8;
        ecc_data[25 * 86 + i] = ecc & 0xff;
    }

    // now that we're done with the P channel, we have to compute Q
    // similar to the P channel, the Q channel is essentially 52 lines of ECC,
    // each spanning over 43 bytes, but the overall stride is much more
    // obnoxious than the P channel, as it's not going to start each line
    // from the next byte in the stride, so the lookup portion is more complex
    // also the storing of the resulting ecc is more complex

    // all in all, this is a very similar algorithm than above, with a
    // bit of a more complex lookup code; because of this, these two loops
    // could be factorized in a single function, but the increased complexity
    // will definitely make it less readable, and we want the compiler to be
    // able to simplify this as much as possible anyway

    // overall, the ecma-130 formula says (44 * j + 43 * i) % 1118, which
    // translates to ((44 * j + 43 * (i / 2)) % 1118) * 2 + (i & 1) for us
    for (i = 0; i < 52; i++) {
        uint16_t ecc = 0;
        for (j = 0; j < 43; j++) {
            // technically this formula could be costly, and if needed, it can
            // be replaced with a linear index that gets adjusted every time
            // it crosses the upper limit
            // also this means we can't parallelize this computation as easily
            // as the P channel, due to how this jumps all over the place
            int l = ((44 * j + 43 * (i / 2)) % 1118) * 2 + (i & 1);
            uint8_t coeff = ecc_data[l];
#ifdef USE_EXPANDED_SYNTHETIC_DIVISION
            coeff ^= ecc & 0xff;
            ecc >>= 8;
            if (coeff == 0) continue;

            coeff = gf_log_table[coeff];
            uint16_t adder = 0;
            adder = gf_exp_table[coeff + 0x01];
            adder <<= 8;
            adder |= gf_exp_table[coeff + 0x19];
            ecc ^= adder;
        }
#else
            ecc = gf_mul2_table[(ecc & 0xff) ^ coeff] | ((ecc & 0xff00) ^ (((uint16_t)coeff) << 8));
        }
        uint8_t ecc_high = ecc >> 8;
        uint8_t ecc_low = gf_div3_table[gf_mul2_table[ecc & 0xff] ^ ecc_high];
        ecc_high ^= ecc_low;

        ecc = ecc_low | (ecc_high << 8);
#endif
        // the ecma-130 formula for the location of the edc says
        // 43 * 26 + i and 44 * 26 + i, which translates to simply
        // multiplying the first hand by two for us, since our i
        // already moves twice as fast as the ecma-130 documentation
        // the bad part about this one is that the readback for the
        // decoder requires the same absurd straddle, and isn't as
        // easy as the P channel
        ecc_data[43 * 26 * 2 + i] = ecc & 0xff;
        ecc >>= 8;
        ecc_data[44 * 26 * 2 + i] = ecc & 0xff;
    }

    // once all is done, we need to restore the location field as it was
    location[0] = actualLocation[0];
    location[1] = actualLocation[1];
    location[2] = actualLocation[2];
    location[3] = 2;

    // and we're all done now
}
