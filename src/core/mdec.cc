/***************************************************************************
 *   Copyright (C) 2010 Gabriele Gorla                                     *
 *   Copyright (C) 2007 Ryan Schultz, PCSX-df Team, PCSX team              *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#include "core/mdec.h"

#include <string.h>

#include <algorithm>

#include "core/debug.h"
#include "core/logger.h"
#include "core/system.h"
#include "core/psxemulator.h"

#define AAN_CONST_BITS 12
#define AAN_PRESCALE_BITS 16

#define AAN_CONST_SIZE 24
#define AAN_CONST_SCALE (AAN_CONST_SIZE - AAN_CONST_BITS)

#define AAN_PRESCALE_SIZE 20
#define AAN_PRESCALE_SCALE (AAN_PRESCALE_SIZE - AAN_PRESCALE_BITS)
#define AAN_EXTRA 12

#define SCALE(x, n) ((x) >> (n))
#define SCALER(x, n) (((x) + ((1 << (n)) >> 1)) >> (n))

#define MULS(var, const) (SCALE((var) * (const), AAN_CONST_BITS))

#define RLE_RUN(a) ((a) >> 10)
#define RLE_VAL(a) (((int)(a) << (sizeof(int) * 8 - 10)) >> (sizeof(int) * 8 - 10))

#define FIX_1_082392200 SCALER(18159528, AAN_CONST_SCALE)  // B6
#define FIX_1_414213562 SCALER(23726566, AAN_CONST_SCALE)  // A4
#define FIX_1_847759065 SCALER(31000253, AAN_CONST_SCALE)  // A2
#define FIX_2_613125930 SCALER(43840978, AAN_CONST_SCALE)  // B2

static inline void fillcol(int *blk, int val) {
    blk[0 * PCSX::MDEC::DSIZE] = blk[1 * PCSX::MDEC::DSIZE] = blk[2 * PCSX::MDEC::DSIZE] = blk[3 * PCSX::MDEC::DSIZE] =
        blk[4 * PCSX::MDEC::DSIZE] = blk[5 * PCSX::MDEC::DSIZE] = blk[6 * PCSX::MDEC::DSIZE] =
            blk[7 * PCSX::MDEC::DSIZE] = val;
}

static inline void fillrow(int *blk, int val) {
    blk[0] = blk[1] = blk[2] = blk[3] = blk[4] = blk[5] = blk[6] = blk[7] = val;
}

static void idct(int *block, int used_col) {
    int tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7;
    int z5, z10, z11, z12, z13;
    int *ptr;

    // the block has only the DC coefficient
    if (used_col == -1) {
        int v = block[0];
        for (int i = 0; i < PCSX::MDEC::DSIZE2; i++) block[i] = v;
        return;
    }

    // last_col keeps track of the highest column with non zero coefficients
    ptr = block;
    for (int i = 0; i < PCSX::MDEC::DSIZE; i++, ptr++) {
        if ((used_col & (1 << i)) == 0) {
            // the column is empty or has only the DC coefficient
            if (ptr[PCSX::MDEC::DSIZE * 0]) {
                fillcol(ptr, ptr[0]);
                used_col |= (1 << i);
            }
            continue;
        }

        // further optimization could be made by keeping track of
        // last_row in rl2blk
        z10 = ptr[PCSX::MDEC::DSIZE * 0] + ptr[PCSX::MDEC::DSIZE * 4];  // s04
        z11 = ptr[PCSX::MDEC::DSIZE * 0] - ptr[PCSX::MDEC::DSIZE * 4];  // d04
        z13 = ptr[PCSX::MDEC::DSIZE * 2] + ptr[PCSX::MDEC::DSIZE * 6];  // s26
        z12 = MULS(ptr[PCSX::MDEC::DSIZE * 2] - ptr[PCSX::MDEC::DSIZE * 6], FIX_1_414213562) - z13;
        //^^^^  d26=d26*2*A4-s26

        tmp0 = z10 + z13;  // os07 = s04 + s26
        tmp3 = z10 - z13;  // os34 = s04 - s26
        tmp1 = z11 + z12;  // os16 = d04 + d26
        tmp2 = z11 - z12;  // os25 = d04 - d26

        z13 = ptr[PCSX::MDEC::DSIZE * 3] + ptr[PCSX::MDEC::DSIZE * 5];  // s53
        z10 = ptr[PCSX::MDEC::DSIZE * 3] - ptr[PCSX::MDEC::DSIZE * 5];  //-d53
        z11 = ptr[PCSX::MDEC::DSIZE * 1] + ptr[PCSX::MDEC::DSIZE * 7];  // s17
        z12 = ptr[PCSX::MDEC::DSIZE * 1] - ptr[PCSX::MDEC::DSIZE * 7];  // d17

        tmp7 = z11 + z13;  // od07 = s17 + s53

        z5 = (z12 - z10) * (FIX_1_847759065);
        tmp6 = SCALE(z10 * (FIX_2_613125930) + z5, AAN_CONST_BITS) - tmp7;
        tmp5 = MULS(z11 - z13, FIX_1_414213562) - tmp6;
        tmp4 = SCALE(z12 * (FIX_1_082392200)-z5, AAN_CONST_BITS) + tmp5;

        // path #1
        // z5 = (z12 - z10)* FIX_1_847759065;
        // tmp0 = (d17 + d53) * 2*A2

        // tmp6 = DESCALE(z10*FIX_2_613125930 + z5, CONST_BITS) - tmp7;
        // od16 = (d53*-2*B2 + tmp0) - od07

        // tmp4 = DESCALE(z12*FIX_1_082392200 - z5, CONST_BITS) + tmp5;
        // od34 = (d17*2*B6 - tmp0) + od25

        // path #2

        // od34 = d17*2*(B6-A2) - d53*2*A2
        // od16 = d53*2*(A2-B2) + d17*2*A2

        // end

        //    tmp5 = MULS(z11 - z13, FIX_1_414213562) - tmp6;
        // od25 = (s17 - s53)*2*A4 - od16

        ptr[PCSX::MDEC::DSIZE * 0] = (tmp0 + tmp7);  // os07 + od07
        ptr[PCSX::MDEC::DSIZE * 7] = (tmp0 - tmp7);  // os07 - od07
        ptr[PCSX::MDEC::DSIZE * 1] = (tmp1 + tmp6);  // os16 + od16
        ptr[PCSX::MDEC::DSIZE * 6] = (tmp1 - tmp6);  // os16 - od16
        ptr[PCSX::MDEC::DSIZE * 2] = (tmp2 + tmp5);  // os25 + od25
        ptr[PCSX::MDEC::DSIZE * 5] = (tmp2 - tmp5);  // os25 - od25
        ptr[PCSX::MDEC::DSIZE * 4] = (tmp3 + tmp4);  // os34 + od34
        ptr[PCSX::MDEC::DSIZE * 3] = (tmp3 - tmp4);  // os34 - od34
    }

    ptr = block;
    if (used_col == 1) {
        for (int i = 0; i < PCSX::MDEC::DSIZE; i++)
            fillrow(block + PCSX::MDEC::DSIZE * i, block[PCSX::MDEC::DSIZE * i]);
    } else {
        for (int i = 0; i < PCSX::MDEC::DSIZE; i++, ptr += PCSX::MDEC::DSIZE) {
            z10 = ptr[0] + ptr[4];
            z11 = ptr[0] - ptr[4];
            z13 = ptr[2] + ptr[6];
            z12 = MULS(ptr[2] - ptr[6], FIX_1_414213562) - z13;

            tmp0 = z10 + z13;
            tmp3 = z10 - z13;
            tmp1 = z11 + z12;
            tmp2 = z11 - z12;

            z13 = ptr[3] + ptr[5];
            z10 = ptr[3] - ptr[5];
            z11 = ptr[1] + ptr[7];
            z12 = ptr[1] - ptr[7];

            tmp7 = z11 + z13;
            z5 = (z12 - z10) * FIX_1_847759065;
            tmp6 = SCALE(z10 * FIX_2_613125930 + z5, AAN_CONST_BITS) - tmp7;
            tmp5 = MULS(z11 - z13, FIX_1_414213562) - tmp6;
            tmp4 = SCALE(z12 * FIX_1_082392200 - z5, AAN_CONST_BITS) + tmp5;

            ptr[0] = tmp0 + tmp7;

            ptr[7] = tmp0 - tmp7;
            ptr[1] = tmp1 + tmp6;
            ptr[6] = tmp1 - tmp6;
            ptr[2] = tmp2 + tmp5;
            ptr[5] = tmp2 - tmp5;
            ptr[4] = tmp3 + tmp4;
            ptr[3] = tmp3 - tmp4;
        }
    }
}

enum {
    // mdec0: command register
    MDEC0_STP = 0x02000000,
    MDEC0_RGB24 = 0x08000000,
    MDEC0_SIZE_MASK = 0x0000FFFF,

    // mdec1: status register
    MDEC1_BUSY = 0x20000000,
    MDEC1_DREQ = 0x18000000,
    MDEC1_FIFO = 0xc0000000,
    MDEC1_RGB24 = 0x02000000,
    MDEC1_STP = 0x00800000,
    MDEC1_RESET = 0x80000000,
};

// The scale matrix every known PSX game uploads, straight out of psx-spx's
// set_scale_table section. Signed halfwords, 14 fractional bits.
static const int16_t c_standardScaleTable[PCSX::MDEC::DSIZE2] = {
    (int16_t)0x5A82, (int16_t)0x5A82, (int16_t)0x5A82, (int16_t)0x5A82, (int16_t)0x5A82, (int16_t)0x5A82,
    (int16_t)0x5A82, (int16_t)0x5A82, (int16_t)0x7D8A, (int16_t)0x6A6D, (int16_t)0x471C, (int16_t)0x18F8,
    (int16_t)0xE707, (int16_t)0xB8E3, (int16_t)0x9592, (int16_t)0x8275, (int16_t)0x7641, (int16_t)0x30FB,
    (int16_t)0xCF04, (int16_t)0x89BE, (int16_t)0x89BE, (int16_t)0xCF04, (int16_t)0x30FB, (int16_t)0x7641,
    (int16_t)0x6A6D, (int16_t)0xE707, (int16_t)0x8275, (int16_t)0xB8E3, (int16_t)0x471C, (int16_t)0x7D8A,
    (int16_t)0x18F8, (int16_t)0x9592, (int16_t)0x5A82, (int16_t)0xA57D, (int16_t)0xA57D, (int16_t)0x5A82,
    (int16_t)0x5A82, (int16_t)0xA57D, (int16_t)0xA57D, (int16_t)0x5A82, (int16_t)0x471C, (int16_t)0x8275,
    (int16_t)0x18F8, (int16_t)0x6A6D, (int16_t)0x9592, (int16_t)0xE707, (int16_t)0x7D8A, (int16_t)0xB8E3,
    (int16_t)0x30FB, (int16_t)0x89BE, (int16_t)0x7641, (int16_t)0xCF04, (int16_t)0xCF04, (int16_t)0x7641,
    (int16_t)0x89BE, (int16_t)0x30FB, (int16_t)0x18F8, (int16_t)0xB8E3, (int16_t)0x6A6D, (int16_t)0x8275,
    (int16_t)0x7D8A, (int16_t)0x9592, (int16_t)0x471C, (int16_t)0xE707,
};

// The dequantizer follows psx-spx's rl_decode_block, and every clause of it has
// now been checked against real consoles with an arm that varies ONE term. Five
// of those arms are bit-exact, 0 of 768 bytes differing: the q_scale == 0 DC rule
// and its ordinary-route control, both zigzag arms, and the DC-saturation arm.
// The rig is src/mips/tests/mdec-roundtrip, one arm per clause, and genjob.py
// documents what each one holds fixed.
//
// What is left is NOT in this function. Every single-term arm's residual is
// exactly +1 on the quadrants whose flat level is an exact .5 and exact
// everywhere else, because the MDEC rounds a tie DOWN and SCALER here rounds it
// up: measured 153.00 -> 153, 153.25 -> 153, 153.75 -> 154, 165.50 -> 165, which
// is round-half-down and not floor. Separately, arms driven far out of range keep
// isolated bytes where silicon reads 0 and this reads 255 - a wrap where we clamp,
// in the colour conversion, which psx-spx does not document at all (yuv_to_rgb is
// called four times on that page and never defined). Both are output-stage
// findings with their own arms still to build; neither is a dequant bug.
//
// Regression control for anything touched here: arm C, the ordinary path, must
// stay bit-identical. It is 332/768 max 2 against hardware and was 0/768 against
// the previous build across this change. The first attempt at the saturation
// clamped in the divided domain, which cost 407 extra differing bytes on an
// ordinary frame while the SATURATING arm appeared to improve - grade on C, never
// on the arm the change was written for.
//
// psx-spx saturates the dequantized value to signed 11 bits. The fast path works
// in an UN-DIVIDED domain: its expression is RLE_VAL*qt*q_scale with the /8 folded
// into the AAN normalisation, so the clamp has to be applied to the spec's value
// while the ORIGINAL expression is what reaches the IDCT. Clamping the divided
// value and multiplying the prescale onto that instead is an 8x error, and it
// costs 407 extra differing bytes against hardware on an ordinary frame - the
// regression control is the only thing that sees it, because the saturating case
// still looks like it improved.
static inline int saturateAanAc(int x) {
    const int v = (x + 4) / 8;
    if (v > 0x3ff) return 0x3ff * 8;
    if (v < -0x400) return -0x400 * 8;
    return x;
}

void PCSX::MDEC::scaletable_init() {
    // Zero, not the standard constants. See the note in mdec.h: silicon has no
    // default here, and a decode before MDEC(3) produces nothing on hardware.
    memset(scaletable, 0, sizeof(scaletable));
    customScaleTable = true;  // an all-zero matrix is not the standard one
    scaleTableUploaded = false;
    warnedNoScaleTable = false;
}

// psx-spx real_idct_core. dst = src * scaletable with src diagonally mirrored,
// two passes with src/dst swapped. 1024 multiplications, and the hardware has no
// idea the table contains cosines: any matrix uploaded here is faithfully applied.
//
// NOTE the hardware only uses the upper 13 bits of each 16-bit table entry, and
// psx-spx itself says of this pseudocode that "the results aren't perfect" and
// that the real rounding points are not known. So this is the documented model,
// not a bit-exact hardware model, and a hardware roundtrip is the only thing that
// can say how far off it is.
void PCSX::MDEC::real_idct(int *block) {
    int temp[DSIZE2];
    int *src = block;
    int *dst = temp;
    for (int pass = 0; pass < 2; pass++) {
        for (int x = 0; x < 8; x++) {
            for (int y = 0; y < 8; y++) {
                int64_t sum = 0;
                for (int z = 0; z < 8; z++) {
                    sum += static_cast<int64_t>(src[y + z * 8]) * (scaletable[x + z * 8] / 8);
                }
                int v = static_cast<int>((sum + 0xfff) >> 13);
                // The second pass leaves psx-spx's pixel-domain result, but the
                // colour conversion downstream expects the AAN path's domain,
                // which carries a 2^10 prescale: MULR/MULB/MULG2 are 1024-fixed
                // point and SCALE8 shifts by 20. Without this the general path
                // hands yuv2rgb values about 1024x too small and every macroblock
                // collapses to flat mid-grey - which reads exactly like the scale
                // table being ignored, and is not.
                if (pass == 1) v <<= 10;
                dst[x + y * 8] = v;
            }
        }
        std::swap(src, dst);
    }
    // Two swaps put the result back in `block` already when passes are even; be
    // explicit rather than relying on it.
    if (src != block) memcpy(block, src, sizeof(temp));
}

void PCSX::MDEC::iqtab_init(int *iqtab, unsigned char *iq_y) {
    for (int i = 0; i < DSIZE2; i++) {
        iqtab[i] = (iq_y[i] * SCALER(aanscales[zscan[i]], AAN_PRESCALE_SCALE));
    }
}

#define MDEC_END_OF_DATA 0xfe00

unsigned short *PCSX::MDEC::rl2blk(int *blk, unsigned short *mdec_rl) {
    int k, q_scale, rl, used_col;
    int *iqtab;

    memset(blk, 0, 6 * DSIZE2 * sizeof(int));
    iqtab = iq_uv;
    const uint8_t *qtab = qt_uv;
    for (int i = 0; i < 6; i++) {
        // decode blocks (Cr,Cb,Y1,Y2,Y3,Y4)
        if (i == 2) {
            iqtab = iq_y;
            qtab = qt_y;
        }

        if (customScaleTable) {
            // General path: no AAN prescale in the dequantized values, saturation
            // to signed 11 bits per psx-spx's rl_decode_block, and the full matrix
            // multiply afterwards. Slower by construction; only taken when
            // something has actually uploaded a non-standard matrix.
            rl = SWAP_LE16(*mdec_rl);
            mdec_rl++;
            q_scale = RLE_RUN(rl);
            // The q_scale == 0 clauses bind here too, and their absence is why
            // running this mode through the general path scored no better than
            // through the fast one - both were wrong about the same two things.
            blk[0] = std::clamp(q_scale == 0 ? RLE_VAL(rl) * 2 : RLE_VAL(rl) * qtab[0], -0x400, 0x3ff);
            for (k = 0;;) {
                rl = SWAP_LE16(*mdec_rl);
                mdec_rl++;
                if (rl == MDEC_END_OF_DATA) break;
                k += RLE_RUN(rl) + 1;
                if (k > 63) break;
                const int spec =
                    q_scale == 0 ? RLE_VAL(rl) * 2 : (RLE_VAL(rl) * qtab[k] * q_scale + 4) / 8;
                blk[q_scale == 0 ? k : zscan[k]] = std::clamp(spec, -0x400, 0x3ff);
            }
            real_idct(blk);
            blk += DSIZE2;
            continue;
        }

        rl = SWAP_LE16(*mdec_rl);
        mdec_rl++;
        q_scale = RLE_RUN(rl);
        {
            // psx-spx's DC term. Every clause here is MEASURED ON SILICON rather
            // than taken from the document on trust, one hardware arm per clause:
            //   val = signed10bit * qt[0], with NO q_scale and NO /8. Arms D8 and
            //     D63 hold everything else and decode byte-identical at q_scale 8
            //     and 63, which settles the "(?)" psx-spx prints on that line.
            //   q_scale == 0 gives val = signed10bit * 2 with no quant table at
            //     all. Arm ZDC against ZDCC, which reaches the same value by the
            //     ordinary route, differ 0/768.
            //   val = minmax(val, -400h, +3FFh). Arm DSAT2 puts two DCs at 1024
            //     and 2044 on a HALVED basis, where the clamp bites before the
            //     8-bit output rail does, and they decode byte-identical. At the
            //     standard basis this is unobservable: a flat block decodes to
            //     128 + val/8, so the clamp at 1023 and the output rail at 1024
            //     are one LSB apart and no DC-only arm can separate them.
            // The clamp lives in the spec's divided domain while this path works
            // in an un-divided one, so the ORIGINAL expression is what is returned
            // when nothing saturates - that keeps the ordinary case bit-identical.
            const int dc = RLE_VAL(rl);
            const int spec = (q_scale == 0) ? dc * 2 : dc * qtab[0];
            const int sat = std::clamp(spec, -0x400, 0x3ff);
            blk[0] = (q_scale != 0 && sat == spec)
                         ? SCALER(iqtab[0] * dc, AAN_EXTRA - 3)
                         : SCALER(sat * SCALER(aanscales[0], AAN_PRESCALE_SCALE), AAN_EXTRA - 3);
        }
        for (k = 0, used_col = 0;;) {
            rl = SWAP_LE16(*mdec_rl);
            mdec_rl++;
            if (rl == MDEC_END_OF_DATA) break;
            k += RLE_RUN(rl) + 1;  // skip zero-coefficients

            if (k > 63) {
                // printf("run lenght exceeded 64 enties\n");
                break;
            }

            // zigzag transformation. q_scale == 0 selects psx-spx's mode with no
            // quant table, a doubled value and NO zigzag; the *8 puts it in this
            // path's un-divided domain. When nothing saturates, the normal branch
            // is bit-identical to what was here before.
            const int dest = q_scale == 0 ? k : zscan[k];
            if (q_scale == 0) {
                // MEASURED: arm ZAC puts one coefficient at k = 2 with q_scale 0
                // and silicon decodes a horizontal frequency-2 basis, i.e. block
                // position 2; the matched-magnitude control ZACC at q_scale 1
                // decodes a vertical frequency-1 basis, position zscan[2] = 8. So
                // psx-spx's "no zigzag" is right - and the AAN prescale has to
                // follow the value to its DESTINATION. iqtab[k] carries
                // aanscales[zscan[k]], which is the factor for the slot this mode
                // specifically does not use, so it cannot be reused here. The *8
                // puts the value in this path's un-divided domain, and psx-spx's
                // clamp is a no-op in this mode because signed10bit*2 spans
                // [-1024, +1022], inside [-400h, +3FFh] at both ends.
                blk[dest] = SCALER(RLE_VAL(rl) * 2 * 8 * SCALER(aanscales[k], AAN_PRESCALE_SCALE), AAN_EXTRA);
            } else {
                blk[dest] = SCALER(saturateAanAc(RLE_VAL(rl) * qtab[k] * q_scale) *
                                       (iqtab[k] / (qtab[k] ? qtab[k] : 1)),
                                   AAN_EXTRA);
            }
            // keep track of used columns to speed up the idtc
            used_col |= (dest > 7) ? 1 << (dest & 7) : 0;
        }

        if (k == 0) used_col = -1;
        // used_col is -1 for blocks with only the DC coefficient
        // any other value is a bitmask of the columns that have
        // at least one non zero cofficient in the rows 1-7
        // single coefficients in row 0 are treted specially
        // in the idtc function
        idct(blk, used_col);
        blk += DSIZE2;
    }
    return mdec_rl;
}

// full scale (JPEG)
// Y/Cb/Cr[0...255] -> R/G/B[0...255]
// R = 1.000 * (Y) + 1.400 * (Cr - 128)
// G = 1.000 * (Y) - 0.343 * (Cb - 128) - 0.711 (Cr - 128)
// B = 1.000 * (Y) + 1.765 * (Cb - 128)
#define MULR(a) ((1434 * (a)))
#define MULB(a) ((1807 * (a)))
#define MULG2(a, b) ((-351 * (a) - 728 * (b)))
#define MULY(a) ((a) << 10)

#define MAKERGB15(r, g, b, a) (SWAP_LE16(a | ((b) << 10) | ((g) << 5) | (r)))
// MEASURED: the MDEC rounds to nearest with TIES GOING DOWN. Arm D8F puts four
// flat quadrants at exactly 153.00, 153.25, 153.75 and 165.50; silicon returns
// 153, 153, 154, 165 - so .75 rounds up and .50 rounds down, which is
// round-half-down and NOT floor (floor would have given 153 for the .75 quadrant).
// SCALER adds half and shifts, i.e. rounds ties up. Subtracting 1 from the bias
// moves the tie and leaves every other fraction alone.
//
// SCOPE, and it is narrower than it first looked. This takes the flat-field DC
// arms D8, D63 and D8F from 384/768 each to 0/768, and is a byte-for-byte no-op on
// arms A, B, C, D, S and Z - ordinary content with AC energy essentially never
// lands on an exact tie. ⛔ It does NOT account for the residual on DSAT2 (192,
// max 1) or ASAT (96, max 1), which are unchanged by it: DSAT2 runs the general
// matrix path, whose own `(sum + 0xfff) >> 13` is a separate rounding stage, and
// ASAT's ties arise inside the AAN butterfly rather than here. Those are a
// different measurement and have not been made. An earlier revision of this
// comment claimed this one bit was the whole residual on every single-term arm;
// that was written before the confirming sweep finished and it was wrong.
#define SCALE8(c) ((((c) + (1 << 19)) - 1) >> 20)
// ⚠ DELIBERATELY still SCALER, i.e. still rounds ties UP, and the asymmetry with
// SCALE8 above is unfinished rather than verified. Every arm of the roundtrip rig
// requests 24bpp, so nothing has driven this path on silicon and I would rather it
// look unmeasured than look checked. The 15-bit arm is a rig change (depth 3 in the
// command word, half the output bytes) plus one farm run.
#define SCALE5(c) SCALER(c, 23)

#define CLAMP5(c) (((c) < -16) ? 0 : (((c) > (31 - 16)) ? 31 : ((c) + 16)))
#define CLAMP8(c) (((c) < -128) ? 0 : (((c) > (255 - 128)) ? 255 : ((c) + 128)))

#define CLAMP_SCALE8(a) (CLAMP8(SCALE8(a)))
#define CLAMP_SCALE5(a) (CLAMP5(SCALE5(a)))

inline void PCSX::MDEC::putlinebw15(uint16_t *image, int *Yblk) {
    int A = (mdec.reg0 & MDEC0_STP) ? 0x8000 : 0;

    for (int i = 0; i < 8; i++, Yblk++) {
        int Y = *Yblk;
        // missing rounding
        image[i] = SWAP_LE16((CLAMP5(Y >> 3) * 0x421) | A);
    }
}

inline void PCSX::MDEC::putquadrgb15(uint16_t *image, int *Yblk, int Cr, int Cb) {
    int Y, R, G, B;
    int A = (mdec.reg0 & MDEC0_STP) ? 0x8000 : 0;
    R = MULR(Cr);
    G = MULG2(Cb, Cr);
    B = MULB(Cb);

    // added transparency
    Y = MULY(Yblk[0]);
    image[0] = MAKERGB15(CLAMP_SCALE5(Y + R), CLAMP_SCALE5(Y + G), CLAMP_SCALE5(Y + B), A);
    Y = MULY(Yblk[1]);
    image[1] = MAKERGB15(CLAMP_SCALE5(Y + R), CLAMP_SCALE5(Y + G), CLAMP_SCALE5(Y + B), A);
    Y = MULY(Yblk[8]);
    image[16] = MAKERGB15(CLAMP_SCALE5(Y + R), CLAMP_SCALE5(Y + G), CLAMP_SCALE5(Y + B), A);
    Y = MULY(Yblk[9]);
    image[17] = MAKERGB15(CLAMP_SCALE5(Y + R), CLAMP_SCALE5(Y + G), CLAMP_SCALE5(Y + B), A);
}

inline void PCSX::MDEC::yuv2rgb15(int *blk, unsigned short *image) {
    int *Yblk = blk + DSIZE2 * 2;
    int *Crblk = blk;
    int *Cbblk = blk + DSIZE2;

    if (!PCSX::g_emulator->settings.get<PCSX::Emulator::SettingBnWMdec>()) {
        for (int y = 0; y < 16; y += 2, Crblk += 4, Cbblk += 4, Yblk += 8, image += 24) {
            if (y == 8) Yblk += DSIZE2;
            for (int x = 0; x < 4; x++, image += 2, Crblk++, Cbblk++, Yblk += 2) {
                putquadrgb15(image, Yblk, *Crblk, *Cbblk);
                putquadrgb15(image + 8, Yblk + DSIZE2, *(Crblk + 4), *(Cbblk + 4));
            }
        }
    } else {
        for (int y = 0; y < 16; y++, Yblk += 8, image += 16) {
            if (y == 8) Yblk += DSIZE2;
            putlinebw15(image, Yblk);
            putlinebw15(image + 8, Yblk + DSIZE2);
        }
    }
}

static inline void putlinebw24(uint8_t *image, int *Yblk) {
    for (int i = 0; i < 8 * 3; i += 3, Yblk++) {
        uint8_t Y = CLAMP8(*Yblk);
        image[i + 0] = Y;
        image[i + 1] = Y;
        image[i + 2] = Y;
    }
}

static inline void putquadrgb24(uint8_t *image, int *Yblk, int Cr, int Cb) {
    int Y, R, G, B;

    R = MULR(Cr);
    G = MULG2(Cb, Cr);
    B = MULB(Cb);

    Y = MULY(Yblk[0]);
    image[0 * 3 + 0] = CLAMP_SCALE8(Y + R);
    image[0 * 3 + 1] = CLAMP_SCALE8(Y + G);
    image[0 * 3 + 2] = CLAMP_SCALE8(Y + B);
    Y = MULY(Yblk[1]);
    image[1 * 3 + 0] = CLAMP_SCALE8(Y + R);
    image[1 * 3 + 1] = CLAMP_SCALE8(Y + G);
    image[1 * 3 + 2] = CLAMP_SCALE8(Y + B);
    Y = MULY(Yblk[8]);
    image[16 * 3 + 0] = CLAMP_SCALE8(Y + R);
    image[16 * 3 + 1] = CLAMP_SCALE8(Y + G);
    image[16 * 3 + 2] = CLAMP_SCALE8(Y + B);
    Y = MULY(Yblk[9]);
    image[17 * 3 + 0] = CLAMP_SCALE8(Y + R);
    image[17 * 3 + 1] = CLAMP_SCALE8(Y + G);
    image[17 * 3 + 2] = CLAMP_SCALE8(Y + B);
}

void yuv2rgb24(int *blk, uint8_t *image) {
    int *Yblk = blk + PCSX::MDEC::DSIZE2 * 2;
    int *Crblk = blk;
    int *Cbblk = blk + PCSX::MDEC::DSIZE2;

    if (!PCSX::g_emulator->settings.get<PCSX::Emulator::SettingBnWMdec>()) {
        for (int y = 0; y < 16; y += 2, Crblk += 4, Cbblk += 4, Yblk += 8, image += 8 * 3 * 3) {
            if (y == 8) Yblk += PCSX::MDEC::DSIZE2;
            for (int x = 0; x < 4; x++, image += 6, Crblk++, Cbblk++, Yblk += 2) {
                putquadrgb24(image, Yblk, *Crblk, *Cbblk);
                putquadrgb24(image + 8 * 3, Yblk + PCSX::MDEC::DSIZE2, *(Crblk + 4), *(Cbblk + 4));
            }
        }
    } else {
        for (int y = 0; y < 16; y++, Yblk += 8, image += 16 * 3) {
            if (y == 8) Yblk += PCSX::MDEC::DSIZE2;
            putlinebw24(image, Yblk);
            putlinebw24(image + 8 * 3, Yblk + PCSX::MDEC::DSIZE2);
        }
    }
}

void PCSX::MDEC::init(void) {
    memset(&mdec, 0, sizeof(mdec));
    memset(iq_y, 0, sizeof(iq_y));
    memset(iq_uv, 0, sizeof(iq_uv));
    memset(qt_y, 0, sizeof(qt_y));
    memset(qt_uv, 0, sizeof(qt_uv));
    scaletable_init();
    mdec.rl = (uint16_t *)&PCSX::g_emulator->m_mem->m_wram[0x100000];
}

// command register
void PCSX::MDEC::write0(uint32_t data) { mdec.reg0 = data; }

uint32_t PCSX::MDEC::read0(void) { return mdec.reg0; }

// status register
void PCSX::MDEC::write1(uint32_t data) {
    if (data & MDEC1_RESET) {  // mdec reset
        mdec.reg0 = 0;
        mdec.reg1 = 0;
        mdec.pending_dma1.adr = 0;
        mdec.block_buffer_pos = 0;
    }
}

uint32_t PCSX::MDEC::read1(void) {
    uint32_t v = mdec.reg1;
    return v;
}

void PCSX::MDEC::dma0(uint32_t adr, uint32_t bcr, uint32_t chcr) {
    int cmd = mdec.reg0;
    int size;

    if (chcr != 0x01000201) {
        return;
    }

    /* mdec is STP till dma0 is released */
    mdec.reg1 |= MDEC1_STP;

    size = (bcr >> 16) * (bcr & 0xffff);
    if (g_emulator->settings.get<Emulator::SettingDebugSettings>().get<Emulator::DebugSettings::Debug>()) {
        g_emulator->m_debug->checkDMAread(0, adr, size * 4);
    }

    switch (cmd >> 28) {
        case 0x3:  // decode
            if (!scaleTableUploaded && !warnedNoScaleTable) {
                warnedNoScaleTable = true;
                g_system->log(LogClass::HARDWARE,
                              _("MDEC decode issued with no scale table uploaded. Real hardware has no default "
                                "here and will decode this to flat grey; send MDEC(3) before MDEC(1).\n"));
            }
            mdec.rl = g_emulator->m_mem->getPointer<uint16_t>(adr);
            /* now the mdec is busy till all data are decoded */
            mdec.reg1 |= MDEC1_BUSY;
            /* detect the end of decoding */
            mdec.rl_end = mdec.rl + (size * 2);

            /* sanity check */
            if (mdec.rl_end <= mdec.rl) {
                scheduleMDECINDMAIRQ(size / 4);
                return;
            }

            /* process the pending dma1 */
            if (mdec.pending_dma1.adr) {
                dma1(mdec.pending_dma1.adr, mdec.pending_dma1.bcr, mdec.pending_dma1.chcr);
            }
            mdec.pending_dma1.adr = 0;
            return;

        case 0x4:  // quantization table upload
        {
            uint8_t *p = g_emulator->m_mem->getPointer<uint8_t>(adr);
            // printf("uploading new quantization table\n");
            // printmatrixu8(p);
            // printmatrixu8(p + 64);
            iqtab_init(iq_y, p);
            iqtab_init(iq_uv, p + 64);
            memcpy(qt_y, p, sizeof(qt_y));
            memcpy(qt_uv, p + 64, sizeof(qt_uv));
        }

            scheduleMDECINDMAIRQ(size / 4);
            return;

        case 0x6: {  // scale table, MDEC(3)
            // 64 signed halfwords with a 14-bit fractional part. This used to be
            // dropped on the floor, which meant a custom table silently decoded
            // with the standard one: correct-looking output here, different output
            // on hardware, and no diagnostic either way.
            const int16_t *p = g_emulator->m_mem->getPointer<int16_t>(adr);
            for (unsigned i = 0; i < DSIZE2; i++) scaletable[i] = SWAP_LE16(p[i]);
            customScaleTable = memcmp(scaletable, c_standardScaleTable, sizeof(scaletable)) != 0;
            scaleTableUploaded = true;
            warnedNoScaleTable = false;
        }
            scheduleMDECINDMAIRQ(size / 4);
            return;

        default:
            // printf("mdec unknown command\n");
            break;
    }

    mdec0Interrupt();
}

void PCSX::MDEC::mdec0Interrupt() {
    auto &mem = g_emulator->m_mem;
    mem->clearDMABusy<0>();
    mem->dmaInterrupt<0>();
}

#define SIZE_OF_24B_BLOCK (16 * 16 * 3)
#define SIZE_OF_16B_BLOCK (16 * 16 * 2)

void PCSX::MDEC::dma1(uint32_t adr, uint32_t bcr, uint32_t chcr) {
    int blk[DSIZE2 * 6];
    uint8_t *image;
    int size;
    int dmacnt;

    if (chcr != 0x01000200) return;

    size = (bcr >> 16) * (bcr & 0xffff);
    /* size in byte */
    size *= 4;
    /* I guess the memory speed is limitating */
    dmacnt = size;
    g_emulator->m_mem->msanDmaWrite(adr, size);
    if (g_emulator->settings.get<Emulator::SettingDebugSettings>().get<Emulator::DebugSettings::Debug>()) {
        g_emulator->m_debug->checkDMAwrite(1, adr, size);
    }

    if (!(mdec.reg1 & MDEC1_BUSY)) {
        /* add to pending */
        mdec.pending_dma1.adr = adr;
        mdec.pending_dma1.bcr = bcr;
        mdec.pending_dma1.chcr = chcr;
        /* do not free the dma */
    } else {
        image = g_emulator->m_mem->getPointer<uint8_t>(adr);

        if (mdec.reg0 & MDEC0_RGB24) {
            /* 16 bits decoding
             * block are 16 px * 16 px, each px are 2 byte
             */

            /* there is some partial block pending ? */
            if (mdec.block_buffer_pos != 0) {
                int n = mdec.block_buffer - mdec.block_buffer_pos + SIZE_OF_16B_BLOCK;
                /* TODO: check if partial block do not  larger than size */
                memcpy(image, mdec.block_buffer_pos, n);
                image += n;
                size -= n;
                mdec.block_buffer_pos = 0;
            }

            while (size >= SIZE_OF_16B_BLOCK) {
                mdec.rl = rl2blk(blk, mdec.rl);
                yuv2rgb15(blk, (uint16_t *)image);
                image += SIZE_OF_16B_BLOCK;
                size -= SIZE_OF_16B_BLOCK;
            }

            if (size != 0) {
                mdec.rl = rl2blk(blk, mdec.rl);
                yuv2rgb15(blk, (uint16_t *)mdec.block_buffer);
                memcpy(image, mdec.block_buffer, size);
                mdec.block_buffer_pos = mdec.block_buffer + size;
            }

        } else {
            /* 24 bits decoding
             * block are 16 px * 16 px, each px are 3 byte
             */

            /* there is some partial block pending ? */
            if (mdec.block_buffer_pos != 0) {
                int n = mdec.block_buffer - mdec.block_buffer_pos + SIZE_OF_24B_BLOCK;
                /* TODO: check if partial block do not  larger than size */
                memcpy(image, mdec.block_buffer_pos, n);
                image += n;
                size -= n;
                mdec.block_buffer_pos = 0;
            }

            while (size >= SIZE_OF_24B_BLOCK) {
                mdec.rl = rl2blk(blk, mdec.rl);
                yuv2rgb24(blk, image);
                image += SIZE_OF_24B_BLOCK;
                size -= SIZE_OF_24B_BLOCK;
            }

            if (size != 0) {
                mdec.rl = rl2blk(blk, mdec.rl);
                yuv2rgb24(blk, mdec.block_buffer);
                memcpy(image, mdec.block_buffer, size);
                mdec.block_buffer_pos = mdec.block_buffer + size;
            }
        }

        /* define the power of mdec */
        scheduleMDECOUTDMAIRQ((int)((dmacnt * MDEC_BIAS)));
    }
}

void PCSX::MDEC::mdec1Interrupt() {
    /* Author : gschwind
     *
     * in that case we have done all decoding stuff
     * Note that : each block end with 0xfe00 flags
     * the list of blocks end with the same 0xfe00 flags
     * data loock like :
     *
     *  data block ...
     *  0xfe00
     *  data block ...
     *  0xfe00
     *  a lost of block ..
     *
     *  0xfe00
     *  the last block
     *  0xfe00
     *  0xfe00
     *
     * OR
     *
     * if the 0xfe00 is not present the data size is important.
     *
     */

    /* this else if avoid to read outside memory */
    if (mdec.rl >= mdec.rl_end) {
        mdec.reg1 &= ~MDEC1_STP;
        mdec0Interrupt();
        mdec.reg1 &= ~MDEC1_BUSY;
    } else if (SWAP_LE16(*(mdec.rl)) == MDEC_END_OF_DATA) {
        mdec.reg1 &= ~MDEC1_STP;
        mdec0Interrupt();
        mdec.reg1 &= ~MDEC1_BUSY;
    }

    auto &mem = g_emulator->m_mem;
    mem->clearDMABusy<1>();
    mem->dmaInterrupt<1>();
}
