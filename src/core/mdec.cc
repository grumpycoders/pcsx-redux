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

#include "core/debug.h"
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
    for (int i = 0; i < 6; i++) {
        // decode blocks (Cr,Cb,Y1,Y2,Y3,Y4)
        if (i == 2) iqtab = iq_y;

        rl = SWAP_LE16(*mdec_rl);
        mdec_rl++;
        q_scale = RLE_RUN(rl);
        blk[0] = SCALER(iqtab[0] * RLE_VAL(rl), AAN_EXTRA - 3);
        for (k = 0, used_col = 0;;) {
            rl = SWAP_LE16(*mdec_rl);
            mdec_rl++;
            if (rl == MDEC_END_OF_DATA) break;
            k += RLE_RUN(rl) + 1;  // skip zero-coefficients

            if (k > 63) {
                // printf("run lenght exceeded 64 enties\n");
                break;
            }

            // zigzag transformation
            blk[zscan[k]] = SCALER(RLE_VAL(rl) * iqtab[k] * q_scale, AAN_EXTRA);
            // keep track of used columns to speed up the idtc
            used_col |= (zscan[k] > 7) ? 1 << (zscan[k] & 7) : 0;
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
#define MULG2(a, b) ((-351 * (a)-728 * (b)))
#define MULY(a) ((a) << 10)

#define MAKERGB15(r, g, b, a) (SWAP_LE16(a | ((b) << 10) | ((g) << 5) | (r)))
#define SCALE8(c) SCALER(c, 20)
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
    mdec.rl = (uint16_t *)&PCSX::g_emulator->m_mem->g_psxM[0x100000];
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
            mdec.rl = (uint16_t *)PSXM(adr);
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
            uint8_t *p = (uint8_t *)PSXM(adr);
            // printf("uploading new quantization table\n");
            // printmatrixu8(p);
            // printmatrixu8(p + 64);
            iqtab_init(iq_y, p);
            iqtab_init(iq_uv, p + 64);
        }

            scheduleMDECINDMAIRQ(size / 4);
            return;

        case 0x6:  // cosine table
            // printf("mdec cosine table\n");

            scheduleMDECINDMAIRQ(size / 4);
            return;

        default:
            // printf("mdec unknown command\n");
            break;
    }

    HW_DMA0_CHCR &= SWAP_LE32(~0x01000000);
    DMA_INTERRUPT(0);
}

void PCSX::MDEC::mdec0Interrupt() {
    HW_DMA0_CHCR &= SWAP_LE32(~0x01000000);
    DMA_INTERRUPT(0);
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
        image = (uint8_t *)PSXM(adr);

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
        HW_DMA0_CHCR &= SWAP_LE32(~0x01000000);
        DMA_INTERRUPT(0);
        mdec.reg1 &= ~MDEC1_BUSY;
    } else if (SWAP_LE16(*(mdec.rl)) == MDEC_END_OF_DATA) {
        mdec.reg1 &= ~MDEC1_STP;
        HW_DMA0_CHCR &= SWAP_LE32(~0x01000000);
        DMA_INTERRUPT(0);
        mdec.reg1 &= ~MDEC1_BUSY;
    }

    HW_DMA1_CHCR &= SWAP_LE32(~0x01000000);
    DMA_INTERRUPT(1);
    return;
}

void PCSX::MDEC::save(PCSX::SaveStates::MDEC &mdecSave) {
    uint8_t *base = (uint8_t *)&PCSX::g_emulator->m_mem->g_psxM[0x100000];
    uint32_t v;

    mdecSave.get<SaveStates::MDECReg0>().value = mdec.reg0;
    mdecSave.get<SaveStates::MDECReg1>().value = mdec.reg1;
    mdecSave.get<SaveStates::MDECRl>().value = reinterpret_cast<uint8_t *>(mdec.rl) - base;
    mdecSave.get<SaveStates::MDECRlEnd>().value = reinterpret_cast<uint8_t *>(mdec.rl_end) - base;
    mdecSave.get<SaveStates::MDECBlockBufferPos>().value = mdec.block_buffer_pos ? mdec.block_buffer_pos - base : 0;
    mdecSave.get<SaveStates::MDECBlockBuffer>().copyFrom(mdec.block_buffer);
    mdecSave.get<SaveStates::MDECDMAADR>().value = mdec.pending_dma1.adr;
    mdecSave.get<SaveStates::MDECDMABCR>().value = mdec.pending_dma1.bcr;
    mdecSave.get<SaveStates::MDECDMACHCR>().value = mdec.pending_dma1.chcr;
    for (unsigned i = 0; i < 64; i++) {
        mdecSave.get<SaveStates::MDECIQY>().value[i].value = iq_y[i];
        mdecSave.get<SaveStates::MDECIQUV>().value[i].value = iq_uv[i];
    }
}

void PCSX::MDEC::load(const PCSX::SaveStates::MDEC &mdecSave) {
    uint8_t *base = (uint8_t *)&PCSX::g_emulator->m_mem->g_psxM[0x100000];
    uint32_t v;

    mdec.reg0 = mdecSave.get<SaveStates::MDECReg0>().value;
    mdec.reg1 = mdecSave.get<SaveStates::MDECReg1>().value;
    mdec.rl = reinterpret_cast<uint16_t *>(mdecSave.get<SaveStates::MDECRl>().value + base);
    mdec.rl_end = reinterpret_cast<uint16_t *>(mdecSave.get<SaveStates::MDECRlEnd>().value + base);
    const auto &pos = mdecSave.get<SaveStates::MDECBlockBufferPos>().value;
    mdec.block_buffer_pos = pos ? pos + base : nullptr;
    mdecSave.get<SaveStates::MDECBlockBuffer>().copyTo(mdec.block_buffer);
    mdec.pending_dma1.adr = mdecSave.get<SaveStates::MDECDMAADR>().value;
    mdec.pending_dma1.bcr = mdecSave.get<SaveStates::MDECDMABCR>().value;
    mdec.pending_dma1.chcr = mdecSave.get<SaveStates::MDECDMACHCR>().value;
    for (unsigned i = 0; i < 64; i++) {
        iq_y[i] = mdecSave.get<SaveStates::MDECIQY>().value[i].value;
        iq_uv[i] = mdecSave.get<SaveStates::MDECIQUV>().value[i].value;
    }
}
