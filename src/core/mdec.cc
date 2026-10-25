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

#include "core/debug.h"
#include "core/logger.h"
#include "core/mdec-decoder.h"
#include "core/psxemulator.h"
#include "core/system.h"

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

// The decoder itself - dequantizer, both IDCTs, colour stage - is in
// core/mdec-decoder.cc, shared with tools/mdec. What stays here is the chip
// around it: registers, DMA, the tables' lifetime, and the diagnostics.

void PCSX::MDEC::scaletable_init() {
    // Zero, not the standard constants. See the note in mdec.h: silicon has no
    // default here, and a decode before MDEC(3) produces nothing on hardware.
    m_tables.clearScale();
    scaleTableUploaded = false;
    warnedNoScaleTable = false;
}

void PCSX::MDEC::standardTables_init() {
    // For save states written before the raw quant tables and the scale matrix
    // were serialised. Those emulators always decoded with the standard matrix,
    // and the standard quant table is what nearly every game uploads.
    m_tables.setStandard();
    scaleTableUploaded = true;
    warnedNoScaleTable = false;
}

void PCSX::MDEC::iqtab_init(int *iqtab, const unsigned char *qt) { MDECDecoder::prescaleQuantTable(iqtab, qt); }

void PCSX::MDEC::qtab_fromIqtab(unsigned char *qt, const int *iqtab) {
    MDECDecoder::quantTableFromPrescaled(qt, iqtab);
}

unsigned short *PCSX::MDEC::rl2blk(int *blk, unsigned short *mdec_rl) {
    // Unbounded, as the chip reads: it keeps pulling halfwords for as long as
    // DMA1 asks for pixels.
    return const_cast<unsigned short *>(MDECDecoder::decodeMacroblock(blk, mdec_rl, m_tables));
}

void PCSX::MDEC::yuv2rgb15(int *blk, unsigned short *image) {
    MDECDecoder::toRGB15(blk, image, g_emulator->settings.get<Emulator::SettingBnWMdec>(),
                         (mdec.reg0 & MDEC0_STP) != 0);
}

void PCSX::MDEC::yuv2rgb24(int *blk, uint8_t *image) {
    MDECDecoder::toRGB24(blk, image, g_emulator->settings.get<Emulator::SettingBnWMdec>());
}

void PCSX::MDEC::init(void) {
    memset(&mdec, 0, sizeof(mdec));
    m_tables = {};
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
            m_tables.setQuant(p, p + 64);
        }

            scheduleMDECINDMAIRQ(size / 4);
            return;

        case 0x6: {  // scale table, MDEC(3)
            // 64 signed halfwords with a 14-bit fractional part. This used to be
            // dropped on the floor, which meant a custom table silently decoded
            // with the standard one: correct-looking output here, different output
            // on hardware, and no diagnostic either way.
            const int16_t *p = g_emulator->m_mem->getPointer<int16_t>(adr);
            int16_t table[DSIZE2];
            for (unsigned i = 0; i < DSIZE2; i++) table[i] = SWAP_LE16(p[i]);
            m_tables.setScale(table);
            scaleTableUploaded = true;
            warnedNoScaleTable = false;
        }
            scheduleMDECINDMAIRQ(size / 4);
            return;

        default:
            // printf("mdec unknown command\n");
            break;
    }

    scheduledCallback0();
}

void PCSX::MDEC::scheduledCallback0() {
    auto &mem = g_emulator->m_mem;
    mem->clearDMABusy<0>();
    mem->dmaInterrupt<0>();
}

#define MDEC_END_OF_DATA 0xfe00
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

void PCSX::MDEC::scheduledCallback1() {
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
        scheduledCallback0();
        mdec.reg1 &= ~MDEC1_BUSY;
    } else if (SWAP_LE16(*(mdec.rl)) == MDEC_END_OF_DATA) {
        mdec.reg1 &= ~MDEC1_STP;
        scheduledCallback0();
        mdec.reg1 &= ~MDEC1_BUSY;
    }

    auto &mem = g_emulator->m_mem;
    mem->clearDMABusy<1>();
    mem->dmaInterrupt<1>();
}
