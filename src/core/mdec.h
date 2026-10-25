/***************************************************************************
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

#pragma once

#include "core/mdec-decoder.h"
#include "core/psxdma.h"
#include "core/psxemulator.h"
#include "core/psxhw.h"
#include "core/r3000a.h"

namespace PCSX {

struct SaveStateWrapper;

class MDEC {
  public:
    void init();
    void write0(uint32_t data);
    void write1(uint32_t data);
    uint32_t read0();
    uint32_t read1();
    void dma0(uint32_t madr, uint32_t bcr, uint32_t chcr);
    void dma1(uint32_t madr, uint32_t bcr, uint32_t chcr);
    void scheduledCallback0();
    void scheduledCallback1();

    static const unsigned DSIZE = MDECDecoder::DSIZE;
    static const unsigned DSIZE2 = MDECDecoder::DSIZE2;

    void serialize(SaveStateWrapper *);
    void deserialize(const SaveStateWrapper *);

    // An uploaded quant table as the AAN decoder caches it (each entry times
    // its prescale factor), and back. The factors are all non-zero, so the
    // reverse is an exact division.
    static void iqtab_init(int *iqtab, const unsigned char *qt);
    static void qtab_fromIqtab(unsigned char *qt, const int *iqtab);

  private:
    /* memory speed is 1 byte per MDEC_BIAS psx clock
     * That mean (PCSX::g_emulator->m_psxClockSpeed / MDEC_BIAS) B/s
     * MDEC_BIAS = 2.0 => ~16MB/s
     * MDEC_BIAS = 3.0 => ~11MB/s
     * and so on ...
     * I guess I have 50 images in 50Hz ... (could be 25 images ?)
     * 320x240x24@50Hz => 11.52 MB/s
     * 320x240x24@60Hz => 13.824 MB/s
     * 320x240x16@50Hz => 7.68 MB/s
     * 320x240x16@60Hz => 9.216 MB/s
     * so 2.0 to 4.0 should be fine.
     */
    static inline const float MDEC_BIAS = 2.0f;

    struct _pending_dma1 {
        uint32_t adr;
        uint32_t bcr;
        uint32_t chcr;
    };

    struct {
        uint32_t reg0;
        uint32_t reg1;
        uint16_t *rl;
        uint16_t *rl_end;
        uint8_t *block_buffer_pos;
        uint8_t block_buffer[16 * 16 * 3];
        struct _pending_dma1 pending_dma1;
    } mdec;

    // The quant tables (raw and AAN-prescaled) and the MDEC(3) matrix. The
    // decoder that reads them is shared with tools/mdec.
    MDECDecoder::Tables m_tables;
    // The hardware does NOT initialise the scale matrix: measured 2026-09-14 on
    // real consoles, a decode with no MDEC(3) upload returns flat mid-grey for
    // every pixel. We reproduce that rather than silently substituting the
    // standard constants, and say so once in the log, because the alternative is
    // homebrew that works here and shows a grey rectangle on console.
    bool scaleTableUploaded = false;
    bool warnedNoScaleTable = false;

    void yuv2rgb15(int *blk, unsigned short *image);
    void yuv2rgb24(int *blk, uint8_t *image);
    void scaletable_init();
    void standardTables_init();
    unsigned short *rl2blk(int *blk, unsigned short *mdec_rl);
};

}  // namespace PCSX
