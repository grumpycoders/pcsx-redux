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

#include "core/psxdma.h"
#include "core/psxemulator.h"
#include "core/psxhw.h"
#include "core/r3000a.h"
#include "core/sstate.h"

namespace PCSX {

class MDEC {
  public:
    void mdecInit();
    void mdecWrite0(uint32_t data);
    void mdecWrite1(uint32_t data);
    uint32_t mdecRead0();
    uint32_t mdecRead1();
    void psxDma0(uint32_t madr, uint32_t bcr, uint32_t chcr);
    void psxDma1(uint32_t madr, uint32_t bcr, uint32_t chcr);
    void mdec0Interrupt();
    void mdec1Interrupt();

    static const unsigned DSIZE = 8;
    static const unsigned DSIZE2 = DSIZE * DSIZE;

    void save(SaveStates::MDEC& mdecSave);
    void load(const SaveStates::MDEC& mdecSave);

  private:
    /* memory speed is 1 byte per MDEC_BIAS psx clock
     * That mean (PCSX::g_emulator.m_psxClockSpeed / MDEC_BIAS) B/s
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
        uint16_t* rl;
        uint16_t* rl_end;
        uint8_t* block_buffer_pos;
        uint8_t block_buffer[16 * 16 * 3];
        struct _pending_dma1 pending_dma1;
    } mdec;

    int iq_y[DSIZE2], iq_uv[DSIZE2];

    static inline const int zscan[DSIZE2] = {
        0,  1,  8,  16, 9,  2,  3,  10, 17, 24, 32, 25, 18, 11, 4,  5,   // 00
        12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6,  7,  14, 21, 28,  // 10
        35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,  // 20
        58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,  // 30
    };

    static inline const int aanscales[DSIZE2] = {
        1048576, 1454417, 1370031, 1232995, 1048576, 823861,  567485, 289301,  // 00
        1454417, 2017334, 1900287, 1710213, 1454417, 1142728, 787125, 401273,  // 08
        1370031, 1900287, 1790031, 1610986, 1370031, 1076426, 741455, 377991,  // 10
        1232995, 1710213, 1610986, 1449849, 1232995, 968758,  667292, 340183,  // 18
        1048576, 1454417, 1370031, 1232995, 1048576, 823861,  567485, 289301,  // 20
        823861,  1142728, 1076426, 968758,  823861,  647303,  445870, 227303,  // 28
        567485,  787125,  741455,  667292,  567485,  445870,  307121, 156569,  // 30
        289301,  401273,  377991,  340183,  289301,  227303,  156569, 79818    // 38
    };

    void putlinebw15(uint16_t* image, int* Yblk);
    void putquadrgb15(uint16_t* image, int* Yblk, int Cr, int Cb);
    void yuv2rgb15(int* blk, unsigned short* image);
    void iqtab_init(int* iqtab, unsigned char* iq_y);
    unsigned short* rl2blk(int* blk, unsigned short* mdec_rl);
};

}  // namespace PCSX
