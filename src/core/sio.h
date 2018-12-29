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

#include "core/plugins.h"
#include "core/psemu_plugin_defs.h"
#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"

namespace PCSX {

class SIO {
  private:
    enum {
        // Status Flags
        TX_RDY = 0x0001,
        RX_RDY = 0x0002,
        TX_EMPTY = 0x0004,
        PARITY_ERR = 0x0008,
        RX_OVERRUN = 0x0010,
        FRAMING_ERR = 0x0020,
        SYNC_DETECT = 0x0040,
        DSR = 0x0080,
        CTS = 0x0100,
        IRQ = 0x0200,

        // Control Flags
        TX_PERM = 0x0001,
        DTR = 0x0002,
        RX_PERM = 0x0004,
        BREAK = 0x0008,
        RESET_ERR = 0x0010,
        RTS = 0x0020,
        SIO_RESET = 0x0040,

        // MCD flags
        MCDST_CHANGED = 0x08,
    };

    static const size_t BUFFER_SIZE = 0x1010;

    uint8_t s_buf[BUFFER_SIZE];

    //[0] -> dummy
    //[1] -> memory card status flag
    //[2] -> card 1 id, 0x5a->plugged, any other not plugged
    //[3] -> card 2 id, 0x5d->plugged, any other not plugged
    uint8_t s_cardh[4] = {0x00, 0x08, 0x5a, 0x5d};

    // Transfer Ready and the Buffer is Empty
    // static unsigned short s_statReg = 0x002b;
    uint16_t s_statReg = TX_RDY | TX_EMPTY;
    uint16_t s_modeReg;
    uint16_t s_ctrlReg;
    uint16_t s_baudReg;

    unsigned int s_bufcount;
    unsigned int s_parp;
    unsigned int s_mcdst, s_rdwr;
    unsigned char s_adrH, s_adrL;
    unsigned int s_padst;
    unsigned int s_gsdonglest;

    static const size_t DONGLE_SIZE = 0x40 * 0x1000;

    unsigned int s_dongleBank;
    unsigned char s_dongleData[DONGLE_SIZE];
    int s_dongleInit;

  public:
    static const uint64_t MCD_SECT_SIZE = 8 * 16;
    static const uint64_t MCD_SIZE = 1024 * MCD_SECT_SIZE;

    char g_mcd1Data[MCD_SIZE], g_mcd2Data[MCD_SIZE];

    void sioWrite8(uint8_t value);
    void sioWriteStat16(uint16_t value);
    void sioWriteMode16(uint16_t value);
    void sioWriteCtrl16(uint16_t value);
    void sioWriteBaud16(uint16_t value);

    uint8_t sioRead8();
    uint16_t sioReadStat16();
    uint16_t sioReadMode16();
    uint16_t sioReadCtrl16();
    uint16_t sioReadBaud16();

    void netError();

    void sioInterrupt();
    int sioFreeze(gzFile f, int Mode);

    void LoadMcd(int mcd, const char *str);
    void LoadMcds(const char *mcd1, const char *mcd2);
    void SaveMcd(const char *mcd, const char *data, uint32_t adr, size_t size);
    void CreateMcd(const char *mcd);
    void ConvertMcd(const char *mcd, const char *data);

    void LoadDongle(const char *filename);
    void SaveDongle(const char *filename);

    typedef struct {
        char Title[48 + 1];       // Title in ASCII
        char sTitle[48 * 2 + 1];  // Title in Shift-JIS
        char ID[12 + 1];
        char Name[16 + 1];
        uint32_t IconCount;
        uint16_t Icon[16 * 16 * 3];
        uint8_t Flags;
    } McdBlock;

    void GetMcdBlockInfo(int mcd, int block, McdBlock *info);

    static void CALLBACK SIO1irq(void) { psxHu32ref(0x1070) |= SWAP_LEu32(0x100); }
};

}  // namespace PCSX
