/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#include <string>

#include "core/psemu_plugin_defs.h"
#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "core/sstate.h"

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

    uint8_t m_buffer[BUFFER_SIZE];

    // Transfer Ready and the Buffer is Empty
    // static unsigned short m_statusReg = 0x002b;
    uint16_t m_statusReg = TX_RDY | TX_EMPTY;
    uint16_t m_modeReg;
    uint16_t m_ctrlReg;
    uint16_t m_baudReg;

    uint32_t m_maxBufferIndex;
    uint32_t m_bufferIndex;
    uint32_t m_mcdState, m_mcdReadWriteState;
    enum {
        MCD_STATE_IDLE = 0,
        MCD_STATE_READ_COMMAND = 1,
        MCD_STATE_READ_ADDR_HIGH = 2,
        MCD_STATE_READ_ADDR_LOW = 3,
        MCD_STATE_READ_ACK = 4,
        MCD_STATE_READWRITE_DATA = 5,
    };
    enum {
        MCD_READWRITE_STATE_IDLE = 0,
        MCD_READWRITE_STATE_READ = 1,
        MCD_READWRITE_STATE_WRITE = 2,
    };
    uint8_t m_mcdAddrHigh, m_mcdAddrLow;
    bool m_wasMcd1Inserted = false;
    bool m_wasMcd2Inserted = false;
    uint32_t m_padState;
    enum {
        PAD_STATE_IDLE = 0,
        PAD_STATE_READ_TYPE = 1,
        PAD_STATE_READ_DATA = 2,
    };
    inline void scheduleInterrupt(uint32_t eCycle) {
        g_emulator->m_psxCpu->scheduleInterrupt(PSXINT_SIO, eCycle);
#if 0
// Breaks Twisted Metal 2 intro
        m_statusReg &= ~RX_RDY;
        m_statusReg &= ~TX_RDY;
#endif
    }
    void writePad(uint8_t value);
    void writeMcd(uint8_t value);

  public:
    static const uint64_t MCD_SECT_SIZE = 8 * 16;
    static const uint64_t MCD_SIZE = 1024 * MCD_SECT_SIZE;

    char g_mcd1Data[MCD_SIZE], g_mcd2Data[MCD_SIZE];

    void write8(uint8_t value);
    void writeStatus16(uint16_t value);
    void writeMode16(uint16_t value);
    void writeCtrl16(uint16_t value);
    void writeBaud16(uint16_t value);

    uint8_t sioRead8();
    uint16_t readStatus16();
    uint16_t readMode16();
    uint16_t readCtrl16();
    uint16_t readBaud16();

    void netError();

    void interrupt();

    void LoadMcd(int mcd, const PCSX::u8string str);
    void LoadMcds(const PCSX::u8string mcd1, const PCSX::u8string mcd2);
    void SaveMcd(const PCSX::u8string mcd, const char *data, uint32_t adr, size_t size);
    void CreateMcd(const PCSX::u8string mcd);
    void ConvertMcd(const PCSX::u8string mcd, const char *data);

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

    static void SIO1irq(void) { psxHu32ref(0x1070) |= SWAP_LEu32(0x100); }

    friend SaveStates::SaveState SaveStates::constructSaveState();
};

}  // namespace PCSX
