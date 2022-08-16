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

    uint8_t last_byte;

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
        MCD_READWRITE_STATE_GET_DIR_INDEX = 3,
    };
    enum class MCD_Commands : uint8_t {
        Read = 0x52,   // Read Command
        GetID = 0x53,  // Get ID Command
        Write = 0x57,  // Write Command
        None = 0x00,   // No command, idle state
        Error = 0xFF,  // Bad command

        // PocketStation command extensions
        PS_ChangeFuncValue = 0x50,  // Change a FUNC 03h related value or so
        PS_GetID = 0x58,            // Get an ID or Version value or so
        PS_PrepFileExec = 0x59,     // Prepare File Execution with Dir_index, and Parameter
        PS_GetDirIndex = 0x5A,      // Get Dir_index, ComFlags, F_SN, Date, and Time
        PS_ExecXferPSToPSX = 0x5B,  // Execute Function and transfer data from Pocketstation to PSX
        PS_ExecXferPSXToPS = 0x5C,  // Execute Function and transfer data from PSX to Pocketstation
        PS_ExecCustom = 0x5D,       // Execute Custom Download Notification Function   ;via SWI 01h with r0=3
        PS_GetComFlagsHi = 0x5E,    // Get-and-Send ComFlags.bit1,3,2
        PS_GetComFlagsLo = 0x5F,    // Get-and-Send ComFlags.bit0
    };
    enum class MCD_Responses : uint8_t {
        IdleHighZ = 0xFF,           // High default state
        Dummy = 0x00,               // Filler Data
        ID1 = 0x5A,                 // Memory Card ID1
        ID2 = 0x5D,                 // Memory Card ID2
        CommandAcknowledge1 = 0x5C,  // Command Acknowledge 1
        CommandAcknowledge2 = 0x5D,  // Command Acknowledge 2
        GoodReadWrite = 0x47,        // Good Read/Write
        BadChecksum = 0x4E,          // Bad Checksum during Write
        BadSector = 0xFF,            // Bad Memory Card Sector
    };
    enum class PAD_Commands : uint8_t {
        Read = 0x42,    // Read Command
        None = 0x00,    // No command, idle state
        Error = 0xFF    // Bad command
    };
    enum class SIO_Device : uint8_t {
        None = 0x00,        // No device selected yet
        PAD = 0x01,         // Pad Select
        NetYaroze = 0x21,   // Net Yaroze Select
        MemoryCard = 0x81,  // Memory Card Select
        Ignore = 0xFF,      // Ignore incoming commands
    };
    enum SIO_Selected : uint16_t {
        Port1 = 0x0002,
        Port2 = 0x2002,
        PortMask = 0x2002,
    };
    uint8_t m_mcdAddrHigh, m_mcdAddrLow;
    bool m_wasMcd1Inserted = false;
    bool m_wasMcd2Inserted = false;
    uint32_t m_padState;

    uint8_t current_device = static_cast<uint8_t>(SIO_Device::None);

    inline void scheduleInterrupt(uint32_t eCycle) {
        g_emulator->m_cpu->scheduleInterrupt(PSXINT_SIO, eCycle);
#if 0
// Breaks Twisted Metal 2 intro
        m_statusReg &= ~RX_RDY;
        m_statusReg &= ~TX_RDY;
#endif
    }
    void writePad(uint8_t value);
    void writeMcd(uint8_t value);

  public:
    SIO();
    static const size_t MCD_SECT_SIZE = 8 * 16;
    static const size_t MCD_BLOCK_SIZE = 8192;
    static const size_t MCD_SIZE = 1024 * MCD_SECT_SIZE;

    char g_mcd1Data[MCD_SIZE], g_mcd2Data[MCD_SIZE];

    void write8(uint8_t value);
    void writeStatus16(uint16_t value);
    void writeMode16(uint16_t value);
    void writeCtrl16(uint16_t value);
    void writeBaud16(uint16_t value);

    uint8_t read8();
    uint16_t readStatus16();
    uint16_t readMode16();
    uint16_t readCtrl16();
    uint16_t readBaud16();

    void netError();
    void interrupt();
    void reset();

    void LoadMcd(int mcd, const PCSX::u8string str);
    void LoadMcds(const PCSX::u8string mcd1, const PCSX::u8string mcd2);
    void saveMcd(const PCSX::u8string mcd, const char *data, uint32_t adr, size_t size);
    void saveMcd(int mcd);
    void CreateMcd(const PCSX::u8string mcd);
    void ConvertMcd(const PCSX::u8string mcd, const char *data);

    struct McdBlock {
        McdBlock() { reset(); }
        int mcd;
        int number;
        std::string titleAscii;
        std::string titleSjis;
        std::string titleUtf8;
        std::string id;
        std::string name;
        uint32_t fileSize;
        uint32_t iconCount;
        uint16_t icon[16 * 16 * 3];
        uint32_t allocState;
        int16_t nextBlock;
        void reset() {
            mcd = 0;
            number = 0;
            titleAscii.clear();
            titleSjis.clear();
            titleUtf8.clear();
            id.clear();
            name.clear();
            fileSize = 0;
            iconCount = 0;
            memset(icon, 0, sizeof(icon));
            allocState = 0;
            nextBlock = -1;
        }
        bool isErased() const { return (allocState & 0xa0) == 0xa0; }
        bool isChained() const { return (allocState & ~1) == 0x52; }
    };

    void getMcdBlockInfo(int mcd, int block, McdBlock &info);
    void eraseMcdFile(const McdBlock &block);
    void eraseMcdFile(int mcd, int block) {
        McdBlock info;
        getMcdBlockInfo(mcd, block, info);
        eraseMcdFile(info);
    }
    static constexpr int otherMcd(int mcd) {
        if ((mcd != 1) && (mcd != 2)) throw std::runtime_error("Bad memory card number");
        if (mcd == 1) return 2;
        return 1;
    }
    static constexpr int otherMcd(const McdBlock &block) { return otherMcd(block.mcd); }
    unsigned getFreeSpace(int mcd);
    unsigned getFileBlockCount(McdBlock block);
    int findFirstFree(int mcd);
    bool copyMcdFile(McdBlock block);
    char *getMcdData(int mcd);
    char *getMcdData(const McdBlock &block) { return getMcdData(block.mcd); }

    static void SIO1irq(void) { psxHu32ref(0x1070) |= SWAP_LEu32(0x100); }

    friend SaveStates::SaveState SaveStates::constructSaveState();
};

}  // namespace PCSX
