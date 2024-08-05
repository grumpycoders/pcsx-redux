/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
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

#include <stdint.h>

#include "core/psxemulator.h"
#include "core/sstate.h"

namespace PCSX {
class SIO;
class Memorycards;

/// <summary>
/// Implements a memory card for SIO
/// </summary>
class MemoryCard {
  public:
    MemoryCard(uint8_t device_index) : m_deviceIndex(device_index) {
        if (m_mcdData) {
            memset(m_mcdData, 0, c_cardSize);
        }

        if (m_tempBuffer) {
            memset(m_tempBuffer, 0, c_blockSize);
        }
    }
    ~MemoryCard(){};

    // Hardware events

    void deselect() {
        memset(&m_tempBuffer, 0, c_sectorSize);
        m_currentCommand = Commands::None;
        m_commandTicks = 0;
        m_dataOffset = 0;
        m_sector = 0;
        m_spdr = Responses::IdleHighZ;
    }
    void reset() {
        deselect();
        m_directoryFlag = Flags::DirectoryUnread;
    }

    void setPocketstationEnabled(bool enabled) { m_pocketstationEnabled = enabled; };

    // File system / data manipulation
    void commit();
    char *getMcdData() { return m_mcdData; }

  private:
    enum Commands : uint8_t {
        Access = 0x81,  // Memory Card Select
        Read = 0x52,    // Read Command
        GetID = 0x53,   // Get ID Command
        Write = 0x57,   // Write Command
        None = 0x00,    // No command, idle state
        Error = 0xFF,   // Bad command

        // PocketStation command extensions
        PS_ChangeFuncValue = 0x50,  // Change a FUNC 03h related value or so
        PS_GetVersion = 0x58,       // Get an ID or Version value or so
        PS_PrepFileExec = 0x59,     // Prepare File Execution with Dir_index, and Parameter
        PS_GetDirIndex = 0x5A,      // Get Dir_index, ComFlags, F_SN, Date, and Time
        PS_ExecXferPSToPSX = 0x5B,  // Execute Function and transfer data from Pocketstation to PSX
        PS_ExecXferPSXToPS = 0x5C,  // Execute Function and transfer data from PSX to Pocketstation
        PS_ExecCustom = 0x5D,       // Execute Custom Download Notification Function   ;via SWI 01h with r0=3
        PS_GetComFlagsHi = 0x5E,    // Get-and-Send ComFlags.bit1,3,2
        PS_GetComFlagsLo = 0x5F,    // Get-and-Send ComFlags.bit0
    };
    enum Flags : uint8_t {
        DirectoryUnread = 0x08,  // Initial power on value
        DirectoryRead = 0x00     // Cleared after good MC Write
                                 // (test write sector 3F = 0x1F80) offset
    };
    enum Responses : uint8_t {
        IdleHighZ = 0xFF,            // High default state
        Dummy = 0x00,                // Filler Data
        ID1 = 0x5A,                  // Memory Card ID1
        ID2 = 0x5D,                  // Memory Card ID2
        CommandAcknowledge1 = 0x5C,  // Command Acknowledge 1
        CommandAcknowledge2 = 0x5D,  // Command Acknowledge 2
        GoodReadWrite = 0x47,        // Good Read/Write
        BadChecksum = 0x4E,          // Bad Checksum during Write
        BadSector = 0xFF,            // Bad Memory Card Sector
    };

    friend class SIO;
    friend SaveStates::SaveState SaveStates::constructSaveState();

    static constexpr size_t c_sectorSize = 8 * 16;            // 80h bytes per sector/frame
    static constexpr size_t c_blockSize = c_sectorSize * 64;  // 40h sectors per block
    static constexpr size_t c_cardSize = c_blockSize * 16;    // 16 blocks per frame(directory+15 saves);

    // State machine / handlers
    uint8_t transceive(uint8_t value, bool *ack);           // *
    uint8_t tickReadCommand(uint8_t value, bool *ack);      // 52h
    uint8_t tickWriteCommand(uint8_t value, bool *ack);     // 57h
    uint8_t tickPS_GetDirIndex(uint8_t value, bool *ack);   // 5Ah
    uint8_t tickPS_GetVersion(uint8_t value, bool *ack);    // 58h
    uint8_t tickPS_PrepFileExec(uint8_t value, bool *ack);  // 59h
    uint8_t tickPS_ExecCustom(uint8_t value, bool *ack);    // 5Dh

    char m_mcdData[c_cardSize];
    uint8_t m_tempBuffer[c_blockSize];
    bool m_savedToDisk = false;

    uint8_t m_checksumIn = 0, m_checksumOut = 0;
    uint16_t m_commandTicks = 0;
    uint8_t m_currentCommand = Commands::None;
    uint16_t m_sector = 0;
    uint32_t m_dataOffset = 0;

    uint8_t m_directoryFlag = Flags::DirectoryUnread;

    uint8_t m_spdr = Responses::IdleHighZ;

    // PocketStation Specific
    bool m_pocketstationEnabled = false;
    uint16_t m_directoryIndex = 0;

    SIO *m_sio = nullptr;
    uint8_t m_deviceIndex = 0;
};

/// <summary>
/// Helper functions for MemoryCard class, gui, and filesystem
/// </summary>
class MemoryCards {
  public:
    void deselect() {
        m_memoryCard[0].deselect();
        m_memoryCard[1].deselect();
    }

    void reset() {
        m_memoryCard[0].reset();
        m_memoryCard[1].reset();
    }

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

    static constexpr size_t c_sectorSize = 8 * 16;            // 80h bytes per sector/frame
    static constexpr size_t c_blockSize = c_sectorSize * 64;  // 40h sectors per block
    static constexpr size_t c_cardSize = c_blockSize * 16;    // 16 blocks per frame(directory+15 saves)

    bool copyMcdFile(McdBlock block);
    void eraseMcdFile(const McdBlock &block);
    void eraseMcdFile(int mcd, int block) {
        McdBlock info;
        getMcdBlockInfo(mcd, block, info);
        eraseMcdFile(info);
    }
    int findFirstFree(int mcd);
    unsigned getFreeSpace(int mcd);
    unsigned getFileBlockCount(McdBlock block);
    void getMcdBlockInfo(int mcd, int block, McdBlock &info);
    char *getMcdData(int mcd);
    char *getMcdData(const McdBlock &block) { return getMcdData(block.mcd); }

    // File operations
    void createMcd(PCSX::u8string mcd);
    void loadMcds(const CommandLine::args &args);
    bool saveMcd(int card_index);

    bool loadMcd(PCSX::u8string mcd, char *data);
    bool saveMcd(PCSX::u8string mcd, const char *data, uint32_t adr, size_t size);

    static constexpr int otherMcd(int mcd) {
        if ((mcd != 0) && (mcd != 1)) throw std::runtime_error("Bad memory card number");
        if (mcd == 0) return 1;
        return 0;
    }

    PCSX::u8string getMcdPath(int index) {
        std::filesystem::path *paths[] = {&PCSX::g_emulator->settings.get<PCSX::Emulator::SettingMcd1>().value,
                                          &PCSX::g_emulator->settings.get<PCSX::Emulator::SettingMcd2>().value};

        PCSX::u8string thepath = paths[index]->u8string();
        return thepath;
    }
    bool isCardInserted(int index) {
        bool *const inserted_lut[] = {&PCSX::g_emulator->settings.get<PCSX::Emulator::SettingMcd1Inserted>().value,
                                      &PCSX::g_emulator->settings.get<PCSX::Emulator::SettingMcd2Inserted>().value};

        return *inserted_lut[index];
    }

    static constexpr int otherMcd(const McdBlock &block) { return otherMcd(block.mcd); }
    void resetCard(int index);
    void setPocketstationEnabled(int index, bool enabled);

    MemoryCard m_memoryCard[2] = {MemoryCard(0), MemoryCard(1)};
};

}  // namespace PCSX
