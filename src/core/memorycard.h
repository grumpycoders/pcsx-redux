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

#include "core/psxemulator.h"
#include "core/r3000a.h"
//#include "core/sio.h"

class SIO;

namespace PCSX {
class MemoryCard {
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

    static const size_t MCD_SECT_SIZE = 8 * 16;
    static const size_t MCD_BLOCK_SIZE = 8192;
    static const size_t MCD_SIZE = 1024 * MCD_SECT_SIZE;

    char g_mcdData[MCD_SIZE];

    uint8_t checksum_in, checksum_out;
    uint32_t command_ticks = 0;
    uint8_t current_command = Commands::None;
    uint8_t flag = Flags::DirectoryUnread;
    bool saved_local = false;
    uint16_t sector = 0;
    uint32_t sector_offset = 0;

    SIO * m_sio;

    // PocketStation Specific
    uint16_t PS_DirectoryIndex;

    void GoIdle() {
        current_command = Commands::None;
        command_ticks = 0;
        sector_offset = 0;
    }

    void CreateMcd(const PCSX::u8string mcd);
    void ConvertMcd(const PCSX::u8string mcd, const char *data);
    char *getMcdData() { return g_mcdData; }

    friend class SIO;

  public:
    MemoryCard() : m_sio(nullptr) {}
    MemoryCard(SIO *parent) : m_sio(parent) {}

    void ACK();
    void Commit(const PCSX::u8string path);
    bool DataChanged() { return !saved_local; }
    void Deselect();
    void LoadMcd(const PCSX::u8string str);
    void saveMcd(const PCSX::u8string mcd, const char *data, uint32_t adr, size_t size);
    void saveMcd(const PCSX::u8string path) { saveMcd(path, g_mcdData, 0, MCD_SIZE); }
    uint8_t ProcessEvents(uint8_t value);
    uint8_t TickReadCommand(uint8_t value);
    uint8_t TickWriteCommand(uint8_t value);

    uint8_t TickPS_GetDirIndex(uint8_t value);
    uint8_t TickPS_GetVersion(uint8_t value);
};

}  // namespace PCSX
