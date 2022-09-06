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

#include <stdbool.h>
#include <stdint.h>

#include <string>

#include "core/psxemulator.h"
#include "core/r3000a.h"

namespace PCSX {
class SIO;

class MemoryCard {
  public:
    MemoryCard() : m_sio(nullptr) { memset(m_mcdData, 0, MCD_SIZE); }
    MemoryCard(SIO *parent) : m_sio(parent) { memset(m_mcdData, 0, MCD_SIZE); }

    // Hardware events
    void acknowledge();
    void deselect() {
        m_currentCommand = Commands::None;
        m_commandTicks = 0;
        m_dataOffset = 0;
    }

    // File system / data manipulation
    void commit(const PCSX::u8string path) {
        if (!m_savedToDisk) saveMcd(path);
    }
    void createMcd(const PCSX::u8string mcd);
    bool dataChanged() { return !m_savedToDisk; }
    char *getMcdData() { return m_mcdData; }
    void loadMcd(const PCSX::u8string str);
    void saveMcd(const PCSX::u8string mcd, const char *data, uint32_t adr, size_t size);
    void saveMcd(const PCSX::u8string path) { saveMcd(path, m_mcdData, 0, MCD_SIZE); }

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

    static const size_t MCD_SECT_SIZE = 8 * 16;
    static const size_t MCD_BLOCK_SIZE = 8192;
    static const size_t MCD_SIZE = 1024 * MCD_SECT_SIZE;

    // State machine / handlers
    uint8_t processEvents(uint8_t value);
    uint8_t tickReadCommand(uint8_t value);
    uint8_t tickWriteCommand(uint8_t value);
    uint8_t tickPS_GetDirIndex(uint8_t value);   // 5Ah
    uint8_t tickPS_GetVersion(uint8_t value);    // 58h
    uint8_t tickPS_PrepFileExec(uint8_t value);  // 59h
    uint8_t tickPS_ExecCustom(uint8_t value);    // 5Dh

    char m_mcdData[MCD_SIZE];
    bool m_savedToDisk = false;

    uint8_t m_checksumIn = 0, m_checksumOut = 0;
    uint32_t m_commandTicks = 0;
    uint8_t m_currentCommand = Commands::None;
    uint16_t m_sector = 0;
    uint32_t m_dataOffset = 0;

    uint8_t m_directoryFlag = Flags::DirectoryUnread;

    // PocketStation Specific
    uint16_t m_directoryIndex = 0;

    SIO *m_sio;
};

}  // namespace PCSX
