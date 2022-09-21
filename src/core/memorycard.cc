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

#include "core/memorycard.h"

#include "core/sio.h"
#include "support/sjis_conv.h"

void PCSX::MemoryCard::acknowledge() { m_sio->acknowledge(); }

uint8_t PCSX::MemoryCard::transceive(uint8_t value) {
    uint8_t data_out = m_spdr;

    if (m_currentCommand == Commands::None || m_currentCommand == Commands::Access) {
        m_currentCommand = value;
    }

    switch (m_currentCommand) {
        // Access memory card device
        case Commands::Access:  // 81h
            // Incoming value is the device command
            m_spdr = m_directoryFlag;
            acknowledge();
            break;

        // Read a sector
        case Commands::Read:  // 52h
            m_spdr = tickReadCommand(value);
            break;

        // Write a sector
        case Commands::Write:  // 57h
            m_spdr = tickWriteCommand(value);
            break;

        //
        case Commands::PS_GetVersion:  // 58h
            if (m_pocketstationEnabled) {
                m_spdr = tickPS_GetVersion(value);
            }
            break;

        //
        case Commands::PS_PrepFileExec:  // 59h
            if (m_pocketstationEnabled) {
                m_spdr = tickPS_PrepFileExec(value);
            }
            break;

        //
        case Commands::PS_GetDirIndex:  // 5Ah
            if (m_pocketstationEnabled) {
                m_spdr = tickPS_GetDirIndex(value);
            }
            break;

        //
        case Commands::PS_ExecCustom:  // 5Dh
            if (m_pocketstationEnabled) {
                m_spdr = tickPS_ExecCustom(value);
            }
            break;

        case Commands::GetID:  // Un-implemented, need data capture
        case Commands::Error:  // Unexpected/Unsupported command
        default:
            m_spdr = Responses::IdleHighZ;
            break;
    }

    return data_out;
}

uint8_t PCSX::MemoryCard::tickReadCommand(uint8_t value) {
    uint8_t data_out = 0xFF;

    switch (m_commandTicks) {
        case 0:
            data_out = Responses::ID1;
            break;

        case 1:
            data_out = Responses::ID2;
            break;

        case 2:
            data_out = Responses::Dummy;
            break;

        case 3:  // MSB
            m_sector = (value << 8);
            data_out = value;
            break;

        case 4:  // LSB
            // Store lower 8 bits of sector
            m_sector |= value;
            m_dataOffset = m_sector * 128;
            data_out = Responses::CommandAcknowledge1;
            break;

        case 5:  // 00h
            data_out = Responses::CommandAcknowledge2;
            break;

        case 6:  // 00h
            // Confirm MSB
            data_out = m_sector >> 8;
            break;

        case 7:  // 00h
            // Confirm LSB
            data_out = (m_sector & 0xFF);
            m_checksumOut = (m_sector >> 8) ^ (m_sector & 0xff);
            break;

        // Cases 8 through 135 overloaded to default operator below
        default:
            if (m_commandTicks >= 8 && m_commandTicks <= 135)  // Stay here for 128 bytes
            {
                if (m_sector >= 1024) {
                    data_out = Responses::BadSector;
                } else {
                    data_out = m_mcdData[m_dataOffset++];
                }

                m_checksumOut ^= data_out;
            } else {
                // Send this till the spooky extra bytes go away
                return Responses::CommandAcknowledge1;
            }
            break;

        case 136:
            data_out = m_checksumOut;
            break;

        case 137:
            data_out = Responses::GoodReadWrite;
            break;
    }

    m_commandTicks++;
    acknowledge();

    return data_out;
}

uint8_t PCSX::MemoryCard::tickWriteCommand(uint8_t value) {
    uint8_t data_out = 0xFF;

    switch (m_commandTicks) {
            // Data is sent and received simultaneously,
            // so the data we send isn't received by the system
            // until the next bytes are exchanged. In this way,
            // you have to basically respond one byte earlier than
            // actually occurs between Slave and Master.
            // Offset "Send" bytes noted from nocash's psx specs.

        case 0:  // 57h
            data_out = Responses::ID1;
            break;

        case 1:  // 00h
            data_out = Responses::ID2;
            break;

        case 2:  // 00h
            data_out = Responses::Dummy;
            break;

        case 3:  // MSB
            // Store upper 8 bits of sector
            m_sector = (value << 8);
            // Reply with (pre)
            data_out = value;
            break;

        case 4:  // LSB
            // Store lower 8 bits of sector
            m_sector |= value;
            //m_dataOffset = (m_sector * 128);
            m_dataOffset = 0;
            m_checksumOut = (m_sector >> 8) ^ (m_sector & 0xFF);
            data_out = value;
            break;

        default:
            if (m_commandTicks >= 5 && m_commandTicks <= 132) {
                // Store data in temp buffer until checksum verified
                // no idea if official cards did this, but why not.
                m_tempBuffer[m_dataOffset] = value;

                // Calculate checksum
                m_checksumOut ^= value;

                // Reply with (pre)
                data_out = value;
                m_dataOffset++;
            } else {
                // Send this till the spooky extra bytes go away
                return Responses::CommandAcknowledge1;
            }

            break;

        case 133:  // CHK
            m_checksumIn = value;

            if (m_sector >= 1024) {
                m_commandTicks = 0xFF;

                // To-do: Need to log actual behavior here
                return Responses::BadSector;
            }
            else if (m_checksumIn != m_checksumOut) {
                // To-do: Log official card behavior
                // Below behavior is from 3rd party hardware
                m_commandTicks = 0xFF;
                return Responses::BadChecksum;
            } else {
                data_out = Responses::CommandAcknowledge1;
            }
            break;

        case 134:  // 00h
            data_out = Responses::CommandAcknowledge2;
            break;

        case 135:  // 00h
                m_directoryFlag = Flags::DirectoryRead;
                data_out = Responses::GoodReadWrite;
                memcpy(&m_mcdData[m_sector * 128], &m_tempBuffer, c_sectorSize);
                m_savedToDisk = false;
            break;
    }

    m_commandTicks++;
    acknowledge();

    return data_out;
}

uint8_t PCSX::MemoryCard::tickPS_GetDirIndex(uint8_t value) {
    uint8_t data_out = Responses::IdleHighZ;

    switch (m_commandTicks) {
            // 81 | 5A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            //         12 00 00 01 01 01 01 13 11 4F 41 20 01 99 19 27 30 09 04
        case 0:  // 5A
            data_out = 0x12;
            break;

        case 1:  //
            data_out = 0x00;
            break;

        case 2:  //
            data_out = 0x00;
            break;

        case 3:  //
            data_out = 0x01;
            break;

        case 4:  //
            data_out = 0x01;
            break;

        case 5:  //
            data_out = 0x01;
            break;

        case 6:  //
            data_out = 0x01;
            break;

        case 7:  //
            data_out = 0x13;
            break;

        case 8:  //
            data_out = 0x11;
            break;

        case 9:  //
            data_out = 0x4F;
            break;

        case 10:  //
            data_out = 0x41;
            break;

        case 11:  //
            data_out = 0x20;
            break;

        case 12:  //
            data_out = 0x01;
            break;

        case 13:  //
            data_out = 0x99;
            break;

        case 14:  //
            data_out = 0x19;
            break;

        case 15:  //
            data_out = 0x27;
            break;

        case 16:  //
            data_out = 0x30;
            break;

        case 17:  //
            data_out = 0x09;
            break;

        case 18:  //
            data_out = 0x04;
            break;

        default:
            return Responses::CommandAcknowledge1;
    }

    m_commandTicks++;
    acknowledge();

    return data_out;
}

uint8_t PCSX::MemoryCard::tickPS_ExecCustom(uint8_t value) {
    uint8_t data_out = Responses::IdleHighZ;

    switch (m_commandTicks) {
        case 0:  // 5D
            data_out = 0x03;
            break;

        default:
            data_out = 0x00;
    }

    m_commandTicks++;
    acknowledge();

    return data_out;
}

uint8_t PCSX::MemoryCard::tickPS_PrepFileExec(uint8_t value) {
    uint8_t data_out = Responses::IdleHighZ;

    switch (m_commandTicks) {
        case 0:  // 59
            data_out = 0x06;
            break;

        default:
            data_out = 0x00;
    }

    m_commandTicks++;
    acknowledge();

    return data_out;
}

uint8_t PCSX::MemoryCard::tickPS_GetVersion(uint8_t value) {
    uint8_t data_out = Responses::IdleHighZ;

    switch (m_commandTicks) {
        case 0:  // 58
            data_out = 0x02;
            break;

        case 1:  //
            data_out = 0x01;
            break;

        case 2:  //
            data_out = 0x01;
            break;

        default:
            data_out = 0xff;
    }

    m_commandTicks++;
    acknowledge();

    return data_out;
}


// To-do: "All the code starting here is terrible and needs to be rewritten"
void PCSX::MemoryCard::loadMcd(const PCSX::u8string str) {
    char *data = m_mcdData;
    const char *fname = reinterpret_cast<const char *>(str.c_str());
    size_t bytesRead;

    m_directoryFlag = Flags::DirectoryUnread;

    FILE *f = fopen(fname, "rb");
    if (f == nullptr) {
        PCSX::g_system->printf(_("The memory card %s doesn't exist - creating it\n"), fname);
        createMcd(str);
        f = fopen(fname, "rb");
        if (f != nullptr) {
            struct stat buf;

            if (stat(fname, &buf) != -1) {
                // Check if the file is a VGS memory card, skip the header if it is
                if (buf.st_size == c_cardSize + 64) {
                    fseek(f, 64, SEEK_SET);
                }
                // Check if the file is a Dexdrive memory card, skip the header if it is
                else if (buf.st_size == c_cardSize + 3904) {
                    fseek(f, 3904, SEEK_SET);
                }
            }
            bytesRead = fread(data, 1, c_cardSize, f);
            fclose(f);
            if (bytesRead != c_cardSize) {
                throw std::runtime_error(_("Error reading memory card."));
            }
        } else
            PCSX::g_system->message(_("Memory card %s failed to load!\n"), fname);
    } else {
        struct stat buf;
        PCSX::g_system->printf(_("Loading memory card %s\n"), fname);
        if (stat(fname, &buf) != -1) {
            if (buf.st_size == c_cardSize + 64) {
                fseek(f, 64, SEEK_SET);
            } else if (buf.st_size == c_cardSize + 3904) {
                fseek(f, 3904, SEEK_SET);
            }
        }
        bytesRead = fread(data, 1, c_cardSize, f);
        fclose(f);
        if (bytesRead != c_cardSize) {
            throw std::runtime_error(_("Error reading memory card."));
        } else {
            m_savedToDisk = true;
        }
    }
}

void PCSX::MemoryCard::saveMcd(const PCSX::u8string mcd, const char *data, uint32_t adr, size_t size) {
    const char *fname = reinterpret_cast<const char *>(mcd.c_str());
    FILE *f = fopen(fname, "r+b");

    if (f != nullptr) {
        struct stat buf;

        if (stat(fname, &buf) != -1) {
            if (buf.st_size == c_cardSize + 64) {
                fseek(f, adr + 64, SEEK_SET);
            } else if (buf.st_size == c_cardSize + 3904) {
                fseek(f, adr + 3904, SEEK_SET);
            } else {
                fseek(f, adr, SEEK_SET);
            }
        } else {
            fseek(f, adr, SEEK_SET);
        }

        fwrite(data + adr, 1, size, f);
        fclose(f);
        m_savedToDisk = true;
        PCSX::g_system->printf(_("Saving memory card %s\n"), fname);
    } else {
        // try to create it again if we can't open it
        f = fopen(fname, "wb");
        if (f != NULL) {
            fwrite(data, 1, c_cardSize, f);
            fclose(f);
        }
    }
}

void PCSX::MemoryCard::createMcd(const PCSX::u8string mcd) {
    const char *fname = reinterpret_cast<const char *>(mcd.c_str());
    int s = c_cardSize;

    const auto f = fopen(fname, "wb");
    if (f == nullptr) return;

    fputc('M', f);
    s--;
    fputc('C', f);
    s--;
    while (s-- > (c_cardSize - 127)) fputc(0, f);
    fputc(0xe, f);
    s--;

    for (int i = 0; i < 15; i++) {  // 15 blocks
        fputc(0xa0, f);
        s--;
        fputc(0x00, f);
        s--;
        fputc(0x00, f);
        s--;
        fputc(0x00, f);
        s--;
        fputc(0x00, f);
        s--;
        fputc(0x00, f);
        s--;
        fputc(0x00, f);
        s--;
        fputc(0x00, f);
        s--;
        fputc(0xff, f);
        s--;
        fputc(0xff, f);
        s--;
        for (int j = 0; j < 117; j++) {
            fputc(0x00, f);
            s--;
        }
        fputc(0xa0, f);
        s--;
    }

    for (int i = 0; i < 20; i++) {
        fputc(0xff, f);
        s--;
        fputc(0xff, f);
        s--;
        fputc(0xff, f);
        s--;
        fputc(0xff, f);
        s--;
        fputc(0x00, f);
        s--;
        fputc(0x00, f);
        s--;
        fputc(0x00, f);
        s--;
        fputc(0x00, f);
        s--;
        fputc(0xff, f);
        s--;
        fputc(0xff, f);
        s--;
        for (int j = 0; j < 118; j++) {
            fputc(0x00, f);
            s--;
        }
    }

    while ((s--) >= 0) fputc(0, f);

    fclose(f);
}
