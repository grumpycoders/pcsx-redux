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

#include <bitset>

#include "core/sio.h"
#include "support/sjis_conv.h"

void PCSX::MemoryCards::loadMcds(const CommandLine::args &args) {
    auto &settings = g_emulator->settings;

    std::filesystem::path *card_paths[] = {
        &settings.get<PCSX::Emulator::SettingMcd1>().value, &settings.get<PCSX::Emulator::SettingMcd2>().value,
        &settings.get<PCSX::Emulator::SettingMcd3>().value, &settings.get<PCSX::Emulator::SettingMcd4>().value,
        &settings.get<PCSX::Emulator::SettingMcd5>().value, &settings.get<PCSX::Emulator::SettingMcd6>().value,
        &settings.get<PCSX::Emulator::SettingMcd7>().value, &settings.get<PCSX::Emulator::SettingMcd8>().value,
    };

    for (int i = 0; i < 8; i++) {
        auto argPath = args.get<std::string>(fmt::format("memcard{}", i + 1));
        if (argPath.has_value()) {
            *card_paths[i] = argPath.value();
        }

        if (card_paths[i]->u8string().empty()) {
            std::string path = std::format("memcard{}.mcd", i + 1);
            *card_paths[i] = path;
        }

        if (i >= m_memoryCard.size()) {
            continue;
        }

        loadMcd(card_paths[i]->u8string(), m_memoryCard[i].getCardData());
    }
}

void PCSX::MemoryCards::getMcdBlockInfo(int mcd, int block, McdBlock &info) {
    if (block < 1 || block > 15) {
        throw std::runtime_error(_("Wrong block number"));
    }

    uint16_t clut[16];

    info.reset();
    info.number = block;
    info.mcd = mcd;

    char *data = getCardData(mcd);
    uint8_t *ptr = reinterpret_cast<uint8_t *>(data) + block * c_blockSize + 2;
    auto &ta = info.titleAscii;
    auto &ts = info.titleSjis;
    info.iconCount = std::max(1, *ptr & 0x3);

    ptr += 2;
    int x = 0;

    for (int i = 0; i < 48; i++) {
        uint8_t b = *ptr++;
        ts += b;
        uint16_t c = b;
        if (b & 0x80) {
            c <<= 8;
            b = *ptr++;
            ts += b;
            c |= b;
        }

        // Poor man's SJIS to ASCII conversion
        if (c >= 0x8281 && c <= 0x829a) {
            c = (c - 0x8281) + 'a';
        } else if (c >= 0x824f && c <= 0x827a) {
            c = (c - 0x824f) + '0';
        } else if (c == 0x8140) {
            c = ' ';
        } else if (c == 0x8143) {
            c = ',';
        } else if (c == 0x8144) {
            c = '.';
        } else if (c == 0x8146) {
            c = ':';
        } else if (c == 0x8147) {
            c = ';';
        } else if (c == 0x8148) {
            c = '?';
        } else if (c == 0x8149) {
            c = '!';
        } else if (c == 0x815e) {
            c = '/';
        } else if (c == 0x8168) {
            c = '"';
        } else if (c == 0x8169) {
            c = '(';
        } else if (c == 0x816a) {
            c = ')';
        } else if (c == 0x816d) {
            c = '[';
        } else if (c == 0x816e) {
            c = ']';
        } else if (c == 0x817c) {
            c = '-';
        } else if (c > 0x7e) {
            c = '?';
        }

        ta += c;
    }

    info.titleUtf8 = Sjis::toUtf8(ts);

    // Read CLUT
    ptr = reinterpret_cast<uint8_t *>(data) + block * c_blockSize + 0x60;
    std::memcpy(clut, ptr, 16 * sizeof(uint16_t));

    // Icons can have 1 to 3 frames of animation
    for (uint32_t i = 0; i < info.iconCount; i++) {
        uint16_t *icon = &info.icon[i * 16 * 16];
        ptr = reinterpret_cast<uint8_t *>(data) + block * c_blockSize + 128 + 128 * i;  // icon data

        // Fetch each pixel, store it in the icon array in ABBBBBGGGGGRRRRR with the alpha bit set to 1
        for (x = 0; x < 16 * 16; x++) {
            const uint8_t entry = (uint8_t)*ptr;
            icon[x++] = clut[entry & 0xf] | (1 << 15);
            icon[x] = clut[entry >> 4] | (1 << 15);
            ptr++;
        }
    }

    // Parse directory frame info
    const auto directoryFrame = (uint8_t *)data + block * c_sectorSize;
    uint32_t allocState = 0;
    allocState |= directoryFrame[0];
    allocState |= directoryFrame[1] << 8;
    allocState |= directoryFrame[2] << 16;
    allocState |= directoryFrame[3] << 24;
    info.allocState = allocState;

    char tmp[17];
    memset(tmp, 0, sizeof(tmp));
    std::strncpy(tmp, (const char *)&directoryFrame[0xa], 12);
    info.id = tmp;
    memset(tmp, 0, sizeof(tmp));
    std::strncpy(tmp, (const char *)&directoryFrame[0x16], 16);
    info.name = tmp;

    uint32_t fileSize = 0;
    fileSize |= directoryFrame[4];
    fileSize |= directoryFrame[5] << 8;
    fileSize |= directoryFrame[6] << 16;
    fileSize |= directoryFrame[7] << 24;
    info.fileSize = fileSize;

    uint16_t nextBlock = 0;
    nextBlock |= directoryFrame[8];
    nextBlock |= directoryFrame[9] << 8;
    info.nextBlock = nextBlock == 0xffff ? -1 : (nextBlock + 1);

    // Check if the block is marked as free in the directory frame and adjust the name/filename if so
    if (info.isErased()) {
        info.reset();
        info.allocState = 0xa0;
        info.titleAscii = "Free Block";
        info.titleSjis = "Free Block";
        info.titleUtf8 = "Free Block";
    }
}

char *PCSX::MemoryCards::getCardData(int mcd) {
    const int index = mcd - 1;
    if (index < 0 || index >= m_memoryCard.size()) {
        throw std::runtime_error("Attempt to access invalid memory card");
        return nullptr;
    } else {
        return m_memoryCard[index].getCardData();
    }
}

// Erase a memory card block by clearing it with 0s
// mcd: The memory card we want to use (1 or 2)
void PCSX::MemoryCards::eraseMcdFile(const McdBlock &block) {
    char *data = getCardData(block.mcd);

    // Set the block data to 0
    const size_t offset = block.number * c_blockSize;
    std::memset(data + offset, 0, c_blockSize);

    // Fix up the corresponding directory frame in block 0.
    const auto frame = (uint8_t *)data + block.number * c_sectorSize;
    frame[0] = 0xa0;                   // Code for a freshly formatted block
    for (auto i = 1; i < 0x7f; i++) {  // Zero the rest of the frame
        frame[i] = 0;
    }
    frame[0x7f] = 0xa0;  // xor checksum of frame

    if (block.isErased()) {
        return;
    }

    auto nextBlock = block.nextBlock;
    if ((nextBlock >= 1) && (nextBlock <= 15)) {
        McdBlock next;
        getMcdBlockInfo(block.mcd, nextBlock, next);
        eraseMcdFile(next);
    }
}

unsigned PCSX::MemoryCards::getFreeSpace(int mcd) {
    unsigned count = 0;
    for (int i = 1; i < 16; i++) {
        McdBlock block;
        getMcdBlockInfo(mcd, i, block);
        if (block.isErased()) {
            count++;
        }
    }

    return count;
}

unsigned PCSX::MemoryCards::getFileBlockCount(McdBlock block) {
    if (block.isErased()) {
        return 0;
    }

    std::bitset<16> walked;
    unsigned count = 1;

    while (true) {
        if ((block.nextBlock < 1) || (block.nextBlock > 15)) {
            return count;
        }
        if (walked.test(block.nextBlock)) {
            return count;
        }
        walked.set(block.nextBlock);
        getMcdBlockInfo(block.mcd, block.nextBlock, block);
        count++;
    }
}

int PCSX::MemoryCards::findFirstFree(int mcd) {
    McdBlock block;
    for (int i = 1; i < 16; i++) {
        getMcdBlockInfo(mcd, i, block);
        if (block.isErased()) {
            return i;
        }
    }

    return -1;
}

bool PCSX::MemoryCards::copyMcdFile(McdBlock block) {
    auto other = otherMcd(block);
    if (getFreeSpace(other) < getFileBlockCount(block)) {
        return false;
    }
    const auto data = getCardData(block);
    const auto otherData = getCardData(other);

    std::bitset<16> walked;
    int prevBlock = -1;

    while (true) {
        int dstBlock = findFirstFree(other);
        if (dstBlock < 1 || dstBlock > 16) {
            throw std::runtime_error("Inconsistent memory card state");
        }

        // copy block data
        size_t srcOffset = block.number * c_blockSize;
        size_t dstOffset = dstBlock * c_blockSize;
        std::memcpy(otherData + dstOffset, data + srcOffset, c_blockSize);

        // copy directory entry
        srcOffset = block.number * c_sectorSize;
        dstOffset = dstBlock * c_sectorSize;
        std::memcpy(otherData + dstOffset, data + srcOffset, c_sectorSize);

        // Fix up the corresponding directory frame in block 0.
        if (prevBlock != -1) {
            const auto frame = reinterpret_cast<uint8_t *>(otherData) + prevBlock * c_sectorSize;
            uint8_t crcFix = frame[8] ^ (dstBlock - 1);
            frame[8] = dstBlock - 1;
            frame[0x7f] ^= crcFix;
        }
        prevBlock = dstBlock;
        if (block.nextBlock == -1) {
            return true;
        }
        if ((block.nextBlock < 1) || (block.nextBlock > 15)) {
            return false;
        }
        if (walked.test(block.nextBlock)) {
            return false;
        }
        walked.set(block.nextBlock);
        getMcdBlockInfo(block.mcd, block.nextBlock, block);
    }
}

// Back up the entire memory card to a file
// index: The memory card to back up (0-7)
bool PCSX::MemoryCards::saveMcd(int index) {
    return saveMcd(getMcdPath(index), m_memoryCard[index].getCardData(), 0, c_cardSize);
}

void PCSX::MemoryCards::resetCard(int index) {
    if (m_memoryCard.size() > 0 && index < m_memoryCard.size()) {
        m_memoryCard[index].reset();
    }
}

void PCSX::MemoryCards::setPocketstationEnabled(int index, bool enabled) {
    bool* pocketstation_settings[] = {
        &g_emulator->settings.get<Emulator::SettingMcd1Pocketstation>().value,   // Slot 1 Port A
        &g_emulator->settings.get<Emulator::SettingMcd2Pocketstation>().value,   // Slot 2 Port A
        &g_emulator->settings.get<Emulator::SettingMcd3Pocketstation>().value,   // Slot 1 Port B
        &g_emulator->settings.get<Emulator::SettingMcd4Pocketstation>().value,   // Slot 1 Port C
        &g_emulator->settings.get<Emulator::SettingMcd5Pocketstation>().value,   // Slot 1 Port D
        &g_emulator->settings.get<Emulator::SettingMcd6Pocketstation>().value,   // Slot 2 Port B
        &g_emulator->settings.get<Emulator::SettingMcd7Pocketstation>().value,   // Slot 2 Port C
        &g_emulator->settings.get<Emulator::SettingMcd8Pocketstation>().value};  // Slot 2 Port D

    m_memoryCard[index].setPocketstationEnabled(enabled);    
}

void PCSX::MemoryCard::commit() {
    for (int retry_count = 0; retry_count < 3; retry_count++) {
        if (g_emulator->m_memoryCards->saveMcd(m_deviceIndex)) {
            m_savedToDisk = true;
            break;
        } else {
            PCSX::g_system->printf(_("Failed to save card %d, attempt %d/3"), m_deviceIndex + 1, retry_count + 1);
        }
    }
}

uint8_t PCSX::MemoryCard::transceive(uint8_t value, bool *ack) {
    uint8_t data_out = m_spdr;

    if (m_currentCommand == Commands::None || m_currentCommand == Commands::Access) {
        m_currentCommand = value;
    }

    switch (m_currentCommand) {
        // Access memory card device
        case Commands::Access:  // 81h
            // Incoming value is the device command
            m_spdr = m_directoryFlag;
            *ack = true;
            break;

        // Read a sector
        case Commands::Read:  // 52h
            m_spdr = tickReadCommand(value, ack);
            break;

        // Write a sector
        case Commands::Write:  // 57h
            m_spdr = tickWriteCommand(value, ack);
            break;

        //
        case Commands::PS_GetVersion:  // 58h
            if (m_pocketstationEnabled) {
                m_spdr = tickPS_GetVersion(value, ack);
            }
            break;

        //
        case Commands::PS_PrepFileExec:  // 59h
            if (m_pocketstationEnabled) {
                m_spdr = tickPS_PrepFileExec(value, ack);
            }
            break;

        //
        case Commands::PS_GetDirIndex:  // 5Ah
            if (m_pocketstationEnabled) {
                m_spdr = tickPS_GetDirIndex(value, ack);
            }
            break;

        //
        case Commands::PS_ExecCustom:  // 5Dh
            if (m_pocketstationEnabled) {
                m_spdr = tickPS_ExecCustom(value, ack);
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

inline uint8_t PCSX::MemoryCard::tickReadCommand(uint8_t value, bool *ack) {
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
            if (m_commandTicks >= 8 && m_commandTicks <= 135) {  // Stay here for 128 bytes
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
    *ack = true;

    return data_out;
}

inline uint8_t PCSX::MemoryCard::tickWriteCommand(uint8_t value, bool *ack) {
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
            // m_dataOffset = (m_sector * 128);
            m_dataOffset = 0;
            m_checksumOut = (m_sector >> 8) ^ (m_sector & 0xFF);
            data_out = value;
            break;

        // Cases 5 through 135 overloaded to default operator below
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
            } else if (m_checksumIn != m_checksumOut) {
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
            if (memcmp(&m_mcdData, &m_tempBuffer, c_sectorSize) != 0) {
                memcpy(&m_mcdData[m_sector * 128], &m_tempBuffer, c_sectorSize);
                m_savedToDisk = false;
                commit();
            }
            break;
    }

    m_commandTicks++;
    *ack = true;

    return data_out;
}

inline uint8_t PCSX::MemoryCard::tickPS_GetDirIndex(uint8_t value, bool *ack) {
    uint8_t data_out = Responses::IdleHighZ;
    static constexpr uint8_t response_count = 19;
    static constexpr uint8_t responses[response_count] = {0x12, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x13, 0x11, 0x4F,
                                                          0x41, 0x20, 0x01, 0x99, 0x19, 0x27, 0x30, 0x09, 0x04};

    if (m_commandTicks < response_count) {
        data_out = responses[m_commandTicks];

        // Don't ack the last byte
        if (m_commandTicks <= (response_count - 1)) {
            *ack = true;
        }
    }

    m_commandTicks++;

    return data_out;
}

inline uint8_t PCSX::MemoryCard::tickPS_ExecCustom(uint8_t value, bool *ack) {
    uint8_t data_out = Responses::IdleHighZ;

    switch (m_commandTicks) {
        case 0:  // 5D
            data_out = 0x03;
            break;

        default:
            data_out = 0x00;
            break;
    }

    m_commandTicks++;
    *ack = true;

    return data_out;
}

inline uint8_t PCSX::MemoryCard::tickPS_PrepFileExec(uint8_t value, bool *ack) {
    uint8_t data_out = Responses::IdleHighZ;

    switch (m_commandTicks) {
        case 0:  // 59
            data_out = 0x06;
            break;

        default:
            data_out = 0x00;
            break;
    }

    m_commandTicks++;
    *ack = true;

    return data_out;
}

inline uint8_t PCSX::MemoryCard::tickPS_GetVersion(uint8_t value, bool *ack) {
    uint8_t data_out = Responses::IdleHighZ;
    static constexpr uint8_t response_count = 3;
    static constexpr uint8_t responses[response_count] = {0x02, 0x01, 0x01};

    if (m_commandTicks < response_count) {
        data_out = responses[m_commandTicks];

        // Don't ack the last byte
        if (m_commandTicks <= (response_count - 1)) {
            *ack = true;
        }
    }

    m_commandTicks++;

    return data_out;
}

// To-do: "All the code starting here is terrible and needs to be rewritten"
bool PCSX::MemoryCards::loadMcd(const PCSX::u8string str, char *data) {
    const char *fname = reinterpret_cast<const char *>(str.c_str());
    size_t bytesRead;

    bool result = false;

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
        } else {
            PCSX::g_system->message(_("Memory card %s failed to load!\n"), fname);
        }
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
            result = true;
        }
    }

    return result;
}

bool PCSX::MemoryCards::saveMcd(const PCSX::u8string mcd, const char *data, uint32_t adr, size_t size) {
    const char *fname = reinterpret_cast<const char *>(mcd.c_str());
    FILE *f = fopen(fname, "r+b");
    bool result = false;

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
        result = true;
        PCSX::g_system->printf(_("Saving memory card %s\n"), fname);
    } else {
        // try to create it again if we can't open it
        f = fopen(fname, "wb");
        if (f != NULL) {
            fwrite(data, 1, c_cardSize, f);
            fclose(f);
        }
    }

    return result;
}

void PCSX::MemoryCards::createMcd(const PCSX::u8string mcd) {
    const char *fname = reinterpret_cast<const char *>(mcd.c_str());
    int s = c_cardSize;

    const auto f = fopen(fname, "wb");
    if (f == nullptr) {
        return;
    }

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
