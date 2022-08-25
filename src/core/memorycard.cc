#include "core/memorycard.h"

#include <bitset>

#include "core/sio.h"
#include "support/sjis_conv.h"


void PCSX::MemoryCard::ACK() { m_sio->ACK(); }

void PCSX::MemoryCard::Deselect() { GoIdle(); }

uint8_t PCSX::MemoryCard::ProcessEvents(uint8_t value) {
    uint8_t data_out = Responses::IdleHighZ;

    switch (current_command) {
        case Commands::None:
            current_command = value;
            data_out = flag;
            ACK();
            break;

        case Commands::Access:
            switch (value) {
                case Commands::Read:
                case Commands::Write:
                case Commands::GetID:
                    current_command = value;
                    return ProcessEvents(value);
                    break;

                default:
                    GoIdle();
                    return Responses::IdleHighZ;
            }
            break;

        case Commands::Read:
            data_out = TickReadCommand(value);
            break;

        case Commands::Write:
            data_out = TickWriteCommand(value);
            break;

        case Commands::GetID:  // Un-implemented, need data capture
        case Commands::Error:  // Unexpected/Unsupported command
        default:
            GoIdle();
            data_out = Responses::IdleHighZ;
    }

    return data_out;
}

uint8_t PCSX::MemoryCard::TickReadCommand(uint8_t value) {
    uint8_t data_out = 0xFF;

    switch (command_ticks) {
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
            sector = (value << 8);
            data_out = value;
            break;

        case 4:  // LSB
            // Store lower 8 bits of sector
            sector |= value;
            sector_offset = sector * 128;
            data_out = Responses::CommandAcknowledge1;
            break;

        case 5:  // 00h
            data_out = Responses::CommandAcknowledge2;
            break;

        case 6:  // 00h
            // Confirm MSB
            data_out = sector >> 8;
            break;

        case 7:  // 00h
            // Confirm LSB
            data_out = (sector & 0xFF);
            checksum_out = (sector >> 8) ^ (sector & 0xff);
            break;

            // Cases 8 through 135 overloaded to default operator below

        case 136:
            data_out = checksum_out;
            break;

        case 137:
            data_out = Responses::GoodReadWrite;
            break;

        default:
            if (command_ticks >= 8 && command_ticks <= 135)  // Stay here for 128 bytes
            {
                if (sector >= 1024) {
                    data_out = 0x00;
                } else {
                    // data_out = memory_card_ram[(sector * (uint16_t)128) + sector_offset];
                    // memcpy(&m_buffer[4], g_mcd1Data + (m_mcdAddrLow | (m_mcdAddrHigh << 8)) * 128, 128);
                    data_out = g_mcdData[sector_offset++];
                }

                checksum_out ^= data_out;
            } else {
                // Send this till the spooky extra bytes go away
                return Responses::CommandAcknowledge1;
            }
    }

    command_ticks++;
    ACK();

    return data_out;
}

uint8_t PCSX::MemoryCard::TickWriteCommand(uint8_t value) {
    uint8_t data_out = 0xFF;

    switch (command_ticks) {
            // Data is sent and received simultaneously,
            // so the data we send isn't received by the system
            // until the next bytes are exchanged. In this way,
            // you have to basically respond one byte earlier than
            // actually occurs between Slave and Master.
            // Offset "Send" bytes noted from nocash's psx specs.

        case 0:  // 52h
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
            sector = (value << 8);
            // Reply with (pre)
            data_out = value;
            break;

        case 4:  // LSB
            // Store lower 8 bits of sector
            sector |= value;
            sector_offset = (sector * 128);
            checksum_out = (sector >> 8) ^ (sector & 0xFF);
            data_out = value;
            break;

        case 133:  // CHK
            checksum_in = value;
            data_out = Responses::CommandAcknowledge1;
            break;

        case 134:  // 00h
            data_out = Responses::CommandAcknowledge2;
            break;

        case 135:  // 00h
            if (sector >= 1024) {
                data_out = Responses::BadSector;
            } else if (checksum_in == checksum_out) {
                flag = Flags::DirectoryRead;
                data_out = Responses::GoodReadWrite;
                // If the incoming sector is within our storage, store it
                if (sector < 1024) {
                    /// uncommited_soft_write = true;
                }
            } else {
                data_out = Responses::BadChecksum;
            }
            GoIdle();
            break;

        default:
            if (command_ticks >= 5 && command_ticks <= 132) {
                // Store data
                g_mcdData[sector_offset] = value;
                // Calculate checksum
                checksum_out ^= value;
                // Reply with (pre)
                data_out = value;
                sector_offset++;
            } else {
                // Send this till the spooky extra bytes go away
                return Responses::CommandAcknowledge1;
            }

            break;
    }

    command_ticks++;
    ACK();

    return data_out;
}

void PCSX::MemoryCard::LoadMcd(const PCSX::u8string str) {
    char *data = g_mcdData;
    const char *fname = reinterpret_cast<const char *>(str.c_str());

    flag = Flags::DirectoryUnread;

    FILE *f = fopen(fname, "rb");
    if (f == nullptr) {
        PCSX::g_system->printf(_("The memory card %s doesn't exist - creating it\n"), fname);
        CreateMcd(str);
        f = fopen(fname, "rb");
        if (f != nullptr) {
            struct stat buf;

            if (stat(fname, &buf) != -1) {
                // Check if the file is a VGS memory card, skip the header if it is
                if (buf.st_size == MCD_SIZE + 64) fseek(f, 64, SEEK_SET);
                // Check if the file is a Dexdrive memory card, skip the header if it is
                else if (buf.st_size == MCD_SIZE + 3904)
                    fseek(f, 3904, SEEK_SET);
            }
            if (fread(data, 1, MCD_SIZE, f) != MCD_SIZE) {
                throw("Error reading memory card.");
            }
            fclose(f);
        } else
            PCSX::g_system->message(_("Memory card %s failed to load!\n"), fname);
    } else {
        struct stat buf;
        PCSX::g_system->printf(_("Loading memory card %s\n"), fname);
        if (stat(fname, &buf) != -1) {
            if (buf.st_size == MCD_SIZE + 64)
                fseek(f, 64, SEEK_SET);
            else if (buf.st_size == MCD_SIZE + 3904)
                fseek(f, 3904, SEEK_SET);
        }
        if (fread(data, 1, MCD_SIZE, f) != MCD_SIZE) {
            throw("Error reading memory card.");
        }
        fclose(f);
    }
}

void PCSX::MemoryCard::saveMcd(const PCSX::u8string mcd, const char *data, uint32_t adr, size_t size) {
    const char *fname = reinterpret_cast<const char *>(mcd.c_str());
    FILE *f = fopen(fname, "r+b");

    if (f != nullptr) {
        struct stat buf;

        if (stat(fname, &buf) != -1) {
            if (buf.st_size == MCD_SIZE + 64)
                fseek(f, adr + 64, SEEK_SET);
            else if (buf.st_size == MCD_SIZE + 3904)
                fseek(f, adr + 3904, SEEK_SET);
            else
                fseek(f, adr, SEEK_SET);
        } else
            fseek(f, adr, SEEK_SET);

        fwrite(data + adr, 1, size, f);
        fclose(f);
        PCSX::g_system->printf(_("Saving memory card %s\n"), fname);
        return;
    }

#if 0
    // try to create it again if we can't open it
    f = fopen(mcd, "wb");
    if (f != NULL) {
        fwrite(data, 1, MCD_SIZE, f);
        fclose(f);
    }
#endif

    ConvertMcd(mcd, data);
}

void PCSX::MemoryCard::CreateMcd(const PCSX::u8string mcd) {
    const char *fname = reinterpret_cast<const char *>(mcd.c_str());
    struct stat buf;
    int s = MCD_SIZE;

    const auto f = fopen(fname, "wb");
    if (f == nullptr) return;

    if (stat(fname, &buf) != -1) {
        if ((buf.st_size == MCD_SIZE + 3904) || strstr(fname, ".gme")) {
            s = s + 3904;
            fputc('1', f);
            s--;
            fputc('2', f);
            s--;
            fputc('3', f);
            s--;
            fputc('-', f);
            s--;
            fputc('4', f);
            s--;
            fputc('5', f);
            s--;
            fputc('6', f);
            s--;
            fputc('-', f);
            s--;
            fputc('S', f);
            s--;
            fputc('T', f);
            s--;
            fputc('D', f);
            s--;
            for (int i = 0; i < 7; i++) {
                fputc(0, f);
                s--;
            }
            fputc(1, f);
            s--;
            fputc(0, f);
            s--;
            fputc(1, f);
            s--;
            fputc('M', f);
            s--;
            fputc('Q', f);
            s--;
            for (int i = 0; i < 14; i++) {
                fputc(0xa0, f);
                s--;
            }
            fputc(0, f);
            s--;
            fputc(0xff, f);
            while (s-- > (MCD_SIZE + 1)) fputc(0, f);
        } else if ((buf.st_size == MCD_SIZE + 64) || strstr(fname, ".mem") || strstr(fname, ".vgs")) {
            s = s + 64;
            fputc('V', f);
            s--;
            fputc('g', f);
            s--;
            fputc('s', f);
            s--;
            fputc('M', f);
            s--;
            for (int i = 0; i < 3; i++) {
                fputc(1, f);
                s--;
                fputc(0, f);
                s--;
                fputc(0, f);
                s--;
                fputc(0, f);
                s--;
            }
            fputc(0, f);
            s--;
            fputc(2, f);
            while (s-- > (MCD_SIZE + 1)) fputc(0, f);
        }
    }
    fputc('M', f);
    s--;
    fputc('C', f);
    s--;
    while (s-- > (MCD_SIZE - 127)) fputc(0, f);
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

void PCSX::MemoryCard::ConvertMcd(const PCSX::u8string mcd, const char *data) {
    const char *fname = reinterpret_cast<const char *>(mcd.c_str());
    int s = MCD_SIZE;

    if (strstr(fname, ".gme")) {
        auto f = fopen(fname, "wb");
        if (f != nullptr) {
            fwrite(data - 3904, 1, MCD_SIZE + 3904, f);
            fclose(f);
        }
        f = fopen(fname, "r+");
        s = s + 3904;
        fputc('1', f);
        s--;
        fputc('2', f);
        s--;
        fputc('3', f);
        s--;
        fputc('-', f);
        s--;
        fputc('4', f);
        s--;
        fputc('5', f);
        s--;
        fputc('6', f);
        s--;
        fputc('-', f);
        s--;
        fputc('S', f);
        s--;
        fputc('T', f);
        s--;
        fputc('D', f);
        s--;
        for (int i = 0; i < 7; i++) {
            fputc(0, f);
            s--;
        }
        fputc(1, f);
        s--;
        fputc(0, f);
        s--;
        fputc(1, f);
        s--;
        fputc('M', f);
        s--;
        fputc('Q', f);
        s--;
        for (int i = 0; i < 14; i++) {
            fputc(0xa0, f);
            s--;
        }
        fputc(0, f);
        s--;
        fputc(0xff, f);
        while (s-- > (MCD_SIZE + 1)) fputc(0, f);
        fclose(f);
    } else if (strstr(fname, ".mem") || strstr(fname, ".vgs")) {
        auto f = fopen(fname, "wb");
        if (f != nullptr) {
            fwrite(data - 64, 1, MCD_SIZE + 64, f);
            fclose(f);
        }
        f = fopen(fname, "r+");
        s = s + 64;
        fputc('V', f);
        s--;
        fputc('g', f);
        s--;
        fputc('s', f);
        s--;
        fputc('M', f);
        s--;
        for (int i = 0; i < 3; i++) {
            fputc(1, f);
            s--;
            fputc(0, f);
            s--;
            fputc(0, f);
            s--;
            fputc(0, f);
            s--;
        }
        fputc(0, f);
        s--;
        fputc(2, f);
        while (s-- > (MCD_SIZE + 1)) fputc(0, f);
        fclose(f);
    } else {
        const auto f = fopen(fname, "wb");
        if (f != nullptr) {
            fwrite(data, 1, MCD_SIZE, f);
            fclose(f);
        }
    }
}

void PCSX::MemoryCard::getMcdBlockInfo(int mcd, int block, McdBlock &info) {
    if (block < 1 || block > 15) {
        throw std::runtime_error(_("Wrong block number"));
    }

    uint16_t clut[16];

    info.reset();
    info.number = block;
    info.mcd = mcd;

    char *data = getMcdData(mcd);
    uint8_t *ptr = reinterpret_cast<uint8_t *>(data) + block * MCD_BLOCK_SIZE + 2;
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
    ptr = reinterpret_cast<uint8_t *>(data) + block * MCD_BLOCK_SIZE + 0x60;
    std::memcpy(clut, ptr, 16 * sizeof(uint16_t));

    // Icons can have 1 to 3 frames of animation
    for (int i = 0; i < info.iconCount; i++) {
        uint16_t *icon = &info.icon[i * 16 * 16];
        ptr = reinterpret_cast<uint8_t *>(data) + block * MCD_BLOCK_SIZE + 128 + 128 * i;  // icon data

        // Fetch each pixel, store it in the icon array in ABBBBBGGGGGRRRRR with the alpha bit set to 1
        for (x = 0; x < 16 * 16; x++) {
            const uint8_t entry = (uint8_t)*ptr;
            icon[x++] = clut[entry & 0xf] | (1 << 15);
            icon[x] = clut[entry >> 4] | (1 << 15);
            ptr++;
        }
    }

    // Parse directory frame info
    const auto directoryFrame = (uint8_t *)data + block * MCD_SECT_SIZE;
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

char *PCSX::MemoryCard::getMcdData(int mcd) { return g_mcdData; }

// Erase a memory card block by clearing it with 0s
// mcd: The memory card we want to use (1 or 2)
void PCSX::MemoryCard::eraseMcdFile(const McdBlock &block) {
    char *data = getMcdData(block.mcd);

    // Set the block data to 0
    const size_t offset = block.number * MCD_BLOCK_SIZE;
    std::memset(data + offset, 0, MCD_BLOCK_SIZE);

    // Fix up the corresponding directory frame in block 0.
    const auto frame = (uint8_t *)data + block.number * MCD_SECT_SIZE;
    frame[0] = 0xa0;                   // Code for a freshly formatted block
    for (auto i = 1; i < 0x7f; i++) {  // Zero the rest of the frame
        frame[i] = 0;
    }
    frame[0x7f] = 0xa0;  // xor checksum of frame

    if (block.isErased()) return;
    auto nextBlock = block.nextBlock;
    if ((nextBlock >= 1) && (nextBlock <= 15)) {
        McdBlock next;
        getMcdBlockInfo(block.mcd, nextBlock, next);
        eraseMcdFile(next);
    }
}

unsigned PCSX::MemoryCard::getFreeSpace(int mcd) {
    unsigned count = 0;
    for (int i = 1; i < 16; i++) {
        McdBlock block;
        getMcdBlockInfo(mcd, i, block);
        if (block.isErased()) count++;
    }

    return count;
}

unsigned PCSX::MemoryCard::getFileBlockCount(McdBlock block) {
    if (block.isErased()) return 0;

    std::bitset<16> walked;
    unsigned count = 1;

    while (true) {
        if ((block.nextBlock < 1) || (block.nextBlock > 15)) return count;
        if (walked.test(block.nextBlock)) return count;
        walked.set(block.nextBlock);
        getMcdBlockInfo(block.mcd, block.nextBlock, block);
        count++;
    }
}

int PCSX::MemoryCard::findFirstFree(int mcd) {
    McdBlock block;
    for (int i = 1; i < 16; i++) {
        getMcdBlockInfo(mcd, i, block);
        if (block.isErased()) return i;
    }

    return -1;
}

bool PCSX::MemoryCard::copyMcdFile(McdBlock block) {
    auto other = otherMcd(block);
    if (getFreeSpace(other) < getFileBlockCount(block)) return false;
    const auto data = getMcdData(block);
    const auto otherData = getMcdData(other);

    std::bitset<16> walked;
    int prevBlock = -1;

    while (true) {
        int dstBlock = findFirstFree(other);
        if (dstBlock < 1 || dstBlock > 16) throw std::runtime_error("Inconsistent memory card state");

        // copy block data
        size_t srcOffset = block.number * MCD_BLOCK_SIZE;
        size_t dstOffset = dstBlock * MCD_BLOCK_SIZE;
        std::memcpy(otherData + dstOffset, data + srcOffset, MCD_BLOCK_SIZE);

        // copy directory entry
        srcOffset = block.number * MCD_SECT_SIZE;
        dstOffset = dstBlock * MCD_SECT_SIZE;
        std::memcpy(otherData + dstOffset, data + srcOffset, MCD_SECT_SIZE);

        // Fix up the corresponding directory frame in block 0.
        if (prevBlock != -1) {
            const auto frame = reinterpret_cast<uint8_t *>(otherData) + prevBlock * MCD_SECT_SIZE;
            uint8_t crcFix = frame[8] ^ (dstBlock - 1);
            frame[8] = dstBlock - 1;
            frame[0x7f] ^= crcFix;
        }
        prevBlock = dstBlock;
        if (block.nextBlock == -1) return true;
        if ((block.nextBlock < 1) || (block.nextBlock > 15)) return false;
        if (walked.test(block.nextBlock)) return false;
        walked.set(block.nextBlock);
        getMcdBlockInfo(block.mcd, block.nextBlock, block);
    }
}

// Back up the entire memory card to a file
// mcd: The memory card to back up (1 or 2)
void PCSX::MemoryCard::saveMcd(int mcd) {
    const auto data = getMcdData(mcd);
    switch (mcd) {
        case 1: {
            const auto path = g_emulator->settings.get<Emulator::SettingMcd1>().string();
            saveMcd(path, data, 0, MCD_SIZE);
            break;
        }
        case 2: {
            const auto path = g_emulator->settings.get<Emulator::SettingMcd2>().string();
            saveMcd(path, data, 0, MCD_SIZE);
            break;
        }
    }
}
