#include "core/memorycard.h"

#include <bitset>

#include "core/sio.h"
#include "support/sjis_conv.h"


void PCSX::MemoryCard::ACK() { m_sio->ACK(); }

void PCSX::MemoryCard::Commit(const PCSX::u8string path) {
    if (!saved_local) saveMcd(path);
}

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

                case Commands::PS_GetVersion:
                //case Commands::PS_ChangeFuncValue:
                case Commands::PS_GetDirIndex:
                    //if (!Settings_blah_blah_PSExtensionsEnabled) { GoIdle(); return Responses::IdleHighZ; }

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

        case Commands::PS_GetVersion:
            data_out = TickPS_GetVersion(value);
            break;

        case Commands::PS_GetDirIndex:
            data_out = TickPS_GetDirIndex(value);
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
                    saved_local = false;
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

uint8_t PCSX::MemoryCard::TickPS_GetDirIndex(uint8_t value) {
    uint8_t data_out = Responses::IdleHighZ;

    switch (command_ticks) {
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
            GoIdle();
    }

    command_ticks++;
    ACK();

    return data_out;
}

uint8_t PCSX::MemoryCard::TickPS_GetVersion(uint8_t value) {
    uint8_t data_out = Responses::IdleHighZ;

    switch (command_ticks) {

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
            return Responses::CommandAcknowledge1;
            GoIdle();
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
        } else {
            saved_local = true;
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
        saved_local = true;
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
