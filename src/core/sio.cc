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

#include "core/sio.h"

#include <sys/stat.h>

#include <algorithm>
#include <bitset>
#include <stdexcept>

#include "core/misc.h"
#include "core/pad.h"
#include "support/sjis_conv.h"

// clk cycle byte
// 4us * 8bits = (PCSX::g_emulator->m_psxClockSpeed / 1000000) * 32; (linuzappz)
// TODO: add SioModePrescaler
#define SIO_CYCLES (m_baudReg * 8)

void PCSX::SIO::writePad(uint8_t value) {
    switch (m_padState) {
        case PAD_STATE_READ_TYPE:
            scheduleInterrupt(SIO_CYCLES);
            /*
            $41-4F
            $41 = Find bits in poll respones
            $42 = Polling command
            $43 = Config mode (Dual shock?)
            $44 = Digital / Analog (after $F3)
            $45 = Get status info (Dual shock?)

            ID:
            $41 = Digital
            $73 = Analogue Red LED
            $53 = Analogue Green LED

            $23 = NegCon
            $12 = Mouse
            */

            if (value & 0x40) {
                m_padState = PAD_STATE_READ_DATA;
                m_bufferIndex = 1;
                switch (m_ctrlReg & 0x2002) {
                    case 0x0002:
                        m_buffer[m_bufferIndex] = PCSX::g_emulator->m_pads->poll(value, Pads::Port1);
                        break;
                    case 0x2002:
                        m_buffer[m_bufferIndex] = PCSX::g_emulator->m_pads->poll(value, Pads::Port2);
                        break;
                }

                if (!(m_buffer[m_bufferIndex] & 0x0f)) {
                    m_maxBufferIndex = 2 + 32;
                } else {
                    m_maxBufferIndex = 2 + (m_buffer[m_bufferIndex] & 0x0f) * 2;
                }

                // Digital / Dual Shock Controller
                if (m_buffer[m_bufferIndex] == 0x41) {
                    switch (value) {
                        // enter config mode
                        case 0x43:
                            m_buffer[1] = 0x43;
                            break;

                        // get status
                        case 0x45:
                            m_buffer[1] = 0xf3;
                            break;
                    }
                }

                // NegCon - Wipeout 3
                if (m_buffer[m_bufferIndex] == 0x23) {
                    switch (value) {
                        // enter config mode
                        case 0x43:
                            m_buffer[1] = 0x79;
                            break;

                        // get status
                        case 0x45:
                            m_buffer[1] = 0xf3;
                            break;
                    }
                }
            } else {
                m_padState = PAD_STATE_IDLE;
            }
            return;
        case PAD_STATE_READ_DATA:
            m_bufferIndex++;
            /*          if (m_buffer[1] == 0x45) {
                                            m_buffer[m_bufferIndex] = 0;
                                            scheduleInterrupt(SIO_CYCLES);
                                            return;
                                    }*/
            switch (m_ctrlReg & 0x2002) {
                case 0x0002:
                    m_buffer[m_bufferIndex] = PCSX::g_emulator->m_pads->poll(value, Pads::Port1);
                    break;
                case 0x2002:
                    m_buffer[m_bufferIndex] = PCSX::g_emulator->m_pads->poll(value, Pads::Port2);
                    break;
            }

            if (m_bufferIndex == m_maxBufferIndex) {
                m_padState = PAD_STATE_IDLE;
                return;
            }
            scheduleInterrupt(SIO_CYCLES);
            return;
    }
}

void PCSX::SIO::writeMcd(uint8_t value) {
    switch (m_mcdState) {
        case MCD_STATE_READ_COMMAND:
            scheduleInterrupt(SIO_CYCLES);
            if (m_mcdReadWriteState) {
                m_bufferIndex++;
                return;
            }
            m_bufferIndex = 1;
            switch (value) {
                case 'R':
                    m_mcdReadWriteState = MCD_READWRITE_STATE_READ;
                    break;
                case 'W':
                    m_mcdReadWriteState = MCD_READWRITE_STATE_WRITE;
                    break;
                default:
                    m_mcdState = MCD_STATE_IDLE;
            }
            return;
        case MCD_STATE_READ_ADDR_HIGH:
            scheduleInterrupt(SIO_CYCLES);
            m_mcdAddrHigh = value;
            *m_buffer = 0;
            m_bufferIndex = 0;
            m_maxBufferIndex = 1;
            m_mcdState = MCD_STATE_READ_ADDR_LOW;
            return;
        case MCD_STATE_READ_ADDR_LOW:
            scheduleInterrupt(SIO_CYCLES);
            m_mcdAddrLow = value;
            *m_buffer = m_mcdAddrHigh;
            m_bufferIndex = 0;
            m_maxBufferIndex = 1;
            m_mcdState = MCD_STATE_READ_ACK;
            return;
        case MCD_STATE_READ_ACK:
            scheduleInterrupt(SIO_CYCLES);
            m_bufferIndex = 0;
            switch (m_mcdReadWriteState) {
                case MCD_READWRITE_STATE_READ:
                    m_buffer[0] = 0x5c;
                    m_buffer[1] = 0x5d;
                    m_buffer[2] = m_mcdAddrHigh;
                    m_buffer[3] = m_mcdAddrLow;
                    switch (m_ctrlReg & 0x2002) {
                        case 0x0002:
                            memcpy(&m_buffer[4], g_mcd1Data + (m_mcdAddrLow | (m_mcdAddrHigh << 8)) * 128, 128);
                            break;
                        case 0x2002:
                            memcpy(&m_buffer[4], g_mcd2Data + (m_mcdAddrLow | (m_mcdAddrHigh << 8)) * 128, 128);
                            break;
                    }
                    {
                        char xorsum = 0;
                        for (int i = 2; i < 128 + 4; i++) xorsum ^= m_buffer[i];
                        m_buffer[132] = xorsum;
                    }
                    m_buffer[133] = 0x47;
                    m_maxBufferIndex = 133;
                    break;
                case MCD_READWRITE_STATE_WRITE:
                    m_buffer[0] = m_mcdAddrLow;
                    m_buffer[1] = value;
                    m_buffer[129] = 0x5c;
                    m_buffer[130] = 0x5d;
                    m_buffer[131] = 0x47;
                    m_maxBufferIndex = 131;
                    break;
            }
            m_mcdState = MCD_STATE_READWRITE_DATA;
            return;
        case MCD_STATE_READWRITE_DATA:
            m_bufferIndex++;
            if (m_mcdReadWriteState == MCD_READWRITE_STATE_WRITE) {
                if (m_bufferIndex < 128) m_buffer[m_bufferIndex + 1] = value;
            }
            scheduleInterrupt(SIO_CYCLES);
            return;
    }
}

void PCSX::SIO::write8(uint8_t value) {
    SIO0_LOG("sio write8 %x (PAR:%x PAD:%x MCDL%x)\n", value, m_bufferIndex, m_padState, m_mcdState);
    if (m_padState) {
        writePad(value);
        return;
    }
    if (m_mcdState) {
        writeMcd(value);
        return;
    }
    switch (value) {
        case 0x01:                  // start pad
            m_statusReg |= RX_RDY;  // Transfer is Ready

            switch (m_ctrlReg & 0x2002) {
                case 0x0002:
                    m_buffer[0] = PCSX::g_emulator->m_pads->startPoll(Pads::Port1);
                    break;
                case 0x2002:
                    m_buffer[0] = PCSX::g_emulator->m_pads->startPoll(Pads::Port2);
                    break;
            }

            m_maxBufferIndex = 2;
            m_bufferIndex = 0;
            m_padState = PAD_STATE_READ_TYPE;
            scheduleInterrupt(SIO_CYCLES);
            return;
        case 0x81:  // start memcard
                    // case 0x82: case 0x83: case 0x84: // Multitap memcard access
            m_statusReg |= RX_RDY;

            std::memset(m_buffer, 0, 4);
            if ((m_ctrlReg & 0x2002) == 0x0002) {
                if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingMcd1Inserted>()) {
                    m_buffer[1] = m_wasMcd1Inserted ? 0 : MCDST_CHANGED;
                    m_buffer[2] = 0x5a;
                    m_buffer[3] = 0x5d;
                    m_wasMcd1Inserted = true;
                } else {
                    m_buffer[1] = m_buffer[2] = m_buffer[3] = 0;
                }
            } else if ((m_ctrlReg & 0x2002) == 0x2002) {
                if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingMcd2Inserted>()) {
                    m_buffer[1] = m_wasMcd2Inserted ? 0 : MCDST_CHANGED;
                    m_buffer[2] = 0x5a;
                    m_buffer[3] = 0x5d;
                    m_wasMcd2Inserted = true;
                } else {
                    m_buffer[1] = m_buffer[2] = m_buffer[3] = 0;
                }
            }

            m_bufferIndex = 0;
            m_maxBufferIndex = 3;
            m_mcdState = MCD_STATE_READ_COMMAND;
            m_mcdReadWriteState = MCD_READWRITE_STATE_IDLE;
            scheduleInterrupt(SIO_CYCLES);
            return;

        default:  // no hardware found
            m_statusReg |= RX_RDY;
            return;
    }
}

void PCSX::SIO::writeStatus16(uint16_t value) {}

void PCSX::SIO::writeMode16(uint16_t value) { m_modeReg = value; }

void PCSX::SIO::writeCtrl16(uint16_t value) {
    SIO0_LOG("sio ctrlwrite16 %x (PAR:%x PAD:%x MCD:%x)\n", value, m_bufferIndex, m_padState, m_mcdState);
    m_ctrlReg = value & ~RESET_ERR;
    if (value & RESET_ERR) m_statusReg &= ~IRQ;
    if ((m_ctrlReg & SIO_RESET) || (!m_ctrlReg)) {
        m_padState = PAD_STATE_IDLE;
        m_mcdState = MCD_STATE_IDLE;
        m_bufferIndex = 0;
        m_statusReg = TX_RDY | TX_EMPTY;
        PCSX::g_emulator->m_psxCpu->m_psxRegs.interrupt &= ~(1 << PCSX::PSXINT_SIO);
    }
}

void PCSX::SIO::writeBaud16(uint16_t value) { m_baudReg = value; }

uint8_t PCSX::SIO::sioRead8() {
    uint8_t ret = 0;

    if ((m_statusReg & RX_RDY) /* && (m_ctrlReg & RX_PERM)*/) {
        //      m_statusReg &= ~RX_OVERRUN;
        ret = m_buffer[m_bufferIndex];
        if (m_bufferIndex == m_maxBufferIndex) {
            m_statusReg &= ~RX_RDY;  // Receive is not Ready now
            if (m_mcdState == MCD_STATE_READWRITE_DATA) {
                m_mcdState = MCD_STATE_IDLE;
                if (m_mcdReadWriteState == MCD_READWRITE_STATE_WRITE) {
                    switch (m_ctrlReg & 0x2002) {
                        case 0x0002:
                            if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingMcd1Inserted>()) {
                                memcpy(g_mcd1Data + (m_mcdAddrLow | (m_mcdAddrHigh << 8)) * 128, &m_buffer[1], 128);
                                saveMcd(PCSX::g_emulator->settings.get<PCSX::Emulator::SettingMcd1>().string().c_str(),
                                        g_mcd1Data, (m_mcdAddrLow | (m_mcdAddrHigh << 8)) * 128, 128);
                            }
                            break;
                        case 0x2002:
                            if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingMcd2Inserted>()) {
                                memcpy(g_mcd2Data + (m_mcdAddrLow | (m_mcdAddrHigh << 8)) * 128, &m_buffer[1], 128);
                                saveMcd(PCSX::g_emulator->settings.get<PCSX::Emulator::SettingMcd2>().string().c_str(),
                                        g_mcd2Data, (m_mcdAddrLow | (m_mcdAddrHigh << 8)) * 128, 128);
                            }
                            break;
                    }
                }
            }
            if (m_padState == PAD_STATE_READ_DATA) m_padState = PAD_STATE_IDLE;
            if (m_mcdState == MCD_STATE_READ_COMMAND) {
                m_mcdState = MCD_STATE_READ_ADDR_HIGH;
                m_statusReg |= RX_RDY;
            }
        }
    }

    SIO0_LOG("sio read8 ;ret = %x (I:%x ST:%x BUF:(%x %x %x))\n", ret, m_bufferIndex, m_statusReg,
             m_buffer[m_bufferIndex > 0 ? m_bufferIndex - 1 : 0], m_buffer[m_bufferIndex],
             m_buffer[m_bufferIndex < BUFFER_SIZE - 1 ? m_bufferIndex + 1 : BUFFER_SIZE - 1]);
    return ret;
}

uint16_t PCSX::SIO::readStatus16() {
    uint16_t hard = m_statusReg;

#if 0
    // wait for IRQ first
    if( PCSX::g_emulator->m_psxCpu->m_psxRegs.interrupt & (1 << PSXINT_SIO) )
    {
        hard &= ~TX_RDY;
        hard &= ~RX_RDY;
        hard &= ~TX_EMPTY;
    }
#endif

    return hard;
}

uint16_t PCSX::SIO::readMode16() { return m_modeReg; }

uint16_t PCSX::SIO::readCtrl16() { return m_ctrlReg; }

uint16_t PCSX::SIO::readBaud16() { return m_baudReg; }

void PCSX::SIO::netError() {
    // ClosePlugins();
    PCSX::g_system->message("%s", _("Connection closed!\n"));

    PCSX::g_emulator->m_cdromId[0] = '\0';
    PCSX::g_emulator->m_cdromLabel[0] = '\0';
}

void PCSX::SIO::interrupt() {
    SIO0_LOG("Sio Interrupt (CP0.Status = %x)\n", PCSX::g_emulator->m_psxCpu->m_psxRegs.CP0.n.Status);
    m_statusReg |= IRQ;
    psxHu32ref(0x1070) |= SWAP_LEu32(0x80);

#if 0
    // Rhapsody: fixes input problems
    // Twisted Metal 2: breaks intro
    m_statusReg |= TX_RDY;
    m_statusReg |= RX_RDY;
#endif
}

void PCSX::SIO::LoadMcd(int mcd, const PCSX::u8string str) {
    char *data = nullptr;
    const char *fname = reinterpret_cast<const char *>(str.c_str());

    if (mcd == 1) {
        data = g_mcd1Data;
        m_wasMcd1Inserted = false;
    }
    if (mcd == 2) {
        data = g_mcd2Data;
        m_wasMcd2Inserted = false;
    }

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

void PCSX::SIO::LoadMcds(const PCSX::u8string mcd1, const PCSX::u8string mcd2) {
    LoadMcd(1, mcd1);
    LoadMcd(2, mcd2);
}

void PCSX::SIO::saveMcd(const PCSX::u8string mcd, const char *data, uint32_t adr, size_t size) {
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

void PCSX::SIO::CreateMcd(const PCSX::u8string mcd) {
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

void PCSX::SIO::ConvertMcd(const PCSX::u8string mcd, const char *data) {
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

void PCSX::SIO::getMcdBlockInfo(int mcd, int block, McdBlock &info) {
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
            c << 8;
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

char *PCSX::SIO::getMcdData(int mcd) {
    switch (mcd) {
        case 1:
            return g_mcd1Data;
        case 2:
            return g_mcd2Data;
        default:
            throw std::runtime_error("Attempt to access invalid memory card");
            return nullptr;
    }
}

// Erase a memory card block by clearing it with 0s
// mcd: The memory card we want to use (1 or 2)
void PCSX::SIO::eraseMcdFile(const McdBlock &block) {
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

unsigned PCSX::SIO::getFreeSpace(int mcd) {
    unsigned count = 0;
    for (int i = 1; i < 16; i++) {
        McdBlock block;
        getMcdBlockInfo(mcd, i, block);
        if (block.isErased()) count++;
    }

    return count;
}

unsigned PCSX::SIO::getFileBlockCount(McdBlock block) {
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

int PCSX::SIO::findFirstFree(int mcd) {
    McdBlock block;
    for (int i = 1; i < 16; i++) {
        getMcdBlockInfo(mcd, i, block);
        if (block.isErased()) return i;
    }

    return -1;
}

bool PCSX::SIO::copyMcdFile(McdBlock block) {
    auto other = otherMcd(block);
    if (getFreeSpace(other) < getFileBlockCount(block)) return false;
    const auto const data = getMcdData(block);
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
void PCSX::SIO::saveMcd(int mcd) {
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
