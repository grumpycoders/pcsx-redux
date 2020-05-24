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

#include <sys/stat.h>

#include "core/misc.h"
#include "core/pad.h"
#include "core/sio.h"

// clk cycle byte
// 4us * 8bits = (PCSX::g_emulator->m_psxClockSpeed / 1000000) * 32; (linuzappz)
// TODO: add SioModePrescaler
#define SIO_CYCLES (m_baudReg * 8)

// rely on this for now - someone's actual testing
//#define SIO_CYCLES (PCSX::g_emulator->m_psxClockSpeed / 57600)
// PCSX 1.9.91
//#define SIO_CYCLES 200
// PCSX 1.9.91
//#define SIO_CYCLES 270
// ePSXe 1.6.0
//#define SIO_CYCLES        535
// ePSXe 1.7.0
//#define SIO_CYCLES 635

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
                        m_buffer[m_bufferIndex] = PCSX::g_emulator->m_pad1->poll(value);
                        break;
                    case 0x2002:
                        m_buffer[m_bufferIndex] = PCSX::g_emulator->m_pad2->poll(value);
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
                    m_buffer[m_bufferIndex] = PCSX::g_emulator->m_pad1->poll(value);
                    break;
                case 0x2002:
                    m_buffer[m_bufferIndex] = PCSX::g_emulator->m_pad2->poll(value);
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
                        int i;
                        for (i = 2; i < 128 + 4; i++) xorsum ^= m_buffer[i];
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
    PAD_LOG("sio write8 %x (PAR:%x PAD:%x MCDL%x)\n", value, m_bufferIndex, m_padState, m_mcdState);
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
                    m_buffer[0] = PCSX::g_emulator->m_pad1->startPoll();
                    break;
                case 0x2002:
                    m_buffer[0] = PCSX::g_emulator->m_pad2->startPoll();
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

            memset(m_buffer, 0, 4);
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
    PAD_LOG("sio ctrlwrite16 %x (PAR:%x PAD:%x MCD:%x)\n", value, m_bufferIndex, m_padState, m_mcdState);
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
                                SaveMcd(PCSX::g_emulator->settings.get<PCSX::Emulator::SettingMcd1>().string().c_str(),
                                        g_mcd1Data, (m_mcdAddrLow | (m_mcdAddrHigh << 8)) * 128, 128);
                            }
                            break;
                        case 0x2002:
                            if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingMcd2Inserted>()) {
                                memcpy(g_mcd2Data + (m_mcdAddrLow | (m_mcdAddrHigh << 8)) * 128, &m_buffer[1], 128);
                                SaveMcd(PCSX::g_emulator->settings.get<PCSX::Emulator::SettingMcd2>().string().c_str(),
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

    PAD_LOG("sio read8 ;ret = %x (I:%x ST:%x BUF:(%x %x %x))\n", ret, m_bufferIndex, m_statusReg,
            m_buffer[m_bufferIndex > 0 ? m_bufferIndex - 1 : 0], m_buffer[m_bufferIndex],
            m_buffer[m_bufferIndex < BUFFER_SIZE - 1 ? m_bufferIndex + 1 : BUFFER_SIZE - 1]);
    return ret;
}

uint16_t PCSX::SIO::readStatus16() {
    uint16_t hard;

    hard = m_statusReg;

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

    PCSX::g_system->runGui();
}

void PCSX::SIO::interrupt() {
    PAD_LOG("Sio Interrupt (CP0.Status = %x)\n", PCSX::g_emulator->m_psxCpu->m_psxRegs.CP0.n.Status);
    //  PCSX::g_system->printf("Sio Interrupt\n");
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
    FILE *f;
    char *data = NULL;
    const char * fname = reinterpret_cast<const char *>(str.c_str());

    if (mcd == 1) {
        data = g_mcd1Data;
        m_wasMcd1Inserted = false;
    }
    if (mcd == 2) {
        data = g_mcd2Data;
        m_wasMcd2Inserted = false;
    }

    f = fopen(fname, "rb");
    if (f == NULL) {
        PCSX::g_system->printf(_("The memory card %s doesn't exist - creating it\n"), fname);
        CreateMcd(str);
        f = fopen(fname, "rb");
        if (f != NULL) {
            struct stat buf;

            if (stat(fname, &buf) != -1) {
                if (buf.st_size == MCD_SIZE + 64)
                    fseek(f, 64, SEEK_SET);
                else if (buf.st_size == MCD_SIZE + 3904)
                    fseek(f, 3904, SEEK_SET);
            }
            if (fread(data, 1, MCD_SIZE, f) != MCD_SIZE) {
                printf("File read error.");
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
            printf("File read error.");
        }
        fclose(f);
    }
}

void PCSX::SIO::LoadMcds(const PCSX::u8string mcd1, const PCSX::u8string mcd2) {
    LoadMcd(1, mcd1);
    LoadMcd(2, mcd2);
}

void PCSX::SIO::SaveMcd(const PCSX::u8string mcd, const char *data, uint32_t adr, size_t size) {
    FILE *f;
    const char * fname = reinterpret_cast<const char*>(mcd.c_str());

    f = fopen(fname, "r+b");
    if (f != NULL) {
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
    FILE *f;
    const char * fname = reinterpret_cast<const char *>(mcd.c_str());
    struct stat buf;
    int s = MCD_SIZE;
    int i = 0, j;

    f = fopen(fname, "wb");
    if (f == NULL) return;

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
            for (i = 0; i < 7; i++) {
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
            for (i = 0; i < 14; i++) {
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
            for (i = 0; i < 3; i++) {
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

    for (i = 0; i < 15; i++) {  // 15 blocks
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
        for (j = 0; j < 117; j++) {
            fputc(0x00, f);
            s--;
        }
        fputc(0xa0, f);
        s--;
    }

    for (i = 0; i < 20; i++) {
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
        for (j = 0; j < 118; j++) {
            fputc(0x00, f);
            s--;
        }
    }

    while ((s--) >= 0) fputc(0, f);

    fclose(f);
}

void PCSX::SIO::ConvertMcd(const PCSX::u8string mcd, const char *data) {
    FILE *f;
    const char * fname = reinterpret_cast<const char*>(mcd.c_str());
    int i = 0;
    int s = MCD_SIZE;

    if (strstr(fname, ".gme")) {
        f = fopen(fname, "wb");
        if (f != NULL) {
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
        for (i = 0; i < 7; i++) {
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
        for (i = 0; i < 14; i++) {
            fputc(0xa0, f);
            s--;
        }
        fputc(0, f);
        s--;
        fputc(0xff, f);
        while (s-- > (MCD_SIZE + 1)) fputc(0, f);
        fclose(f);
    } else if (strstr(fname, ".mem") || strstr(fname, ".vgs")) {
        f = fopen(fname, "wb");
        if (f != NULL) {
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
        for (i = 0; i < 3; i++) {
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
        f = fopen(fname, "wb");
        if (f != NULL) {
            fwrite(data, 1, MCD_SIZE, f);
            fclose(f);
        }
    }
}

void PCSX::SIO::GetMcdBlockInfo(int mcd, int block, McdBlock *Info) {
    char *data = NULL, *ptr, *str, *sstr;
    unsigned short clut[16];
    unsigned short c;
    int i, x;

    memset(Info, 0, sizeof(McdBlock));

    if (mcd == 1) data = g_mcd1Data;
    if (mcd == 2) data = g_mcd2Data;

    ptr = data + block * 8192 + 2;

    Info->IconCount = *ptr & 0x3;

    ptr += 2;

    x = 0;

    str = Info->Title;
    sstr = Info->sTitle;

    for (i = 0; i < 48; i++) {
        c = *(ptr) << 8;
        c |= *(ptr + 1);
        if (!c) break;

        // Convert ASCII characters to half-width
        if (c >= 0x8281 && c <= 0x829A)
            c = (c - 0x8281) + 'a';
        else if (c >= 0x824F && c <= 0x827A)
            c = (c - 0x824F) + '0';
        else if (c == 0x8140)
            c = ' ';
        else if (c == 0x8143)
            c = ',';
        else if (c == 0x8144)
            c = '.';
        else if (c == 0x8146)
            c = ':';
        else if (c == 0x8147)
            c = ';';
        else if (c == 0x8148)
            c = '?';
        else if (c == 0x8149)
            c = '!';
        else if (c == 0x815E)
            c = '/';
        else if (c == 0x8168)
            c = '"';
        else if (c == 0x8169)
            c = '(';
        else if (c == 0x816A)
            c = ')';
        else if (c == 0x816D)
            c = '[';
        else if (c == 0x816E)
            c = ']';
        else if (c == 0x817C)
            c = '-';
        else {
            str[i] = ' ';
            sstr[x++] = *ptr++;
            sstr[x++] = *ptr++;
            continue;
        }

        str[i] = sstr[x++] = c;
        ptr += 2;
    }

    trim(str);
    trim(sstr);

    ptr = data + block * 8192 + 0x60;  // icon palette data

    for (i = 0; i < 16; i++) {
        clut[i] = *((unsigned short *)ptr);
        ptr += 2;
    }

    for (i = 0; i < Info->IconCount; i++) {
        uint16_t *icon = &Info->Icon[i * 16 * 16];

        ptr = data + block * 8192 + 128 + 128 * i;  // icon data

        for (x = 0; x < 16 * 16; x++) {
            icon[x++] = clut[*ptr & 0xf];
            icon[x] = clut[*ptr >> 4];
            ptr++;
        }
    }

    ptr = data + block * 128;

    Info->Flags = *ptr;

    ptr += 0xa;
    strncpy(Info->ID, ptr, 12);
    ptr += 12;
    strncpy(Info->Name, ptr, 16);
}
