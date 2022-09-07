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

#include "core/memorycard.h"
#include "core/pad.h"
#include "support/sjis_conv.h"
#include "support/strings-helpers.h"

// clk cycle byte
// 4us * 8bits = (PCSX::g_emulator->m_psxClockSpeed / 1000000) * 32; (linuzappz)
// TODO: add SioModePrescaler
#define SIO_CYCLES (m_regs.baud * 8)

PCSX::SIO::SIO() { reset(); }

void PCSX::SIO::reset() {
    m_padState = PAD_STATE_IDLE;
    m_regs.status = TX_RDY | TX_READY2;
    m_regs.mode = 0;
    m_regs.control = 0;
    m_regs.baud = 0;
    m_bufferIndex = 0;
    m_memoryCard[0].deselect();
    m_memoryCard[1].deselect();
    m_currentDevice = SIO_Device::None;    
}

void PCSX::SIO::writePad(uint8_t value) {
    switch (m_padState) {
        case PAD_STATE_IDLE:        // start pad
            m_regs.status |= RX_RDY;  // Transfer is Ready

            switch (m_regs.control & SIO_Selected::PortMask) {
                case SIO_Selected::Port1:
                    if (!PCSX::g_emulator->m_pads->isPadConnected(1)) return;
                    m_buffer[0] = PCSX::g_emulator->m_pads->startPoll(Pads::Port::Port1);
                    break;
                case SIO_Selected::Port2:
                    if (!PCSX::g_emulator->m_pads->isPadConnected(2)) return;
                    m_buffer[0] = PCSX::g_emulator->m_pads->startPoll(Pads::Port::Port2);
                    break;
            }

            m_maxBufferIndex = 2;
            m_bufferIndex = 0;
            m_padState = PAD_STATE_READ_COMMAND;
            break;

        case PAD_STATE_READ_COMMAND:
            m_padState = PAD_STATE_READ_DATA;
            m_bufferIndex = 1;
            switch (m_regs.control & SIO_Selected::PortMask) {
                case SIO_Selected::Port1:
                    m_buffer[m_bufferIndex] = PCSX::g_emulator->m_pads->poll(value, Pads::Port::Port1, m_padState);
                    break;
                case SIO_Selected::Port2:
                    m_buffer[m_bufferIndex] = PCSX::g_emulator->m_pads->poll(value, Pads::Port::Port2, m_padState);
                    break;
            }

            if (!(m_buffer[m_bufferIndex] & 0x0f)) {
                m_maxBufferIndex = 2 + 32;
            } else {
                m_maxBufferIndex = 2 + (m_buffer[m_bufferIndex] & 0x0f) * 2;
            }
            break;

        case PAD_STATE_READ_DATA:
            m_bufferIndex++;
            switch (m_regs.control & SIO_Selected::PortMask) {
                case SIO_Selected::Port1:
                    m_buffer[m_bufferIndex] = PCSX::g_emulator->m_pads->poll(value, Pads::Port::Port1, m_padState);
                    break;
                case SIO_Selected::Port2:
                    m_buffer[m_bufferIndex] = PCSX::g_emulator->m_pads->poll(value, Pads::Port::Port2, m_padState);
                    break;
            }

            if (m_bufferIndex == m_maxBufferIndex) {
                m_padState = PAD_STATE_IDLE;
                m_currentDevice = SIO_Device::Ignore;
                return;
            }
            break;
    }
    scheduleInterrupt(SIO_CYCLES);
}

void PCSX::SIO::write8(uint8_t value) {
    SIO0_LOG("sio write8 %x (PAR:%x PAD:%x)\n", value, m_bufferIndex, m_padState);

    m_regs.data = 0xff;

    if (m_currentDevice == SIO_Device::None) {
        m_currentDevice = value;
        m_regs.status |= RX_RDY;
        m_delayedOut = 0xff;
    }

    switch (m_currentDevice) {
        case SIO_Device::PAD:
            // Pad Process events
            writePad(value);
            m_regs.data = m_buffer[m_bufferIndex];
            break;

        case SIO_Device::MemoryCard:
            switch (m_regs.control & SIO_Selected::PortMask) {
                case SIO_Selected::Port1:
                    if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingMcd1Inserted>()) {
                        m_regs.data = m_delayedOut;
                        m_delayedOut = m_memoryCard[0].processEvents(value);
                        if (m_memoryCard[0].dataChanged()) {
                            m_memoryCard[0].commit(
                                PCSX::g_emulator->settings.get<PCSX::Emulator::SettingMcd1>().string().c_str());
                        }
                    } else {
                        m_currentDevice = SIO_Device::Ignore;
                        m_memoryCard[0].deselect();
                    }
                    break;

                case SIO_Selected::Port2:
                    if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingMcd2Inserted>()) {
                        m_regs.data = m_delayedOut;
                        m_delayedOut = m_memoryCard[1].processEvents(value);
                        if (m_memoryCard[1].dataChanged()) {
                            m_memoryCard[1].commit(
                                PCSX::g_emulator->settings.get<PCSX::Emulator::SettingMcd2>().string().c_str());
                        }
                    } else {
                        m_currentDevice = SIO_Device::Ignore;
                        m_memoryCard[1].deselect();
                    }
                    break;
            }
            break;

        case SIO_Device::Ignore:
            return;

        default:
            m_currentDevice = SIO_Device::None;
            m_padState = PAD_STATE_IDLE;
            m_memoryCard[0].deselect();
            m_memoryCard[1].deselect();
    }
}

void PCSX::SIO::writeStatus16(uint16_t value) {}

void PCSX::SIO::writeMode16(uint16_t value) { m_regs.mode = value; }

void PCSX::SIO::writeCtrl16(uint16_t value) {
    SIO0_LOG("sio ctrlwrite16 %x (PAR:%x PAD:%x)\n", value, m_bufferIndex, m_padState);
    
    if ((m_regs.control & ControlFlags::TX_ENABLE) && (!(value & ControlFlags::TX_ENABLE))) {
        // Select line de-activated, reset state machines
        m_currentDevice = SIO_Device::None;
        m_padState = PAD_STATE_IDLE;
        m_memoryCard[0].deselect();
        m_memoryCard[1].deselect();
        m_bufferIndex = 0;
    }

    m_regs.control = value & ~ControlFlags::RESET_ERR;
    if (value & ControlFlags::RESET_ERR) m_regs.status &= ~IRQ;
    if ((m_regs.control & ControlFlags::SIO_RESET) || (!m_regs.control)) {
        m_padState = PAD_STATE_IDLE;
        m_memoryCard[0].deselect();
        m_memoryCard[1].deselect();
        m_bufferIndex = 0;
        m_regs.status = StatusFlags::TX_RDY | StatusFlags::TX_READY2;
        PCSX::g_emulator->m_cpu->m_regs.interrupt &= ~(1 << PCSX::PSXINT_SIO);
        m_currentDevice = SIO_Device::None;
    }
}

void PCSX::SIO::writeBaud16(uint16_t value) { m_regs.baud = value; }

uint8_t PCSX::SIO::read8() {
    uint8_t ret = 0xFF;

    if ((m_regs.status & RX_RDY) /* && (m_ctrlReg & RX_ENABLE)*/) {
        //      m_regs.status &= ~RX_OVERRUN;
        if (m_bufferIndex == m_maxBufferIndex) {
            m_regs.status &= ~RX_RDY;
            if (m_padState == PAD_STATE_READ_DATA) m_padState = PAD_STATE_IDLE;
            m_currentDevice = SIO_Device::None;
        }

        ret = m_regs.data;
    }

    SIO0_LOG("sio read8 ;ret = %x (I:%x ST:%x BUF:(%x %x %x))\n", ret, m_bufferIndex, m_regs.status,
             m_buffer[m_bufferIndex > 0 ? m_bufferIndex - 1 : 0], m_buffer[m_bufferIndex],
             m_buffer[m_bufferIndex < BUFFER_SIZE - 1 ? m_bufferIndex + 1 : BUFFER_SIZE - 1]);
    return ret;
}

uint16_t PCSX::SIO::readStatus16() {
    uint16_t hard = m_regs.status;

#if 0
    // wait for IRQ first
    if( PCSX::g_emulator->m_cpu->m_regs.interrupt & (1 << PSXINT_SIO) )
    {
        hard &= ~TX_RDY;
        hard &= ~RX_RDY;
        hard &= ~TX_READY2;
    }
#endif

    return hard;
}

uint16_t PCSX::SIO::readMode16() { return m_regs.mode; }

uint16_t PCSX::SIO::readCtrl16() { return m_regs.control; }

uint16_t PCSX::SIO::readBaud16() { return m_regs.baud; }


void PCSX::SIO::interrupt() {
    SIO0_LOG("Sio Interrupt (CP0.Status = %x)\n", PCSX::g_emulator->m_cpu->m_regs.CP0.n.Status);
    m_regs.status |= IRQ;
    psxHu32ref(0x1070) |= SWAP_LEu32(0x80);

#if 0
    // Rhapsody: fixes input problems
    // Twisted Metal 2: breaks intro
    m_statusReg |= TX_RDY;
    m_statusReg |= RX_RDY;
#endif
}

void PCSX::SIO::loadMcds(const PCSX::u8string mcd1, const PCSX::u8string mcd2) {
    m_memoryCard[0].loadMcd(mcd1);
    m_memoryCard[1].loadMcd(mcd2);
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
    for (uint32_t i = 0; i < info.iconCount; i++) {
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
            return m_memoryCard[0].getMcdData();
        case 2:
            return m_memoryCard[1].getMcdData();
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
void PCSX::SIO::saveMcd(int mcd) {
    switch (mcd) {
        case 1: {
            const auto path = g_emulator->settings.get<Emulator::SettingMcd1>().string();
            m_memoryCard[0].saveMcd(path);
            break;
        }
        case 2: {
            const auto path = g_emulator->settings.get<Emulator::SettingMcd2>().string();
            m_memoryCard[1].saveMcd(path);
            break;
        }
    }
}
