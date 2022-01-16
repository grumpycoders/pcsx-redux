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

#include <string>

#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "core/sstate.h"
#include "core/uart-server.h"

namespace PCSX {

class UART {
  public:
    unsigned char SIO1_readData8() {
        uint8_t ret = 0;

        if (m_statusReg & SR_RXRDY)
        {
            ret = m_slices.getByte();
            m_statusReg &= ~SR_RXRDY;
        }

        return ret;
    }
    unsigned char SIO1_readStat8() {
        if (m_slices.m_sliceQueue.size() > 0) {
            m_statusReg |= SR_RXRDY;
            m_statusReg |= SR_TXRDY | SR_TXEMPTY;
        } else {
            m_statusReg &= ~SR_RXRDY;
        }
        
        return m_statusReg & 0x00FF;
    }
    unsigned short SIO1_readData16() {
        
        return psxHu16(0x1050);
    }
    uint32_t SIO1_readData32() {
        return psxHu32(0x1050);
    }

    unsigned short SIO1_readStat16() { return m_statusReg; }
    unsigned short SIO1_readMode16() { return m_modeReg; }
    unsigned short SIO1_readCtrl16() { return m_ctrlReg; }
    unsigned short SIO1_readBaud16() { return m_baudReg; }

    void SIO1_writeData8(unsigned char v) {
        PCSX::g_emulator->m_uartServer->write(v);
    }

    void SIO1_writeData16(unsigned short v) { psxHu16(0x1050) = v; }
    void SIO1_writeData32(uint32_t v) { psxHu16(0x1050) = v; }

    void SIO1_writeStat8(unsigned char v) { psxHu16(0x1054) = v; }

    void SIO1_writeStat16(uint16_t v) { 
        m_statusReg = v;
    }
    void SIO1_writeMode16(uint16_t v) { 
        m_modeReg = v;
    }
    void SIO1_writeCtrl16(uint16_t v) {
        m_ctrlReg = v;
        if (m_ctrlReg & CR_ACK) {
            m_ctrlReg &= ~CR_ACK;
            m_statusReg &= ~(SR_PARITYERR | SR_RXOVERRUN | SR_FRAMINGERR | SR_IRQ);
        }

        if (m_ctrlReg & CR_UNKNOWN) {
            m_statusReg &= ~SR_IRQ;
            m_statusReg |= SR_TXRDY | SR_TXEMPTY;
            m_modeReg = 0;
            m_ctrlReg = 0;
            m_baudReg = 0;
        }
    }
    void SIO1_writeBaud16(uint16_t v) {
        m_baudReg = v;
    }

    struct Slices {
        void pushSlice(const Slice& slice) { m_sliceQueue.push(slice); }
        ~Slices() {
            while (!m_sliceQueue.empty()) m_sliceQueue.pop();
        }

        uint8_t getByte() {
            Slice& slice = m_sliceQueue.front();
            uint8_t r = slice.getByte(m_cursor);
            if (++m_cursor >= slice.size()) {
                m_cursor = 0;
                m_sliceQueue.pop();
            }
            return r;
        }

        std::queue<Slice> m_sliceQueue;
        uint32_t m_cursor = 0;
    };

    Slices m_slices;

  private:
    enum {
        // Status Flags
        SR_TXRDY = 0x0001,
        SR_RXRDY = 0x0002,    // RX_NOTEMPTY
        SR_TXEMPTY = 0x0004,  // TX_RDY2
        SR_PARITYERR = 0x0008,
        SR_RXOVERRUN = 0x0010,
        SR_FRAMINGERR = 0x0020,
        SR_SYNCDETECT = 0x0040,
        SR_DSR = 0x0080,
        SR_CTS = 0x0100,
        SR_IRQ = 0x0200,
    };

    enum {
        // Control Flags
        CR_TXEN = 0x0001,
        CR_DTR = 0x0002,
        CR_RXEN = 0x0004,
        CR_TXOUTLVL = 0x0008,
        CR_ACK = 0x0010,
        CR_RTSOUTLVL = 0x0020,
        CR_UNKNOWN = 0x0040, // RESET?
        CR_RXIRQMODE = 0x0080,
        CR_TXIRQMODE = 0x0100,
        CR_RXIRQEN = 0x0200,
        CR_DSRIRQEN = 0x0400,
    };

    // Transfer Ready and the Buffer is Empty
    uint16_t m_statusReg = SR_TXRDY | SR_TXEMPTY | SR_DSR | SR_CTS;
    uint16_t m_modeReg = 0;
    uint16_t m_ctrlReg = 0;
    uint16_t m_baudReg = 0;
};
}  // namespace PCSX
