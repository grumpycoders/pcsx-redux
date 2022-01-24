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
#include "core/sio1-server.h"
#include "core/sstate.h"

//#define SIO1_CYCLES (m_baudReg * 8)
#define SIO1_CYCLES (1)

namespace PCSX {
class SIO1 {
    /*
     * To-do:
     * STAT Baudrate timer + BAUD register
     *
     * FIFO buffer - not 100% how this will work, spx
     * unclear and the server receives large packets[2048+] at a time.
     * 
     * Test and finish interrupts, only RX is tested
     * 
     * Add/verify cases for all R/W functions exist in psxhw.cpp
    */

  public:
    void interrupt();

    uint8_t readBaud8() { return m_baudReg & 0xFF; }
    uint16_t readBaud16() { return m_baudReg; }

    uint16_t readCtrl16() { return m_ctrlReg; }

    uint8_t readData8();
    uint16_t readData16() { return psxHu16(0x1050); }
    uint32_t readData32() { return psxHu32(0x1050); }

    uint8_t readMode8() { return m_modeReg & 0xFF; }
    uint16_t readMode16() { return m_modeReg; }

    uint8_t readStat8();
    uint16_t readStat16() { return m_statusReg; }

    void writeBaud16(uint16_t v);

    void writeCtrl16(uint16_t v);

    void writeData8(uint8_t v);
    void writeData16(uint16_t v) { psxHu16(0x1050) = v; }
    void writeData32(uint32_t v) { psxHu32(0x1050) = v; }

    void writeMode8(uint8_t v);
    void writeMode16(uint16_t v);

    void writeStat8(uint8_t v);
    void writeStat16(uint16_t v);
    void writeStat32(uint32_t v);

    void receiveCallback();
    void pushSlice(Slice slice) { m_slices.pushSlice(slice); }

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
        CR_RESET = 0x0040,  // RESET INT?
        CR_UNKNOWN = 0x0080,
        CR_RXIRQMODE = 0x0100,  // FIFO byte count, need to implement
        CR_TXIRQEN = 0x0400,
        CR_RXIRQEN = 0x0800,
        CR_DSRIRQEN = 0x0400,
    };

    struct Slices {
        void pushSlice(const Slice& slice) { m_sliceQueue.push(slice); }
        ~Slices() {
            while (!m_sliceQueue.empty()) m_sliceQueue.pop();
        }

        uint8_t getByte() {
            if (m_sliceQueue.empty()) return 0xff;  // derp?
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

    // uint32_t m_dataReg = 0;
    uint32_t m_statusReg = SR_TXRDY | SR_TXEMPTY | SR_DSR | SR_CTS;
    uint16_t m_modeReg = 0;
    uint16_t m_ctrlReg = 0;
    // uint16_t m_miscReg = 0;
    uint16_t m_baudReg = 0;
    Slices m_slices;

    inline void scheduleInterrupt(uint32_t eCycle) { g_emulator->m_psxCpu->scheduleInterrupt(PSXINT_SIO1, eCycle); }
};
}  // namespace PCSX
