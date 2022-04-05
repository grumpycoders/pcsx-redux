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

#include <stdint.h>
#include <string>

#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "core/sio1-server.h"
#include "core/sstate.h"

//#define SIO1_CYCLES (m_regs.baud * 8)
#define SIO1_CYCLES (1)

namespace PCSX {

struct sio1Registers {
    uint32_t data;
    uint32_t status;
    uint16_t mode;
    uint16_t control;
    uint16_t baud;
};

class SIO1 {
    /*
     * To-do:
     * STAT Baudrate timer + BAUD register
     *
     * FIFO buffer - not 100% how this will work,
     * spx unclear and the server receives large packets[2048+] at a time.
     *
     * Test and finish interrupts,
     * only RX is tested
     *
     * Add/verify cases for all R/W functions exist in psxhw.cpp
     */

  public:
    void interrupt();

    void reset() {
        m_slices.discardSlices();
        fifo_rx.empty();
        m_regs.data = 0;
        m_regs.status = (SR_TXRDY | SR_TXRDY2 | SR_DSR | SR_CTS);
        m_regs.mode = 0;
        m_regs.control = 0;
        m_regs.baud = 0;

        PCSX::g_emulator->m_cpu->m_regs.interrupt &= ~(1 << PCSX::PSXINT_SIO1);
    }

    uint8_t readBaud8() { return m_regs.baud & 0xFF; }
    uint16_t readBaud16() { return m_regs.baud; }

    uint8_t readCtrl8() { return m_regs.control & 0xFF; }
    uint16_t readCtrl16() { return m_regs.control; }

    uint8_t readData8();
    uint16_t readData16() { return psxHu16(0x1050); }
    uint32_t readData32() { return psxHu32(0x1050); }

    uint8_t readMode8() { return m_regs.mode & 0xFF; }
    uint16_t readMode16() { return m_regs.mode; }

    uint8_t readStat8();
    uint16_t readStat16();
    uint32_t readStat32();

    void writeBaud8(uint8_t v) { writeBaud16(v); }
    void writeBaud16(uint16_t v);

    void writeCtrl8(uint8_t v) { writeCtrl16(v); }
    void writeCtrl16(uint16_t v);

    void writeData8(uint8_t v);
    void writeData16(uint16_t v) {
        writeData8(v);
        writeData8(v >> 8);
    }
    void writeData32(uint32_t v) {
        writeData8(v);
        writeData8(v >> 8);
        writeData8(v >> 16);
        writeData8(v >> 24);
    }

    void writeMode8(uint8_t v) { writeMode16(v); };
    void writeMode16(uint16_t v);

    void writeStat8(uint8_t v) { writeStat32(v); }
    void writeStat16(uint16_t v) { writeStat32(v); }
    void writeStat32(uint32_t v);

    void receiveCallback();

    void pushSlice(Slice slice) { m_slices.pushSlice(slice); }

    sio1Registers m_regs;

  private:
    enum {
        // Status Flags
        SR_TXRDY = 0x0001,
        SR_RXRDY = 0x0002,   // RX_NOTEMPTY
        SR_TXRDY2 = 0x0004,  // TX_RDY2
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

    enum {
        // I_STAT
        IRQ8_SIO = 0x100
    };

    template <size_t buffer_size, typename T>
    class FIFO {
      public:
        ~FIFO() { empty(); }

        void empty() {
            while (!queue_.empty()) queue_.pop();
        }
        bool isEmpty() { return queue_.empty(); }
        T pull() {
            T ret = T();
            if (!queue_.empty()) {
                ret = queue_.front();
                queue_.pop();
            }

            return ret;
        }
        void push(T data) {
            if (queue_.size() >= buffer_size) {
                queue_.back() = data;
            } else {
                queue_.push(data);
            }
        }

        size_t bytesAvailable() { return queue_.size(); }

      private:
        std::queue<T> queue_;
    };

    struct Slices {
        ~Slices() { discardSlices(); }

        void discardSlices() {
            while (!m_sliceQueueRX.empty()) m_sliceQueueRX.pop();
        }
        void pushSlice(const Slice& slice) { m_sliceQueueRX.push(slice); }

        uint8_t getByte() {
            if (m_sliceQueueRX.empty()) return 0xff;  // derp?
            Slice& slice = m_sliceQueueRX.front();
            uint8_t r = slice.getByte(m_cursor);
            if (++m_cursor >= slice.size()) {
                m_cursor = 0;
                m_sliceQueueRX.pop();
            }
            return r;
        }

        uint32_t getBytesRemaining() {
            Slice& slice = m_sliceQueueRX.front();

            if (m_sliceQueueRX.empty()) return 0;

            return slice.size() - m_cursor;
        }

        std::queue<Slice> m_sliceQueueRX;

        uint32_t m_cursor = 0;
    };

    inline void scheduleInterrupt(uint32_t eCycle) { g_emulator->m_cpu->scheduleInterrupt(PSXINT_SIO1, eCycle); }

    void updateFIFO();
    void updateStat();
    void transmitData();
    bool isTransmitReady();

    Slices m_slices;
    FIFO<8, uint8_t> fifo_rx;
};
}  // namespace PCSX
