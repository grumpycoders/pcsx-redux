/***************************************************************************
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

#pragma once

#include <string>
#include <vector>

#include "core/memorycard.h"
#include "core/pads.h"
#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "core/sstate.h"

namespace PCSX {

struct SIORegisters {
    uint32_t data;
    uint32_t status;
    uint16_t mode;
    uint16_t control;
    uint16_t baud;
};

class SIO {
  public:
    static constexpr size_t c_padCount = 2;

    SIO() {
        for (int i = 0; i < c_padCount; i++) {
            Pad pad = Pad(i);
            m_pads.push_back(pad);
        }

        reset();
    }
    
    ~SIO() {       
        if (m_pads.size() > 0) {
            m_pads.clear();
        }
    }

    void write8(uint8_t value);
    void writeStatus16(uint16_t value);
    void writeMode16(uint16_t value);
    void writeCtrl16(uint16_t value);
    void writeBaud16(uint16_t value);

    uint8_t read8();
    uint16_t readStatus16();
    uint16_t readMode16() { return m_regs.mode; }
    uint16_t readCtrl16() { return m_regs.control; }
    uint16_t readBaud16() { return m_regs.baud; }

    void acknowledge();
    void init();
    void interrupt();
    void reset();
    
  private:
    struct StatusFlags {
        enum : uint16_t {
            TX_DATACLEAR = 0x0001,  // 0 = pending transmit, 1 = transmit completed
            RX_FIFONOTEMPTY = 0x0002,
            TX_FINISHED = 0x0004,
            RX_PARITYERR = 0x0008,
            RX_OVERRUN =
                0x0010,  //(unlike SIO, this isn't RX FIFO Overrun flag), to-do: investigate this claim -skitchin
            FRAMING_ERR = 0x0020,
            SYNC_DETECT = 0x0040,
            ACK = 0x0080,  // ack input level
            CTS = 0x0100,  // unknown
            IRQ = 0x0200,
        };
    };
    struct ControlFlags {
        enum : uint16_t {
            TX_ENABLE = 0x0001,
            SELECT_ENABLE = 0x0002,
            RX_ENABLE = 0x0004,
            BREAK = 0x0008,
            RESET_ERR = 0x0010,
            RTS = 0x0020,
            RESET = 0x0040,
            RX_IRQMODE = 0x0100,  // FIFO byte count, to-do: implement
            TX_IRQEN = 0x0400,
            RX_IRQEN = 0x0800,
            ACK_IRQEN = 0x1000,
            WHICH_PORT = 0x2000,  // 0=/JOY1, 1=/JOY2
        };
    };
    enum {
        // MCD flags
        MCDST_CHANGED = 0x08,
    };

    struct PAD_Commands {
        enum : uint8_t {
            Read = 0x42,  // Read Command
            None = 0x00,  // No command, idle state
            Error = 0xFF  // Bad command
        };
    };
    struct DeviceType {
        enum : uint8_t {
            None = 0x00,        // No device selected yet
            PAD = 0x01,         // Pad Select
            NetYaroze = 0x21,   // Net Yaroze Select
            MemoryCard = 0x81,  // Memory Card Select
            Ignore = 0xFF,      // Ignore incoming commands
        };
    };
    struct SelectedPort {
        enum : uint16_t {
            Port1 = 0x0000,
            Port2 = 0x2000,
        };
    };

    template <typename T, size_t buffer_size>
    class FIFO {
      public:
        ~FIFO() { clear(); }

        void clear() {
            while (!queue_.empty()) queue_.pop();
        }
        bool isEmpty() { return queue_.empty(); }
        T peek() {
            T ret = T();
            if (!queue_.empty()) {
                ret = queue_.front();
            }

            return ret;
        }
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

        size_t size() { return queue_.size(); }

      private:
        std::queue<T> queue_;
    };

    friend SaveStates::SaveState SaveStates::constructSaveState();

    static constexpr size_t c_padBufferSize = 0x1010;

    bool isReceiveIRQReady();
    bool isTransmitReady();
    static inline void scheduleInterrupt(uint32_t eCycle) {
        g_emulator->m_cpu->scheduleInterrupt(PSXINT_SIO, eCycle);
#if 0
// Breaks Twisted Metal 2 intro
        m_statusReg &= ~RX_FIFONOTEMPTY;
        m_statusReg &= ~TX_DATACLEAR;
#endif
    }
    void transmitData();
    void updateFIFOStatus();
    uint8_t writeCard(uint8_t value);
    uint8_t writePad(uint8_t value);
    uint8_t writePad2(uint8_t value);

    SIORegisters m_regs = {
        .status = StatusFlags::TX_DATACLEAR | StatusFlags::TX_FINISHED,  // Transfer Ready and the Buffer is Empty
    };

    uint8_t m_currentDevice = DeviceType::None;

    // Pads
    uint8_t m_buffer[c_padBufferSize];
    uint32_t m_bufferIndex;
    uint32_t m_maxBufferIndex;
    uint32_t m_padState;

    std::vector<Pad> m_pads;

    FIFO<uint8_t, 8> m_rxFIFO;
};

}  // namespace PCSX
