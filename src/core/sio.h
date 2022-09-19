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

#include "core/memorycard.h"
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
    struct McdBlock {
        McdBlock() { reset(); }
        int mcd;
        int number;
        std::string titleAscii;
        std::string titleSjis;
        std::string titleUtf8;
        std::string id;
        std::string name;
        uint32_t fileSize;
        uint32_t iconCount;
        uint16_t icon[16 * 16 * 3];
        uint32_t allocState;
        int16_t nextBlock;
        void reset() {
            mcd = 0;
            number = 0;
            titleAscii.clear();
            titleSjis.clear();
            titleUtf8.clear();
            id.clear();
            name.clear();
            fileSize = 0;
            iconCount = 0;
            memset(icon, 0, sizeof(icon));
            allocState = 0;
            nextBlock = -1;
        }
        bool isErased() const { return (allocState & 0xa0) == 0xa0; }
        bool isChained() const { return (allocState & ~1) == 0x52; }
    };

    static const size_t s_sectorSize = 8 * 16;            // 80h bytes per sector/frame
    static const size_t s_blockSize = s_sectorSize * 64;  // 40h sectors per block
    static const size_t s_cardSize = s_blockSize * 16;    // 16 blocks per frame(directory+15 saves)
    static const size_t s_cardCount = 2;

    SIO() { reset(); }

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

    bool copyMcdFile(McdBlock block);
    void eraseMcdFile(const McdBlock &block);
    void eraseMcdFile(int mcd, int block) {
        McdBlock info;
        getMcdBlockInfo(mcd, block, info);
        eraseMcdFile(info);
    }
    int findFirstFree(int mcd);
    unsigned getFreeSpace(int mcd);
    unsigned getFileBlockCount(McdBlock block);
    void getMcdBlockInfo(int mcd, int block, McdBlock &info);
    char *getMcdData(int mcd);
    char *getMcdData(const McdBlock &block) { return getMcdData(block.mcd); }
    void loadMcds(const PCSX::u8string mcd1, const PCSX::u8string mcd2);
    void saveMcd(int mcd);
    static constexpr int otherMcd(int mcd) {
        if ((mcd != 1) && (mcd != 2)) throw std::runtime_error("Bad memory card number");
        if (mcd == 1) return 2;
        return 1;
    }

    void togglePocketstationMode();
    static constexpr int otherMcd(const McdBlock &block) { return otherMcd(block.mcd); }

    static void SIO1irq(void) { psxHu32ref(0x1070) |= SWAP_LEu32(0x100); }

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

    template <size_t buffer_size, typename T>
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

    friend MemoryCard;
    friend SaveStates::SaveState SaveStates::constructSaveState();

    static const size_t s_padBufferSize = 0x1010;

    bool isReceiveIRQReady();
    bool isTransmitReady();
    inline void scheduleInterrupt(uint32_t eCycle) {
        g_emulator->m_cpu->scheduleInterrupt(PSXINT_SIO, eCycle);
#if 0
// Breaks Twisted Metal 2 intro
        m_statusReg &= ~RX_FIFONOTEMPTY;
        m_statusReg &= ~TX_DATACLEAR;
#endif
    }
    void transmitData();
    void updateFIFOStatus();
    void writePad(uint8_t value);

    SIORegisters m_regs = {
        .status = StatusFlags::TX_DATACLEAR | StatusFlags::TX_FINISHED,  // Transfer Ready and the Buffer is Empty
    };

    uint8_t m_currentDevice = DeviceType::None;

    // Pads
    uint8_t m_buffer[s_padBufferSize];
    uint32_t m_bufferIndex;
    uint32_t m_maxBufferIndex;
    uint32_t m_padState;

    MemoryCard m_memoryCard[s_cardCount] = {this, this};

    FIFO<8, uint8_t> m_rxFIFO;
};

}  // namespace PCSX
