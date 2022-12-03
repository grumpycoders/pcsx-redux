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

#include <compare>
#include <string>

#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "core/sio1-server.h"
#include "support/file.h"
#include "support/protobuf.h"

#define SIO1_PB_VERSION (1)

namespace PCSX {

struct SIO1Registers {
    uint32_t data;
    uint16_t status;
    uint16_t mode;
    uint16_t control;
    uint16_t baud;
};

typedef Protobuf::Field<Protobuf::UInt16, TYPESTRING("flow_control_reg"), 1> FlowControlReg;
typedef Protobuf::Message<TYPESTRING("FlowControl"), FlowControlReg> FlowControl;
typedef Protobuf::MessageField<FlowControl, TYPESTRING("flow_control"), 2> FlowControlField;
typedef Protobuf::Field<Protobuf::Bytes, TYPESTRING("data"), 1> DataTransferData;
typedef Protobuf::Message<TYPESTRING("DataTransfer"), DataTransferData> DataTransfer;
typedef Protobuf::MessageField<DataTransfer, TYPESTRING("data_transfer"), 1> DataTransferField;
typedef Protobuf::Message<TYPESTRING("SIOPayload"), DataTransferField, FlowControlField> SIOPayload;

// SIO1Info Message for future use
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("version_number"), 1> SIO1Version;
typedef Protobuf::MessageField<SIO1Version, TYPESTRING("sio1_version"), 1> SIO1VersionField;
typedef Protobuf::Message<TYPESTRING("SIO1Version"), SIO1VersionField> SIO1Info;

class SIO1 {
    /*
     * TODO:
     * STAT Baudrate timer
     * Add/verify cases for all R/W functions exist in psxhw.cpp
     */

  public:
    enum class SIO1Mode { Raw, Protobuf };
    SIO1Mode m_sio1Mode = SIO1Mode::Protobuf;
    SIO1Mode getSIO1Mode() { return m_sio1Mode; }
    void interrupt();

    void poll() {
        if (fifoError()) return;
        if (m_sio1Mode == SIO1Mode::Protobuf) {
            sio1StateMachine();
        } else {
            if (m_sio1fifo->size() >= 1) {
                receiveCallback();
            }
        }
    }

    void reset() {
        if (m_sio1fifo.isA<Fifo>()) m_sio1fifo.asA<Fifo>()->reset();
        m_regs.data = 0;
        m_regs.status = (SR_TXRDY | SR_TXRDY2 | SR_DSR | SR_CTS);
        m_regs.mode = 0;
        m_regs.control = 0;
        m_regs.baud = 0;
        m_decodeState = READ_SIZE;
        messageSize = 0;
        m_slaveDelay = true;
        g_emulator->m_cpu->m_regs.interrupt &= ~(1 << PCSX::PSXINT_SIO1);
    }

    void stopSIO1Connection() {
        m_decodeState = READ_SIZE;
        messageSize = 0;
        m_slaveDelay = true;
        if (m_sio1fifo.isA<Fifo>()) {
            m_sio1fifo.asA<Fifo>()->reset();
        } else if (m_sio1fifo) {
            m_sio1fifo.reset();
        }
        if (m_fifo) m_fifo.reset();
    }

    void setFifo(IO<File> newFifo) {
        if (m_sio1Mode == SIO1Mode::Raw) {
            m_sio1fifo = newFifo;
        } else {
            m_fifo = newFifo;
            m_sio1fifo.setFile(new Fifo());
        }
    }

    bool connecting() { return m_fifo.asA<UvFifo>()->isConnecting(); }

    bool fifoError() {
        if (m_sio1Mode == SIO1Mode::Raw) {
            return (!m_sio1fifo || m_sio1fifo->failed() || m_sio1fifo->eof() || m_sio1fifo->isClosed());
        } else {
            return (!m_fifo || m_fifo->failed() || m_fifo->eof() || m_fifo->isClosed());
        }
    }

    uint16_t readBaud16() { return m_regs.baud; }

    uint16_t readCtrl16() {
        if (m_sio1Mode == SIO1Mode::Protobuf) sio1StateMachine();
        return m_regs.control;
    }

    uint8_t readData8();
    uint16_t readData16();
    uint32_t readData32();

    uint16_t readMode16() { return m_regs.mode; }

    uint16_t readStat16();
    uint32_t readStat32();

    void writeBaud16(uint16_t v);
    void writeCtrl16(uint16_t v);

    void writeData8(uint8_t v);
    void writeData16(uint16_t v) { writeData8(v & 0xff); }
    void writeData32(uint32_t v) { writeData8(v & 0xff); }

    void writeMode16(uint16_t v);
    void writeStat16(uint16_t v);
    void writeStat32(uint32_t v) { writeStat16(v); };

    void receiveCallback();
    void sio1StateMachine(bool data = false);

    SIO1Registers m_regs;

  private:
    uint8_t messageSize = 0;
    bool m_slaveDelay = true;
    uint64_t m_cycleCount = 2352;  // Default to cycles for 115200 baud
    uint64_t m_baudRate = 115200;  // Default to 115200 baud

    SIOPayload makeDataMessage(std::string &&data);
    SIOPayload makeFlowControlMessage();
    std::string encodeMessage(SIOPayload message);
    void sendDataMessage();
    void sendFlowControlMessage();
    void transmitMessage(std::string &&message);
    void decodeMessage();
    void processMessage(SIOPayload payload);
    void calcCycleCount();
    void updateStat();
    void transmitData();
    bool isTransmitReady();

    inline void slaveDelay() {
        uint16_t ctrl = CR_DTR | CR_RTS;
        SIOPayload payload = {
            DataTransfer{},
            FlowControl{ctrl},
        };
        for (int i = 0; i < 4; ++i) {
            std::string message = encodeMessage(payload);
            transmitMessage(std::move(message));
        }
        m_slaveDelay = false;
    }

    inline void waitOnMessage() {
        while (m_fifo->size() == 0)
            ;                          // Wait for the next message to force sync
        messageSize = m_fifo->byte();  // Retrieve size of message
        while (m_fifo->size() < messageSize)
            ;  // Wait until full message has been received
    }

    inline void setDsr(bool value) {
        if (value) {
            m_regs.status |= SR_DSR;
        } else {
            m_regs.status &= ~SR_DSR;
        }
    }
    inline void setCts(bool value) {
        if (value) {
            m_regs.status |= SR_CTS;
        } else {
            m_regs.status &= ~SR_CTS;
        }
    }

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
        CR_RTS = 0x0020,
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

    int m_reloadFactor[4] = {0, 1, 16, 64};

    enum { READ_SIZE, READ_MESSAGE } m_decodeState = READ_SIZE;

    inline void scheduleInterrupt(uint32_t eCycle) { g_emulator->m_cpu->scheduleInterrupt(PSXINT_SIO1, eCycle); }

    IO<File> m_fifo;
    IO<File> m_sio1fifo;
};
}  // namespace PCSX
