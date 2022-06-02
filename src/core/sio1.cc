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

#include "core/sio1.h"

PCSX::SIOPayload PCSX::SIO1::makeFlowControlMessage() {
    return SIOPayload{
        DataTransfer{},
        FlowControl{m_flowControl.dxr, m_flowControl.xts},
    };
}

PCSX::SIOPayload PCSX::SIO1::makeDataMessage(std::string &&data) {
    return SIOPayload{
        DataTransfer{
            DataTransferData{std::move(data)},
        },
        FlowControl{},
    };
}

void PCSX::SIO1::transmitMessage(std::string &&message) {
    if (fifoError()) return;

    m_fifo->write<uint8_t>(message.size());
    m_fifo->write(std::move(message));
}

std::string PCSX::SIO1::encodeMessage(SIOPayload message) {
    Protobuf::OutSlice outslice;
    message.serialize(&outslice);
    return std::string(outslice.finalize());
}

void PCSX::SIO1::sendDataMessage() {
    if (fifoError()) return;

    std::string txByte(1, m_regs.data);
    SIOPayload payload = makeDataMessage(std::move(txByte));
    std::string message = encodeMessage(payload);
    transmitMessage(std::move(message));
}

void PCSX::SIO1::sendFlowControlMessage() {
    if (fifoError()) return;

    pollFlowControl();
    if (!initialMessage) {
        if (m_flowControl == m_prevFlowControl) return;
    }
    m_prevFlowControl = m_flowControl;

    SIOPayload payload = makeFlowControlMessage();
    std::string message = encodeMessage(payload);
    transmitMessage(std::move(message));

    if (initialMessage) {
        if (!connecting() && !fifoError()) g_system->printf("%s", _("SIO1 client connected\n"));
        initialMessage = false;
    }
}

void PCSX::SIO1::decodeMessage() {
    if (fifoError()) return;
    std::string message = m_fifo->readString(messageSize);

    SIOPayload payload;
    Protobuf::InSlice inslice(reinterpret_cast<const uint8_t *>(message.data()), message.size());
    try {
        payload.deserialize(&inslice, 0);
    } catch (...) {
        g_system->message(
            "%s",
            _("SIO1 TCP session closing due to unreliable connection.\nRestart SIO1 server/client and try again."));
        g_system->log(LogClass::SIO1, "SIO1 TCP session closing due to unreliable connection\n");
        stopSIO1Connection();
        return;
    }
    processMessage(payload);
}

void PCSX::SIO1::processMessage(SIOPayload payload) {
    if (!payload.get<DataTransferField>().get<DataTransferData>().hasData()) {
        setDsr(payload.get<FlowControlField>().get<FlowControlDXR>().value);
        setCts(payload.get<FlowControlField>().get<FlowControlXTS>().value);
    } else {
        std::string &byte = payload.get<DataTransferField>().get<DataTransferData>().value;
        PCSX::Slice pushByte;
        pushByte.acquire(std::move(byte));
        if (m_regs.control & CR_RTS) {
            m_sio1fifo.asA<Fifo>()->pushSlice(std::move(pushByte));
            receiveCallback();
        }
    }
}

void PCSX::SIO1::sio1StateMachine() {
    if (fifoError()) return;

    switch (m_decodeState) {
        case READ_SIZE:
            while (m_fifo->size() >= 1) {
                messageSize = m_fifo->byte();
                m_decodeState = READ_MESSAGE;
                case READ_MESSAGE:
                    if (m_fifo->size() < messageSize) return;
                    decodeMessage();
                    m_decodeState = READ_SIZE;
            }
    }
}

void PCSX::SIO1::interrupt() {
    SIO1_LOG("SIO1 Interrupt (CP0.Status = %x)\n", PCSX::g_emulator->m_cpu->m_regs.CP0.n.Status);
    psxHu32ref(0x1070) |= SWAP_LEu32(IRQ8_SIO);
    m_regs.status |= SR_IRQ;

    if (!m_sio1fifo || m_sio1fifo->eof()) return;
    if (m_sio1Mode == SIO1Mode::Raw) {
        if (m_sio1fifo->size() >= 1) {
            scheduleInterrupt(m_cycleCount);
        }
    }
    if (m_sio1fifo.isA<Fifo>()) {
        if (m_sio1fifo->size() > 8) m_sio1fifo.asA<Fifo>()->reset();
    }
}

uint8_t PCSX::SIO1::readData8() {
    updateStat();
    if (m_sio1fifo || !m_sio1fifo->eof()) {
        if (m_regs.status & SR_RXRDY) {
            m_regs.data = m_sio1fifo->byte();
            psxHu8(0x1050) = m_regs.data;
        }
    }
    updateStat();
    return m_regs.data;
}

uint16_t PCSX::SIO1::readData16() {
    updateStat();
    if (m_sio1fifo || !m_sio1fifo->eof()) {
        if (m_regs.status & SR_RXRDY) {
            m_sio1fifo->read(&m_regs.data, 2);
            psxHu16(0x1050) = m_regs.data;
        }
    }
    updateStat();
    return m_regs.data;
}

uint32_t PCSX::SIO1::readData32() {
    updateStat();
    if (m_sio1fifo || !m_sio1fifo->eof()) {
        if (m_regs.status & SR_RXRDY) {
            m_sio1fifo->read(&m_regs.data, 4);
            psxHu32(0x1050) = m_regs.data;
        }
    }
    updateStat();
    return m_regs.data;
}

uint8_t PCSX::SIO1::readStat8() {
    updateStat();
    return m_regs.status;
}

uint16_t PCSX::SIO1::readStat16() {
    updateStat();
    return m_regs.status;
}

uint32_t PCSX::SIO1::readStat32() {
    updateStat();
    return m_regs.status;
}

void PCSX::SIO1::receiveCallback() {
    updateStat();
    if (!m_sio1fifo || m_sio1fifo->eof()) return;
    if (m_regs.control & CR_RXIRQEN) {
        if (!(m_regs.status & SR_IRQ)) {
            switch ((m_regs.control & 0x300) >> 8) {
                case 0:
                    if (!(m_sio1fifo->size() >= 1)) return;
                    break;

                case 1:
                    if (!(m_sio1fifo->size() >= 2)) return;
                    break;

                case 2:
                    if (!(m_sio1fifo->size() >= 4)) return;
                    break;

                case 3:
                    if (!(m_sio1fifo->size() >= 8)) return;
                    break;
            }
            scheduleInterrupt(m_cycleCount);
        }
    }
}

void PCSX::SIO1::transmitData() {
    switch (m_sio1Mode) {
        case SIO1Mode::Protobuf:
            if (fifoError()) return;
            sendDataMessage();
            break;
        case SIO1Mode::Raw:
            if (!m_sio1fifo || m_sio1fifo->eof()) return;
            m_sio1fifo->write<uint8_t>(m_regs.data);
            break;
    }

    if (m_regs.control & CR_TXIRQEN) {
        if (m_regs.status & SR_TXRDY || m_regs.status & SR_TXRDY2) {
            if (!(m_regs.status & SR_IRQ)) {
                scheduleInterrupt(m_cycleCount);
                m_regs.status |= SR_IRQ;
            }
        }
    }
}

bool PCSX::SIO1::isTransmitReady() {
    return (m_regs.control & CR_TXEN) && (m_regs.status & SR_CTS) && (m_regs.status & SR_TXRDY2);
}

void PCSX::SIO1::updateStat() {
    if (fifoError()) return;
    if (m_sio1fifo->size() > 0) {
        m_regs.status |= SR_RXRDY;
    } else {
        m_regs.status &= ~SR_RXRDY;
    }
    psxHu32ref(0x1054) = SWAP_LEu32(m_regs.status);
}

void PCSX::SIO1::writeBaud16(uint16_t v) {
    m_regs.baud = v;
    psxHu8ref(0x105E) = m_regs.baud;
    calcCycleCount();
}

void PCSX::SIO1::writeCtrl16(uint16_t v) {
    m_regs.control = v;

    if (m_regs.control & CR_ACK) {
        m_regs.control &= ~CR_ACK;
        m_regs.status &= ~(SR_PARITYERR | SR_RXOVERRUN | SR_FRAMINGERR | SR_IRQ);
    }

    if (m_regs.control & CR_RESET) {
        m_regs.status &= ~SR_IRQ;
        m_regs.status |= (SR_TXRDY | SR_TXRDY2);
        m_regs.mode = 0;
        m_regs.control = 0;
        m_regs.baud = 0;
        m_regs.data = 0;
        if (m_sio1fifo.isA<Fifo>()) {
            m_sio1fifo.asA<Fifo>()->reset();
        }

        PCSX::g_emulator->m_cpu->m_regs.interrupt &= ~(1 << PCSX::PSXINT_SIO1);
    }

    if (!(m_regs.control & CR_RXEN)) {
        if (m_sio1fifo.isA<Fifo>()) {
            m_sio1fifo.asA<Fifo>()->reset();
        }
    }

    if (m_sio1Mode == SIO1Mode::Protobuf) sendFlowControlMessage();
    psxHu16ref(0x105A) = SWAP_LE16(m_regs.control);
}

void PCSX::SIO1::writeData8(uint8_t v) {
    m_regs.data = v;
    if (isTransmitReady()) {
        transmitData();
    }
    psxHu8ref(0x1050) = m_regs.data;
}

void PCSX::SIO1::writeMode16(uint16_t v) { m_regs.mode = v; }

void PCSX::SIO1::writeStat32(uint32_t v) {
    m_regs.status = v;
    if (isTransmitReady()) {
        transmitData();
    }
    psxHu32ref(0x1054) = SWAP_LE32(m_regs.status);
}

void PCSX::SIO1::calcCycleCount() {
    int reload = m_reloadFactor[m_regs.mode & 0x3];
    if (m_regs.baud * reload <= 0) return;
    m_baudRate = g_emulator->m_psxClockSpeed / (m_regs.baud * reload);
    m_cycleCount = g_emulator->m_psxClockSpeed / m_baudRate * 8;
}
