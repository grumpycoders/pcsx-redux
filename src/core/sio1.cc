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
        FlowControl{m_regs.control},
    };
}

PCSX::SIOPayload PCSX::SIO1::makeDataMessage(std::string &&data) {
    return SIOPayload{
        DataTransfer{
            DataTransferData{std::move(data)},
        },
        FlowControl{m_regs.control},
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

    SIOPayload payload = makeFlowControlMessage();
    std::string message = encodeMessage(payload);
    transmitMessage(std::move(message));
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
    // Flow control is always sent/received to ensure synchronization
    setDsr(payload.get<FlowControlField>().get<FlowControlReg>().value & CR_DTR);
    setCts(payload.get<FlowControlField>().get<FlowControlReg>().value & CR_RTS);
    if (payload.get<DataTransferField>().get<DataTransferData>().hasData()) {
        std::string &byte = payload.get<DataTransferField>().get<DataTransferData>().value;
        PCSX::Slice pushByte;
        pushByte.acquire(std::move(byte));
        m_sio1fifo.asA<Fifo>()->pushSlice(std::move(pushByte));
        receiveCallback();
    }

    if (m_sio1fifo->size() > 8) {
        m_regs.status |= SR_RXOVERRUN;
    }

    updateStat();

    // DSR Interrupt
    if (m_regs.control & CR_DSRIRQEN) {
        if (m_regs.status & SR_DSR) {
            if (!(m_regs.status & SR_IRQ)) {
                scheduleInterrupt(m_cycleCount);
                m_regs.status |= SR_IRQ;
            }
        }
    }
}

void PCSX::SIO1::sio1StateMachine(bool data) {
    if (fifoError()) return;

    // Server is master - send first, receive after
    if (g_emulator->m_sio1Server->getServerStatus() == SIO1Server::SIO1ServerStatus::SERVER_STARTED) {
        if (data) {
            sendDataMessage();
        } else {
            sendFlowControlMessage();
        }

        waitOnMessage();  // Wait for the next message to be fully received
    }

    // Client is slave - receive first, send after
    if (g_emulator->m_sio1Client->getClientStatus() == SIO1Client::SIO1ClientStatus::CLIENT_STARTED) {
        // If connection is new, run slave delay
        if (m_slaveDelay) {
            slaveDelay();
            return;
        }

        waitOnMessage();  // Wait for the next message to be fully received

        if (data) {
            sendDataMessage();
        } else {
            sendFlowControlMessage();
        }
    }

    decodeMessage();
}

void PCSX::SIO1::interrupt() {
    SIO1_LOG("SIO1 Interrupt (CP0.Status = %x)\n", PCSX::g_emulator->m_cpu->m_regs.CP0.n.Status);
    psxHu32ref(0x1070) |= SWAP_LEu32(IRQ8_SIO);
    m_regs.status |= SR_IRQ;

    if (!m_sio1fifo || m_sio1fifo->eof()) return;
    if (m_sio1Mode == SIO1Mode::Raw) {
        if (m_sio1fifo->size() >= 1) {
            receiveCallback();
        }
    }
    if (m_sio1fifo.isA<Fifo>()) {
        if (m_sio1fifo->size() > 8) m_sio1fifo.asA<Fifo>()->reset();
    }
}

uint8_t PCSX::SIO1::readData8() {
    if (m_sio1fifo || !m_sio1fifo->eof()) {
        m_regs.data = m_sio1fifo->byte();
    }
    if (m_sio1Mode == SIO1Mode::Protobuf) sio1StateMachine();
    return m_regs.data;
}

uint16_t PCSX::SIO1::readData16() {
    if (m_sio1fifo || !m_sio1fifo->eof()) {
        m_sio1fifo->read(&m_regs.data, 2);
    }
    if (m_sio1Mode == SIO1Mode::Protobuf) sio1StateMachine();
    return m_regs.data;
}

uint32_t PCSX::SIO1::readData32() {
    if (m_sio1fifo || !m_sio1fifo->eof()) {
        m_sio1fifo->read(&m_regs.data, 4);
    }
    if (m_sio1Mode == SIO1Mode::Protobuf) sio1StateMachine();
    return m_regs.data;
}

uint16_t PCSX::SIO1::readStat16() {
    if (m_sio1Mode == SIO1Mode::Protobuf) sio1StateMachine();
    return m_regs.status;
}

uint32_t PCSX::SIO1::readStat32() { return m_regs.status; }

void PCSX::SIO1::receiveCallback() {
    if (!m_sio1fifo || m_sio1fifo->eof()) return;
    // RX Interrupt
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
            sio1StateMachine(true);
            break;
        case SIO1Mode::Raw:
            if (!m_sio1fifo || m_sio1fifo->eof()) return;
            m_sio1fifo->write<uint8_t>(m_regs.data);
            break;
    }
    // TX Interrupt
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
}

void PCSX::SIO1::writeBaud16(uint16_t v) {
    m_regs.baud = v;
    calcCycleCount();
}

void PCSX::SIO1::writeCtrl16(uint16_t v) {
    uint16_t control_backup = m_regs.control;
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

    // Behavior to clear FIFO if RXEN is disabled
    if (!(m_regs.control & CR_RXEN)) {
        if (m_sio1fifo.isA<Fifo>()) {
            m_sio1fifo.asA<Fifo>()->reset();
        }
    }

    if (((m_regs.control >> 8) & 0x03) != ((control_backup >> 8) & 0x03)) {
        if (m_sio1fifo.isA<Fifo>()) {
            m_sio1fifo.asA<Fifo>()->reset();
        }
    }

    if (m_sio1Mode == SIO1Mode::Protobuf) sio1StateMachine();
}

void PCSX::SIO1::writeData8(uint8_t v) {
    m_regs.data = v;
    transmitData();
}

void PCSX::SIO1::writeMode16(uint16_t v) { m_regs.mode = v; }

void PCSX::SIO1::writeStat16(uint16_t v) { m_regs.status = v; }

void PCSX::SIO1::calcCycleCount() {
    int reload = m_reloadFactor[m_regs.mode & 0x3];
    if (m_regs.baud * reload <= 0) return;
    m_baudRate = g_emulator->m_psxClockSpeed / (m_regs.baud * reload);
    m_cycleCount = g_emulator->m_psxClockSpeed / (m_baudRate * 8);
}
