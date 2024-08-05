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
#include <stdexcept>

#include "core/memorycard.h"
#include "core/pad.h"
#include "support/sjis_conv.h"
#include "support/strings-helpers.h"

// clk cycle byte
// 4us * 8bits = (PCSX::g_emulator->m_psxClockSpeed / 1000000) * 32; (linuzappz)
// TODO: add SioModePrescaler
#define SIO_CYCLES (m_regs.baud * 8)

void PCSX::SIO::acknowledge() {
    if (m_regs.control & ControlFlags::TX_ENABLE) {
        if (m_regs.control & ControlFlags::ACK_IRQEN) {
            scheduleInterrupt(SIO_CYCLES);
        }
    }
}

void PCSX::SIO::init() {
    g_emulator->m_pads->init();
    reset();
    g_emulator->m_mem->writeHardwareRegister<0x1044>(m_regs.status);
}

bool PCSX::SIO::isReceiveIRQReady() {
    if (m_regs.control & ControlFlags::RX_IRQEN) {
        switch ((m_regs.control & 0x300) >> 8) {
            case 0:
                if (!(m_rxFIFO.size() >= 1)) {
                    return false;
                }
                break;

            case 1:
                if (!(m_rxFIFO.size() >= 2)) {
                    return false;
                }
                break;

            case 2:
                if (!(m_rxFIFO.size() >= 4)) {
                    return false;
                }
                break;

            case 3:
                if (!(m_rxFIFO.size() >= 8)) {
                    return false;
                }
                break;
        }
        return true;
    }

    return false;
}

bool PCSX::SIO::isTransmitReady() {
    const bool tx_enabled = m_regs.control & ControlFlags::TX_ENABLE;
    const bool tx_finished = m_regs.status & StatusFlags::TX_FINISHED;
    const bool tx_data_empty = m_regs.status & StatusFlags::TX_DATACLEAR;

    return (tx_enabled && tx_finished && !tx_data_empty);
}

void PCSX::SIO::reset() {
    m_regs.mode = 0;
    m_regs.control = 0;
    m_regs.baud = 0;

    m_rxFIFO.clear();
    m_currentDevice = DeviceType::None;
    m_regs.status = StatusFlags::TX_DATACLEAR | StatusFlags::TX_FINISHED;
    if (g_emulator) {
        g_emulator->m_mem->writeHardwareRegister<0x1044>(m_regs.status);
        g_emulator->m_cpu->m_regs.interrupt &= ~(1 << PCSX::PSXINT_SIO);
        g_emulator->m_memoryCards->deselect();
        g_emulator->m_pads->deselect();
    }
}

uint8_t PCSX::SIO::writeCard(uint8_t value) {
    const int port_index = ((m_regs.control & ControlFlags::WHICH_PORT) == SelectedPort::Port1) ? 0 : 1;
    const bool is_connected = g_emulator->m_memoryCards->isCardInserted(port_index);

    bool ack = false;
    uint8_t rx_buffer = 0xff;

    if (is_connected) {
        rx_buffer = g_emulator->m_memoryCards->m_memoryCard[port_index].transceive(m_regs.data, &ack);
    } else {
        m_currentDevice = DeviceType::Ignore;
    }

    if (ack) {
        acknowledge();
    }

    return rx_buffer;
}

uint8_t PCSX::SIO::writePad(uint8_t value) {
    const int port_index = ((m_regs.control & ControlFlags::WHICH_PORT) == SelectedPort::Port1) ? 0 : 1;
    const bool is_connected = g_emulator->m_pads->isPadConnected(port_index);

    bool ack = false;
    uint8_t rx_buffer = 0xff;

    if (is_connected) {
        rx_buffer = g_emulator->m_pads->transceive(port_index, m_regs.data, &ack);
    } else {
        m_currentDevice = DeviceType::Ignore;
    }

    if (ack) {
        acknowledge();
    }

    return rx_buffer;
}

void PCSX::SIO::transmitData() {
    m_regs.status &= ~StatusFlags::TX_FINISHED;
    g_emulator->m_mem->writeHardwareRegister<0x1044>(m_regs.status);

    uint8_t rx_buffer = 0xff;

    if (m_currentDevice == DeviceType::None) {
        m_currentDevice = m_regs.data;
    }

    switch (m_currentDevice) {
        case DeviceType::PAD:
            rx_buffer = writePad(m_regs.data);
            break;

        case DeviceType::MemoryCard:
            rx_buffer = writeCard(m_regs.data);
            break;

        case DeviceType::Ignore:
            break;

        default:
            m_currentDevice = DeviceType::Ignore;
    }

    m_rxFIFO.push(rx_buffer);
    updateFIFOStatus();
    m_regs.data = rx_buffer;
    g_emulator->m_mem->writeHardwareRegister<0x1040, uint8_t>(rx_buffer);

    if (isReceiveIRQReady() && !(m_regs.status & StatusFlags::IRQ)) {
        scheduleInterrupt(SIO_CYCLES);
    }
    m_regs.status |= StatusFlags::TX_DATACLEAR | StatusFlags::TX_FINISHED;
    g_emulator->m_mem->writeHardwareRegister<0x1044>(m_regs.status);
}

void PCSX::SIO::write8(uint8_t value) {
    SIO0_LOG("sio write8 %x\n", value);

    m_regs.data = value;
    m_regs.status &= ~StatusFlags::TX_DATACLEAR;
    g_emulator->m_mem->writeHardwareRegister<0x1044>(m_regs.status);

    if (isTransmitReady()) {
        transmitData();
    }
}

void PCSX::SIO::writeStatus16(uint16_t value) {}

void PCSX::SIO::writeMode16(uint16_t value) { m_regs.mode = value; }

void PCSX::SIO::writeCtrl16(uint16_t value) {
    const bool deselected = (m_regs.control & ControlFlags::SELECT_ENABLE) && (!(value & ControlFlags::SELECT_ENABLE));
    const bool selected = (!(m_regs.control & ControlFlags::SELECT_ENABLE)) && (value & ControlFlags::SELECT_ENABLE);
    const bool port_changed = (m_regs.control & ControlFlags::WHICH_PORT) && (!(value & ControlFlags::WHICH_PORT));
    const bool was_ready = isTransmitReady();

    m_regs.control = value;

    SIO0_LOG("sio ctrlwrite16 %x\n", value);

    if (selected && (m_regs.control & ControlFlags::TX_IRQEN) && !(m_regs.status & StatusFlags::IRQ)) {
        scheduleInterrupt(SIO_CYCLES);
    }

    if (deselected || port_changed) {
        // Select line de-activated, reset state machines
        m_currentDevice = DeviceType::None;
        g_emulator->m_memoryCards->deselect();
        g_emulator->m_pads->deselect();
    }

    if (m_regs.control & ControlFlags::RESET_ERR) {
        m_regs.status &= ~(StatusFlags::RX_PARITYERR | StatusFlags::IRQ);
        m_regs.control &= ~ControlFlags::RESET_ERR;

        if (isReceiveIRQReady()) {
            m_regs.status |= StatusFlags::IRQ;
            g_emulator->m_mem->writeHardwareRegister<0x1044>(m_regs.status);
        }
    }

    if (m_regs.control & ControlFlags::RESET) {
        reset();
    }

    updateFIFOStatus();

    if (m_regs.control & ControlFlags::TX_IRQEN) {
        m_regs.status |= StatusFlags::IRQ;
        g_emulator->m_mem->writeHardwareRegister<0x1044>(m_regs.status);
    }

    if (was_ready == false && isTransmitReady()) {
        transmitData();
    }
}

void PCSX::SIO::writeBaud16(uint16_t value) { m_regs.baud = value; }

uint8_t PCSX::SIO::read8() {
    uint8_t ret = 0xFF;

    if ((m_regs.status & StatusFlags::RX_FIFONOTEMPTY) && !m_rxFIFO.isEmpty()) {
        ret = m_rxFIFO.pull();
        updateFIFOStatus();
    }

    SIO0_LOG("sio read8 ;ret = %x\n", ret);

    g_emulator->m_mem->writeHardwareRegister<0x1040, uint8_t>(ret);

    return ret;
}

uint16_t PCSX::SIO::readStatus16() {
    uint16_t hard = m_regs.status;

    return hard;
}

void PCSX::SIO::interrupt() {
    SIO0_LOG("Sio Interrupt (CP0.Status = %x)\n", PCSX::g_emulator->m_cpu->m_regs.CP0.n.Status);
    m_regs.status |= StatusFlags::IRQ;
    g_emulator->m_mem->writeHardwareRegister<0x1044>(m_regs.status);
    g_emulator->m_mem->setIRQ(0x80);

#if 0
    // Rhapsody: fixes input problems
    // Twisted Metal 2: breaks intro
    m_statusReg |= StatusFlags::TX_DATACLEAR;
    m_statusReg |= StatusFlags::RX_FIFONOTEMPTY;
#endif
}

void PCSX::SIO::updateFIFOStatus() {
    if (m_rxFIFO.size() > 0) {
        m_regs.status |= StatusFlags::RX_FIFONOTEMPTY;
    } else {
        m_regs.status &= ~StatusFlags::RX_FIFONOTEMPTY;
    }
    g_emulator->m_mem->writeHardwareRegister<0x1044>(m_regs.status);
}
