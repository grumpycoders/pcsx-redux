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

void PCSX::SIO1::interrupt() {
    SIO1_LOG("SIO1 Interrupt (CP0.Status = %x)\n", PCSX::g_emulator->m_cpu->m_regs.CP0.n.Status);
    m_regs.status |= SR_IRQ;
    psxHu32ref(0x1070) |= SWAP_LEu32(IRQ8_SIO);
    if (m_fifo.size() > 1) scheduleInterrupt(SIO1_CYCLES);
}

uint8_t PCSX::SIO1::readData8() {
    updateStat();
    if (m_regs.status & SR_RXRDY) {
        m_regs.data = m_fifo.byte();
        psxHu8(0x1050) = m_regs.data;
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
    return m_regs.status & 0xFFFF;
}

uint32_t PCSX::SIO1::readStat32() {
    updateStat();
    return m_regs.status;
}

void PCSX::SIO1::receiveCallback() {
    updateStat();

    if (m_regs.control & CR_RXIRQEN) {
        if (!(m_regs.status & SR_IRQ)) {
            switch ((m_regs.control & 0x300) >> 8) {
                case 0:
                    if (!(m_fifo.size() >= 1)) return;
                    break;

                case 1:
                    if (!(m_fifo.size() >= 2)) return;
                    break;

                case 2:
                    if (!(m_fifo.size() >= 4)) return;
                    break;

                case 3:
                    if (!(m_fifo.size() >= 8)) return;
                    break;
            }

            scheduleInterrupt(SIO1_CYCLES);
            m_regs.status |= SR_IRQ;
        }
    }
}

void PCSX::SIO1::transmitData() {
    PCSX::g_emulator->m_sio1Server->write(m_regs.data);
    if (m_regs.control & CR_TXIRQEN) {
        if (m_regs.status & SR_TXRDY || m_regs.status & SR_TXRDY2) {
            if (!(m_regs.status & SR_IRQ)) {
                scheduleInterrupt(SIO1_CYCLES);
                m_regs.status |= SWAP_LEu32(SR_IRQ);
            }
        }
    }
}

bool PCSX::SIO1::isTransmitReady() {
    return (m_regs.control & CR_TXEN) && (m_regs.status & SR_CTS) && (m_regs.status & SR_TXRDY2);
}

void PCSX::SIO1::updateStat() {
    if (m_fifo.size() > 0) {
        m_regs.status |= SR_RXRDY;
    } else {
        m_regs.status &= ~SR_RXRDY;
    }

    psxHu32ref(0x1054) = SWAP_LEu32(m_regs.status);
}
void PCSX::SIO1::writeBaud16(uint16_t v) {
    m_regs.baud = v;
    psxHu8ref(0x105E) = m_regs.baud;
}

void PCSX::SIO1::writeCtrl16(uint16_t v) {
    uint16_t old_ctrl = m_regs.control;
    m_regs.control = v;
    if (!(old_ctrl & CR_TXEN) && (m_regs.control & CR_TXEN)) {
        if (isTransmitReady()) {
            transmitData();
        }
    }

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

        PCSX::g_emulator->m_cpu->m_regs.interrupt &= ~(1 << PCSX::PSXINT_SIO1);
    }

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
