/***************************************************************************
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
    SIO1_LOG("SIO1 Interrupt (CP0.Status = %x)\n", PCSX::g_emulator->m_psxCpu->m_psxRegs.CP0.n.Status);
    m_statusReg |= SR_IRQ;
    psxHu32ref(0x1070) |= SWAP_LEu32(0x100);
}

uint8_t PCSX::SIO1::readData8() {
    uint8_t ret = 0;

    if (m_statusReg & SR_RXRDY) {
        ret = m_slices.getByte();
        readStat8();
        psxHu8(0x1050) = ret;
    }

    return ret;
}

uint8_t PCSX::SIO1::readStat8() {
    if (m_slices.m_sliceQueue.empty()) {
        m_statusReg &= ~SR_RXRDY;
    } else {
        m_statusReg |= SR_RXRDY;
    }
    psxHu32(0x1054) = m_statusReg;

    return m_statusReg & 0xFF;
}

void PCSX::SIO1::receiveCallback() {
    if (m_ctrlReg & CR_RXIRQEN) {
        if (!(m_statusReg & SR_IRQ)) {
            scheduleInterrupt(SIO1_CYCLES);
            m_statusReg |= SR_IRQ;
        }
    }
}

void PCSX::SIO1::writeBaud16(uint16_t v) {
    m_baudReg = v;
    psxHu16(0x105E) = m_baudReg;
}

void PCSX::SIO1::writeCtrl16(uint16_t v) {
    m_ctrlReg = v;
    if (m_ctrlReg & CR_ACK) {
        m_ctrlReg &= ~CR_ACK;
        psxHu16(0x105A) = m_ctrlReg;

        m_statusReg &= ~(SR_PARITYERR | SR_RXOVERRUN | SR_FRAMINGERR | SR_IRQ);
        psxHu32(0x1054) = m_statusReg;
    }

    if (m_ctrlReg & CR_ACK) {
        m_ctrlReg &= ~CR_ACK;
        m_statusReg &= ~(SR_PARITYERR | SR_RXOVERRUN | SR_FRAMINGERR | SR_IRQ);
    }

    if (m_ctrlReg & CR_RESET) {
        m_statusReg &= ~SR_IRQ;
        m_statusReg |= SR_TXRDY | SR_TXEMPTY;
        psxHu32(0x1054) = m_statusReg;

        m_modeReg = 0;
        psxHu16(0x1058) = m_modeReg;

        m_ctrlReg = 0;
        psxHu16(0x105A) = m_ctrlReg;

        m_baudReg = 0;
        psxHu16(0x105E) = m_baudReg;

        PCSX::g_emulator->m_psxCpu->m_psxRegs.interrupt &= ~(1 << PCSX::PSXINT_SIO1);
    }
}

void PCSX::SIO1::writeData8(uint8_t v) {
    psxHu8(0x1050) = v;
    PCSX::g_emulator->m_sio1Server->write(v);

    if (m_ctrlReg & CR_TXIRQEN) {
        if (!(m_statusReg & SR_IRQ)) {
            scheduleInterrupt(SIO1_CYCLES);
            m_statusReg |= SR_IRQ;
        }
    }

    m_statusReg |= SR_TXRDY | SR_TXEMPTY;
    psxHu32(0x1054) = m_statusReg;
}

void PCSX::SIO1::writeMode8(uint8_t v) {
    m_modeReg = v;
    psxHu16(0x1058) = v;
}

void PCSX::SIO1::writeMode16(uint16_t v) {
    m_modeReg = v;
    psxHu16(0x1058) = v;
}

void PCSX::SIO1::writeStat8(uint8_t v) {
    m_statusReg = v;
    psxHu32(0x1054) = m_statusReg;
}

void PCSX::SIO1::writeStat16(uint16_t v) {
    m_statusReg = v;
    psxHu32(0x1054) = m_statusReg;
}

void PCSX::SIO1::writeStat32(uint32_t v) {
    m_statusReg = v;
    psxHu32(0x1054) = m_statusReg;
}
