/***************************************************************************
 *   Copyright (C) 2023 PCSX-Redux authors                                 *
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

#include "pio-cart.h"

#include <stdint.h>

#include "core/psxemulator.h"
#include "core/psxmem.h"

static constexpr bool between(uint32_t val, uint32_t beg, uint32_t end) {
    return (beg > end) ? false : (val >= beg && val <= end);
}

void PCSX::PIOCart::setLuts() {
    const auto &m_readLUT = g_emulator->m_mem->m_readLUT;
    const auto &m_writeLUT = g_emulator->m_mem->m_writeLUT;
    const auto &m_exp1 = g_emulator->m_mem->m_exp1;

    if (g_emulator->settings.get<Emulator::SettingPIOConnected>().value) {
        for (int i = 0; i < 4; i++) {
            m_readLUT[i + 0x1f00] = &m_exp1[i << 16];
        }

        m_readLUT[0x1f04] = &m_exp1[0 << 16];
        m_readLUT[0x1f05] = &m_exp1[1 << 16];
        m_pal.reset();
    } else {
        memset(&m_readLUT[0x1f00], 0, 0x6 * sizeof(void *));
    }

    // nullptr by default, wipe to ensure writes are properly intercepted
    memset(&m_writeLUT[0x1f00], 0, 0x6 * sizeof(void *));
    memset(&m_writeLUT[0x9f00], 0, 0x6 * sizeof(void *));
    memset(&m_writeLUT[0xbf00], 0, 0x6 * sizeof(void *));

    memcpy(&m_readLUT[0x9f00], &m_readLUT[0x1f00], 0x6 * sizeof(void *));
    memcpy(&m_readLUT[0xbf00], &m_readLUT[0x1f00], 0x6 * sizeof(void *));
}

uint8_t PCSX::PIOCart::read8(uint32_t address) {
    uint32_t hwadd = address & 0x1fffffff;

    if (g_emulator->settings.get<Emulator::SettingPIOConnected>().value) {
        return m_pal.read8(hwadd);
    } else {
        return 0xff;
    }
}

void PCSX::PIOCart::write8(uint32_t address, uint8_t value) {
    uint32_t hwadd = address & 0x1fffffff;
    if (g_emulator->settings.get<Emulator::SettingPIOConnected>().value) {
        m_pal.write8(hwadd, value);
    }
}

bool PCSX::PIOCart::PAL::FlashMemory::checkCommand() {
    bool result = false;

    uint8_t commandHistory[6];

    for (int i = 0, j = 0; i < m_bufferSize; i++, j--) {
        if (j < 0) {
            j = m_bufferSize - 1;
        }
        commandHistory[i] = m_commandBuffer[(m_busCycle + j) % m_bufferSize];
    }

    // Check 3-cycle commands
    if (commandHistory[2] == 0xaa && commandHistory[1] == 0x55) {
        switch (commandHistory[0]) {
            case 0xa0:  // Software Data Protect Enable & Page - Write
                softwareDataProtectEnablePageWrite();
                result = true;
                break;

            case 0x90:  // Software ID Entry
                enterSoftwareIDMode();
                result = true;
                break;

            case 0xf0:  // Software ID Exit
                exitSoftwareIDMode();
                result = true;
                break;
        }
    }

    if (!result) {
        // Check 6-cycle commands
        if (commandHistory[5] == 0xaa && commandHistory[4] == 0x55 && commandHistory[3] == 0x80 &&
            commandHistory[2] == 0xaa && commandHistory[1] == 0x55) {
            switch (commandHistory[0]) {
                case 0x20:  // Software Data Protect Disable
                    softwareDataProtectDisable();
                    result = true;
                    break;

                case 0x10:  // Software Chip-Erase
                    softwareChipErase();
                    result = true;
                    break;

                case 0x60:  // Alternate Software ID Entry
                    enterSoftwareIDMode();
                    result = true;
                    break;
            }
        }
    }

    return result;
}

void PCSX::PIOCart::PAL::setLUTFlashBank(uint8_t bank) {
    const auto &m_readLUT = g_emulator->m_mem->m_readLUT;
    const auto &m_exp1 = g_emulator->m_mem->m_exp1;

    if (m_readLUT == nullptr || m_exp1 == nullptr) return;

    switch (bank) {
        case 0:
            m_readLUT[0x1f04] = &m_exp1[0 << 16];
            m_readLUT[0x1f05] = &m_exp1[1 << 16];
            break;

        default:
            m_readLUT[0x1f04] = m_pio->m_detachedMemory;
            m_readLUT[0x1f05] = m_pio->m_detachedMemory;
    }

    memcpy(&m_readLUT[0x9f04], &m_readLUT[0x1f04], 0x2 * sizeof(void *));
    memcpy(&m_readLUT[0xbf04], &m_readLUT[0x1f04], 0x2 * sizeof(void *));

    m_bank = bank;
}

void PCSX::PIOCart::PAL::FlashMemory::setLUTNormal() {
    const auto &m_readLUT = g_emulator->m_mem->m_readLUT;
    const auto &m_exp1 = g_emulator->m_mem->m_exp1;

    for (int i = 0; i < 4; i++) {
        m_readLUT[i + 0x1f00] = &m_exp1[i << 16];
    }

    memcpy(&m_readLUT[0x9f00], &m_readLUT[0x1f00], 0x4 * sizeof(void *));
    memcpy(&m_readLUT[0xbf00], &m_readLUT[0x1f00], 0x4 * sizeof(void *));
}

void PCSX::PIOCart::PAL::FlashMemory::setLUTSoftwareID() {
    const auto &m_readLUT = g_emulator->m_mem->m_readLUT;
    const auto &m_exp1 = g_emulator->m_mem->m_exp1;

    for (int i = 0; i < 4; i++) {
        m_readLUT[i + 0x1f00] = m_softwareID;
    }

    memcpy(&m_readLUT[0x9f00], &m_readLUT[0x1f00], 0x4 * sizeof(void *));
    memcpy(&m_readLUT[0xbf00], &m_readLUT[0x1f00], 0x4 * sizeof(void *));
}

void PCSX::PIOCart::PAL::FlashMemory::writeCommandBus(uint32_t addr, uint8_t data) {
    m_commandBuffer[m_busCycle] = data;

    const uint32_t masked_addr = (addr & 0xffff);

    switch (masked_addr) {
        case 0x2aaa:
        case 0x5555:
            if (!checkCommand()) {
                m_busCycle = (m_busCycle + 1) % 6;
            }
            break;
    }
}

uint8_t PCSX::PIOCart::PAL::read8(uint32_t address) {
    const uint32_t page = (address >> 16);

    if (page == 0x1f06) {
        switch (address & 7) {
            case 0:
                return (0xfe | (m_pio->m_switchOn & 1));  // Bit 0 = Switch status
            case 1:
                return 0x00;
            case 2:
                return 0xfe;
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
                return 0xff;
        }
    }

    g_system->log(LogClass::CPU, _("Unknown 8-bit read in EXP1/PIO: %8.8lx\n"), address);
    return 0xff;
};

void PCSX::PIOCart::PAL::write8(uint32_t address, uint8_t value) {
    if (between(address, 0x1f000000, 0x1f03ffff)) {
        m_flashMemory.write8(address & 0x3ffff, value);
    } else if (between(address, 0x1f040000, 0x1f060000 - 1)) {
        if (m_bank == 0) {  // To-do: Does PAL send writes to bank selected flash chip?
            m_flashMemory.write8(address & 0x3ffff, value);
        }
    } else if (address == 0x1f060001) {  // Bank select
        setLUTFlashBank(value);
    } else {
        g_system->log(LogClass::CPU, _("Unknown 8-bit write in EXP1/PIO: %8.8lx\n"), address);
    }
}

void PCSX::PIOCart::PAL::FlashMemory::write8(uint32_t address, uint8_t value) {
    const uint32_t offset = address & 0x3ffff;

    if (m_pageWriteEnabled) {
        if (m_targetWritePage == -1) {
            m_targetWritePage = address / 128;
        }

        if ((address / 128) == m_targetWritePage) {
            g_emulator->m_mem->m_exp1[address] = value;

            if (((address & 0xff) % 0x80) == 0x7f) {
                m_pageWriteEnabled = false;
                m_targetWritePage = -1;
            }

            return;
        }
    } else if (!m_dataProtectEnabled) {
        g_emulator->m_mem->m_exp1[address] = value;
    } else {
        switch (address) {
            case 0x2aaa:  // Command bus
            case 0x5555:  // Command bus
                writeCommandBus(address, value);
                break;
        }
    }
}
