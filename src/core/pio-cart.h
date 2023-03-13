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

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <string>

#include "core/psxemulator.h"
#include "core/psxmem.h"

namespace PCSX {

class PIOCart {
  public:
    PIOCart() : m_pal(this) {
        m_detachedMemory = static_cast<uint8_t *>(calloc(64 * 1024, 1));
        if (m_detachedMemory == NULL) {
            g_system->message("%s", _("Error allocating memory!"));
        } else {
            memset(m_detachedMemory, 0xff, static_cast<size_t>(64 * 1024));
        }
    }

    void setLuts();

    bool getSwitch() { return m_switchOn; }
    void setSwitch(bool on) { m_switchOn = on & 1; }

    uint8_t read8(uint32_t address);
    uint16_t read16(uint32_t address) { return 0xffff; }      // 2 reads?
    uint32_t read32(uint32_t address) { return 0xffffffff; }  // 4 read?
    void write8(uint32_t address, uint8_t value);
    void write16(uint32_t address, uint16_t value) {}  // 2 writes?
    void write32(uint32_t address, uint32_t value) {}  // 4 writes?

  private:
    bool m_switchOn = true;
    uint8_t *m_detachedMemory = NULL;

    class PAL {
      public:
        PAL(PIOCart *parent) : m_flashMemory(this), m_pio(parent) {}

        uint8_t read8(uint32_t address);
        void write8(uint32_t address, uint8_t value);

        void reset() {
            m_flashMemory.resetFlash();
            m_bank = 0;
        }
        void setLUTFlashBank(uint8_t bank);

        friend class PIOCart;

      private:
        class FlashMemory {
          public:
            FlashMemory(PAL *parent) : m_pal(parent) {
                m_softwareID = static_cast<uint8_t *>(calloc(64 * 1024, 1));
                if (m_softwareID == NULL) {
                    g_system->message("%s", _("Error allocating memory!"));
                } else {
                    for (int i = 0; i < (64 * 1024) - 1; i += 2) {
                        m_softwareID[i] = 0xbf;
                        m_softwareID[i + 1] = 0x10;
                    }
                }
            }

            void write8(uint32_t address, uint8_t value);

            void softwareDataProtectEnablePageWrite() {
                m_dataProtectEnabled = true;
                m_pageWriteEnabled = true;
                // To-do: Grab address/page from next write?
            }

            void softwareDataProtectDisable() { m_dataProtectEnabled = false; }
            void softwareChipErase() { memset(g_emulator->m_mem->m_exp1, 0xff, 256 * 1024); }
                
            void enterSoftwareIDMode() {
                setLUTSoftwareID();
                resetCommandBuffer();
            }

            void exitSoftwareIDMode() {
                setLUTNormal();
                resetCommandBuffer();
            }

            bool checkCommand();

            void resetCommandBuffer() {
                memset(m_commandBuffer, 0, 6);
                m_busCycle = 0;
            }

            void resetFlash() {
                resetCommandBuffer();
                m_dataProtectEnabled = true;
                m_pageWriteEnabled = false;
            }

            void sectorErase() {}

            void setLUTNormal();
            void setLUTSoftwareID();

            void writeCommandBus(uint32_t addr, uint8_t data);

          private:
            PAL *m_pal;

            static const size_t m_bufferSize = 6;
            uint8_t m_commandBuffer[m_bufferSize] = {0};
            uint8_t m_busCycle = 0;

            uint8_t *m_softwareID = NULL;

            bool m_dataProtectEnabled = true;
            bool m_pageWriteEnabled = false;
            int32_t m_targetWritePage = -1;
        };

        FlashMemory m_flashMemory;
        PIOCart *m_pio;
        uint8_t m_bank = 0;
    };
    PAL m_pal;
};
}  // namespace PCSX
