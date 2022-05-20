/***************************************************************************
 *   Copyright (C) 2007 Ryan Schultz, PCSX-df Team, PCSX team              *
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

/*
 * PSX memory functions.
 */

#include "core/psxmem.h"

#include <zlib.h>

#include <map>
#include <string_view>

#include "core/psxhw.h"
#include "core/r3000a.h"
#include "mips/common/util/encoder.hh"
#include "support/file.h"

static const std::map<uint32_t, std::string_view> s_knownBioses = {
    {0x1002e6b5, "SCPH-1002 (EU)"},
    {0x1ac46cf1, "SCPH-5000 (JP)"},
    {0x24e21a0e, "SCPH-7003 (US)"},
    {0x38f5c1fe, "SCPH-1000 (JP)"},
    {0x42ea6879, "SCPH-1002 - DTLH-3002 (EU)"},
    {0x48ba1524, "????"},
    {0x4e501b56, "SCPH-5502 - SCPH-5552 (2) (EU)"},
    {0x560e2da1, "????"},
    {0x61e5b760, "SCPH-7001 (US)"},
    {0x649db764, "SCPH-7502 (EU)"},
    {0x68d2dd36, "????"},
    {0x68ee15cc, "SCPH-5502 - SCPH-5552 (EU)"},
    {0x7de956a4, "SCPH-101"},
    {0x80a156a8, "????"},
    {0x9e7d4faa, "SCPH-3000 (JP)"},
    {0x9eff111b, "SCPH-7000 (JP)"},
    {0xa6cf18fe, "SCPH-5500 (JP)"},
    {0xa8e56981, "SCPH-3500 (JP)"},
    {0xb6ef0d64, "????"},
    {0xd10b6509, "????"},
    {0xdaa2e0a6, "SCPH-1001 - DTLH-3000 (US)"},
    {0xe7ca4fad, "????"},
    {0xf380c9ff, "SCPH-5000"},
    {0xfb4afc11, "SCPH-5000 (2)"},
};

int PCSX::Memory::init() {
    m_readLUT = (uint8_t **)calloc(0x10000, sizeof(void *));
    m_writeLUT = (uint8_t **)calloc(0x10000, sizeof(void *));

    m_psxM = (uint8_t *)calloc(0x00800000, 1);
    m_psxP = (uint8_t *)calloc(0x00010000, 1);
    m_psxH = (uint8_t *)calloc(0x00010000, 1);
    m_psxR = (uint8_t *)calloc(0x00080000, 1);

    if (m_readLUT == NULL || m_writeLUT == NULL || m_psxM == NULL || m_psxP == NULL || m_psxH == NULL) {
        PCSX::g_system->message("%s", _("Error allocating memory!"));
        return -1;
    }

    // MemR
    for (int i = 0; i < 0x80; i++) m_readLUT[i + 0x0000] = (uint8_t *)&m_psxM[(i & 0x1f) << 16];

    memcpy(m_readLUT + 0x8000, m_readLUT, 0x80 * sizeof(void *));
    memcpy(m_readLUT + 0xa000, m_readLUT, 0x80 * sizeof(void *));

    m_readLUT[0x1f00] = (uint8_t *)m_psxP;

    for (int i = 0; i < 0x08; i++) m_readLUT[i + 0x1fc0] = (uint8_t *)&m_psxR[i << 16];

    memcpy(m_readLUT + 0x9fc0, m_readLUT + 0x1fc0, 0x08 * sizeof(void *));
    memcpy(m_readLUT + 0xbfc0, m_readLUT + 0x1fc0, 0x08 * sizeof(void *));

    // MemW
    for (int i = 0; i < 0x80; i++) m_writeLUT[i + 0x0000] = (uint8_t *)&m_psxM[(i & 0x1f) << 16];

    memcpy(m_writeLUT + 0x8000, m_writeLUT, 0x80 * sizeof(void *));
    memcpy(m_writeLUT + 0xa000, m_writeLUT, 0x80 * sizeof(void *));

    m_writeLUT[0x1f00] = (uint8_t *)m_psxP;

    return 0;
}

void PCSX::Memory::reset() {
    const uint32_t bios_size = 0x00080000;
    memset(m_psxM, 0, 0x00800000);
    memset(m_psxP, 0, 0x00010000);
    memset(m_psxR, 0, bios_size);
    static const uint32_t nobios[6] = {
        Mips::Encoder::lui(Mips::Encoder::Reg::V0, 0xbfc0),  // v0 = 0xbfc00000
        Mips::Encoder::lui(Mips::Encoder::Reg::V1, 0x1f80),  // v1 = 0x1f800000
        Mips::Encoder::addiu(Mips::Encoder::Reg::T0, Mips::Encoder::Reg::V0, sizeof(nobios)),
        Mips::Encoder::sw(Mips::Encoder::Reg::T0, 0x2084, Mips::Encoder::Reg::V1),  // display notification
        Mips::Encoder::j(0xbfc00000),
        Mips::Encoder::sb(Mips::Encoder::Reg::R0, 0x2081, Mips::Encoder::Reg::V1),  // pause
    };

    int index = 0;
    for (auto w : nobios) {
        m_psxR[index++] = w & 0xff;
        w >>= 8;
        m_psxR[index++] = w & 0xff;
        w >>= 8;
        m_psxR[index++] = w & 0xff;
        w >>= 8;
        m_psxR[index++] = w & 0xff;
        w >>= 8;
    }
    strcpy((char *)m_psxR + index, _(R"(
                   No BIOS loaded, emulation halted.

Set a BIOS file into the configuration, and do a hard reset of the emulator.
The distributed OpenBIOS.bin file can be an appropriate BIOS replacement.
)"));

    // Load BIOS
    auto &biosPath = g_emulator->settings.get<PCSX::Emulator::SettingBios>().value;
    IO<File> f(new PosixFile(biosPath.string()));
    if (f->failed()) {
        PCSX::g_system->printf(_("Could not open BIOS:\"%s\". Retrying with the OpenBIOS\n"), biosPath.string());

        g_system->findResource(
            [&f](const std::filesystem::path &filename) {
                f.setFile(new PosixFile(filename));
                return !f->failed();
            },
            "openbios.bin", "resources", std::filesystem::path("src") / "mips" / "openbios");
        if (f->failed()) {
            PCSX::g_system->printf(_(
                "Could not open OpenBIOS fallback. Things won't work properly.\nAdd a valid BIOS in the configuration "
                "and hard reset.\n"));
        } else {
            biosPath = f->filename();
        }
    }

    if (!f->failed()) {
        f->read(m_psxR, bios_size);
        f->close();
        PCSX::g_system->printf(_("Loaded BIOS: %s\n"), biosPath.string());
    }
    uint32_t adler = adler32(0L, Z_NULL, 0);
    m_biosAdler32 = adler = adler32(adler, m_psxR, bios_size);
    auto it = s_knownBioses.find(adler);
    if (it != s_knownBioses.end()) {
        g_system->printf(_("Known BIOS detected: %s (%08x)\n"), it->second, adler);
    } else if (strncmp((const char *)&m_psxR[0x78], "OpenBIOS", 8) == 0) {
        g_system->printf(_("OpenBIOS detected (%08x)\n"), adler);
    } else {
        g_system->printf(_("Unknown bios loaded (%08x)\n"), adler);
    }

    for (auto &overlay : g_emulator->settings.get<Emulator::SettingBiosOverlay>()) {
        if (!overlay.get<Emulator::OverlaySetting::Enabled>()) continue;
        const auto &filename = overlay.get<Emulator::OverlaySetting::Filename>().value;
        auto foffset = overlay.get<Emulator::OverlaySetting::FileOffset>();
        auto loffset = overlay.get<Emulator::OverlaySetting::LoadOffset>();
        auto lsize = overlay.get<Emulator::OverlaySetting::LoadSize>();
        bool failed = false;
        IO<File> f(new PosixFile(filename));

        if (f->failed()) {
            PCSX::g_system->message(_("Could not open BIOS Overlay:\"%s\"!\n"), filename.string());
            failed = true;
        }

        ssize_t fsize;
        if (!failed) {
            fsize = f->size();

            if (foffset < 0) {
                // negative offset means from end of file
                foffset = foffset + fsize;

                if (foffset < 0) {
                    // fail if the negative offset is more than the total file size
                    PCSX::g_system->message(_("Invalid file offset for BIOS Overlay:\"%s\"!\n"), filename.string());
                    failed = true;
                }
            } else if (foffset > fsize) {
                PCSX::g_system->message(_("Invalid file offset for BIOS Overlay:\"%s\"!\n"), filename.string());
                failed = true;
            }
        }
        if (!failed) {
            f->rSeek(foffset, SEEK_SET);

            fsize = fsize - foffset;

            if (lsize <= 0) {
                // lsize <= 0 means "from file size"

                lsize = fsize + lsize;

                if (lsize < 0) {
                    PCSX::g_system->message(_("Invalid load size specified BIOS Overlay:\"%s\"!\n"), filename.string());
                    failed = true;
                }
            }
        }
        if (!failed) {
            if (lsize > fsize) {
                PCSX::g_system->message(_("Invalid load size specified BIOS Overlay:\"%s\"!\n"), filename.string());
                failed = true;
            }
        }
        if (!failed) {
            if (loffset < 0) {
                // negative offset means from end of device memory region

                loffset = loffset + bios_size;

                if (loffset < 0) {
                    // fail if the negative offset is more than the BIOS size
                    PCSX::g_system->message(_("Invalid load offset for BIOS Overlay:\"%s\"!\n"), filename.string());
                    failed = true;
                }
            } else if (loffset > bios_size) {
                PCSX::g_system->message(_("Invalid load offset for BIOS Overlay:\"%s\"!\n"), filename.string());
                failed = true;
            }
        }
        if (!failed) {
            f->read(m_psxR + loffset, lsize);
            PCSX::g_system->printf(_("Loaded BIOS overlay: %s\n"), filename.string());
        }

        f->close();
    }
}

void PCSX::Memory::shutdown() {
    free(m_psxM);
    free(m_psxP);
    free(m_psxH);
    free(m_psxR);

    free(m_readLUT);
    free(m_writeLUT);
}

uint8_t PCSX::Memory::read8(uint32_t address) {
    PCSX::g_emulator->m_cpu->m_regs.cycle += 1;
    const uint32_t page = address >> 16;
    const auto pointer = (uint8_t *)m_readLUT[page];

    if (pointer != nullptr) {
        const uint32_t offset = address & 0xffff;
        return *(pointer + offset);
    } else {
        if (page == 0x1f80 || page == 0x9f80 || page == 0xbf80) {
            if ((address & 0xffff) < 0x400)
                return psxHu8(address);
            else
                return PCSX::g_emulator->m_hw->read8(address);
        } else {
            PSXMEM_LOG("8-bit read from unknown address: %8.8lx\n", address);
            return 0xff;
        }
    }
}

uint16_t PCSX::Memory::read16(uint32_t address) {
    PCSX::g_emulator->m_cpu->m_regs.cycle += 1;
    const uint32_t page = address >> 16;
    const auto pointer = (uint8_t *)m_readLUT[page];

    if (pointer != nullptr) {
        const uint32_t offset = address & 0xffff;
        return SWAP_LEu16(*(uint16_t *)(pointer + offset));
    } else {
        if (page == 0x1f80 || page == 0x9f80 || page == 0xbf80) {
            if ((address & 0xffff) < 0x400)
                return psxHu16(address);
            else
                return PCSX::g_emulator->m_hw->read16(address);
        } else {
            PSXMEM_LOG("16-bit read from unknown address: %8.8lx\n", address);
            return 0xffff;
        }
    }
}

uint32_t PCSX::Memory::read32(uint32_t address) {
    PCSX::g_emulator->m_cpu->m_regs.cycle += 1;
    const uint32_t page = address >> 16;
    const auto pointer = (uint8_t *)m_readLUT[page];

    if (pointer != nullptr) {
        const uint32_t offset = address & 0xffff;
        return SWAP_LEu32(*(uint32_t *)(pointer + offset));
    } else {
        if (page == 0x1f80 || page == 0x9f80 || page == 0xbf80) {
            if ((address & 0xffff) < 0x400)
                return psxHu32(address);
            else
                return PCSX::g_emulator->m_hw->read32(address);
        } else {
            if (m_writeok) {
                PSXMEM_LOG("32-bit read from unknown address: %8.8lx\n", address);
            }
            return 0xffffffff;
        }
    }
}

void PCSX::Memory::write8(uint32_t address, uint32_t value) {
    PCSX::g_emulator->m_cpu->m_regs.cycle += 1;
    const uint32_t page = address >> 16;
    const auto pointer = (uint8_t *)m_writeLUT[page];

    if (pointer != nullptr) {
        const uint32_t offset = address & 0xffff;
        *(pointer + offset) = static_cast<uint8_t>(value);
        PCSX::g_emulator->m_cpu->Clear((address & (~3)), 1);
    } else {
        if (page == 0x1f80 || page == 0x9f80 || page == 0xbf80) {
            if ((address & 0xffff) < 0x400)
                psxHu8(address) = value;
            else
                PCSX::g_emulator->m_hw->write8(address, value);
        } else {
            PSXMEM_LOG("8-bit write to unknown address: %8.8lx\n", address);
        }
    }
}

void PCSX::Memory::write16(uint32_t address, uint32_t value) {
    PCSX::g_emulator->m_cpu->m_regs.cycle += 1;
    const uint32_t page = address >> 16;
    const auto pointer = (uint8_t *)m_writeLUT[page];

    if (pointer != nullptr) {
        const uint32_t offset = address & 0xffff;
        *(uint16_t *)(pointer + offset) = SWAP_LEu16(static_cast<uint16_t>(value));
        PCSX::g_emulator->m_cpu->Clear((address & (~3)), 1);
    } else {
        if (page == 0x1f80 || page == 0x9f80 || page == 0xbf80) {
            if ((address & 0xffff) < 0x400)
                psxHu16ref(address) = SWAP_LEu16(value);
            else
                PCSX::g_emulator->m_hw->write16(address, value);
        } else {
            PSXMEM_LOG("16-bit write to unknown address: %8.8lx\n", address);
        }
    }
}

void PCSX::Memory::write32(uint32_t address, uint32_t value) {
    PCSX::g_emulator->m_cpu->m_regs.cycle += 1;
    const uint32_t page = address >> 16;
    const auto pointer = (uint8_t *)m_writeLUT[page];

    if (pointer != nullptr) {
        const uint32_t offset = address & 0xffff;
        *(uint32_t *)(pointer + offset) = SWAP_LEu32(value);
        PCSX::g_emulator->m_cpu->Clear((address & (~3)), 1);
    } else {
        if (page == 0x1f80 || page == 0x9f80 || page == 0xbf80) {
            if ((address & 0xffff) < 0x400)
                psxHu32ref(address) = SWAP_LEu32(value);
            else
                PCSX::g_emulator->m_hw->write32(address, value);
        } else if (address != 0xfffe0130) {
            if (!m_writeok) PCSX::g_emulator->m_cpu->Clear(address, 1);

            if (m_writeok) {
                PSXMEM_LOG("32-bit write to unknown address: %8.8lx\n", address);
            }
        } else {
            // a0-44: used for cache flushing
            switch (value) {
                case 0x800:
                case 0x804:
                    if (m_writeok == 0) break;
                    m_writeok = 0;
                    setLuts();

                    PCSX::g_emulator->m_cpu->invalidateCache();
                    break;
                case 0x00:
                case 0x1e988:
                    if (m_writeok == 1) break;
                    m_writeok = 1;
                    setLuts();
                    break;
                default:
                    PSXMEM_LOG("unk %8.8lx = %x\n", address, value);
                    break;
            }
        }
    }
}

const void *PCSX::Memory::pointerRead(uint32_t address) {
    const auto page = address >> 16;

    if (page == 0x1f80 || page == 0x9f80 || page == 0xbf80) {
        if ((address & 0xffff) < 0x400)
            return &m_psxH[address & 0x3FF];
        else {
            switch (address) {  // IO regs that are safe to read from directly
                case 0x1f801080:
                case 0x1f801084:
                case 0x1f801088:
                case 0x1f801090:
                case 0x1f801094:
                case 0x1f801098:
                case 0x1f8010a0:
                case 0x1f8010a4:
                case 0x1f8010a8:
                case 0x1f8010b0:
                case 0x1f8010b4:
                case 0x1f8010b8:
                case 0x1f8010c0:
                case 0x1f8010c4:
                case 0x1f8010c8:
                case 0x1f8010d0:
                case 0x1f8010d4:
                case 0x1f8010d8:
                case 0x1f8010e0:
                case 0x1f8010e4:
                case 0x1f8010e8:
                case 0x1f801070:
                case 0x1f801074:
                case 0x1f8010f0:
                case 0x1f8010f4:
                    return &m_psxH[address & 0xffff];

                default:
                    return nullptr;
            }
        }
    } else {
        const auto pointer = (char *)(m_readLUT[page]);
        if (pointer != nullptr) {
            return (void *)(pointer + (address & 0xffff));
        }
        return nullptr;
    }
}

const void *PCSX::Memory::pointerWrite(uint32_t address, int size) {
    const auto page = address >> 16;

    if (page == 0x1f80 || page == 0x9f80 || page == 0xbf80) {
        if ((address & 0xffff) < 0x400)
            return &m_psxH[address & 0x3FF];
        else {
            switch (address) {
                // IO regs that are safe to write to directly. For some of these,
                // Writing a 8-bit/16-bit value actually writes the entire 32-bit reg, so they're not safe to write
                // directly
                case 0x1f801080:
                case 0x1f801084:
                case 0x1f801090:
                case 0x1f801094:
                case 0x1f8010a0:
                case 0x1f8010a4:
                case 0x1f8010b0:
                case 0x1f8010b4:
                case 0x1f8010c0:
                case 0x1f8010c4:
                case 0x1f8010d0:
                case 0x1f8010d4:
                case 0x1f8010e0:
                case 0x1f8010e4:
                case 0x1f801074:
                case 0x1f8010f0:
                    return size == 32 ? &m_psxH[address & 0xffff] : nullptr;

                default:
                    return nullptr;
            }
        }
    } else {
        const auto pointer = (char *)(m_writeLUT[page]);
        if (pointer != nullptr) {
            return (void *)(pointer + (address & 0xffff));
        }
        return nullptr;
    }
}

void PCSX::Memory::setLuts() {
    if (m_writeok) {
        int max = (m_psxH[0x1061] & 0x1) ? 0x80 : 0x20;
        if (!g_emulator->settings.get<Emulator::Setting8MB>()) max = 0x20;
        for (int i = 0; i < 0x80; i++) m_writeLUT[i + 0x0000] = (uint8_t *)&m_psxM[(i & (max - 1)) << 16];
        memcpy(m_writeLUT + 0x8000, m_writeLUT, 0x80 * sizeof(void *));
        memcpy(m_writeLUT + 0xa000, m_writeLUT, 0x80 * sizeof(void *));
    } else {
        memset(m_writeLUT + 0x0000, 0, 0x80 * sizeof(void *));
        memset(m_writeLUT + 0x8000, 0, 0x80 * sizeof(void *));
        memset(m_writeLUT + 0xa000, 0, 0x80 * sizeof(void *));
    }
}

std::string_view PCSX::Memory::getBiosVersionString() {
    auto it = s_knownBioses.find(m_biosAdler32);
    if (it == s_knownBioses.end()) return "Unknown";
    return it->second;
}
