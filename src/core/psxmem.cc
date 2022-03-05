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

int PCSX::Memory::psxMemInit() {
    g_psxMemRLUT = (uint8_t **)calloc(0x10000, sizeof(void *));
    g_psxMemWLUT = (uint8_t **)calloc(0x10000, sizeof(void *));

    g_psxM = (uint8_t *)calloc(0x00800000, 1);
    g_psxP = (uint8_t *)calloc(0x00010000, 1);
    g_psxH = (uint8_t *)calloc(0x00010000, 1);
    g_psxR = (uint8_t *)calloc(0x00080000, 1);

    if (g_psxMemRLUT == NULL || g_psxMemWLUT == NULL || g_psxM == NULL || g_psxP == NULL || g_psxH == NULL) {
        PCSX::g_system->message("%s", _("Error allocating memory!"));
        return -1;
    }

    // MemR
    for (int i = 0; i < 0x80; i++) g_psxMemRLUT[i + 0x0000] = (uint8_t *)&g_psxM[(i & 0x1f) << 16];

    memcpy(g_psxMemRLUT + 0x8000, g_psxMemRLUT, 0x80 * sizeof(void *));
    memcpy(g_psxMemRLUT + 0xa000, g_psxMemRLUT, 0x80 * sizeof(void *));

    g_psxMemRLUT[0x1f00] = (uint8_t *)g_psxP;
    g_psxMemRLUT[0x1f80] = (uint8_t *)g_psxH;

    for (int i = 0; i < 0x08; i++) g_psxMemRLUT[i + 0x1fc0] = (uint8_t *)&g_psxR[i << 16];

    memcpy(g_psxMemRLUT + 0x9fc0, g_psxMemRLUT + 0x1fc0, 0x08 * sizeof(void *));
    memcpy(g_psxMemRLUT + 0xbfc0, g_psxMemRLUT + 0x1fc0, 0x08 * sizeof(void *));

    // MemW
    for (int i = 0; i < 0x80; i++) g_psxMemWLUT[i + 0x0000] = (uint8_t *)&g_psxM[(i & 0x1f) << 16];

    memcpy(g_psxMemWLUT + 0x8000, g_psxMemWLUT, 0x80 * sizeof(void *));
    memcpy(g_psxMemWLUT + 0xa000, g_psxMemWLUT, 0x80 * sizeof(void *));

    g_psxMemWLUT[0x1f00] = (uint8_t *)g_psxP;
    g_psxMemWLUT[0x1f80] = (uint8_t *)g_psxH;

    return 0;
}

void PCSX::Memory::psxMemReset() {
    const uint32_t bios_size = 0x00080000;
    memset(g_psxM, 0, 0x00800000);
    memset(g_psxP, 0, 0x00010000);
    memset(g_psxR, 0, bios_size);
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
        g_psxR[index++] = w & 0xff;
        w >>= 8;
        g_psxR[index++] = w & 0xff;
        w >>= 8;
        g_psxR[index++] = w & 0xff;
        w >>= 8;
        g_psxR[index++] = w & 0xff;
        w >>= 8;
    }
    strcpy((char *)g_psxR + index, _(R"(
                   No BIOS loaded, emulation halted.

Set a BIOS file into the configuration, and do a hard reset of the emulator.
The distributed OpenBIOS.bin file can be an appropriate BIOS replacement.
)"));

    // Load BIOS
    auto &biosPath = g_emulator->settings.get<PCSX::Emulator::SettingBios>().value;
    std::unique_ptr<File> f(new File(biosPath.string()));
    if (f->failed()) {
        PCSX::g_system->printf(_("Could not open BIOS:\"%s\". Retrying with the OpenBIOS\n"), biosPath.string());

        g_system->findResource(
            [&f](const std::filesystem::path &filename) {
                std::unique_ptr<File> newFile(new File(filename));
                f.swap(newFile);
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
        f->read(g_psxR, bios_size);
        f->close();
        if ((g_psxR[0] == 0x7f) && (g_psxR[1] == 'E') && (g_psxR[2] == 'L') && (g_psxR[3] == 'F')) {
            Elf e;
            if (e.load(biosPath.string())) m_elfs.push_back(std::move(e));
            auto [entry, stack] = (--m_elfs.end())->findByAddress(0xbfc00000);
            if (entry.valid()) PCSX::g_system->printf(_("BIOS entry point: %s\n"), entry.get_description());
        }
        PCSX::g_system->printf(_("Loaded BIOS: %s\n"), biosPath.string());
    }
    uint32_t adler = adler32(0L, Z_NULL, 0);
    m_biosAdler32 = adler = adler32(adler, g_psxR, bios_size);
    auto it = s_knownBioses.find(adler);
    if (it != s_knownBioses.end()) {
        g_system->printf(_("Known BIOS detected: %s (%08x)\n"), it->second, adler);
    } else if (strncmp((const char *)&g_psxR[0x78], "OpenBIOS", 8) == 0) {
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
        std::unique_ptr<File> f(new File(filename));

        if (f->failed()) {
            PCSX::g_system->message(_("Could not open BIOS Overlay:\"%s\"!\n"), filename.string());
            failed = true;
        }

        ssize_t fsize;
        if (!failed) {
            f->seek(0, SEEK_END);
            fsize = f->tell();

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
            f->seek(foffset, SEEK_SET);

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
            f->read(g_psxR + loffset, lsize);
            PCSX::g_system->printf(_("Loaded BIOS overlay: %s\n"), filename.string());
        }

        f->close();
    }
}

void PCSX::Memory::psxMemShutdown() {
    free(g_psxM);
    free(g_psxP);
    free(g_psxH);
    free(g_psxR);

    free(g_psxMemRLUT);
    free(g_psxMemWLUT);
}

uint8_t PCSX::Memory::psxMemRead8(uint32_t mem) {
    char *p;
    uint32_t t;

    if (!PCSX::g_emulator->config().MemHack) {
        PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle += 1;
    }

    t = mem >> 16;
    if (t == 0x1f80 || t == 0x9f80 || t == 0xbf80) {
        if ((mem & 0xffff) < 0x400)
            return psxHu8(mem);
        else
            return PCSX::g_emulator->m_hw->psxHwRead8(mem);
    } else {
        p = (char *)(g_psxMemRLUT[t]);
        if (p != NULL) {
            return *(uint8_t *)(p + (mem & 0xffff));
        } else {
            PSXMEM_LOG("err lb %8.8lx\n", mem);
            return 0xff;
        }
    }
}

uint16_t PCSX::Memory::psxMemRead16(uint32_t mem) {
    char *p;
    uint32_t t;

    if (!PCSX::g_emulator->config().MemHack) {
        PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle += 1;
    }

    t = mem >> 16;
    if (t == 0x1f80 || t == 0x9f80 || t == 0xbf80) {
        if ((mem & 0xffff) < 0x400)
            return psxHu16(mem);
        else
            return PCSX::g_emulator->m_hw->psxHwRead16(mem);
    } else {
        p = (char *)(g_psxMemRLUT[t]);
        if (p != NULL) {
            return SWAP_LEu16(*(uint16_t *)(p + (mem & 0xffff)));
        } else {
            PSXMEM_LOG("err lh %8.8lx\n", mem);
            return 0xffff;
        }
    }
}

uint32_t PCSX::Memory::psxMemRead32(uint32_t mem) {
    char *p;
    uint32_t t;

    if (!PCSX::g_emulator->config().MemHack) {
        PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle += 1;
    }

    t = mem >> 16;
    if (t == 0x1f80 || t == 0x9f80 || t == 0xbf80) {
        if ((mem & 0xffff) < 0x400)
            return psxHu32(mem);
        else
            return PCSX::g_emulator->m_hw->psxHwRead32(mem);
    } else {
        p = (char *)(g_psxMemRLUT[t]);
        if (p != NULL) {
            return SWAP_LEu32(*(uint32_t *)(p + (mem & 0xffff)));
        } else {
            if (m_writeok) {
                PSXMEM_LOG("err lw %8.8lx\n", mem);
            }
            return 0xffffffff;
        }
    }
}

void PCSX::Memory::psxMemWrite8(uint32_t mem, uint32_t value) {
    char *p;
    uint32_t t;

    if (!PCSX::g_emulator->config().MemHack) {
        PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle += 1;
    }

    t = mem >> 16;
    if (t == 0x1f80 || t == 0x9f80 || t == 0xbf80) {
        if ((mem & 0xffff) < 0x400)
            psxHu8(mem) = value;
        else
            PCSX::g_emulator->m_hw->psxHwWrite8(mem, value);
    } else {
        p = (char *)(g_psxMemWLUT[t]);
        if (p != NULL) {
            *(uint8_t *)(p + (mem & 0xffff)) = value;
            PCSX::g_emulator->m_psxCpu->Clear((mem & (~3)), 1);
        } else {
            PSXMEM_LOG("err sb %8.8lx\n", mem);
        }
    }
}

void PCSX::Memory::psxMemWrite16(uint32_t mem, uint32_t value) {
    char *p;
    uint32_t t;

    if (!PCSX::g_emulator->config().MemHack) {
        PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle += 1;
    }

    t = mem >> 16;
    if (t == 0x1f80 || t == 0x9f80 || t == 0xbf80) {
        if ((mem & 0xffff) < 0x400)
            psxHu16ref(mem) = SWAP_LEu16(value);
        else
            PCSX::g_emulator->m_hw->psxHwWrite16(mem, value);
    } else {
        p = (char *)(g_psxMemWLUT[t]);
        if (p != NULL) {
            *(uint16_t *)(p + (mem & 0xffff)) = SWAP_LEu16(value);
            PCSX::g_emulator->m_psxCpu->Clear((mem & (~3)), 1);
        } else {
            PSXMEM_LOG("err sh %8.8lx\n", mem);
        }
    }
}

void PCSX::Memory::psxMemWrite32(uint32_t mem, uint32_t value) {
    char *p;
    uint32_t t;

    if (!PCSX::g_emulator->config().MemHack) {
        PCSX::g_emulator->m_psxCpu->m_psxRegs.cycle += 1;
    }

    //  if ((mem&0x1fffff) == 0x71E18 || value == 0x48088800) PCSX::g_system->printf("t2fix!!\n");
    t = mem >> 16;
    if (t == 0x1f80 || t == 0x9f80 || t == 0xbf80) {
        if ((mem & 0xffff) < 0x400)
            psxHu32ref(mem) = SWAP_LEu32(value);
        else
            PCSX::g_emulator->m_hw->psxHwWrite32(mem, value);
    } else {
        p = (char *)(g_psxMemWLUT[t]);
        if (p != NULL) {
            *(uint32_t *)(p + (mem & 0xffff)) = SWAP_LEu32(value);
            PCSX::g_emulator->m_psxCpu->Clear(mem, 1);
        } else {
            if (mem != 0xfffe0130) {
                if (!m_writeok) PCSX::g_emulator->m_psxCpu->Clear(mem, 1);

                if (m_writeok) {
                    PSXMEM_LOG("err sw %8.8lx\n", mem);
                }
            } else {
                int i;

                // a0-44: used for cache flushing
                switch (value) {
                    case 0x800:
                    case 0x804:
                        if (m_writeok == 0) break;
                        m_writeok = 0;
                        setLuts();

                        PCSX::g_emulator->m_psxCpu->invalidateCache();
                        break;
                    case 0x00:
                    case 0x1e988:
                        if (m_writeok == 1) break;
                        m_writeok = 1;
                        setLuts();
                        break;
                    default:
                        PSXMEM_LOG("unk %8.8lx = %x\n", mem, value);
                        break;
                }
            }
        }
    }
}

const void *PCSX::Memory::psxMemPointerRead(uint32_t address) {
    const auto page = address >> 16;

    if (page == 0x1f80 || page == 0x9f80 || page == 0xbf80) {
        if ((address & 0xffff) < 0x400)
            return &g_psxH[address & 0x3FF];
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
                    return &g_psxH[address & 0xffff];

                default:
                    return nullptr;
            }
        }
    } else {
        const auto pointer = (char *)(g_psxMemRLUT[page]);
        if (pointer != nullptr) {
            return (void *)(pointer + (address & 0xffff));
        }
        return nullptr;
    }
}

const void *PCSX::Memory::psxMemPointerWrite(uint32_t address, int size) {
    const auto page = address >> 16;

    if (page == 0x1f80 || page == 0x9f80 || page == 0xbf80) {
        if ((address & 0xffff) < 0x400)
            return &g_psxH[address & 0x3FF];
        else {
            switch (address) {
                // IO regs that are safe to write to directly. For some of these,
                // Writing a 8-bit/16-bit value actually writes the entire 32-bit reg, so they're not safe to write directly
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
                    return size == 32 ? &g_psxH[address & 0xffff] : nullptr;

                default:
                    return nullptr;
            }
        }
    } else {
        const auto pointer = (char *)(g_psxMemWLUT[page]);
        if (pointer != nullptr) {
            return (void *)(pointer + (address & 0xffff));
        }
        return nullptr;
    }
}

void PCSX::Memory::setLuts() {
    if (m_writeok) {
        int max = (g_psxH[0x1061] & 0x1) ? 0x80 : 0x20;
        if (!g_emulator->settings.get<Emulator::Setting8MB>()) max = 0x20;
        for (int i = 0; i < 0x80; i++) g_psxMemWLUT[i + 0x0000] = (uint8_t *)&g_psxM[(i & (max - 1)) << 16];
        memcpy(g_psxMemWLUT + 0x8000, g_psxMemWLUT, 0x80 * sizeof(void *));
        memcpy(g_psxMemWLUT + 0xa000, g_psxMemWLUT, 0x80 * sizeof(void *));
    } else {
        memset(g_psxMemWLUT + 0x0000, 0, 0x80 * sizeof(void *));
        memset(g_psxMemWLUT + 0x8000, 0, 0x80 * sizeof(void *));
        memset(g_psxMemWLUT + 0xa000, 0, 0x80 * sizeof(void *));
    }
}

std::string_view PCSX::Memory::getBiosVersionString() {
    auto it = s_knownBioses.find(m_biosAdler32);
    if (it == s_knownBioses.end()) return "Unknown";
    return it->second;
}
