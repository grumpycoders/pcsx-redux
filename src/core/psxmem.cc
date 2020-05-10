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

#include "core/debug.h"
#include "core/psxhw.h"
#include "core/r3000a.h"
#include "support/file.h"

int PCSX::Memory::psxMemInit() {
    int i;

    g_psxMemRLUT = (uint8_t **)calloc(0x10000, sizeof(void *));
    g_psxMemWLUT = (uint8_t **)calloc(0x10000, sizeof(void *));

    g_psxM = (uint8_t *)calloc(0x00200000, 1);
    g_psxP = (uint8_t *)calloc(0x00010000, 1);
    g_psxH = (uint8_t *)calloc(0x00010000, 1);
    g_psxR = (uint8_t *)calloc(0x00080000, 1);

    if (g_psxMemRLUT == NULL || g_psxMemWLUT == NULL || g_psxM == NULL || g_psxP == NULL || g_psxH == NULL) {
        PCSX::g_system->message("%s", _("Error allocating memory!"));
        return -1;
    }

    // MemR
    for (i = 0; i < 0x80; i++) g_psxMemRLUT[i + 0x0000] = (uint8_t *)&g_psxM[(i & 0x1f) << 16];

    memcpy(g_psxMemRLUT + 0x8000, g_psxMemRLUT, 0x80 * sizeof(void *));
    memcpy(g_psxMemRLUT + 0xa000, g_psxMemRLUT, 0x80 * sizeof(void *));

    g_psxMemRLUT[0x1f00] = (uint8_t *)g_psxP;
    g_psxMemRLUT[0x1f80] = (uint8_t *)g_psxH;

    for (i = 0; i < 0x08; i++) g_psxMemRLUT[i + 0x1fc0] = (uint8_t *)&g_psxR[i << 16];

    memcpy(g_psxMemRLUT + 0x9fc0, g_psxMemRLUT + 0x1fc0, 0x08 * sizeof(void *));
    memcpy(g_psxMemRLUT + 0xbfc0, g_psxMemRLUT + 0x1fc0, 0x08 * sizeof(void *));

    // MemW
    for (i = 0; i < 0x80; i++) g_psxMemWLUT[i + 0x0000] = (uint8_t *)&g_psxM[(i & 0x1f) << 16];

    memcpy(g_psxMemWLUT + 0x8000, g_psxMemWLUT, 0x80 * sizeof(void *));
    memcpy(g_psxMemWLUT + 0xa000, g_psxMemWLUT, 0x80 * sizeof(void *));

    g_psxMemWLUT[0x1f00] = (uint8_t *)g_psxP;
    g_psxMemWLUT[0x1f80] = (uint8_t *)g_psxH;

    return 0;
}

void PCSX::Memory::psxMemReset() {
    const uint32_t bios_size = 0x00080000;
    memset(g_psxM, 0, 0x00200000);
    memset(g_psxP, 0, 0x00010000);
    memset(g_psxR, 0, bios_size);

    // Load BIOS
    PCSX::u8string biosPath = PCSX::g_emulator.settings.get<PCSX::Emulator::SettingBios>().string();
    File *f = new File(biosPath);
    if (f->failed()) {
        PCSX::g_system->message(_("Could not open BIOS:\"%s\". Retrying with the OpenBIOS\n"), biosPath.c_str());
        delete f;
        f = new File("openbios.bin");
        if (f->failed()) {
            PCSX::g_system->message(_("Could not open OpenBIOS fallback. Things won't work properly\n"));
        } else {
            g_emulator.settings.get<Emulator::SettingBios>() = "openbios.bin";
        }
    } else {
        f->read(g_psxR, bios_size);
        f->close();
        if ((g_psxR[0] == 0x7f) && (g_psxR[1] == 'E') && (g_psxR[2] == 'L') && (g_psxR[3] == 'F')) {
            Elf e;
            if (e.load(biosPath)) m_elfs.push_back(std::move(e));
            auto [entry, stack] = (--m_elfs.end())->findByAddress(0xbfc00000);
            if (entry.valid()) PCSX::g_system->printf(_("BIOS entry point: %s\n"), entry.get_description().c_str());
        }
        PCSX::g_system->printf(_("Loaded BIOS: %s\n"), biosPath.c_str());
    }
    delete f;

    for (auto &overlay : g_emulator.settings.get<Emulator::SettingBiosOverlay>()) {
        if (!overlay.get<Emulator::OverlaySetting::Enabled>()) continue;
        const auto &filename = overlay.get<Emulator::OverlaySetting::Filename>();
        auto foffset = overlay.get<Emulator::OverlaySetting::FileOffset>();
        auto loffset = overlay.get<Emulator::OverlaySetting::LoadOffset>();
        auto lsize = overlay.get<Emulator::OverlaySetting::LoadSize>();
        bool failed = false;
        File *f = new File(filename);

        if (f->failed()) {
            PCSX::g_system->message(_("Could not open BIOS Overlay:\"%s\"!\n"), filename.string().c_str());
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
                    PCSX::g_system->message(_("Invalid file offset for BIOS Overlay:\"%s\"!\n"),
                                            filename.string().c_str());
                    failed = true;
                }
            } else if (foffset > fsize) {
                PCSX::g_system->message(_("Invalid file offset for BIOS Overlay:\"%s\"!\n"), filename.string().c_str());
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
                    PCSX::g_system->message(_("Invalid load size specified BIOS Overlay:\"%s\"!\n"),
                                            filename.string().c_str());
                    failed = true;
                }
            }
        }
        if (!failed) {
            if (lsize > fsize) {
                PCSX::g_system->message(_("Invalid load size specified BIOS Overlay:\"%s\"!\n"),
                                        filename.string().c_str());
                failed = true;
            }
        }
        if (!failed) {
            if (loffset < 0) {
                // negative offset means from end of device memory region

                loffset = loffset + bios_size;

                if (loffset < 0) {
                    // fail if the negative offset is more than the BIOS size
                    PCSX::g_system->message(_("Invalid load offset for BIOS Overlay:\"%s\"!\n"),
                                            filename.string().c_str());
                    failed = true;
                }
            } else if (loffset > bios_size) {
                PCSX::g_system->message(_("Invalid load offset for BIOS Overlay:\"%s\"!\n"), filename.string().c_str());
                failed = true;
            }
        }
        if (!failed) {
            f->read(g_psxR + loffset, lsize);
            PCSX::g_system->printf(_("Loaded BIOS overlay: %s\n"), filename.string().c_str());
        }

        f->close();
        delete f;
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

static int m_writeok = 1;

uint8_t PCSX::Memory::psxMemRead8(uint32_t mem) {
    char *p;
    uint32_t t;

    if (!PCSX::g_emulator.config().MemHack) {
        PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle += 1;
    }

    t = mem >> 16;
    if (t == 0x1f80 || t == 0x9f80 || t == 0xbf80) {
        if ((mem & 0xffff) < 0x400)
            return psxHu8(mem);
        else
            return PCSX::g_emulator.m_hw->psxHwRead8(mem);
    } else {
        p = (char *)(g_psxMemRLUT[t]);
        if (p != NULL) {
            if (PCSX::g_emulator.settings.get<PCSX::Emulator::SettingDebug>()) {
                PCSX::g_emulator.m_debug->checkBP(mem, PCSX::Debug::BR1);
            }
            return *(uint8_t *)(p + (mem & 0xffff));
        } else {
            PSXMEM_LOG("err lb %8.8lx\n", mem);
            return 0;
        }
    }
}

uint16_t PCSX::Memory::psxMemRead16(uint32_t mem) {
    char *p;
    uint32_t t;

    if (!PCSX::g_emulator.config().MemHack) {
        PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle += 1;
    }

    t = mem >> 16;
    if (t == 0x1f80 || t == 0x9f80 || t == 0xbf80) {
        if ((mem & 0xffff) < 0x400)
            return psxHu16(mem);
        else
            return PCSX::g_emulator.m_hw->psxHwRead16(mem);
    } else {
        p = (char *)(g_psxMemRLUT[t]);
        if (p != NULL) {
            if (PCSX::g_emulator.settings.get<PCSX::Emulator::SettingDebug>()) {
                PCSX::g_emulator.m_debug->checkBP(mem, PCSX::Debug::BR2);
            }
            return SWAP_LEu16(*(uint16_t *)(p + (mem & 0xffff)));
        } else {
            PSXMEM_LOG("err lh %8.8lx\n", mem);
            return 0;
        }
    }
}

uint32_t PCSX::Memory::psxMemRead32(uint32_t mem) {
    char *p;
    uint32_t t;

    if (!PCSX::g_emulator.config().MemHack) {
        PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle += 1;
    }

    t = mem >> 16;
    if (t == 0x1f80 || t == 0x9f80 || t == 0xbf80) {
        if ((mem & 0xffff) < 0x400)
            return psxHu32(mem);
        else
            return PCSX::g_emulator.m_hw->psxHwRead32(mem);
    } else {
        p = (char *)(g_psxMemRLUT[t]);
        if (p != NULL) {
            if (PCSX::g_emulator.settings.get<PCSX::Emulator::SettingDebug>()) {
                PCSX::g_emulator.m_debug->checkBP(mem, PCSX::Debug::BR4);
            }
            return SWAP_LEu32(*(uint32_t *)(p + (mem & 0xffff)));
        } else {
            if (m_writeok) {
                PSXMEM_LOG("err lw %8.8lx\n", mem);
            }
            return 0;
        }
    }
}

void PCSX::Memory::psxMemWrite8(uint32_t mem, uint8_t value) {
    char *p;
    uint32_t t;

    if (!PCSX::g_emulator.config().MemHack) {
        PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle += 1;
    }

    t = mem >> 16;
    if (t == 0x1f80 || t == 0x9f80 || t == 0xbf80) {
        if ((mem & 0xffff) < 0x400)
            psxHu8(mem) = value;
        else
            PCSX::g_emulator.m_hw->psxHwWrite8(mem, value);
    } else {
        p = (char *)(g_psxMemWLUT[t]);
        if (p != NULL) {
            if (PCSX::g_emulator.settings.get<PCSX::Emulator::SettingDebug>()) {
                PCSX::g_emulator.m_debug->checkBP(mem, PCSX::Debug::BW1);
            }
            *(uint8_t *)(p + (mem & 0xffff)) = value;
            PCSX::g_emulator.m_psxCpu->Clear((mem & (~3)), 1);
        } else {
            PSXMEM_LOG("err sb %8.8lx\n", mem);
        }
    }
}

void PCSX::Memory::psxMemWrite16(uint32_t mem, uint16_t value) {
    char *p;
    uint32_t t;

    if (!PCSX::g_emulator.config().MemHack) {
        PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle += 1;
    }

    t = mem >> 16;
    if (t == 0x1f80 || t == 0x9f80 || t == 0xbf80) {
        if ((mem & 0xffff) < 0x400)
            psxHu16ref(mem) = SWAP_LEu16(value);
        else
            PCSX::g_emulator.m_hw->psxHwWrite16(mem, value);
    } else {
        p = (char *)(g_psxMemWLUT[t]);
        if (p != NULL) {
            if (PCSX::g_emulator.settings.get<PCSX::Emulator::SettingDebug>()) {
                PCSX::g_emulator.m_debug->checkBP(mem, PCSX::Debug::BW2);
            }
            *(uint16_t *)(p + (mem & 0xffff)) = SWAP_LEu16(value);
            PCSX::g_emulator.m_psxCpu->Clear((mem & (~3)), 1);
        } else {
            PSXMEM_LOG("err sh %8.8lx\n", mem);
        }
    }
}

void PCSX::Memory::psxMemWrite32(uint32_t mem, uint32_t value) {
    char *p;
    uint32_t t;

    if (!PCSX::g_emulator.config().MemHack) {
        PCSX::g_emulator.m_psxCpu->m_psxRegs.cycle += 1;
    }

    //  if ((mem&0x1fffff) == 0x71E18 || value == 0x48088800) PCSX::g_system->printf("t2fix!!\n");
    t = mem >> 16;
    if (t == 0x1f80 || t == 0x9f80 || t == 0xbf80) {
        if ((mem & 0xffff) < 0x400)
            psxHu32ref(mem) = SWAP_LEu32(value);
        else
            PCSX::g_emulator.m_hw->psxHwWrite32(mem, value);
    } else {
        p = (char *)(g_psxMemWLUT[t]);
        if (p != NULL) {
            if (PCSX::g_emulator.settings.get<PCSX::Emulator::SettingDebug>()) {
                PCSX::g_emulator.m_debug->checkBP(mem, PCSX::Debug::BW4);
            }
            *(uint32_t *)(p + (mem & 0xffff)) = SWAP_LEu32(value);
            PCSX::g_emulator.m_psxCpu->Clear(mem, 1);
        } else {
            if (mem != 0xfffe0130) {
                if (!m_writeok) PCSX::g_emulator.m_psxCpu->Clear(mem, 1);

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
                        memset(g_psxMemWLUT + 0x0000, 0, 0x80 * sizeof(void *));
                        memset(g_psxMemWLUT + 0x8000, 0, 0x80 * sizeof(void *));
                        memset(g_psxMemWLUT + 0xa000, 0, 0x80 * sizeof(void *));

                        PCSX::g_emulator.m_psxCpu->m_psxRegs.ICache_valid = false;
                        break;
                    case 0x00:
                    case 0x1e988:
                        if (m_writeok == 1) break;
                        m_writeok = 1;
                        for (i = 0; i < 0x80; i++) g_psxMemWLUT[i + 0x0000] = (uint8_t *)&g_psxM[(i & 0x1f) << 16];
                        memcpy(g_psxMemWLUT + 0x8000, g_psxMemWLUT, 0x80 * sizeof(void *));
                        memcpy(g_psxMemWLUT + 0xa000, g_psxMemWLUT, 0x80 * sizeof(void *));
                        break;
                    default:
                        PSXMEM_LOG("unk %8.8lx = %x\n", mem, value);
                        break;
                }
            }
        }
    }
}

void *PCSX::Memory::psxMemPointer(uint32_t mem) {
    char *p;
    uint32_t t;

    t = mem >> 16;
    if (t == 0x1f80 || t == 0x9f80 || t == 0xbf80) {
        if ((mem & 0xffff) < 0x400)
            return (void *)&g_psxH[mem];
        else
            return NULL;
    } else {
        p = (char *)(g_psxMemWLUT[t]);
        if (p != NULL) {
            return (void *)(p + (mem & 0xffff));
        }
        return NULL;
    }
}
