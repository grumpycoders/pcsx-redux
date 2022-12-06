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

/*
 * Handles all CD-ROM registers and functions.
 */

#include "core/cdrom.h"

#include "cdrom/iso9660-reader.h"
#include "core/debug.h"
#include "core/psxdma.h"
#include "core/psxemulator.h"
#include "magic_enum/include/magic_enum.hpp"
#include "spu/interface.h"
#include "support/strings-helpers.h"

namespace {

class CDRomImpl final : public PCSX::CDRom {
    enum Commands {
        CdlSync = 0,
        CdlGetStat = 1,
        CdlSetloc = 2,
        CdlPlay = 3,
        CdlForward = 4,
        CdlBackward = 5,
        CdlReadN = 6,
        CdlStandby = 7,
        CdlStop = 8,
        CdlPause = 9,
        CdlReset = 10,
        CdlMute = 11,
        CdlDemute = 12,
        CdlSetfilter = 13,
        CdlSetmode = 14,
        CdlGetparam = 15,
        CdlGetlocL = 16,
        CdlGetlocP = 17,
        CdlReadT = 18,
        CdlGetTN = 19,
        CdlGetTD = 20,
        CdlSeekL = 21,
        CdlSeekP = 22,
        CdlSetclock = 23,
        CdlGetclock = 24,
        CdlTest = 25,
        CdlID = 26,
        CdlReadS = 27,
        CdlInit = 28,
        CdlGetQ = 29,
        CdlReadToc = 30,
    };

    static constexpr size_t c_cdCmdEnumCount = magic_enum::enum_count<Commands>();

    void reset() override {}

    void interrupt() override {}
    void dmaInterrupt() override {}
    uint8_t read0() override { return 0; }
    uint8_t read1() override { return 0; }
    uint8_t read2() override { return 0; }
    uint8_t read3() override { return 0; }
    void write0(uint8_t rt) override {}
    void write1(uint8_t rt) override {}
    void write2(uint8_t rt) override {}
    void write3(uint8_t rt) override {}

    void dma(uint32_t madr, uint32_t bcr, uint32_t chcr) override {}

    void logCDROM(int command) {
        uint32_t pc = PCSX::g_emulator->m_cpu->m_regs.pc;

        switch (command & 0xff) {
            // TODO: decode more commands
            case CdlTest:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "%08x [CDROM] Command: CdlTest %02x\n", pc, m_param[0]);
                break;
            case CdlSetloc:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "%08x [CDROM] Command: CdlSetloc %02x:%02x:%02x\n", pc,
                                    m_param[0], m_param[1], m_param[2]);
                break;
            case CdlPlay:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "%08x [CDROM] Command: CdlPlay %i\n", pc, m_param[0]);
                break;
            case CdlSetfilter:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "%08x [CDROM] Command: CdlSetfilter file: %i, channel: %i\n",
                                    pc, m_param[0], m_param[1]);
                break;
            case CdlSetmode: {
                auto mode = m_param[0];
                std::string modeDecode = mode & 1 ? "CDDA" : "DATA";
                if (mode & 2) modeDecode += " Autopause";
                if (mode & 4) modeDecode += " Report";
                if (mode & 8) modeDecode += " SubheaderFilter";
                switch ((mode & 0x30) >> 4) {
                    case 0:
                        modeDecode += " 2048bytes";
                        break;
                    case 1:
                        modeDecode += " 2328bytes";
                        break;
                    case 2:
                        modeDecode += " 2340bytes";
                        break;
                    case 3:
                        modeDecode += " *wrong read mode*";
                        break;
                }
                if (mode & 0x40) modeDecode += " RealTimePlay";
                modeDecode += mode & 0x80 ? " @2x" : " @1x";
                PCSX::g_system->log(PCSX::LogClass::CDROM, "%08x [CDROM] Command: CdlSetmode %02x (%s)\n", pc,
                                    m_param[0], modeDecode);
            } break;
            case CdlGetTN:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "%08x [CDROM] Command: CdlGetTN (returns %i)\n", pc,
                                    m_iso->getTN());
                break;
            case CdlGetTD: {
                auto ret = m_iso->getTD(m_param[0]);
                PCSX::g_system->log(PCSX::LogClass::CDROM,
                                    "%08x [CDROM] Command: CdlGetTD %i (returns %02i:%02i:%02i)\n", pc, m_param[0],
                                    ret.m, ret.s, ret.f);
            } break;
            default:
                if ((command & 0xff) > c_cdCmdEnumCount) {
                    PCSX::g_system->log(PCSX::LogClass::CDROM, "%08x [CDROM] Command: CdlUnknown(0x%02X)\n", pc,
                                        command & 0xff);
                } else {
                    PCSX::g_system->log(PCSX::LogClass::CDROM, "%08x [CDROM] Command: %s\n", pc,
                                        magic_enum::enum_names<Commands>()[command & 0xff]);
                }
                break;
        }
    }
};

}  // namespace

PCSX::CDRom *PCSX::CDRom::factory() { return new CDRomImpl; }
void PCSX::CDRom::parseIso() {
    m_cdromId.clear();
    m_cdromLabel.clear();
    ISO9660Reader reader(m_iso);
    if (reader.failed()) return;
    IO<File> systemcnf(reader.open("SYSTEM.CNF;1"));
    std::string exename;
    m_cdromLabel = StringsHelpers::trim(reader.getLabel());

    if (!systemcnf->failed()) {
        while (!systemcnf->eof()) {
            std::string lineStorage = systemcnf->gets();
            auto line = StringsHelpers::trim(lineStorage);
            if (!StringsHelpers::startsWith(line, "BOOT")) continue;
            auto pathLoc = line.find("cdrom:");
            if (pathLoc == std::string::npos) break;
            auto paths = StringsHelpers::split(line.substr(pathLoc + 6), "/\\");
            if (paths.empty()) break;

            for (auto &path : paths) {
                exename += path;
                exename += '/';
            }
            exename.resize(exename.size() - 1);

            auto filename = paths[paths.size() - 1];
            // pattern is XXXX_YYY.ZZ;1
            if ((filename.size() == 13) && (filename[4] == '_') && (filename[8] == '.') && (filename[11] == ';') &&
                (filename[12] == '1')) {
                m_cdromId = filename.substr(0, 4);
                m_cdromId += filename.substr(5, 3);
                m_cdromId += filename.substr(9, 2);
            }

            break;
        }
    } else {
        IO<File> psxexe(reader.open("PSX.EXE;1"));
        if (!psxexe->failed()) {
            m_cdromId = "SLUS99999";
            exename = "PSX.EXE;1";
        }
    }

    g_system->printf(_("CD-ROM Label: %.32s\n"), m_cdromLabel);
    g_system->printf(_("CD-ROM ID: %.9s\n"), m_cdromId);
    g_system->printf(_("CD-ROM EXE Name: %.255s\n"), exename);
}
