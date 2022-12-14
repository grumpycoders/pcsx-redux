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
        CdlSetLoc = 2,
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
        CdlSetFilter = 13,
        CdlSetMode = 14,
        CdlGetParam = 15,
        CdlGetLocL = 16,
        CdlGetLocP = 17,
        CdlReadT = 18,
        CdlGetTN = 19,
        CdlGetTD = 20,
        CdlSeekL = 21,
        CdlSeekP = 22,
        CdlSetClock = 23,
        CdlGetClock = 24,
        CdlTest = 25,
        CdlID = 26,
        CdlReadS = 27,
        CdlInit = 28,
        CdlGetQ = 29,
        CdlReadToc = 30,
    };

    static constexpr size_t c_cdCmdEnumCount = magic_enum::enum_count<Commands>();

    void reset() override {
        m_dataFIFOIndex = 0;
        m_dataFIFOSize = 0;
        m_paramFIFOSize = 0;
        m_responseFIFOIndex = 0;
        m_responseFIFOSize = 0;
        m_registerIndex = 0;
        m_busy = false;
        m_state = 0;
        m_command = 0;
    }

    void interrupt() override {}
    void dmaInterrupt() override {}

    uint8_t read0() override {
        uint8_t v01 = m_registerIndex & 3;
        uint8_t adpcmPlaying = 0;
        uint8_t v3 = m_paramFIFOSize == 0 ? 0x08 : 0;
        uint8_t v4 = paramFIFOFull() ? 0x10 : 0;
        uint8_t v5 = responseFIFOEmpty() ? 0x20 : 0;
        uint8_t v6 = m_dataFIFOSize == m_dataFIFOIndex ? 0x40 : 0;
        uint8_t v7 = m_busy ? 0x80 : 0;

        return v01 | adpcmPlaying | v3 | v4 | v5 | v6 | v7;
    }

    uint8_t read1() override {
        if (responseFIFOEmpty()) return 0;
        return m_responseFIFO[m_responseFIFOIndex++];
    }

    uint8_t read2() override {
        if (dataFIFOEmpty()) return 0;
        return m_dataFIFO[m_dataFIFOIndex++];
    }

    uint8_t read3() override {
        switch (m_registerIndex & 1) {
            case 0: {
                // cause mask
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom r0:0 not available yet\n");
                PCSX::g_system->pause();
                return 0;
            } break;
            case 1: {
                // cause
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom r0:1 not available yet\n");
                PCSX::g_system->pause();
                return 0;
            } break;
        }
        // should not be reachable
        return 0;
    }

    void write0(uint8_t value) override { m_registerIndex = value & 3; }

    void write1(uint8_t value) override {
        switch (m_registerIndex) {
            case 0: {
                if (m_busy) {
                    // The CD-Rom controller is already executing a command.
                    // This basically results in undefined behavior. We'll still
                    // have to address this, as some games will do it anyway.
                    PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom command while controller is busy\n");
                    PCSX::g_system->pause();
                }
                startCommand(value);
            } break;
            case 1: {
                // ??
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom w1:1 not available yet\n");
                PCSX::g_system->pause();
            } break;
            case 2: {
                // ??
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom w1:2 not available yet\n");
                PCSX::g_system->pause();
            } break;
            case 3: {
                // Volume setting RR
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom w1:3 not available yet\n");
                PCSX::g_system->pause();
            } break;
        }
    }

    void write2(uint8_t value) override {
        switch (m_registerIndex) {
            case 0: {
                if (!paramFIFOFull()) m_paramFIFO[m_paramFIFOSize++] = value;
            } break;
            case 1: {
                // cause mask
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom w2:1 not available yet\n");
                PCSX::g_system->pause();
            } break;
            case 2: {
                // Volume setting LL
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom w2:2 not available yet\n");
                PCSX::g_system->pause();
            } break;
            case 3: {
                // Volume setting RL
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom w2:3 not available yet\n");
                PCSX::g_system->pause();
            } break;
        }
    }

    void write3(uint8_t value) override {
        switch (m_registerIndex) {
            case 0: {
                // ??
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom w3:0 not available yet\n");
                PCSX::g_system->pause();
            } break;
            case 1: {
                // cause ack
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom w3:1 not available yet\n");
                PCSX::g_system->pause();
            } break;
            case 2: {
                // Volume setting LR
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom w3:2 not available yet\n");
                PCSX::g_system->pause();
            } break;
            case 3: {
                // SPU settings latch
                PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom w3:3 not available yet\n");
                PCSX::g_system->pause();
            } break;
        }
    }

    void dma(uint32_t madr, uint32_t bcr, uint32_t chcr) override {
        PCSX::g_system->log(PCSX::LogClass::CDROM, "CD-Rom DMA not available yet\n");
        PCSX::g_system->pause();
    }

    void startCommand(uint8_t command) {
        m_busy = true;
        m_command = command;
        if (PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>()
                .get<PCSX::Emulator::DebugSettings::LoggingCDROM>()) {
            logCDROM(command);
        }

        if (command > 30) {
            PCSX::g_system->log(PCSX::LogClass::CDROM, "Unknown CD-Rom command\n");
            PCSX::g_system->pause();
        }

        auto handler = c_commandsHandlers[command];

        (this->*handler)();
    }

    void cdlUnimplemented() {
        PCSX::g_system->log(PCSX::LogClass::CDROM, "Unknown CD-Rom command\n");
        PCSX::g_system->pause();
    }

    typedef void(CDRomImpl::*CommandType)();

    const CommandType c_commandsHandlers[31] {
#if 0
        &CDRomImpl::cdlSync, &CDRomImpl::cdlGetStat, &CDRomImpl::cdlSetLoc, &CDRomImpl::cdlPlay, // 0
        &CDRomImpl::cdlForward, &CDRomImpl::cdlBackward, &CDRomImpl::cdlReadN, &CDRomImpl::cdlStandby, // 4
        &CDRomImpl::cdlStop, &CDRomImpl::cdlPause, &CDRomImpl::cdlReset, &CDRomImpl::cdlMute, // 8
        &CDRomImpl::cdlDemute, &CDRomImpl::cdlSetFilter, &CDRomImpl::cdlSetMode, &CDRomImpl::cdlGetParam, // 12
        &CDRomImpl::cdlGetLocL, &CDRomImpl::cdlGetLocP, &CDRomImpl::cdlReadT, &CDRomImpl::cdlGetTN, // 16
        &CDRomImpl::cdlGetTD, &CDRomImpl::cdlSeekL, &CDRomImpl::cdlSeekP, &CDRomImpl::cdlSetClock,  // 20
        &CDRomImpl::cdlGetClock, &CDRomImpl::cdlTest, &CDRomImpl::cdlID, &CDRomImpl::cdlReadS, // 24
        &CDRomImpl::cdlInit, &CDRomImpl::cdlGetQ, &CDRomImpl::cdlReadTOC,                    // 28
#else
        &CDRomImpl::cdlUnimplemented, &CDRomImpl::cdlUnimplemented, &CDRomImpl::cdlUnimplemented, &CDRomImpl::cdlUnimplemented, // 0
        &CDRomImpl::cdlUnimplemented, &CDRomImpl::cdlUnimplemented, &CDRomImpl::cdlUnimplemented, &CDRomImpl::cdlUnimplemented, // 4
        &CDRomImpl::cdlUnimplemented, &CDRomImpl::cdlUnimplemented, &CDRomImpl::cdlUnimplemented, &CDRomImpl::cdlUnimplemented, // 8
        &CDRomImpl::cdlUnimplemented, &CDRomImpl::cdlUnimplemented, &CDRomImpl::cdlUnimplemented, &CDRomImpl::cdlUnimplemented, // 12
        &CDRomImpl::cdlUnimplemented, &CDRomImpl::cdlUnimplemented, &CDRomImpl::cdlUnimplemented, &CDRomImpl::cdlUnimplemented, // 16
        &CDRomImpl::cdlUnimplemented, &CDRomImpl::cdlUnimplemented, &CDRomImpl::cdlUnimplemented, &CDRomImpl::cdlUnimplemented, // 20
        &CDRomImpl::cdlUnimplemented, &CDRomImpl::cdlUnimplemented, &CDRomImpl::cdlUnimplemented, &CDRomImpl::cdlUnimplemented, // 24
        &CDRomImpl::cdlUnimplemented, &CDRomImpl::cdlUnimplemented, &CDRomImpl::cdlUnimplemented,                   // 28
#endif
    };

    void logCDROM(uint8_t command) {
        uint32_t pc = PCSX::g_emulator->m_cpu->m_regs.pc;

        switch (command & 0xff) {
            case CdlTest:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "%08x [CDROM] Command: CdlTest %02x\n", pc, m_paramFIFO[0]);
                break;
            case CdlSetLoc:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "%08x [CDROM] Command: CdlSetloc %02x:%02x:%02x\n", pc,
                                    m_paramFIFO[0], m_paramFIFO[1], m_paramFIFO[2]);
                break;
            case CdlPlay:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "%08x [CDROM] Command: CdlPlay %i\n", pc, m_paramFIFO[0]);
                break;
            case CdlSetFilter:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "%08x [CDROM] Command: CdlSetfilter file: %i, channel: %i\n",
                                    pc, m_paramFIFO[0], m_paramFIFO[1]);
                break;
            case CdlSetMode: {
                auto mode = m_paramFIFO[0];
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
                                    m_paramFIFO[0], modeDecode);
            } break;
            case CdlGetTN:
                PCSX::g_system->log(PCSX::LogClass::CDROM, "%08x [CDROM] Command: CdlGetTN (returns %i)\n", pc,
                                    m_iso->getTN());
                break;
            case CdlGetTD: {
                auto ret = m_iso->getTD(m_paramFIFO[0]);
                PCSX::g_system->log(PCSX::LogClass::CDROM,
                                    "%08x [CDROM] Command: CdlGetTD %i (returns %02i:%02i:%02i)\n", pc, m_paramFIFO[0],
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
