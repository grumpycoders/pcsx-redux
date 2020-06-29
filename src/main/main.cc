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

#include <SDL.h>

#include <filesystem>
#include <iostream>
#include <map>
#include <string>

#include "core/cdrom.h"
#include "core/gpu.h"
#include "core/psxemulator.h"
#include "core/r3000a.h"
#include "core/sstate.h"
#include "flags.h"
#include "gui/gui.h"
#include "spu/interface.h"

static PCSX::GUI *s_gui;

class SystemImpl : public PCSX::System {
    virtual void printf(const char *fmt, ...) final {
        // print message to debugging console
        va_list a;
        va_start(a, fmt);
        if (m_logfile) {
            va_list c;
            va_copy(c, a);
            vfprintf(m_logfile, fmt, c);
            va_end(c);
        }
        if (m_enableStdout) {
            va_list c;
            va_copy(c, a);
            vprintf(fmt, c);
            va_end(c);
        }
        s_gui->addLog(fmt, a);
        va_end(a);
    }

    virtual void biosPutc(int c) final {
        if (c == '\r') return;
        if (c == '\n') {
            biosPrintf("%s\n", m_putcharBuffer.c_str());
            m_putcharBuffer.clear();
            return;
        }
        m_putcharBuffer += std::string(1, c);
    }

    virtual void biosPrintf(const char *fmt, ...) final {
        // print message to debugging console
        va_list a;
        va_start(a, fmt);
        if (m_logfile) {
            va_list c;
            va_copy(c, a);
            vfprintf(m_logfile, fmt, c);
            va_end(c);
        }
        if (m_enableStdout) {
            va_list c;
            va_copy(c, a);
            vprintf(fmt, c);
            va_end(c);
        }
        s_gui->addLog(fmt, a);
        va_end(a);
    }

    virtual void vbiosPrintf(const char *fmt, va_list a) final {
        if (m_logfile) {
            va_list c;
            va_copy(c, a);
            vfprintf(m_logfile, fmt, c);
            va_end(c);
        }
        if (m_enableStdout) {
            va_list c;
            va_copy(c, a);
            vprintf(fmt, c);
            va_end(c);
        }
        s_gui->addLog(fmt, a);
    }

    virtual void message(const char *fmt, ...) final {
        // display message to user as a pop-up
        va_list a;
        va_start(a, fmt);
        if (m_logfile) {
            va_list c;
            va_copy(c, a);
            vfprintf(m_logfile, fmt, c);
            va_end(c);
        }
        if (m_enableStdout) {
            va_list c;
            va_copy(c, a);
            vprintf(fmt, c);
            va_end(c);
        }
        s_gui->addLog(fmt, a);
        s_gui->addNotification(fmt, a);
        va_end(a);
    }

    virtual void log(const char *facility, const char *fmt, va_list a) final {
        if (m_logfile) {
            va_list c;
            va_copy(c, a);
            vfprintf(m_logfile, fmt, c);
            va_end(c);
        }
        if (m_enableStdout) {
            va_list c;
            va_copy(c, a);
            vprintf(fmt, c);
            va_end(c);
        }
        s_gui->addLog(fmt, a);
    }

    virtual void update() final {
        // called on vblank to update states
        s_gui->update();
    }

    virtual void runGui() final {
        // called when the UI needs to show up
    }

    virtual void softReset() final {
        // debugger or UI is requesting a reset
        PCSX::g_emulator->m_psxCpu->psxReset();
    }

    virtual void hardReset() final {
        // debugger or UI is requesting a reset
        PCSX::g_emulator->EmuReset();
    }

    virtual void close() final {
        // emulator is requesting a shutdown of the emulation
    }

    virtual void purgeAllEvents() final { PCSX::g_emulator->m_loop->run(); }

    std::string m_putcharBuffer;
    FILE *m_logfile = nullptr;

  public:
    ~SystemImpl() {
        if (m_logfile) fclose(m_logfile);
    }

    void useLogfile(const PCSX::u8string &filename) {
        m_logfile = fopen(reinterpret_cast<const char *>(filename.c_str()), "w");
    }

    bool m_enableStdout = false;
};

using json = nlohmann::json;

int pcsxMain(int argc, char **argv) {
    const flags::args args(argc, argv);

    if (args.get<bool>("dumpproto")) {
        PCSX::SaveStates::ProtoFile::dumpSchema(std::cout);
        return 0;
    }

    SystemImpl *system = new SystemImpl;
    PCSX::g_system = system;
    PCSX::Emulator *emulator = new PCSX::Emulator();
    PCSX::g_emulator = emulator;
    std::filesystem::path self = argv[0];
    std::filesystem::path binDir = self.parent_path();
    system->setBinDir(binDir);
    system->loadAllLocales();

    if (SDL_Init(SDL_INIT_EVERYTHING ^ SDL_INIT_VIDEO) != 0) {
        abort();
    }

    s_gui = new PCSX::GUI(args);
    s_gui->init();
    system->m_enableStdout = emulator->settings.get<PCSX::Emulator::SettingStdout>();
    const auto &logfileArgOpt = args.get<std::string>("logfile");
    const PCSX::u8string logfileArg = MAKEU8(logfileArgOpt.has_value() ? logfileArgOpt->c_str() : "");
    const PCSX::u8string &logfileSet = emulator->settings.get<PCSX::Emulator::SettingLogfile>().string();
    const auto &logfile = logfileArg.empty() ? logfileSet : logfileArg;
    if (!logfile.empty()) system->useLogfile(logfile);

    system->activateLocale(emulator->settings.get<PCSX::Emulator::SettingLocale>());

    LoadPlugins();
    emulator->m_gpu->open(s_gui);
    emulator->m_spu->open();

    emulator->EmuInit();
    emulator->EmuReset();

    std::string iso = args.get<std::string>("iso", "");
    if (!iso.empty()) SetIsoFile(iso.c_str());
    emulator->m_cdrom->m_iso.open();
    CheckCdrom();

    if (args.get<bool>("run", false)) system->start();

    while (!system->quitting()) {
        if (system->running()) {
            emulator->m_psxCpu->Execute();
        } else {
            s_gui->update();
        }
    }

    emulator->m_spu->close();
    emulator->m_gpu->close();
    emulator->m_cdrom->m_iso.close();

    emulator->m_psxCpu->psxShutdown();
    emulator->m_spu->shutdown();
    emulator->m_gpu->shutdown();
    emulator->m_cdrom->m_iso.shutdown();
    s_gui->close();
    delete s_gui;

    delete emulator;
    PCSX::g_emulator = nullptr;

    int exitCode = system->exitCode();
    delete system;
    PCSX::g_system = nullptr;

    return exitCode;
}
