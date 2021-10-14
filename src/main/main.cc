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

#include <filesystem>
#include <iostream>
#include <map>
#include <string>

#include "core/cdrom.h"
#include "core/gpu.h"
#include "core/logger.h"
#include "core/psxemulator.h"
#include "core/r3000a.h"
#include "core/sstate.h"
#include "flags.h"
#include "gui/gui.h"
#include "lua/luawrapper.h"
#include "spu/interface.h"
#include "tracy/Tracy.hpp"

static PCSX::GUI *s_gui;

class SystemImpl final : public PCSX::System {
    virtual void biosPutc(int c) final {
        if (c == '\r') return;
        m_putcharBuffer += std::string(1, c);
        if (c == '\n') {
            log(PCSX::LogClass::MIPS, m_putcharBuffer);
            m_putcharBuffer.clear();
        }
    }
    virtual void message(const std::string &s) final {
        if (s_gui->addLog(PCSX::LogClass::UI, s)) {
            if (m_logfile) fprintf(m_logfile, "%s", s.c_str());
            if (m_enableStdout) ::printf("%s", s.c_str());
            m_eventBus->signal(PCSX::Events::LogMessage{PCSX::LogClass::UI, s});
        }
        s_gui->addNotification(s.c_str());
    }

    virtual void log(PCSX::LogClass logClass, const std::string &s) final {
        if (!s_gui->addLog(logClass, s)) return;
        if (m_logfile) fprintf(m_logfile, "%s", s.c_str());
        if (m_enableStdout) ::printf("%s", s.c_str());
        m_eventBus->signal(PCSX::Events::LogMessage{logClass, s});
    }

    virtual void printf(const std::string &s) final {
        if (!s_gui->addLog(PCSX::LogClass::UNCATEGORIZED, s)) return;
        if (m_logfile) fprintf(m_logfile, "%s", s.c_str());
        if (m_enableStdout) ::printf("%s", s.c_str());
        m_eventBus->signal(PCSX::Events::LogMessage{PCSX::LogClass::UNCATEGORIZED, s});
    }

    virtual void update(bool vsync = false) final {
        // called on vblank to update states
        s_gui->update(vsync);
    }

    virtual void softReset() final {
        // debugger or UI is requesting a reset
        m_eventBus->signal(PCSX::Events::ExecutionFlow::Reset{});
        PCSX::g_emulator->m_psxCpu->psxReset();
    }

    virtual void hardReset() final {
        // debugger or UI is requesting a reset
        m_eventBus->signal(PCSX::Events::ExecutionFlow::Reset{true});
        PCSX::g_emulator->EmuReset();

        // Upon hard-reset, clear the VRAM texture displayed by the VRAM viewers as well
        s_gui->setViewport();
        s_gui->bindVRAMTexture();
        glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 1024, 512, GL_RGBA, GL_UNSIGNED_SHORT_1_5_5_5_REV,
                        PCSX::g_emulator->m_gpu->getVRAM());
    }

    virtual void close() final {
        // emulator is requesting a shutdown of the emulation
    }

    virtual void purgeAllEvents() final {
        uv_stop(&PCSX::g_emulator->m_loop);
        uv_run(&PCSX::g_emulator->m_loop, UV_RUN_DEFAULT);
    }

    virtual void testQuit(int code) final {
        if (m_args.get<bool>("testmode")) {
            quit(code);
        } else {
            PCSX::System::log(PCSX::LogClass::UI, "PSX software requested an exit with code %i\n", code);
            pause();
        }
    }

    std::string m_putcharBuffer;
    FILE *m_logfile = nullptr;

  public:
    void setBinDir(std::filesystem::path path) { m_binDir = path; }

    SystemImpl(const flags::args &args) : m_args(args) {}
    ~SystemImpl() {
        if (m_logfile) fclose(m_logfile);
    }

    void useLogfile(const PCSX::u8string &filename) {
        m_logfile = fopen(reinterpret_cast<const char *>(filename.c_str()), "w");
    }

    bool m_enableStdout = false;
    const flags::args &m_args;
};

using json = nlohmann::json;

int pcsxMain(int argc, char **argv) {
    ZoneScoped;
    const flags::args args(argc, argv);

#if defined(_WIN32) || defined(_WIN64)
    if (args.get<bool>("stdout")) {
        AllocConsole();
        freopen("CONIN$", "r", stdin);
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
    }
#endif

    if (args.get<bool>("dumpproto")) {
        PCSX::SaveStates::ProtoFile::dumpSchema(std::cout);
        return 0;
    }

    SystemImpl *system = new SystemImpl(args);
    PCSX::g_system = system;
    PCSX::Emulator *emulator = new PCSX::Emulator();
    PCSX::g_emulator = emulator;
    std::filesystem::path self = argv[0];
    std::filesystem::path binDir = self.parent_path();
    system->setBinDir(binDir);
    system->loadAllLocales();

    s_gui = new PCSX::GUI(args);
    s_gui->init();
    system->m_enableStdout = emulator->settings.get<PCSX::Emulator::SettingStdout>();
    if (args.get<bool>("stdout")) system->m_enableStdout = true;
    const auto &logfileArgOpt = args.get<std::string>("logfile");
    const PCSX::u8string logfileArg = MAKEU8(logfileArgOpt.has_value() ? logfileArgOpt->c_str() : "");
    const PCSX::u8string &logfileSet = emulator->settings.get<PCSX::Emulator::SettingLogfile>().string();
    const auto &logfile = logfileArg.empty() ? logfileSet : logfileArg;
    if (!logfile.empty()) system->useLogfile(logfile);

    emulator->m_cdrom->m_iso.init();
    emulator->m_gpu->init();
    emulator->m_spu->init();

    emulator->m_gpu->open(s_gui);
    emulator->m_spu->open();

    emulator->EmuInit();
    emulator->EmuReset();

    if (args.get<bool>("run", false)) system->start();
    s_gui->m_exeToLoad.set(MAKEU8(args.get<std::string>("loadexe", "").c_str()));
    if (s_gui->m_exeToLoad.empty()) s_gui->m_exeToLoad.set(MAKEU8(args.get<std::string>("exe", "").c_str()));

    auto luaexecs = args.values("exec");
    for (auto &luaexec : luaexecs) {
        try {
            emulator->m_lua->load(luaexec.data(), "cmdline", false);
            emulator->m_lua->pcall();
        } catch (std::exception &e) {
            if (args.get<bool>("lua_stdout", false)) {
                fprintf(stderr, "%s\n", e.what());
            }
        }
    }

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
