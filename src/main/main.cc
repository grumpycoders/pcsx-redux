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
#include "support/uvfile.h"
#include "support/version.h"
#include "tracy/Tracy.hpp"

static PCSX::GUI *s_gui;

class SystemImpl final : public PCSX::System {
    virtual void biosPutc(int c) final override {
        if (c == '\r') return;
        m_putcharBuffer += std::string(1, c);
        if (c == '\n') {
            log(PCSX::LogClass::MIPS, std::move(m_putcharBuffer));
            m_putcharBuffer.clear();
        }
    }
    virtual void message(std::string &&s) final override {
        if (!m_noGuiLog) s_gui->addNotification(s.c_str());
        if (s_gui->addLog(PCSX::LogClass::UI, s)) {
            if (m_enableStdout) ::printf("%s", s.c_str());
            m_eventBus->signal(PCSX::Events::LogMessage{PCSX::LogClass::UI, s});
            if (m_logfile) m_logfile->write(std::move(s));
        }
    }

    virtual void log(PCSX::LogClass logClass, std::string &&s) final override {
        if (!m_noGuiLog) {
            if (!s_gui->addLog(logClass, s)) return;
        }
        if (m_enableStdout) ::printf("%s", s.c_str());
        m_eventBus->signal(PCSX::Events::LogMessage{logClass, s});
        if (m_logfile) m_logfile->write(std::move(s));
    }

    virtual void printf(std::string &&s) final override {
        if (!m_noGuiLog) {
            if (!s_gui->addLog(PCSX::LogClass::UNCATEGORIZED, s)) return;
        }
        if (m_enableStdout) ::printf("%s", s.c_str());
        m_eventBus->signal(PCSX::Events::LogMessage{PCSX::LogClass::UNCATEGORIZED, s});
        if (m_logfile) m_logfile->write(std::move(s));
    }

    virtual void luaMessage(const std::string &s, bool error) final override {
        if (!m_noGuiLog) {
            s_gui->addLuaLog(s, error);
        }
        if ((error && m_inStartup) || args.get<bool>("lua_stdout", false)) {
            if (error) {
                fprintf(stderr, "%s\n", s.c_str());
            } else {
                fprintf(stdout, "%s\n", s.c_str());
            }
        }
    }

    virtual void update(bool vsync = false) final override {
        // called on vblank to update states
        s_gui->update(vsync);
    }

    virtual void softReset() final override {
        // debugger or UI is requesting a reset
        m_eventBus->signal(PCSX::Events::ExecutionFlow::Reset{});
        PCSX::g_emulator->m_cpu->psxReset();
    }

    virtual void hardReset() final override {
        // debugger or UI is requesting a reset
        m_eventBus->signal(PCSX::Events::ExecutionFlow::Reset{true});
        PCSX::g_emulator->reset();
    }

    virtual void close() final override {
        // emulator is requesting a shutdown of the emulation
    }

    virtual void purgeAllEvents() final override { uv_run(getLoop(), UV_RUN_DEFAULT); }

    virtual void testQuit(int code) final override {
        if (testmode()) {
            quit(code);
        } else {
            PCSX::System::log(PCSX::LogClass::UI, "PSX software requested an exit with code %i\n", code);
            pause();
        }
    }

    virtual const CommandLine::args &getArgs() final override { return args; }

    std::string m_putcharBuffer;
    PCSX::IO<PCSX::UvFile> m_logfile;

  public:
    void setTestmode() { m_testmode = true; }
    void setBinDir(std::filesystem::path path) {
        m_binDir = path;
        m_version.loadFromFile(new PCSX::PosixFile(path / "version.json"));
        if (m_version.failed()) {
            m_version.loadFromFile(
                new PCSX::PosixFile(path / ".." / "share" / "pcsx-redux" / "resources" / "version.json"));
        }
        if (m_version.failed()) {
            m_version.loadFromFile(
                new PCSX::PosixFile(path / ".." / "Resources" / "share" / "pcsx-redux" / "resources" / "version.json"));
        }
    }

    explicit SystemImpl(const CommandLine::args &args) : args(args) {}
    ~SystemImpl() {}

    void setEmergencyExit() { m_emergencyExit = true; }

    void useLogfile(const PCSX::u8string &filename) {
        m_logfile.setFile(new PCSX::UvFile(filename, PCSX::FileOps::TRUNCATE));
    }

    bool m_enableStdout = false;
    const CommandLine::args &args;
    bool m_inStartup = true;
    bool m_noGuiLog = false;
};

using json = nlohmann::json;

struct Cleaner {
    Cleaner(std::function<void()> &&f) : f(std::move(f)) {}
    ~Cleaner() { f(); }

  private:
    std::function<void()> f;
};

int pcsxMain(int argc, char **argv) {
    ZoneScoped;
    const CommandLine::args args(argc, argv);
    PCSX::UvThreadOp::UvThread uvThread;

#if defined(_WIN32) || defined(_WIN64)
    if (args.get<bool>("stdout")) {
        if (AllocConsole()) {
            freopen("CONIN$", "r", stdin);
            freopen("CONOUT$", "w", stdout);
            freopen("CONOUT$", "w", stderr);
        }
    }
#endif

    if (args.get<bool>("dumpproto")) {
        PCSX::SaveStates::ProtoFile::dumpSchema(std::cout);
        return 0;
    }

    SystemImpl *system = new SystemImpl(args);
    if (args.get<bool>("testmode").value_or(false)) {
        system->setTestmode();
    }
    if (args.get<bool>("stdout").value_or(false)) system->m_enableStdout = true;
    const auto &logfileArgOpt = args.get<std::string>("logfile");
    const PCSX::u8string logfileArg = MAKEU8(logfileArgOpt.has_value() ? logfileArgOpt->c_str() : "");
    if (!logfileArg.empty()) system->useLogfile(logfileArg);
    if (args.get<bool>("testmode").value_or(false) || args.get<bool>("no-gui-log").value_or(false)) {
        system->m_noGuiLog = true;
    }
    PCSX::g_system = system;
    PCSX::Emulator *emulator = new PCSX::Emulator();
    PCSX::g_emulator = emulator;
    std::filesystem::path self = argv[0];
    std::filesystem::path binDir = self.parent_path();
    system->setBinDir(binDir);
    system->loadAllLocales();

    s_gui = new PCSX::GUI(args);
    s_gui->init();
    auto &emuSettings = emulator->settings;
    auto &debugSettings = emuSettings.get<PCSX::Emulator::SettingDebugSettings>();
    if (emuSettings.get<PCSX::Emulator::SettingMcd1>().empty()) {
        emuSettings.get<PCSX::Emulator::SettingMcd1>() = MAKEU8(u8"memcard1.mcd");
    }

    if (emuSettings.get<PCSX::Emulator::SettingMcd2>().empty()) {
        emuSettings.get<PCSX::Emulator::SettingMcd2>() = MAKEU8(u8"memcard2.mcd");
    }

    auto argPath1 = args.get<std::string>("memcard1");
    auto argPath2 = args.get<std::string>("memcard2");
    if (argPath1.has_value()) emuSettings.get<PCSX::Emulator::SettingMcd1>().value = argPath1.value();
    if (argPath2.has_value()) emuSettings.get<PCSX::Emulator::SettingMcd2>().value = argPath1.value();
    PCSX::u8string path1 = emuSettings.get<PCSX::Emulator::SettingMcd1>().string();
    PCSX::u8string path2 = emuSettings.get<PCSX::Emulator::SettingMcd2>().string();

    emulator->m_sio->LoadMcds(path1, path2);
    auto biosCfg = args.get<std::string>("bios");
    if (biosCfg.has_value()) emuSettings.get<PCSX::Emulator::SettingBios>() = biosCfg.value();

    system->activateLocale(emuSettings.get<PCSX::Emulator::SettingLocale>());

    if (args.get<bool>("debugger", false)) {
        debugSettings.get<PCSX::Emulator::DebugSettings::Debug>().value = true;
    }

    if (args.get<bool>("no-debugger", false)) {
        debugSettings.get<PCSX::Emulator::DebugSettings::Debug>().value = false;
    }

    if (args.get<bool>("trace", false)) {
        debugSettings.get<PCSX::Emulator::DebugSettings::Trace>().value = true;
    }

    if (args.get<bool>("no-trace", false)) {
        debugSettings.get<PCSX::Emulator::DebugSettings::Trace>().value = false;
    }

    if (args.get<bool>("8mb", false)) {
        emuSettings.get<PCSX::Emulator::Setting8MB>().value = true;
    }

    std::filesystem::path isoToOpen = args.get<std::string>("iso", "");
    if (isoToOpen.empty()) isoToOpen = args.get<std::string>("loadiso", "");
    if (isoToOpen.empty()) isoToOpen = args.get<std::string>("disk", "");
    if (!isoToOpen.empty()) PCSX::g_emulator->m_cdrom->setIso(new PCSX::CDRIso(isoToOpen));
    PCSX::g_emulator->m_cdrom->check();
    auto argPCdrvBase = args.get<std::string>("pcdrvbase");
    if (args.get<bool>("pcdrv", false)) {
        debugSettings.get<PCSX::Emulator::DebugSettings::PCdrv>().value = true;
    }
    if (argPCdrvBase.has_value()) {
        debugSettings.get<PCSX::Emulator::DebugSettings::PCdrvBase>().value = argPCdrvBase.value();
    }

    if (!args.get<bool>("stdout", false)) {
        system->m_enableStdout = emulator->settings.get<PCSX::Emulator::SettingStdout>();
    }
    const PCSX::u8string &logfileSet = emulator->settings.get<PCSX::Emulator::SettingLogfile>().string();
    if (logfileArg.empty() && !logfileSet.empty()) system->useLogfile(logfileSet);

    emulator->setLua();
    s_gui->setLua(*emulator->m_lua);
    emulator->m_spu->init();
    emulator->m_spu->setLua(*emulator->m_lua);
    emulator->m_spu->open();

    emulator->init();
    emulator->m_gpu->open(s_gui);
    emulator->m_gpu->init();
    emulator->m_gpu->setDither(emuSettings.get<PCSX::Emulator::SettingDither>());
    emulator->m_gpu->setLinearFiltering(emuSettings.get<PCSX::Emulator::SettingLinearFiltering>());
    emulator->reset();

    if (args.get<bool>("run", false)) system->start();
    s_gui->m_exeToLoad.set(MAKEU8(args.get<std::string>("loadexe", "").c_str()));
    if (s_gui->m_exeToLoad.empty()) s_gui->m_exeToLoad.set(MAKEU8(args.get<std::string>("exe", "").c_str()));

    assert(emulator->m_lua->gettop() == 0);
    auto luaexecs = args.values("exec");
    int exitCode = 0;
    {
        Cleaner cleaner([&emulator, &system, &exitCode]() {
            emulator->m_spu->close();
            emulator->m_gpu->close();
            emulator->m_cdrom->clearIso();

            emulator->m_cpu->psxShutdown();
            emulator->m_spu->shutdown();
            emulator->m_gpu->shutdown();
            s_gui->close();
            delete s_gui;

            delete emulator;
            PCSX::g_emulator = nullptr;

            exitCode = system->exitCode();
            delete system;
            PCSX::g_system = nullptr;
        });
        try {
            for (auto &luaexec : luaexecs) {
                try {
                    emulator->m_lua->load(luaexec.data(), "cmdline", false);
                    emulator->m_lua->pcall();
                } catch (std::exception &e) {
                    fprintf(stderr, "%s\n", e.what());
                }
            }

            system->m_inStartup = false;

            while (!system->quitting()) {
                if (system->running()) {
                    emulator->m_cpu->Execute();
                } else {
                    s_gui->update();
                }
            }
        } catch (...) {
            system->setEmergencyExit();
            uvThread.setEmergencyExit();
            throw;
        }
    }

    return exitCode;
}
