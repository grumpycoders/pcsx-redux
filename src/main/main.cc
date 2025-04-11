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

#include <csignal>
#include <filesystem>
#include <iostream>
#include <map>
#include <string>

#include "core/arguments.h"
#include "core/cdrom.h"
#include "core/gpu.h"
#include "core/logger.h"
#include "core/psxemulator.h"
#include "core/r3000a.h"
#include "core/sstate.h"
#include "core/ui.h"
#include "flags.h"
#include "fmt/chrono.h"
#include "gui/gui.h"
#include "lua/extra.h"
#include "lua/luawrapper.h"
#include "main/textui.h"
#include "spu/interface.h"
#include "support/binpath.h"
#include "support/uvfile.h"
#include "support/version.h"
#include "tracy/Tracy.hpp"

static PCSX::UI *s_ui;

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
        if (m_args.isGUILogsEnabled()) s_ui->addNotification(s.c_str());
        if (s_ui->addLog(PCSX::LogClass::UI, s)) {
            if (m_args.isStdoutEnabled()) ::fputs(s.c_str(), stdout);
            if (m_logfile) m_logfile->write(std::move(s));
            m_eventBus->signal(PCSX::Events::LogMessage{PCSX::LogClass::UI, s});
        }
    }

    virtual void log(PCSX::LogClass logClass, std::string &&s) final override {
        if (m_args.isGUILogsEnabled()) {
            if (!s_ui->addLog(logClass, s)) return;
        }
        if (m_args.isStdoutEnabled()) ::fputs(s.c_str(), stdout);
        if (m_logfile) m_logfile->write(std::move(s));
        m_eventBus->signal(PCSX::Events::LogMessage{logClass, s});
    }

    virtual void printf(std::string &&s) final override {
        if (m_args.isGUILogsEnabled()) {
            if (!s_ui->addLog(PCSX::LogClass::UNCATEGORIZED, s)) return;
        }
        if (m_args.isStdoutEnabled()) ::fputs(s.c_str(), stdout);
        if (m_logfile) m_logfile->write(std::move(s));
        m_eventBus->signal(PCSX::Events::LogMessage{PCSX::LogClass::UNCATEGORIZED, s});
    }

    virtual void luaMessage(const std::string &s, bool error) final override {
        if (m_args.isGUILogsEnabled()) {
            s_ui->addLuaLog(s, error);
        }
        if ((error && m_inStartup) || m_args.isLuaStdoutEnabled()) {
            if (error) {
                fputs(s.c_str(), stderr);
                fputc('\n', stderr);
            } else {
                puts(s.c_str());
            }
        }
    }

    virtual void update(bool vsync = false) final override {
        // called on vblank to update states
        s_ui->update(vsync);
    }

    virtual void softReset() final override {
        // debugger or UI is requesting a reset
        PCSX::g_emulator->m_cpu->psxReset();
        m_eventBus->signal(PCSX::Events::ExecutionFlow::Reset{});
    }

    virtual void hardReset() final override {
        // debugger or UI is requesting a reset
        PCSX::g_emulator->reset();
        m_eventBus->signal(PCSX::Events::ExecutionFlow::Reset{true});
    }

    virtual void close() final override {
        // emulator is requesting a shutdown of the emulation
    }

    virtual void testQuit(int code) final override {
        if (m_args.isTestModeEnabled()) {
            quit(code);
        } else {
            PCSX::System::log(PCSX::LogClass::UI, "PSX software requested an exit with code %i\n", code);
            pause();
        }
    }

    virtual const PCSX::Arguments &getArgs() const final override { return m_args; }

    std::string m_putcharBuffer;
    PCSX::IO<PCSX::UvFile> m_logfile;
    const PCSX::Arguments m_args;

  public:
    virtual void purgeAllEvents() final override { uv_run(getLoop(), UV_RUN_DEFAULT); }

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

    explicit SystemImpl(const CommandLine::args &args) : m_args(args) {}
    ~SystemImpl() {}

    void setEmergencyExit() { m_emergencyExit = true; }

    void useLogfile(const PCSX::u8string &filename) {
        m_logfile.setFile(new PCSX::UvFile(filename, PCSX::FileOps::TRUNCATE));
    }
    bool m_inStartup = true;
};

struct Cleaner {
    Cleaner(std::function<void()> &&f) : f(std::move(f)) {}
    ~Cleaner() { f(); }

  private:
    std::function<void()> f;
};

void handleSignal(int signal) { PCSX::g_system->quit(-1); }

int pcsxMain(int argc, char **argv) {
    ZoneScoped;
    // Command line arguments are parsed after this point.
    const CommandLine::args args(argc, argv);
    // The UvFile and UvFifo should work past this point.
    PCSX::UvThreadOp::UvThread uvThread;

#if defined(_WIN32) || defined(_WIN64)
    if (args.get<bool>("stdout") || args.get<bool>("no-ui") || args.get<bool>("cli")) {
        if (AllocConsole()) {
            freopen("CONIN$", "r", stdin);
            freopen("CONOUT$", "w", stdout);
            freopen("CONOUT$", "w", stderr);
        }
    }
#endif

    // This is an easy early-out.
    if (args.get<bool>("dumpproto")) {
        PCSX::SaveStates::ProtoFile::dumpSchema(std::cout);
        return 0;
    }

    // Creating the "system" global object first, making sure anything logging-related is
    // enabled as much as possible.
    SystemImpl *system = new SystemImpl(args);
    PCSX::g_system = system;
    auto sigint = std::signal(SIGINT, handleSignal);
    auto sigterm = std::signal(SIGTERM, handleSignal);
#ifndef _WIN32
    std::signal(SIGPIPE, SIG_IGN);
#endif
    const auto &logfileArgOpt = args.get<std::string>("logfile");
    const PCSX::u8string logfileArg = MAKEU8(logfileArgOpt.has_value() ? logfileArgOpt->c_str() : "");
    if (!logfileArg.empty()) system->useLogfile(logfileArg);
    std::filesystem::path self = PCSX::BinPath::getExecutablePath();
    std::filesystem::path binDir = std::filesystem::absolute(self).parent_path();
    system->setBinDir(binDir);
    system->loadAllLocales();

    // This is another early out, which can only be done once we have a system object.
    if (args.get<bool>("version")) {
        auto &version = system->getVersion();
        if (version.failed()) {
            fmt::print("Failed to load version.json\n");
            return 1;
        }
        fmt::print(
            "{{\n  \"version\": \"{}\",\n  \"changeset\": \"{}\",\n  \"timestamp\": \"{}\",\n  \"timestampDecoded\": "
            "\"{:%Y-%m-%d %H:%M:%S}\"\n}}\n",
            version.version, version.changeset, version.timestamp, fmt::localtime(version.timestamp));
        return 0;
    }

    // At this point, we're committed to run the emulator, so we first create it, and the UI next.
    PCSX::Emulator *emulator = new PCSX::Emulator();
    PCSX::g_emulator = emulator;
    auto &favorites = emulator->settings.get<PCSX::Emulator::SettingOpenDialogFavorites>().value;

    s_ui = args.get<bool>("no-ui") || args.get<bool>("cli") ? reinterpret_cast<PCSX::UI *>(new PCSX::TUI())
                                                            : reinterpret_cast<PCSX::UI *>(new PCSX::GUI(favorites));
    // Settings will be loaded after this initialization.
    s_ui->init([&emulator, &args, &system]() {
        // Start tweaking / sanitizing settings a bit, while continuing to parse the command line
        // to handle overrides properly.
        auto &emuSettings = emulator->settings;
        auto &debugSettings = emuSettings.get<PCSX::Emulator::SettingDebugSettings>();

        PCSX::g_emulator->m_memoryCards->loadMcds(args);
        
        auto biosCfg = args.get<std::string>("bios");
        if (biosCfg.has_value()) emuSettings.get<PCSX::Emulator::SettingBios>() = biosCfg.value();

        system->activateLocale(emuSettings.get<PCSX::Emulator::SettingLocale>());

        if (args.get<bool>("debugger")) {
            debugSettings.get<PCSX::Emulator::DebugSettings::Debug>() = true;
        }
        if (args.get<bool>("no-debugger")) {
            debugSettings.get<PCSX::Emulator::DebugSettings::Debug>() = false;
        }

        if (args.get<bool>("trace")) {
            debugSettings.get<PCSX::Emulator::DebugSettings::Trace>() = true;
        }
        if (args.get<bool>("no-trace")) {
            debugSettings.get<PCSX::Emulator::DebugSettings::Trace>() = false;
        }

        if (args.get<bool>("8mb")) {
            emuSettings.get<PCSX::Emulator::Setting8MB>() = true;
        }
        if (args.get<bool>("2mb")) {
            emuSettings.get<PCSX::Emulator::Setting8MB>() = false;
        }

        if (args.get<bool>("fastboot")) {
            emuSettings.get<PCSX::Emulator::SettingFastBoot>() = true;
        }
        if (args.get<bool>("no-fastboot")) {
            emuSettings.get<PCSX::Emulator::SettingFastBoot>() = false;
        }

        if (args.get<bool>("gdb")) {
            debugSettings.get<PCSX::Emulator::DebugSettings::GdbServer>() = true;
        }
        if (args.get<bool>("no-gdb")) {
            debugSettings.get<PCSX::Emulator::DebugSettings::GdbServer>() = false;
        }

        if (args.get<int>("gdb-port")) {
            debugSettings.get<PCSX::Emulator::DebugSettings::GdbServerPort>() = args.get<int>("gdb-port").value();
        }

        auto argPCdrvBase = args.get<std::string>("pcdrvbase");
        if (args.get<bool>("pcdrv")) {
            debugSettings.get<PCSX::Emulator::DebugSettings::PCdrv>() = true;
        }
        if (args.get<bool>("no-pcdrv")) {
            debugSettings.get<PCSX::Emulator::DebugSettings::PCdrv>() = false;
        }
        if (argPCdrvBase.has_value()) {
            debugSettings.get<PCSX::Emulator::DebugSettings::PCdrvBase>() = argPCdrvBase.value();
        }

        if (args.get<bool>("dynarec")) {
            emuSettings.get<PCSX::Emulator::SettingDynarec>() = true;
        }
        if (args.get<bool>("interpreter")) {
            emuSettings.get<PCSX::Emulator::SettingDynarec>() = false;
        }

        if (args.get<bool>("openglgpu")) {
            emuSettings.get<PCSX::Emulator::SettingHardwareRenderer>() = true;
        }

        if (args.get<bool>("softgpu")) {
            emuSettings.get<PCSX::Emulator::SettingHardwareRenderer>() = false;
        }

        if (args.get<bool>("kiosk")) {
            emuSettings.get<PCSX::Emulator::SettingKioskMode>() = true;
        }
        if (args.get<bool>("no-kiosk")) {
            emuSettings.get<PCSX::Emulator::SettingKioskMode>() = false;
        }
    });

    // Now it's time to mount our iso filesystem
    std::filesystem::path isoToOpen = args.get<std::string>("iso", "");
    if (isoToOpen.empty()) isoToOpen = args.get<std::string>("loadiso", "");
    if (isoToOpen.empty()) isoToOpen = args.get<std::string>("disk", "");
    if (!isoToOpen.empty()) emulator->m_cdrom->setIso(new PCSX::CDRIso(isoToOpen));
    emulator->m_cdrom->check();

    // After settings are loaded, we're fine setting the SPU part of the emulation.
    emulator->m_spu->init();

    // Make sure the Lua environment is set.
    bool luacovEnabled = false;
    if (args.get<bool>("luacov")) {
        auto L = *emulator->m_lua;
        L.load(
            "package.path = package.path .. "
            "';./lua_modules/share/lua/5.1/?.lua;../../../third_party/luacov/src/?.lua;./third_party/luacov/src/?.lua'",
            "internal:package.path.lua");
        try {
            L.load(R"(
local runner = require 'luacov.runner'
runner.init({
    nameparser = function(name)
        if name:sub(1, 4) == 'src:' then
            return 'src/' .. name:sub(5)
        elseif name:sub(1, 12) == 'third_party:' then
            return 'third_party/' .. name:sub(13)
        end
        return nil
    end,
}))",
                   "internal:luacov.lua");
            luacovEnabled = true;
        } catch (...) {
            luacovEnabled = false;
        }
    }
    emulator->setLua();
    s_ui->setLua(*emulator->m_lua);
    emulator->m_spu->setLua(*emulator->m_lua);
    assert(emulator->m_lua->gettop() == 0);

    // Starting up the whole emulator; we delay setting the GPU only now because why not.
    auto &emuSettings = emulator->settings;
    emulator->m_spu->open();
    emulator->init();
    emulator->m_gpu->init(s_ui);
    emulator->m_gpu->setDither(emuSettings.get<PCSX::Emulator::SettingDither>());
    emulator->m_gpu->setCachedDithering(emuSettings.get<PCSX::Emulator::SettingCachedDithering>());
    emulator->m_gpu->setLinearFiltering();
    emulator->reset();

    // Looking at setting up what to run exactly within the emulator, if requested.
    if (args.get<bool>("run")) system->resume();
    s_ui->m_exeToLoad.set(MAKEU8(args.get<std::string>("loadexe", "").c_str()));
    if (s_ui->m_exeToLoad.empty()) s_ui->m_exeToLoad.set(MAKEU8(args.get<std::string>("exe", "").c_str()));

    // And finally, let's run things.
    int exitCode = 0;
    {
        // First, set up a closer. This makes sure that everything is shut down gracefully,
        // in the right order, once we exit the scope. This is because of how we're still
        // allowing exceptions to occur.
        Cleaner cleaner([&emulator, &system, &exitCode, luacovEnabled, sigint, sigterm]() {
            emulator->m_spu->close();
            emulator->m_cdrom->clearIso();

            emulator->m_spu->shutdown();
            emulator->m_gpu->shutdown();
            emulator->shutdown();
            s_ui->close();
            delete s_ui;

            if (luacovEnabled) {
                auto L = *emulator->m_lua;
                L.load("(require 'luacov.runner').shutdown()", "internal:luacov-shutdown.lua");
            }

            delete emulator;
            PCSX::g_emulator = nullptr;

            exitCode = system->exitCode();
            std::signal(SIGINT, sigint);
            std::signal(SIGTERM, sigterm);
            delete system;
            PCSX::g_system = nullptr;
        });
        try {
            auto &L = emulator->m_lua;
            // Before going into the main loop, let's first load all of the Lua files
            // from the command-line specified using the -dofile switch.
            auto archives = args.values("archive");
            for (auto &archive : archives) {
                PCSX::IO<PCSX::File> file = new PCSX::PosixFile(archive);
                if (file->failed()) {
                    throw std::runtime_error(fmt::format("Couldn't load file {}", archive));
                }
                PCSX::LuaFFI::addArchive(*L, file);
            }
            auto dofiles = args.values("dofile");
            L->load("return function(name) Support.extra.dofile(name) end", "internal:dofile.lua");
            for (auto &dofile : dofiles) {
                L->copy(-1);
                L->push(dofile);
                L->pcall(1);
            }
            L->pop();

            // Then run all of the Lua "exec" commands.
            auto luaexecs = args.values("exec");
            for (auto &luaexec : luaexecs) {
                L->load(std::string(luaexec), "cmdline:");
            }

            system->m_inStartup = false;

            // And finally, main loop.
            while (!system->quitting()) {
                if (system->running()) {
                    // This will run until paused or interrupted somehow.
                    emulator->m_cpu->Execute();
                } else {
                    // The "update" method will be called periodically by the emulator while
                    // it's running, meaning if we want our UI to work, we have to manually
                    // call "update" when the emulator is paused.
                    s_ui->update();
                }
            }
            system->pause();
            system->m_eventBus->signal(PCSX::Events::Quitting{});
            system->purgeAllEvents();
        } catch (...) {
            // This will ensure we don't do certain cleanups that are awaiting other tasks,
            // which could result in deadlocks on exit in case we encountered a serious problem.
            // This may cause data loss when writing files, but that's life when encountering
            // a serious problem in a software.
            system->setEmergencyExit();
            uvThread.setEmergencyExit();
            throw;
        }
    }

    return exitCode;
}
