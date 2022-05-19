/***************************************************************************
 *   Copyright (C) 2018 PCSX-Redux authors                                 *
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

#include <stdarg.h>
#include <uv.h>

#include <chrono>
#include <filesystem>
#include <limits>
#include <map>
#include <string>
#include <vector>

#include "flags.h"
#include "fmt/format.h"
#include "fmt/printf.h"
#include "imgui.h"
#include "support/djbhash.h"
#include "support/eventbus.h"
#include "support/version.h"

namespace PCSX {

enum class LogClass : unsigned;

// a hack, until C++-20 is fully adopted everywhere.
typedef decltype(std::filesystem::path().u8string()) u8string;
#define MAKEU8(x) reinterpret_cast<const decltype(PCSX::u8string::value_type()) *>(x)

// another hack, until C++-20 properly gets std::chrono::clock_cast
template <typename DstTP, typename SrcTP, typename DstClk = typename DstTP::clock,
          typename SrcClk = typename SrcTP::clock>
DstTP ClockCast(const SrcTP tp) {
    const SrcTP srcNow = SrcClk::now();
    const DstTP dstNow = DstClk::now();
    return std::chrono::time_point_cast<typename DstClk::duration>(tp - srcNow + dstNow);
}

namespace Events {
struct SettingsLoaded {
    bool safe = false;
};
struct Quitting {};
struct LogMessage {
    LogClass logClass;
    std::string message;
};
namespace ExecutionFlow {
struct ShellReached {};
struct Run {};
struct Pause {
    bool exception = false;
};
struct Reset {
    bool hard = false;
};
}  // namespace ExecutionFlow
namespace GUI {
struct JumpToPC {
    uint32_t pc;
};
struct JumpToMemory {
    uint32_t address;
    unsigned size;
};
}  // namespace GUI
struct CreatedVRAMTexture {
    unsigned int id;
};
struct Keyboard {
    int key, scancode, action, mods;
};
}  // namespace Events

class System {
  public:
    System() { uv_loop_init(&m_loop); }
    virtual ~System() { uv_loop_close(&m_loop); }
    // Requests a system reset
    virtual void softReset() = 0;
    virtual void hardReset() = 0;
    // Putc used by bios syscalls
    virtual void biosPutc(int c) = 0;
    virtual const CommandLine::args &getArgs() = 0;

    // Legacy printf stuff; needs to be replaced with loggers
    template <typename... Args>
    void printf(const char *format, const Args &... args) {
        std::string s = fmt::sprintf(format, args...);
        printf(std::move(s));
    }
    virtual void printf(std::string &&) = 0;
    // Add a log line
    template <typename... Args>
    void log(LogClass logClass, const char *format, const Args &... args) {
        std::string s = fmt::sprintf(format, args...);
        log(logClass, std::move(s));
    }
    virtual void log(LogClass, std::string &&) = 0;
    // Display a popup message to the user
    template <typename... Args>
    void message(const char *format, const Args &... args) {
        std::string s = fmt::sprintf(format, args...);
        message(std::move(s));
    }
    virtual void message(std::string &&) = 0;
    // For the Lua output
    virtual void luaMessage(const std::string &, bool error) = 0;
    // Called periodically; if vsync = true, this while the emulated hardware vsyncs
    virtual void update(bool vsync = false) = 0;
    // Close mem and plugins
    virtual void close() = 0;
    virtual void purgeAllEvents() = 0;
    bool running() { return m_running; }
    const bool *runningPtr() { return &m_running; }
    bool quitting() { return m_quitting; }
    int exitCode() { return m_exitCode; }
    void start() {
        if (m_running) return;
        m_running = true;
        m_eventBus->signal(Events::ExecutionFlow::Run{});
    }
    void stop() {
        if (!m_running) return;
        m_running = false;
        m_eventBus->signal(Events::ExecutionFlow::Pause{});
    }
    void pause(bool exception = false) {
        if (!m_running) return;
        m_running = false;
        m_eventBus->signal(Events::ExecutionFlow::Pause{exception});
    }
    void resume() {
        if (m_running) return;
        m_running = true;
        m_eventBus->signal(Events::ExecutionFlow::Run{});
    }
    virtual void testQuit(int code) = 0;
    void quit(int code = 0) {
        m_quitting = true;
        pause();
        m_exitCode = code;
        m_eventBus->signal(Events::Quitting{});
        purgeAllEvents();
    }

    std::shared_ptr<EventBus::EventBus> m_eventBus = std::make_shared<EventBus::EventBus>();

    const char *getStr(uint64_t hash, const char *str) const {
        auto ret = m_i18n.find(hash);
        if (ret == m_i18n.end()) return str;
        return ret->second.c_str();
    }

    bool findResource(std::function<bool(const std::filesystem::path &path)> walker, const std::filesystem::path &name,
                      const std::filesystem::path &releasePath, const std::filesystem::path &sourcePath);
    void loadAllLocales() {
        for (auto &l : LOCALES) {
            findResource([name = l.first, this](std::filesystem::path filename) { return loadLocale(name, filename); },
                         l.second.filename, "i18n", "i18n");
        }
    }

    bool loadLocale(const std::string &name, const std::filesystem::path &path);
    void activateLocale(const std::string &name) {
        if (name == "English") {
            m_currentLocale = "English";
            m_i18n = {};
            return;
        }
        auto locale = m_locales.find(name);
        if (locale == m_locales.end()) return;
        m_i18n = locale->second;
        m_currentLocale = name;
    }
    std::string localeName() const { return m_currentLocale; }
    const ImWchar *getLocaleRanges() const {
        auto localeInfo = LOCALES.find(m_currentLocale);
        if (localeInfo == LOCALES.end()) return nullptr;
        return localeInfo->second.ranges;
    }
    std::vector<std::pair<PCSX::u8string, const ImWchar *>> getLocaleExtra() {
        auto localeInfo = LOCALES.find(m_currentLocale);
        if (localeInfo == LOCALES.end()) return {};
        return localeInfo->second.extraFonts;
    }
    std::vector<std::string> localesNames() {
        std::vector<std::string> locales;
        for (auto &l : m_locales) {
            locales.push_back(l.first);
        }
        return locales;
    }

    std::filesystem::path getBinDir() const { return m_binDir; }
    const VersionInfo &getVersion() const { return m_version; }

    // needs to be odd, and is a replica of ImGui's range tables
    enum class Range {
        KOREAN = 1,
        JAPANESE = 3,
        CHINESE_FULL = 5,
        CHINESE_SIMPLIFIED = 7,
        CYRILLIC = 9,
        THAI = 11,
        VIETNAMESE = 13,
    };

    uv_loop_t *getLoop() { return &m_loop; }

  private:
    uv_loop_t m_loop;
    std::map<uint64_t, std::string> m_i18n;
    std::map<std::string, decltype(m_i18n)> m_locales;
    std::string m_currentLocale;
    bool m_running = false;
    bool m_quitting = false;
    int m_exitCode = 0;
    struct LocaleInfo {
        const std::string filename;
        const std::vector<std::pair<PCSX::u8string, const ImWchar *>> extraFonts;
        const ImWchar *ranges = nullptr;
    };
    static const std::map<std::string, LocaleInfo> LOCALES;

  protected:
    std::filesystem::path m_binDir;
    PCSX::VersionInfo m_version;
};

extern System *g_system;

}  // namespace PCSX

#define _(str) PCSX::g_system->getStr(PCSX::djbHash::ctHash(str), str)
#define f_(str) fmt::runtime(PCSX::g_system->getStr(PCSX::djbHash::ctHash(str), str))
