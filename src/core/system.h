/***************************************************************************
 *   Copyright (C) 2018 PCSX-Redux authors                                 *
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

#pragma once

#include <stdarg.h>

#include <filesystem>
#include <map>
#include <string>
#include <vector>

#include "support/eventbus.h"

namespace PCSX {

// a hack, until c++-20 is fully adopted everywhere.
#if defined(__cpp_lib_char8_t)
typedef std::u8string u8string;
#define MAKEU8(x) x
#else
typedef std::string u8string;
#define MAKEU8(x) reinterpret_cast<const char *>(x)
#endif

namespace Events {
struct SettingsLoaded {};
struct Quitting {};
namespace ExecutionFlow {
struct Run {};
struct Pause {};
struct SoftReset {};
struct HardReset {};
}  // namespace ExecutionFlow
}  // namespace Events

class System {
  public:
    virtual ~System() {}
    // Requests a system reset
    virtual void softReset() = 0;
    virtual void hardReset() = 0;
    // Printf used by bios syscalls
    virtual void biosPutc(int c) = 0;
    virtual void biosPrintf(const char *fmt, ...) = 0;
    virtual void vbiosPrintf(const char *fmt, va_list va) = 0;
    // Printf used by the code in general, to indicate errors most of the time
    // TODO: convert them all to logs
    virtual void printf(const char *fmt, ...) = 0;
    // Add a log line
    virtual void log(const char *facility, const char *fmt, va_list a) = 0;
    // Message used to print msg to users
    virtual void message(const char *fmt, ...) = 0;
    // Called on VBlank (to update i.e. pads)
    virtual void update() = 0;
    // Returns to the Gui
    virtual void runGui() = 0;
    // Close mem and plugins
    virtual void close() = 0;
    bool running() { return m_running; }
    bool quitting() { return m_quitting; }
    int exitCode() { return m_exitCode; }
    void start() {
        m_running = true;
        m_eventBus->signal(Events::ExecutionFlow::Run{});
    }
    void stop() {
        m_running = false;
        m_eventBus->signal(Events::ExecutionFlow::Pause{});
    }
    void pause() {
        m_running = false;
        m_eventBus->signal(Events::ExecutionFlow::Pause{});
    }
    void resume() {
        m_running = true;
        m_eventBus->signal(Events::ExecutionFlow::Run{});
    }
    void quit(int code = 0) {
        m_eventBus->signal(Events::Quitting{});
        m_quitting = true;
        pause();
        m_exitCode = code;
    }

    std::shared_ptr<EventBus::EventBus> m_eventBus = std::make_shared<EventBus::EventBus>();

  private:
    static inline constexpr uint64_t djbProcess(uint64_t hash, const char str[], size_t n) {
        return n ? djbProcess(((hash << 5) + hash) ^ str[0], str + 1, n - 1) : hash;
    }

  public:
    void setBinDir(std::filesystem::path path) { m_binDir = path; }
    template <size_t S>
    static inline constexpr uint64_t ctHash(const char (&str)[S]) {
        return djbProcess(5381, str, S - 1);
    }
    static inline constexpr uint64_t hash(const char *str, size_t n) { return djbProcess(5381, str, n); }
    static inline uint64_t hash(const std::string &str) { return djbProcess(5381, str.c_str(), str.length()); }

    const char *getStr(uint64_t hash, const char *str) {
        auto ret = m_i18n.find(hash);
        if (ret == m_i18n.end()) return str;
        return ret->second.c_str();
    }

    void loadAllLocales() {
        static const std::map<std::string, std::string> locales = {{"Français", "fr.po"}, {"Deutsch", "de.po"}};

        for (auto &l : locales) {
            if (loadLocale(l.first, m_binDir / "i18n" / l.second)) {
            } else if (loadLocale(l.first, std::filesystem::current_path() / "i18n" / l.second)) {
            } else if (loadLocale(l.first, m_binDir / l.second)) {
            } else {
                loadLocale(l.first, std::filesystem::current_path() / l.second);
            }
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
    std::string localeName() { return m_currentLocale; }
    std::vector<std::string> localesNames() {
        std::vector<std::string> locales;
        for (auto &l : m_locales) {
            locales.push_back(l.first);
        }
        return locales;
    }

  private:
    std::map<uint64_t, std::string> m_i18n;
    std::map<std::string, decltype(m_i18n)> m_locales;
    std::string m_currentLocale;
    bool m_running = false;
    bool m_quitting = false;
    int m_exitCode = 0;
    std::filesystem::path m_binDir;
};

extern System *g_system;

}  // namespace PCSX

#define _(str) PCSX::g_system->getStr(PCSX::System::ctHash(str), str)
