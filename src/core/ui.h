/***************************************************************************
 *   Copyright (C) 2023 PCSX-Redux authors                                 *
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

#include <string>
#include <utility>

#include "core/system.h"
#include "json.hpp"
#include "lua/luawrapper.h"
#include "flags.h"

namespace PCSX {

enum class LogClass : unsigned;

class UI {
  public:
    UI(const CommandLine::args &args);
    virtual void addNotification(const std::string &notification) = 0;
    virtual bool addLog(LogClass logClass, const std::string &msg) = 0;
    virtual void addLuaLog(const std::string &msg, bool error) = 0;
    virtual void init() = 0;
    virtual void setLua(Lua L) = 0;
    virtual void close() = 0;
    virtual void update(bool vsync = false) = 0;

    struct {
        bool empty() const { return filename.empty(); }
        void set(const PCSX::u8string &newfilename) {
            filename = newfilename;
            pauseAfterLoad = !g_system->running();
            if (!empty()) {
                g_system->resume();
            }
        }
        PCSX::u8string &&get() { return std::move(filename); }
        bool hasToPause() { return pauseAfterLoad; }

      private:
        PCSX::u8string filename;
        bool pauseAfterLoad = true;
    } m_exeToLoad;

  protected:
    using json = nlohmann::json;
    json m_settingsJson;
    const CommandLine::args &m_args;
    EventBus::Listener m_listener;

    bool loadSettings();
    void finishLoadSettings();
    void setLuaCommon(Lua L);
    void tick();

  private:
    void shellReached();
};

}  // namespace PCSX
