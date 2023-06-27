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

#include "core/ui.h"

namespace PCSX {

class TUI : public UI {
  public:
    TUI(const CommandLine::args &args);
    ~TUI();
    bool addLog(LogClass logClass, const std::string &msg) override;
    void addLuaLog(const std::string &msg, bool error) override;
    void init() override;
    void setLua(Lua L) override;
    void close() override;
    void update(bool vsync = false) override;
    void addNotification(const std::string &notification) override;
};

}  // namespace PCSX
