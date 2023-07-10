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

#include "main/textui.h"

#include <chrono>
#include <thread>

PCSX::TUI::TUI(const CommandLine::args &args) : UI(args) {}
PCSX::TUI::~TUI() {}

bool PCSX::TUI::addLog(LogClass logClass, const std::string &msg) { return true; }

void PCSX::TUI::addLuaLog(const std::string &msg, bool error) {}

void PCSX::TUI::init(std::function<void()> applyArguments) {
    loadSettings();
    applyArguments();
    finishLoadSettings();
}

void PCSX::TUI::setLua(Lua L) { setLuaCommon(L); }

void PCSX::TUI::close() {}

void PCSX::TUI::update(bool vsync) {
    tick();
    if (!g_system->running()) {
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(10ms);
    }
}

void PCSX::TUI::addNotification(const std::string &notification) {}
