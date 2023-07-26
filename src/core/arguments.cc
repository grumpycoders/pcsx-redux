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

#include "core/arguments.h"

#include <filesystem>

PCSX::Arguments::Arguments(const CommandLine::args& args) {
    if (args.get<bool>("lua_stdout") || args.get<bool>("no-ui") || args.get<bool>("cli")) {
        m_luaStdoutEnabled = true;
    }
    if (args.get<bool>("stdout") && !args.get<bool>("tui")) m_stdoutEnabled = true;
    if (args.get<bool>("no-ui") || args.get<bool>("cli")) m_stdoutEnabled = true;
    if (args.get<bool>("testmode") || args.get<bool>("no-gui-log")) m_guiLogsEnabled = false;
    if (args.get<bool>("testmode")) m_testModeEnabled = true;
    if (args.get<bool>("portable")) m_portable = true;
    if (std::filesystem::exists("pcsx.json")) m_portable = true;
    if (std::filesystem::exists("Makefile")) m_portable = true;
    if (std::filesystem::exists(std::filesystem::path("..") / "pcsx-redux.sln")) m_portable = true;
    if (args.get<bool>("safe") || args.get<bool>("testmode") || args.get<bool>("cli")) m_safeModeEnabled = true;
    if (args.get<bool>("resetui")) m_uiResetRequested = true;
    if (args.get<bool>("noshaders")) m_shadersDisabled = true;
    if (args.get<bool>("noupdate")) m_updateDisabled = true;
    if (args.get<bool>("viewports")) m_viewportsEnabled = true;
    if (args.get<bool>("no-viewports")) m_viewportsEnabled = false;
}
