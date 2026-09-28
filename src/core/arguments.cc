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

#include "support/binpath.h"

PCSX::Arguments::Arguments(const PCSX::CommandLine& args) {
    if (args.has("lua_stdout") || args.has("no-ui") || args.has("cli")) {
        m_luaStdoutEnabled = true;
    }
    if (args.has("stdout") && !args.has("tui")) m_stdoutEnabled = true;
    if (args.has("no-ui") || args.has("cli")) m_stdoutEnabled = true;
    if (args.has("testmode") || args.has("no-gui-log")) m_guiLogsEnabled = false;
    if (args.has("testmode")) m_testModeEnabled = true;
    if (args.has("portable")) m_portable = true;
    auto portablePath = args.value("portable");
    if (portablePath.has_value()) m_portablePath = portablePath.value();
    if (std::filesystem::exists("pcsx.json")) m_portable = true;
    if (std::filesystem::exists(std::filesystem::path("vsprojects") / "pcsx-redux.sln")) m_portable = true;
    if (std::filesystem::exists(std::filesystem::path("..") / "pcsx-redux.sln")) m_portable = true;
    if (!m_portable) {
        // The probes above are relative to the current directory, which is only the install
        // directory when the binary was started from it. A shortcut with its own start-in, a
        // file association on a disc image, or a frontend will all hand us something else, so
        // look next to the binary too, and anchor the portable directory there when that's
        // what matched. Without this, whether an install is portable depends on how it was
        // launched rather than on where it lives.
        std::filesystem::path binDir = std::filesystem::path(BinPath::getExecutablePath()).parent_path();
        if (!binDir.empty() && std::filesystem::exists(binDir / "pcsx.json")) {
            m_portable = true;
            m_portablePath = binDir.string();
        }
    }
    if (args.has("no-portable")) m_portable = false;
    if (args.has("safe") || args.has("testmode") || args.has("cli")) m_safeModeEnabled = true;
    if (args.has("resetui")) m_uiResetRequested = true;
    if (args.has("noshaders")) m_shadersDisabled = true;
    if (args.has("noupdate")) m_updateDisabled = true;
    if (args.has("viewports")) m_viewportsEnabled = true;
    if (args.has("no-viewports")) m_viewportsEnabled = false;
}
