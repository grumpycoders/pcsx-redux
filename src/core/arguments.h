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

#include <stdint.h>

#include "flags.h"

namespace PCSX {

class Arguments {
  public:
    Arguments(const CommandLine::args& args);
    Arguments(const Arguments&) = delete;
    Arguments(Arguments&&) = delete;
    Arguments& operator=(const Arguments&) = delete;
    Arguments& operator=(Arguments&&) = delete;

    // Returns true if stdout should be enabled.
    // Enabled with the flags -stdout (but not when -tui is used), -no-ui, or -cli.
    bool isStdoutEnabled() const { return m_stdoutEnabled; }

    // Returns true if Lua should be displaying its console output to stdout.
    // Enabled with the flags -lua_stdout, -no-ui, or -cli.
    bool isLuaStdoutEnabled() const { return m_luaStdoutEnabled; }

    // Returns true if the GUI logs window should be enabled.
    // Disabled with -testmode or -no-gui-log.
    bool enableGUILogs() const { return m_guiLogsEnabled; }

    // Returns true if the the flag -testmode was used.
    bool isTestModeEnabled() const { return m_testModeEnabled; }

  private:
    bool m_luaStdoutEnabled = false;
    bool m_stdoutEnabled = false;
    bool m_guiLogsEnabled = true;
    bool m_testModeEnabled = false;
};

}  // namespace PCSX
