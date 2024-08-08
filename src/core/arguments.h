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

#include <string>
#include <string_view>

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
    bool isGUILogsEnabled() const { return m_guiLogsEnabled; }

    // Returns true if the the flag -testmode was used.
    bool isTestModeEnabled() const { return m_testModeEnabled; }

    // Returns true if the the flag -portable was used, if the executable is
    // located in the same directory as the pcsx.json file, or if the
    // executable is being run from its source tree.
    bool isPortable() const { return m_portable; }

    // Returns true if the safe mode was enabled. This implies
    // that the pcsx.json file won't be loaded.
    // Enabled with the flags -safe, -testmode, or -cli.
    bool isSafeModeEnabled() const { return m_safeModeEnabled; }

    // Returns true if the user requested to reset the UI.
    // Enabled with the flag -resetui.
    bool isUIResetRequested() const { return m_uiResetRequested; }

    // Returns true if the user requested that no shaders be used.
    // Enabled with the flag -noshaders.
    bool isShadersDisabled() const { return m_shadersDisabled; }

    // Returns true if the user requested that no update be performed.
    // Enabled with the flag -noupdate.
    bool isUpdateDisabled() const { return m_updateDisabled; }

    // Returns true if the user requested that viewports be enabled.
    // Toggled with the flags -viewports / -no-viewports.
    bool isViewportsEnabled() const { return m_viewportsEnabled; }

    // Returns the path to the portable directory.
    // Set with the flag -portable.
    std::string_view getPortablePath() const { return m_portablePath; }

  private:
    std::string m_portablePath = "";
    bool m_luaStdoutEnabled = false;
    bool m_stdoutEnabled = false;
    bool m_guiLogsEnabled = true;
    bool m_testModeEnabled = false;
    bool m_portable = false;
    bool m_safeModeEnabled = false;
    bool m_uiResetRequested = false;
    bool m_shadersDisabled = false;
    bool m_updateDisabled = false;
#ifdef __linux__
    bool m_viewportsEnabled = false;
#else
    bool m_viewportsEnabled = true;
#endif
};

}  // namespace PCSX
