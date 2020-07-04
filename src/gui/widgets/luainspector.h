/***************************************************************************
 *   Copyright (C) 2020 PCSX-Redux authors                                 *
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

namespace PCSX {
class Lua;
namespace Widgets {

class LuaInspector {
  public:
    LuaInspector(bool& show) : m_show(show) {}
    void draw(const char* title, Lua* L);

    bool& m_show;

  private:
    void dumpTree(const std::string& label, Lua* L, int i);
    enum class Display {
        GLOBALS,
        STACK,
        REGISTRY,
    } m_display = Display::GLOBALS;
};

}  // namespace Widgets
}  // namespace PCSX
