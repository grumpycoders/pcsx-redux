/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#include "imgui.h"

namespace PCSX {
namespace Widgets {

class Log {
  public:
    void clear();
    void addLog(const char* fmt, ...) IM_FMTARGS(2) {
        va_list args;
        va_start(args, fmt);
        addLog(fmt, args);
        va_end(args);
    }
    void addLog(const char* fmt, va_list args);
    void draw(const char* title);

    bool m_show = false;

  private:
    ImGuiTextBuffer m_buffer;
    ImGuiTextFilter m_filter;
    ImVector<int> m_lineOffsets;  // Index to lines offset
    bool m_scrollToBottom = false;
    bool m_follow = true;
};

}  // namespace Widgets
}  // namespace PCSX
