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

namespace PCSX {

namespace Widgets {

class Breakpoints {
  public:
    void draw(const char* title);
    bool m_show = false;

  private:
    bool m_filterE = true;
    bool m_filterR1 = true;
    bool m_filterR2 = true;
    bool m_filterR4 = true;
    bool m_filterW1 = true;
    bool m_filterW2 = true;
    bool m_filterW4 = true;
    char m_bpAddressString[20];
    int m_breakpointType = 0;
    int m_breakpointWidth = 1;
};

}  // namespace Widgets

}  // namespace PCSX
