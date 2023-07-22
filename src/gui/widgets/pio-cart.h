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

#include <stdbool.h>

#include "gui/widgets/filedialog.h"

namespace PCSX {

namespace Widgets {
class PIOCart {
  public:
    PIOCart(bool& show) : m_show(show) {}
    bool draw(const char* title);
    bool& m_show;

  private:
    Widgets::FileDialog<> m_selectEXP1Dialog = {[]() { return _("Select EXP1"); }};
    int m_flashSizeIndex;
    bool m_switchOn = 1;
};
}  // namespace Widgets
}  // namespace PCSX
