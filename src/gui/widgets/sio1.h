/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
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
struct SIO1Registers;
struct SIO1RegisterText;
class GUI;

namespace Widgets {

class SIO1 {
  public:
    void draw(GUI* gui, SIO1Registers* registers, const char* title);

    bool m_show = false;

  private:
    template <typename T>
    void DrawRegisterEditor(T* reg, const char* regname, SIO1RegisterText* reg_text, int bit_length,
                                             const char* displayformat);

    char m_registerEditor[9]; // Room for 8 nibbles + \0
};

}  // namespace Widgets
}  // namespace PCSX
