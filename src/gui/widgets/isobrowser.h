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

#include <stdint.h>

#include <functional>

#include "support/coroutine.h"

namespace PCSX {

class CDRom;
class CDRIso;

namespace Widgets {

class IsoBrowser {
  public:
    IsoBrowser(bool& show) : m_show(show) {}
    void draw(CDRom* cdrom, const char* title);

    bool& m_show;

  private:
    uint32_t m_fullCRC = 0;
    uint32_t m_crcs[100] = {0};
    Coroutine<> m_crcCalculator;
    float m_crcProgress = 0.0f;

    Coroutine<> computeCRC(CDRIso*);
};

}  // namespace Widgets
}  // namespace PCSX
