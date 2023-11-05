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

#include <limits>

namespace PCSX {
class GPULogger;
namespace Widgets {

class GPULogger {
  public:
    GPULogger(bool& show) : m_show(show) {}
    void draw(PCSX::GPULogger* logger, const char* title);

    bool& m_show;
    bool m_replay = false;
    bool m_showOrigins = false;
    bool m_expandAll = false;
    bool m_collapseAll = false;
    bool m_setHighlightRange = false;
    bool m_hoverHighlight = false;
    uint64_t m_frameCounterOrigin = 0;
    unsigned m_beginHighlight = 0;
    unsigned m_endHighlight = std::numeric_limits<unsigned>::max();
};

}  // namespace Widgets
}  // namespace PCSX
