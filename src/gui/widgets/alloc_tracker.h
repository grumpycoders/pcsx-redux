/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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

#include <cstddef>

namespace PCSX {

namespace Widgets {

/*

Viewer for the generic allocator tracker.

Deliberately not folded into the PSYQo heap viewer even though the two look
similar on screen. That one walks an allocator's own free list and therefore
knows which space is free; this one only knows the blocks it watched being
handed out, so the space between them is UNKNOWN. Rendering both through one
widget is how "unknown" quietly becomes "free", and a fragmentation number
derived from it would be fiction. They also have different requirements: this
one needs the interpreter with the debugger on, and has to say so loudly rather
than showing an empty map that reads as a healthy heap.

*/

class AllocTrackerViewer {
  public:
    AllocTrackerViewer(bool& show) : m_show(show) {}
    void draw(const char* title);

    bool& m_show;

  private:
    size_t m_selectedArena = 0;
    bool m_onlySinceMark = false;
};

}  // namespace Widgets
}  // namespace PCSX
