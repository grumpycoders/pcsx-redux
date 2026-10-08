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

#include <string>

namespace PCSX {

class GUI;

namespace Widgets {

// Explorer for the binary CPU trace. Reads g_emulator->m_cpuTrace and renders
// each captured instruction by feeding its sparse values back through the
// disassembler (PlaybackValueSource), so the line matches what live "with
// values" disassembly would have shown - reconstructed from the 32-byte record.
class CpuTrace {
  public:
    CpuTrace(bool& show) : m_show(show) {}
    void draw(GUI* gui, const char* title);

    bool& m_show;

  private:
    char m_jumpString[16] = {0};
    int64_t m_scrollTo = -1;     // row to scroll to on the next frame, or -1
    bool m_followTail = false;   // keep the view pinned to the latest record
};

}  // namespace Widgets
}  // namespace PCSX
