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

#include <list>
#include <memory>
#include <string>
#include <vector>

#include "core/cputrace.h"
#include "gui/widgets/filedialog.h"

namespace PCSX {

class GUI;

namespace Widgets {

// Explorer for the binary CPU trace. The main window reads g_emulator->m_cpuTrace;
// traces loaded from disk open in windows of their own. Each row is rendered by
// feeding the record's sparse values back through the disassembler
// (PlaybackValueSource), so the line matches what live "with values" disassembly
// would have shown. Windows with Sync ticked scroll together by record index.
class CpuTrace {
  public:
    CpuTrace(bool& show, std::vector<std::string>& favorites);
    void draw(GUI* gui, const char* title);

    bool& m_show;

  private:
    struct View {
        char jumpString[16] = {0};
        int64_t scrollTo = -1;  // row to scroll to on the next frame, or -1
        bool followTail = false;
        bool sync = false;
        int64_t lastTop = -1;
    };
    struct Loaded {
        std::string name;
        PCSX::CpuTrace trace;
        View view;
        bool show = true;
    };

    void drawView(GUI* gui, const PCSX::CpuTrace& trace, View& view, bool live);

    View m_live;
    std::list<Loaded> m_loaded;
    int64_t m_syncRow = -1;
    std::string m_error;
    FileDialog<FileDialogMode::Save> m_exportTextDialog;
    FileDialog<FileDialogMode::Save> m_saveDialog;
    FileDialog<FileDialogMode::Open> m_loadDialog;
};

}  // namespace Widgets
}  // namespace PCSX
