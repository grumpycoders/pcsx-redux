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
#include <memory>
#include <string>
#include <vector>

#include "cdrom/iso9660-reader.h"
#include "gui/widgets/filedialog.h"
#include "imgui_memory_editor/imgui_memory_editor.h"
#include "support/coroutine.h"
#include "support/file.h"
#include "supportpsx/iso9660-lowlevel.h"

namespace PCSX {

class CDRom;
class CDRIso;

namespace Widgets {

class IsoBrowser {
  public:
    IsoBrowser(bool& show, std::vector<std ::string>& favorites)
        : m_show(show),
          m_openIsoFileDialog(l_("Open Disk Image"), favorites),
          m_saveFileDialog(l_("Extract File"), favorites),
          m_openReplaceFileDialog(l_("Replace File"), favorites) {}
    void draw(CDRom* cdrom, const char* title);

    bool& m_show;

  private:
    uint32_t m_fullCRC = 0;
    uint32_t m_crcs[100] = {0};
    Coroutine<> m_crcCalculator;
    float m_crcProgress = 0.0f;
    Coroutine<> computeCRC(CDRIso*);

    std::unique_ptr<ISO9660Reader> m_reader;
    std::weak_ptr<CDRIso> m_cachedIso;
    std::string m_selectedPath;
    ISO9660LowLevel::DirEntry m_selectedEntry;
    uint32_t m_selectedLBA = 0;
    uint32_t m_selectedSize = 0;
    bool m_hasSelection = false;
    bool m_selectedIsDir = false;
    bool m_selectedIsGap = false;

    Coroutine<> m_extractionCoroutine;
    float m_extractionProgress = 0.0f;

    bool m_flatView = false;
    struct FlatEntry {
        std::string path;
        uint32_t lba;
        uint32_t size;
        bool isDir;
        bool isGap;
        ISO9660LowLevel::DirEntry dirEntry;
    };
    std::vector<FlatEntry> m_flatEntries;
    bool m_flatEntriesDirty = true;

    void drawFilesystemTree(const ISO9660LowLevel::DirEntry& entry, const std::string& path);
    void drawFilesystemFlat();
    void collectFlatEntries(const ISO9660LowLevel::DirEntry& entry, const std::string& path);

    FileDialog<> m_openIsoFileDialog;
    FileDialog<FileDialogMode::Save> m_saveFileDialog;
    FileDialog<> m_openReplaceFileDialog;

    bool m_hexEditorOpen = false;
    size_t m_hexEditorOffset = 0;
    MemoryEditor m_hexEditor{m_hexEditorOpen, 0, m_hexEditorOffset};
    IO<File> m_hexEditFile;
};

}  // namespace Widgets
}  // namespace PCSX
