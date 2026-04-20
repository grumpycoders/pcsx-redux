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
#include "support/list.h"
#include "supportpsx/iso9660-lowlevel.h"

namespace PCSX {

class CDRom;
class CDRIso;

namespace Widgets {

class IsoBrowser {
  public:
    IsoBrowser(bool& show, std::vector<std ::string>& favorites, std::function<void()> monoFont = nullptr)
        : m_show(show),
          m_openIsoFileDialog(l_("Open Disk Image"), favorites),
          m_saveFileDialog(l_("Extract File"), favorites),
          m_openReplaceFileDialog(l_("Replace File"), favorites),
          m_monoFont(monoFont) {}
    ~IsoBrowser() { m_hexEditors.destroyAll(); }
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
        enum Type { File, Directory, Gap, HiddenM1, HiddenM2F1, HiddenM2F2, System };
        std::string path;
        uint32_t lba;
        uint32_t size;
        uint32_t sectors;  // Actual sector span on disc, derived from XA form for Form 2 files.
        Type type;
        ISO9660LowLevel::DirEntry dirEntry;

        bool isGap() const { return type == Gap; }
        bool isDir() const { return type == Directory; }
        bool isHidden() const { return type == HiddenM1 || type == HiddenM2F1 || type == HiddenM2F2; }
        bool isSelectable() const { return type != Directory; }
    };
    std::vector<FlatEntry> m_flatEntries;
    bool m_flatEntriesDirty = true;
    bool m_gapsScanned = false;

    void drawFilesystemTree(const ISO9660LowLevel::DirEntry& entry, const std::string& path);
    void drawFilesystemFlat();
    void collectFlatEntries(const ISO9660LowLevel::DirEntry& entry, const std::string& path);
    void scanGapSectors(std::vector<FlatEntry>& out, uint32_t startLBA, uint32_t sectorCount,
                        std::shared_ptr<CDRIso> iso);

    FileDialog<> m_openIsoFileDialog;
    FileDialog<FileDialogMode::Save> m_saveFileDialog;
    FileDialog<> m_openReplaceFileDialog;

    struct HexEditorInstance : public Intrusive::List<HexEditorInstance>::Node {
        HexEditorInstance(const std::string& title, IO<File> file, std::function<void()> monoFont)
            : m_title(title), m_file(file), m_editor(m_open, 0, m_offset) {
            m_editor.OptShowDataPreview = true;
            m_editor.OptUpperCaseHex = false;
            m_editor.PushMonoFont = monoFont;
        }
        std::string m_title;
        IO<File> m_file;
        bool m_open = true;
        size_t m_offset = 0;
        MemoryEditor m_editor;
    };
    Intrusive::List<HexEditorInstance> m_hexEditors;
    std::function<void()> m_monoFont;

    void openHexEditor(const std::string& title, IO<File> file);
};

}  // namespace Widgets
}  // namespace PCSX
