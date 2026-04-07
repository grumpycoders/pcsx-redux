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

#include "gui/widgets/isobrowser.h"

#include <zlib.h>

#include <algorithm>
#include <chrono>

#include "cdrom/cdriso.h"
#include "cdrom/ppf.h"
#include "core/cdrom.h"
#include "fmt/format.h"
#include "imgui/imgui.h"
#include "support/imgui-helpers.h"
#include "support/uvfile.h"

PCSX::Coroutine<> PCSX::Widgets::IsoBrowser::computeCRC(PCSX::CDRIso* iso) {
    auto time = std::chrono::steady_clock::now();

    uint32_t fullCRC = crc32(0L, Z_NULL, 0);
    uint32_t lba = 0;
    for (unsigned t = 1; t <= iso->getTN(); t++) {
        uint32_t len = iso->getLength(t).toLBA();
        uint32_t crc = crc32(0L, Z_NULL, 0);
        uint8_t buffer[2352];
        for (unsigned s = 0; s < len; s++) {
            iso->readSectors(lba++, buffer, 1);
            fullCRC = crc32(fullCRC, buffer, 2352);
            crc = crc32(crc, buffer, 2352);
            if (std::chrono::steady_clock::now() - time > std::chrono::milliseconds(50)) {
                m_crcProgress = (float)s / (float)len;
                co_yield m_crcCalculator.awaiter();
                time = std::chrono::steady_clock::now();
            }
        }
        m_crcs[t] = crc;
    }

    m_fullCRC = fullCRC;
};

void PCSX::Widgets::IsoBrowser::drawFilesystemTree(const ISO9660LowLevel::DirEntry& entry, const std::string& path) {
    auto entries = m_reader->listAllEntriesFrom(entry);

    for (auto& [dirEntry, xa] : entries) {
        const auto& filename = dirEntry.get<ISO9660LowLevel::DirEntry_Filename>().value;
        if (filename.size() == 1 && (filename[0] == '\0' || filename[0] == '\1')) continue;

        bool isDir = (dirEntry.get<ISO9660LowLevel::DirEntry_Flags>().value & 2) != 0;
        uint32_t lba = dirEntry.get<ISO9660LowLevel::DirEntry_LBA>();
        uint32_t size = dirEntry.get<ISO9660LowLevel::DirEntry_Size>();
        auto fullPath = path.empty() ? filename : path + "/" + filename;

        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);

        if (isDir) {
            bool open = ImGui::TreeNodeEx(filename.c_str(), ImGuiTreeNodeFlags_SpanFullWidth);
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%u", lba);
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(_("<DIR>"));
            if (open) {
                drawFilesystemTree(dirEntry, fullPath);
                ImGui::TreePop();
            }
        } else {
            ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_Bullet |
                                       ImGuiTreeNodeFlags_NoTreePushOnOpen | ImGuiTreeNodeFlags_SpanFullWidth;
            if (m_hasSelection && m_selectedPath == fullPath) flags |= ImGuiTreeNodeFlags_Selected;
            ImGui::TreeNodeEx(filename.c_str(), flags);
            if (ImGui::IsItemClicked()) {
                m_selectedPath = fullPath;
                m_selectedEntry = dirEntry;
                m_hasSelection = true;
                m_selectedIsDir = false;
            }
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%u", lba);
            ImGui::TableSetColumnIndex(2);
            auto str = fmt::format("{}", size);
            ImGui::TextUnformatted(str.c_str());
        }
    }
}

void PCSX::Widgets::IsoBrowser::collectFlatEntries(const ISO9660LowLevel::DirEntry& entry, const std::string& path) {
    auto entries = m_reader->listAllEntriesFrom(entry);
    for (auto& [dirEntry, xa] : entries) {
        const auto& filename = dirEntry.get<ISO9660LowLevel::DirEntry_Filename>().value;
        if (filename.size() == 1 && (filename[0] == '\0' || filename[0] == '\1')) continue;

        bool isDir = (dirEntry.get<ISO9660LowLevel::DirEntry_Flags>().value & 2) != 0;
        uint32_t lba = dirEntry.get<ISO9660LowLevel::DirEntry_LBA>();
        uint32_t size = dirEntry.get<ISO9660LowLevel::DirEntry_Size>();
        auto fullPath = path.empty() ? filename : path + "/" + filename;

        m_flatEntries.push_back({fullPath, lba, size, isDir, dirEntry});
        if (isDir) collectFlatEntries(dirEntry, fullPath);
    }
}

void PCSX::Widgets::IsoBrowser::drawFilesystemFlat() {
    if (m_flatEntriesDirty) {
        m_flatEntries.clear();
        collectFlatEntries(m_reader->getRootDirEntry(), "");
        std::sort(m_flatEntries.begin(), m_flatEntries.end(),
                  [](const FlatEntry& a, const FlatEntry& b) { return a.lba < b.lba; });
        m_flatEntriesDirty = false;
    }

    if (ImGui::BeginTable("FilesystemFlat", 4,
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY |
                              ImGuiTableFlags_Sortable,
                          ImVec2(0, 300))) {
        ImGui::TableSetupColumn(_("Path"), ImGuiTableColumnFlags_NoHide);
        ImGui::TableSetupColumn(_("LBA"), ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_DefaultSort, 80.0f);
        ImGui::TableSetupColumn(_("Size"), ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn(_("Type"), ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableHeadersRow();

        for (auto& entry : m_flatEntries) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            bool selected = m_hasSelection && m_selectedPath == entry.path;
            if (ImGui::Selectable(entry.path.c_str(), selected,
                                  ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap)) {
                m_selectedPath = entry.path;
                m_selectedEntry = entry.dirEntry;
                m_hasSelection = true;
                m_selectedIsDir = entry.isDir;
            }
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%u", entry.lba);
            ImGui::TableSetColumnIndex(2);
            auto str = fmt::format("{}", entry.size);
            ImGui::TextUnformatted(str.c_str());
            ImGui::TableSetColumnIndex(3);
            ImGui::TextUnformatted(entry.isDir ? _("<DIR>") : _("File"));
        }
        ImGui::EndTable();
    }
}

void PCSX::Widgets::IsoBrowser::draw(CDRom* cdrom, const char* title) {
    if (!ImGui::Begin(title, &m_show, ImGuiWindowFlags_MenuBar)) {
        ImGui::End();
        return;
    }

    bool showOpenIsoFileDialog = false;

    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu(_("File"))) {
            showOpenIsoFileDialog = ImGui::MenuItem(_("Open Disk Image"));
            if (ImGui::MenuItem(_("Close Disk Image"))) {
                g_emulator->m_cdrom->setIso(new CDRIso(new FailedFile));
                g_emulator->m_cdrom->check();
            }
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }

    auto& isoPath = g_emulator->settings.get<Emulator::SettingIsoPath>();

    if (showOpenIsoFileDialog) {
        if (!isoPath.empty()) {
            m_openIsoFileDialog.m_currentPath = isoPath.value;
        }
        m_openIsoFileDialog.openDialog();
    }
    if (m_openIsoFileDialog.draw()) {
        isoPath.value = m_openIsoFileDialog.m_currentPath;
        std::vector<PCSX::u8string> fileToOpen = m_openIsoFileDialog.selected();
        if (!fileToOpen.empty()) {
            g_emulator->m_cdrom->setIso(new CDRIso(reinterpret_cast<const char*>(fileToOpen[0].c_str())));
            g_emulator->m_cdrom->check();
        }
    }
    auto iso = cdrom->m_iso.get();

    if (iso->failed()) {
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextUnformatted(_("No iso or invalid iso loaded."));
        ImGui::PopTextWrapPos();
        ImGui::End();
        return;
    }
    ImGui::Text(_("GAME ID: %s"), g_emulator->m_cdrom->getCDRomID().c_str());
    ImGui::Text(_("GAME Label: %s"), g_emulator->m_cdrom->getCDRomLabel().c_str());

    bool canCache = false;
    bool isCaching = false;
    float cacheProgress = 0.0f;
    UvThreadOp::iterateOverAllOps([&canCache, &isCaching, &cacheProgress](UvThreadOp* f) {
        if (f->caching() && (f->cacheProgress() < 1.0f)) {
            isCaching = true;
            cacheProgress = f->cacheProgress();
        }
        if (f->canCache() && !f->caching()) canCache = true;
    });
    if (isCaching) {
        ImGui::ProgressBar(cacheProgress);
    } else {
        if (!canCache) ImGui::BeginDisabled();
        if (ImGui::Button(_("Cache files"))) {
            UvThreadOp::iterateOverAllOps([](UvThreadOp* f) {
                if (!f->caching() && f->canCache()) f->startCaching();
            });
        }
        if (!canCache) ImGui::EndDisabled();
    }

    if (m_crcCalculator.done()) {
        if (ImGui::Button(_("Compute CRCs"))) {
            m_crcProgress = 0.0f;
            m_crcCalculator = computeCRC(iso);
        }

        ImGuiHelpers::ShowHelpMarker(_(R"(Computes the CRC32 of each track, and of
the whole disk. The CRC32 is computed on the raw data,
after decompression of the tracks. This is useful to
check the disk image against redump's information.

The computation can be slow, and can be sped up
significantly by caching the files beforehand.)"));
    } else {
        ImGui::ProgressBar(m_crcProgress);
        m_crcCalculator.resume();
    }

    auto str = fmt::format(f_("Disc size: {} ({}) - CRC32: {:08x}"), iso->getTD(0), iso->getTD(0).toLBA(), m_fullCRC);
    ImGui::TextUnformatted(str.c_str());
    if (ImGui::BeginTable("Tracks", 5, ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn(_("Track"));
        ImGui::TableSetupColumn(_("Start"));
        ImGui::TableSetupColumn(_("Length"));
        ImGui::TableSetupColumn(_("Pregap"));
        ImGui::TableSetupColumn("CRC32");
        ImGui::TableHeadersRow();
        for (unsigned t = 1; t <= iso->getTN(); t++) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%d", t);
            ImGui::TableSetColumnIndex(1);
            str = fmt::format("{} ({})", iso->getTD(t), iso->getTD(t).toLBA());
            ImGui::TextUnformatted(str.c_str());
            ImGui::TableSetColumnIndex(2);
            str = fmt::format("{} ({})", iso->getLength(t), iso->getLength(t).toLBA());
            ImGui::TextUnformatted(str.c_str());
            ImGui::TableSetColumnIndex(3);
            str = fmt::format("{} ({})", iso->getPregap(t), iso->getPregap(t).toLBA());
            ImGui::TextUnformatted(str.c_str());
            ImGui::TableSetColumnIndex(4);
            str = fmt::format("{:08x}", m_crcs[t]);
            ImGui::TextUnformatted(str.c_str());
        }
        ImGui::EndTable();
    }

    // Filesystem browser
    auto currentIso = cdrom->getIso();
    if (m_cachedIso.lock() != currentIso) {
        m_cachedIso = currentIso;
        m_reader.reset();
        m_hasSelection = false;
        m_selectedPath.clear();
        m_flatEntriesDirty = true;
        if (currentIso && !currentIso->failed()) {
            m_reader = std::make_unique<ISO9660Reader>(currentIso);
            if (m_reader->failed()) m_reader.reset();
        }
    }

    if (m_reader && ImGui::CollapsingHeader(_("Filesystem"), ImGuiTreeNodeFlags_DefaultOpen)) {
        bool extracting = !m_extractionCoroutine.done();
        bool showSaveDialog = false;
        bool showReplaceDialog = false;

        if (extracting) {
            ImGui::ProgressBar(m_extractionProgress);
            m_extractionCoroutine.resume();
        } else {
            if (!m_hasSelection || m_selectedIsDir) ImGui::BeginDisabled();
            showSaveDialog = ImGui::Button(_("Extract"));
            ImGui::SameLine();
            showReplaceDialog = ImGui::Button(_("Replace"));
            if (!m_hasSelection || m_selectedIsDir) ImGui::EndDisabled();
        }

        if (showSaveDialog) {
            m_saveFileDialog.openDialog();
        }
        if (showReplaceDialog) {
            m_openReplaceFileDialog.openDialog();
        }

        // Handle extract dialog result
        if (m_saveFileDialog.draw()) {
            auto selected = m_saveFileDialog.selected();
            if (!selected.empty() && m_hasSelection) {
                auto destPath = reinterpret_cast<const char*>(selected[0].c_str());
                uint32_t lba = m_selectedEntry.get<ISO9660LowLevel::DirEntry_LBA>();
                uint32_t size = m_selectedEntry.get<ISO9660LowLevel::DirEntry_Size>();
                auto isoPtr = m_cachedIso.lock();
                if (isoPtr) {
                    m_extractionProgress = 0.0f;
                    m_extractionCoroutine = [](IsoBrowser* self, std::shared_ptr<CDRIso> iso, uint32_t lba,
                                               uint32_t size,
                                               std::string dest) -> Coroutine<> {
                        auto time = std::chrono::steady_clock::now();
                        IO<File> src(new CDRIsoFile(iso, lba, size));
                        IO<File> out(new UvFile(dest, FileOps::TRUNCATE));
                        if (out->failed()) co_return;
                        uint8_t buffer[2048];
                        uint32_t remaining = size;
                        uint32_t written = 0;
                        while (remaining > 0) {
                            uint32_t chunk = std::min(remaining, (uint32_t)sizeof(buffer));
                            auto read = src->read(buffer, chunk);
                            if (read <= 0) break;
                            out->write(buffer, read);
                            remaining -= read;
                            written += read;
                            if (std::chrono::steady_clock::now() - time > std::chrono::milliseconds(50)) {
                                self->m_extractionProgress = (float)written / (float)size;
                                co_yield self->m_extractionCoroutine.awaiter();
                                time = std::chrono::steady_clock::now();
                            }
                        }
                        self->m_extractionProgress = 1.0f;
                    }(this, isoPtr, lba, size, destPath);
                }
            }
        }

        // Handle replace dialog result
        if (m_openReplaceFileDialog.draw()) {
            auto selected = m_openReplaceFileDialog.selected();
            if (!selected.empty() && m_hasSelection) {
                auto srcPath = reinterpret_cast<const char*>(selected[0].c_str());
                uint32_t lba = m_selectedEntry.get<ISO9660LowLevel::DirEntry_LBA>();
                uint32_t originalSize = m_selectedEntry.get<ISO9660LowLevel::DirEntry_Size>();
                auto isoPtr = m_cachedIso.lock();
                if (isoPtr) {
                    IO<File> replacement(new UvFile(srcPath));
                    if (!replacement->failed()) {
                        IO<File> isoFile(new CDRIsoFile(isoPtr, lba, originalSize));
                        uint32_t replaceSize = std::min((uint32_t)replacement->size(), originalSize);
                        uint8_t buffer[2048];
                        uint32_t remaining = replaceSize;
                        while (remaining > 0) {
                            uint32_t chunk = std::min(remaining, (uint32_t)sizeof(buffer));
                            auto read = replacement->read(buffer, chunk);
                            if (read <= 0) break;
                            isoFile->write(buffer, read);
                            remaining -= read;
                        }
                    }
                }
            }
        }

        ImGui::Checkbox(_("Flat view (by sector)"), &m_flatView);

        if (m_flatView) {
            drawFilesystemFlat();
        } else {
            if (ImGui::BeginTable("Filesystem", 3,
                                  ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY,
                                  ImVec2(0, 300))) {
                ImGui::TableSetupColumn(_("Name"), ImGuiTableColumnFlags_NoHide);
                ImGui::TableSetupColumn(_("LBA"), ImGuiTableColumnFlags_WidthFixed, 80.0f);
                ImGui::TableSetupColumn(_("Size"), ImGuiTableColumnFlags_WidthFixed, 100.0f);
                ImGui::TableHeadersRow();
                drawFilesystemTree(m_reader->getRootDirEntry(), "");
                ImGui::EndTable();
            }
        }

        // PPF patch controls
        ImGui::Separator();
        if (ImGui::Button(_("Clear Patches"))) {
            currentIso->getPPF()->clear();
        }
        ImGui::SameLine();
        if (ImGui::Button(_("Save PPF"))) {
            currentIso->getPPF()->save(currentIso->getIsoPath());
        }
    }

    ImGui::End();
}
