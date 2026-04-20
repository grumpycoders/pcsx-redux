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
                m_selectedLBA = lba;
                m_selectedSize = size;
                m_hasSelection = true;
                m_selectedIsDir = false;
                m_selectedIsGap = false;
            }
            if (ImGui::BeginPopupContextItem()) {
                if (ImGui::MenuItem(_("Extract"))) {
                    m_selectedPath = fullPath;
                    m_selectedLBA = lba;
                    m_selectedSize = size;
                    m_hasSelection = true;
                    m_saveFileDialog.openDialog();
                }
                if (ImGui::MenuItem(_("Replace"))) {
                    m_selectedPath = fullPath;
                    m_selectedLBA = lba;
                    m_selectedSize = size;
                    m_hasSelection = true;
                    m_openReplaceFileDialog.openDialog();
                }
                if (ImGui::MenuItem(_("Hex Edit"))) {
                    auto isoPtr = m_cachedIso.lock();
                    if (isoPtr) {
                        openHexEditor(fullPath, IO<File>(new CDRIsoFile(isoPtr, lba, size)));
                    }
                }
                ImGui::EndPopup();
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

        // Form 2 files use 2324-byte data sectors; everything else logical uses 2048.
        uint16_t xaAttribs = xa.get<ISO9660LowLevel::DirEntry_XA_Attribs>();
        uint32_t sectorSize = (xaAttribs & 0x1000) ? 2324 : 2048;
        uint32_t sectors = (size + sectorSize - 1) / sectorSize;
        m_flatEntries.push_back(
            {fullPath, lba, size, sectors, isDir ? FlatEntry::Directory : FlatEntry::File, dirEntry});
        if (isDir) collectFlatEntries(dirEntry, fullPath);
    }
}

void PCSX::Widgets::IsoBrowser::scanGapSectors(std::vector<FlatEntry>& out, uint32_t startLBA, uint32_t sectorCount,
                                                std::shared_ptr<CDRIso> iso) {
    uint32_t lba = startLBA;
    uint32_t end = startLBA + sectorCount;

    while (lba < end) {
        uint8_t sector[2352];
        if (iso->readSectors(lba, sector, 1) != 1) {
            // Read failed, treat rest as gap
            uint32_t remaining = end - lba;
            auto label = fmt::format(f_("<gap {} sectors>"), remaining);
            out.push_back({label, lba, remaining * 2352, remaining, FlatEntry::Gap, {}});
            break;
        }

        uint8_t mode = sector[15];

        if (mode == 0) {
            // Mode 0: true gap. Accumulate consecutive mode 0 sectors.
            uint32_t gapStart = lba;
            while (lba < end) {
                if (lba != gapStart) {
                    if (iso->readSectors(lba, sector, 1) != 1) break;
                    if (sector[15] != 0) break;
                }
                lba++;
            }
            uint32_t count = lba - gapStart;
            auto label = fmt::format(f_("<gap {} sectors>"), count);
            out.push_back({label, gapStart, count * 2352, count, FlatEntry::Gap, {}});
            continue;
        }

        if (mode == 1) {
            // Mode 1 hidden data. Accumulate until mode changes or gap ends.
            uint32_t fileStart = lba;
            lba++;
            while (lba < end) {
                if (iso->readSectors(lba, sector, 1) != 1) break;
                if (sector[15] != 1) break;
                lba++;
            }
            uint32_t count = lba - fileStart;
            auto label = fmt::format(f_("<hidden M1 {} sectors>"), count);
            out.push_back({label, fileStart, count * 2048, count, FlatEntry::HiddenM1, {}});
            continue;
        }

        if (mode == 2) {
            // Mode 2: parse subheader for form and file boundaries
            uint8_t* sub = sector + 16;
            uint8_t fileNum = sub[0];
            uint8_t channelNum = sub[1];
            uint8_t submode = sub[2];
            bool isForm2 = (submode & 0x20) != 0;
            auto type = isForm2 ? FlatEntry::HiddenM2F2 : FlatEntry::HiddenM2F1;

            uint32_t fileStart = lba;
            bool hitEof = (submode & 0x80) != 0;
            lba++;

            while (lba < end && !hitEof) {
                if (iso->readSectors(lba, sector, 1) != 1) break;
                if (sector[15] != 2) break;
                sub = sector + 16;
                // Different file/channel = new subfile
                if (sub[0] != fileNum || sub[1] != channelNum) break;
                hitEof = (sub[2] & 0x80) != 0;
                lba++;
            }

            uint32_t count = lba - fileStart;
            uint32_t dataSize = isForm2 ? count * 2324 : count * 2048;
            auto label = fmt::format(f_("<hidden {} f={} ch={} {} sectors>"),
                                     isForm2 ? "M2F2" : "M2F1", fileNum, channelNum, count);
            out.push_back({label, fileStart, dataSize, count, type, {}});
            continue;
        }

        // Unknown mode, skip sector
        lba++;
    }
}

void PCSX::Widgets::IsoBrowser::drawFilesystemFlat() {
    if (m_flatEntriesDirty) {
        m_flatEntries.clear();

        // Add ISO9660 system structures
        auto& pvd = m_reader->getPVD();
        uint32_t vdEnd = m_reader->getVDEnd();
        m_flatEntries.push_back({_("<License/System Area>"), 0, 16 * 2352, 16, FlatEntry::System, {}});
        // Volume descriptor set spans from LBA 16 up to (but not including) vdEnd,
        // including the PVD, any SVDs, and the terminator.
        uint32_t vdSectors = vdEnd > 16 ? vdEnd - 16 : 1;
        m_flatEntries.push_back(
            {_("<Volume Descriptors>"), 16, vdSectors * 2048, vdSectors, FlatEntry::System, {}});
        uint32_t lPathLoc = pvd.get<ISO9660LowLevel::PVD_LPathTableLocation>();
        uint32_t pathTableSize = pvd.get<ISO9660LowLevel::PVD_PathTableSize>();
        uint32_t pathTableSectors = (pathTableSize + 2047) / 2048;
        m_flatEntries.push_back(
            {_("<L Path Table>"), lPathLoc, pathTableSize, pathTableSectors, FlatEntry::System, {}});
        uint32_t lPathOptLoc = pvd.get<ISO9660LowLevel::PVD_LPathTableOptLocation>();
        if (lPathOptLoc != 0) {
            m_flatEntries.push_back(
                {_("<L Path Table (opt)>"), lPathOptLoc, pathTableSize, pathTableSectors, FlatEntry::System, {}});
        }
        uint32_t mPathLoc = pvd.get<ISO9660LowLevel::PVD_MPathTableLocation>();
        m_flatEntries.push_back(
            {_("<M Path Table>"), mPathLoc, pathTableSize, pathTableSectors, FlatEntry::System, {}});
        uint32_t mPathOptLoc = pvd.get<ISO9660LowLevel::PVD_MPathTableOptLocation>();
        if (mPathOptLoc != 0) {
            m_flatEntries.push_back(
                {_("<M Path Table (opt)>"), mPathOptLoc, pathTableSize, pathTableSectors, FlatEntry::System, {}});
        }
        auto& rootDir = m_reader->getRootDirEntry();
        uint32_t rootLBA = rootDir.get<ISO9660LowLevel::DirEntry_LBA>();
        uint32_t rootSize = rootDir.get<ISO9660LowLevel::DirEntry_Size>();
        uint32_t rootSectors = (rootSize + 2047) / 2048;
        m_flatEntries.push_back({_("<Root Directory>"), rootLBA, rootSize, rootSectors, FlatEntry::System, {}});

        collectFlatEntries(m_reader->getRootDirEntry(), "");
        std::sort(m_flatEntries.begin(), m_flatEntries.end(),
                  [](const FlatEntry& a, const FlatEntry& b) { return a.lba < b.lba; });

        // Insert simple gap placeholders (no sector scanning yet)
        std::vector<FlatEntry> withGaps;
        uint32_t nextExpected = 0;
        for (auto& entry : m_flatEntries) {
            if (entry.lba > nextExpected) {
                uint32_t gapSectors = entry.lba - nextExpected;
                auto label = fmt::format(f_("<gap {} sectors>"), gapSectors);
                withGaps.push_back({label, nextExpected, gapSectors * 2352, gapSectors, FlatEntry::Gap, {}});
            }
            withGaps.push_back(entry);
            uint32_t end = entry.lba + entry.sectors;
            if (end > nextExpected) nextExpected = end;
        }
        m_flatEntries = std::move(withGaps);
        m_flatEntriesDirty = false;
        m_gapsScanned = false;
    }

    if (!m_gapsScanned) {
        if (ImGui::Button(_("Scan gaps for hidden files"))) {
            auto iso = m_cachedIso.lock();
            if (iso) {
                std::vector<FlatEntry> scanned;
                for (auto& entry : m_flatEntries) {
                    if (entry.isGap()) {
                        uint32_t sectorCount = entry.size / 2352;
                        scanGapSectors(scanned, entry.lba, sectorCount, iso);
                    } else {
                        scanned.push_back(entry);
                    }
                }
                m_flatEntries = std::move(scanned);
                m_gapsScanned = true;
            }
        }
        ImGuiHelpers::ShowHelpMarker(_(R"(Reads sector headers in gap regions to detect
hidden files that were removed from the ISO9660
directory but still have intact Mode 1/2 sector
headers and subheader file boundary markers.)"));
    }

    if (ImGui::BeginTable("FilesystemFlat", 4,
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY,
                          ImVec2(0, ImGui::GetContentRegionAvail().y - ImGui::GetFrameHeightWithSpacing() - ImGui::GetStyle().ItemSpacing.y))) {
        ImGui::TableSetupColumn(_("Path"), ImGuiTableColumnFlags_NoHide);
        ImGui::TableSetupColumn(_("LBA"), ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn(_("Size"), ImGuiTableColumnFlags_WidthFixed, 100.0f);
        ImGui::TableSetupColumn(_("Type"), ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableHeadersRow();

        for (size_t i = 0; i < m_flatEntries.size(); i++) {
            auto& entry = m_flatEntries[i];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            bool selected = m_hasSelection && m_selectedLBA == entry.lba &&
                            m_selectedIsGap == entry.isGap();
            auto id = fmt::format("{}##{}", entry.path, i);
            if (ImGui::Selectable(id.c_str(), selected,
                                  ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap)) {
                m_selectedPath = entry.path;
                m_selectedLBA = entry.lba;
                m_selectedSize = entry.size;
                m_selectedEntry = entry.dirEntry;
                m_hasSelection = true;
                m_selectedIsDir = entry.isDir();
                m_selectedIsGap = entry.isGap() || entry.isHidden();
            }
            if (!entry.isDir() && ImGui::BeginPopupContextItem()) {
                if (ImGui::MenuItem(_("Extract"))) {
                    m_selectedPath = entry.path;
                    m_selectedLBA = entry.lba;
                    m_selectedSize = entry.size;
                    m_hasSelection = true;
                    m_saveFileDialog.openDialog();
                }
                if (ImGui::MenuItem(_("Replace"))) {
                    m_selectedPath = entry.path;
                    m_selectedLBA = entry.lba;
                    m_selectedSize = entry.size;
                    m_hasSelection = true;
                    m_openReplaceFileDialog.openDialog();
                }
                if (ImGui::MenuItem(_("Hex Edit"))) {
                    auto isoPtr = m_cachedIso.lock();
                    if (isoPtr) {
                        IEC60908b::SectorMode mode = IEC60908b::SectorMode::GUESS;
                        switch (entry.type) {
                            case FlatEntry::Gap:
                            case FlatEntry::System: mode = IEC60908b::SectorMode::RAW; break;
                            case FlatEntry::HiddenM1: mode = IEC60908b::SectorMode::M1; break;
                            case FlatEntry::HiddenM2F1: mode = IEC60908b::SectorMode::M2_FORM1; break;
                            case FlatEntry::HiddenM2F2: mode = IEC60908b::SectorMode::M2_FORM2; break;
                            default: break;
                        }
                        openHexEditor(entry.path, IO<File>(new CDRIsoFile(isoPtr, entry.lba, entry.size, mode)));
                    }
                }
                ImGui::EndPopup();
            }
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%u", entry.lba);
            ImGui::TableSetColumnIndex(2);
            auto str = fmt::format("{}", entry.size);
            ImGui::TextUnformatted(str.c_str());
            ImGui::TableSetColumnIndex(3);
            const char* typeStr;
            switch (entry.type) {
                case FlatEntry::File: typeStr = _("File"); break;
                case FlatEntry::Directory: typeStr = _("<DIR>"); break;
                case FlatEntry::Gap: typeStr = _("Gap"); break;
                case FlatEntry::HiddenM1: typeStr = _("M1"); break;
                case FlatEntry::HiddenM2F1: typeStr = _("M2F1"); break;
                case FlatEntry::HiddenM2F2: typeStr = _("M2F2"); break;
                case FlatEntry::System: typeStr = _("System"); break;
            }
            ImGui::TextUnformatted(typeStr);
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

        if (extracting) {
            ImGui::ProgressBar(m_extractionProgress);
            m_extractionCoroutine.resume();
        }

        // Handle extract dialog result
        if (m_saveFileDialog.draw()) {
            auto selected = m_saveFileDialog.selected();
            if (!selected.empty() && m_hasSelection) {
                auto destPath = reinterpret_cast<const char*>(selected[0].c_str());
                uint32_t lba = m_selectedLBA;
                uint32_t size = m_selectedSize;
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
                uint32_t lba = m_selectedLBA;
                uint32_t originalSize = m_selectedSize;
                auto isoPtr = m_cachedIso.lock();
                if (isoPtr) {
                    m_extractionProgress = 0.0f;
                    m_extractionCoroutine = [](IsoBrowser* self, std::shared_ptr<CDRIso> iso, uint32_t lba,
                                               uint32_t originalSize, std::string src) -> Coroutine<> {
                        auto time = std::chrono::steady_clock::now();
                        IO<File> replacement(new UvFile(src));
                        if (replacement->failed()) co_return;
                        IO<File> isoFile(new CDRIsoFile(iso, lba, originalSize));
                        uint32_t replaceSize = std::min((uint32_t)replacement->size(), originalSize);
                        if (replacement->size() > originalSize) {
                            // Replacement too large; truncated to original size.
                            g_system->printf(
                                _("ISO replace: replacement file is larger than target (%zu > %u). Truncating.\n"),
                                replacement->size(), originalSize);
                        }
                        uint8_t buffer[2048];
                        uint32_t remaining = replaceSize;
                        uint32_t written = 0;
                        while (remaining > 0) {
                            uint32_t chunk = std::min(remaining, (uint32_t)sizeof(buffer));
                            auto read = replacement->read(buffer, chunk);
                            if (read <= 0) break;
                            isoFile->write(buffer, read);
                            remaining -= read;
                            written += read;
                            if (std::chrono::steady_clock::now() - time > std::chrono::milliseconds(50)) {
                                self->m_extractionProgress = (float)written / (float)originalSize;
                                co_yield self->m_extractionCoroutine.awaiter();
                                time = std::chrono::steady_clock::now();
                            }
                        }
                        // Zero-pad the tail if the replacement was smaller than the original,
                        // so stale bytes from the original don't leak through.
                        if (written < originalSize) {
                            uint8_t zeros[2048] = {0};
                            uint32_t padRemaining = originalSize - written;
                            while (padRemaining > 0) {
                                uint32_t chunk = std::min(padRemaining, (uint32_t)sizeof(zeros));
                                isoFile->write(zeros, chunk);
                                padRemaining -= chunk;
                                written += chunk;
                                if (std::chrono::steady_clock::now() - time > std::chrono::milliseconds(50)) {
                                    self->m_extractionProgress = (float)written / (float)originalSize;
                                    co_yield self->m_extractionCoroutine.awaiter();
                                    time = std::chrono::steady_clock::now();
                                }
                            }
                        }
                        self->m_extractionProgress = 1.0f;
                    }(this, isoPtr, lba, originalSize, srcPath);
                }
            }
        }

        ImGui::Checkbox(_("Flat view (by sector)"), &m_flatView);

        if (m_flatView) {
            drawFilesystemFlat();
        } else {
            if (ImGui::BeginTable("Filesystem", 3,
                                  ImGuiTableFlags_Resizable | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY,
                                  ImVec2(0, ImGui::GetContentRegionAvail().y - ImGui::GetFrameHeightWithSpacing() - ImGui::GetStyle().ItemSpacing.y))) {
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

    // Render hex editor windows and clean up closed ones
    for (auto it = m_hexEditors.begin(); it != m_hexEditors.end();) {
        auto& inst = *it;
        if (!inst.m_open) {
            it = m_hexEditors.erase(it);
            delete &inst;
            continue;
        }
        auto size = inst.m_file->size();
        inst.m_editor.ReadFn = [&inst](size_t off) -> ImU8 {
            ImU8 b;
            inst.m_file->readAt(&b, 1, off);
            return b;
        };
        inst.m_editor.WriteFn = [&inst](size_t off, ImU8 d) { inst.m_file->writeAt(&d, 1, off); };
        inst.m_editor.Cache.BulkReadFn = [&inst](void* dest, size_t off, size_t len) {
            inst.m_file->readAt(dest, len, off);
        };
        inst.m_editor.DrawWindow(inst.m_title.c_str(), size);
        ++it;
    }
}

void PCSX::Widgets::IsoBrowser::openHexEditor(const std::string& title, IO<File> file) {
    auto label = fmt::format(f_("Hex Editor - {}"), title);
    auto* inst = new HexEditorInstance(label, file, m_monoFont);
    m_hexEditors.push_back(inst);
}
