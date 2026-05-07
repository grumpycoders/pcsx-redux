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
#include <cstring>

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

void PCSX::Widgets::IsoBrowser::drawFilesystemTree(const ISO9660LowLevel::DirEntry& entry, const std::string& path,
                                                     std::unordered_set<uint32_t>& visitedDirs) {
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
                // Guard against malformed ISOs with directory cycles pointing back to an ancestor.
                if (visitedDirs.insert(lba).second) {
                    drawFilesystemTree(dirEntry, fullPath, visitedDirs);
                }
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
                m_selectedMode = IEC60908b::SectorMode::GUESS;
                m_hasSelection = true;
                m_selectedIsDir = false;
                m_selectedIsGap = false;
            }
            if (ImGui::BeginPopupContextItem()) {
                if (ImGui::MenuItem(_("Extract"))) {
                    m_selectedPath = fullPath;
                    m_selectedLBA = lba;
                    m_selectedSize = size;
                    m_selectedMode = IEC60908b::SectorMode::GUESS;
                    m_hasSelection = true;
                    m_saveFileDialog.openDialog();
                }
                if (ImGui::MenuItem(_("Replace"))) {
                    m_selectedPath = fullPath;
                    m_selectedLBA = lba;
                    m_selectedSize = size;
                    m_selectedMode = IEC60908b::SectorMode::GUESS;
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

void PCSX::Widgets::IsoBrowser::collectFlatEntries(const ISO9660LowLevel::DirEntry& entry, const std::string& path,
                                                     std::unordered_set<uint32_t>& visitedDirs) {
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
        // Guard against malformed ISOs with directory cycles.
        if (isDir && visitedDirs.insert(lba).second) {
            collectFlatEntries(dirEntry, fullPath, visitedDirs);
        }
    }
}

PCSX::Coroutine<> PCSX::Widgets::IsoBrowser::scanAllGaps(std::shared_ptr<CDRIso> iso) {
    auto time = std::chrono::steady_clock::now();
    std::vector<FlatEntry> scanned;

    // Count total gap sectors to scan for progress reporting.
    uint32_t totalGapSectors = 0;
    for (auto& entry : m_flatEntries) {
        if (entry.isGap()) totalGapSectors += entry.sectors;
    }
    uint32_t scannedSectors = 0;

    for (auto& entry : m_flatEntries) {
        if (!entry.isGap()) {
            scanned.push_back(entry);
            continue;
        }

        uint32_t lba = entry.lba;
        uint32_t end = entry.lba + entry.sectors;

        while (lba < end) {
            uint8_t sector[2352];
            if (iso->readSectors(lba, sector, 1) != 1) {
                uint32_t remaining = end - lba;
                auto label = fmt::format(f_("<gap {} sectors>"), remaining);
                scanned.push_back({label, lba, remaining * 2352, remaining, FlatEntry::Gap, {}});
                scannedSectors += remaining;
                break;
            }

            uint8_t mode = sector[15];

            if (mode == 0) {
                uint32_t gapStart = lba;
                while (lba < end) {
                    if (lba != gapStart) {
                        if (iso->readSectors(lba, sector, 1) != 1) break;
                        if (sector[15] != 0) break;
                    }
                    lba++;
                    scannedSectors++;
                    if (std::chrono::steady_clock::now() - time > std::chrono::milliseconds(50)) {
                        m_gapScanProgress =
                            totalGapSectors > 0 ? (float)scannedSectors / (float)totalGapSectors : 1.0f;
                        co_yield m_gapScanCoroutine.awaiter();
                        time = std::chrono::steady_clock::now();
                    }
                }
                uint32_t count = lba - gapStart;
                auto label = fmt::format(f_("<gap {} sectors>"), count);
                scanned.push_back({label, gapStart, count * 2352, count, FlatEntry::Gap, {}});
                continue;
            }

            if (mode == 1) {
                uint32_t fileStart = lba;
                lba++;
                scannedSectors++;
                while (lba < end) {
                    if (iso->readSectors(lba, sector, 1) != 1) break;
                    if (sector[15] != 1) break;
                    lba++;
                    scannedSectors++;
                    if (std::chrono::steady_clock::now() - time > std::chrono::milliseconds(50)) {
                        m_gapScanProgress =
                            totalGapSectors > 0 ? (float)scannedSectors / (float)totalGapSectors : 1.0f;
                        co_yield m_gapScanCoroutine.awaiter();
                        time = std::chrono::steady_clock::now();
                    }
                }
                uint32_t count = lba - fileStart;
                auto label = fmt::format(f_("<hidden M1 {} sectors>"), count);
                scanned.push_back({label, fileStart, count * 2048, count, FlatEntry::HiddenM1, {}});
                continue;
            }

            if (mode == 2) {
                uint8_t* sub = sector + 16;
                uint8_t fileNum = sub[0];
                uint8_t channelNum = sub[1];
                uint8_t submode = sub[2];
                bool isForm2 = (submode & 0x20) != 0;
                auto type = isForm2 ? FlatEntry::HiddenM2F2 : FlatEntry::HiddenM2F1;

                uint32_t fileStart = lba;
                bool hitEof = (submode & 0x80) != 0;
                lba++;
                scannedSectors++;

                while (lba < end && !hitEof) {
                    if (iso->readSectors(lba, sector, 1) != 1) break;
                    if (sector[15] != 2) break;
                    sub = sector + 16;
                    if (sub[0] != fileNum || sub[1] != channelNum) break;
                    hitEof = (sub[2] & 0x80) != 0;
                    lba++;
                    scannedSectors++;
                    if (std::chrono::steady_clock::now() - time > std::chrono::milliseconds(50)) {
                        m_gapScanProgress =
                            totalGapSectors > 0 ? (float)scannedSectors / (float)totalGapSectors : 1.0f;
                        co_yield m_gapScanCoroutine.awaiter();
                        time = std::chrono::steady_clock::now();
                    }
                }

                uint32_t count = lba - fileStart;
                uint32_t dataSize = isForm2 ? count * 2324 : count * 2048;
                auto label = fmt::format(f_("<hidden {} f={} ch={} {} sectors>"),
                                         isForm2 ? "M2F2" : "M2F1", fileNum, channelNum, count);
                scanned.push_back({label, fileStart, dataSize, count, type, {}});
                continue;
            }

            // Unknown sector mode. Accumulate consecutive unknown-mode sectors
            // and emit a single gap entry so the bytes stay visible in the flat
            // view instead of silently disappearing.
            uint32_t unknownStart = lba;
            while (lba < end) {
                if (iso->readSectors(lba, sector, 1) != 1) break;
                uint8_t m = sector[15];
                if (m == 0 || m == 1 || m == 2) break;
                lba++;
                scannedSectors++;
                if (std::chrono::steady_clock::now() - time > std::chrono::milliseconds(50)) {
                    m_gapScanProgress =
                        totalGapSectors > 0 ? (float)scannedSectors / (float)totalGapSectors : 1.0f;
                    co_yield m_gapScanCoroutine.awaiter();
                    time = std::chrono::steady_clock::now();
                }
            }
            uint32_t unknownCount = lba - unknownStart;
            auto unknownLabel = fmt::format(f_("<gap {} sectors>"), unknownCount);
            scanned.push_back({unknownLabel, unknownStart, unknownCount * 2352, unknownCount, FlatEntry::Gap, {}});
        }
    }

    m_flatEntries = std::move(scanned);
    m_gapsScanned = true;
    m_gapScanProgress = 1.0f;
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

        std::unordered_set<uint32_t> visitedDirs;
        visitedDirs.insert(rootLBA);
        collectFlatEntries(m_reader->getRootDirEntry(), "", visitedDirs);
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
        // Trailing gap: append any unreferenced sectors at the end of the loaded image.
        // Prefer the actual loaded disc length over PVD_VolumeSpaceSize (which is the
        // logical volume length and can differ from what's actually on disc).
        uint32_t discEnd = pvd.get<ISO9660LowLevel::PVD_VolumeSpaceSize>();
        if (auto iso = m_cachedIso.lock()) {
            discEnd = iso->getTD(0).toLBA();
        }
        if (discEnd > nextExpected) {
            uint32_t gapSectors = discEnd - nextExpected;
            auto label = fmt::format(f_("<gap {} sectors>"), gapSectors);
            withGaps.push_back({label, nextExpected, gapSectors * 2352, gapSectors, FlatEntry::Gap, {}});
        }
        m_flatEntries = std::move(withGaps);
        m_flatEntriesDirty = false;
        m_gapsScanned = false;
    }

    if (!m_gapsScanned) {
        if (m_gapScanCoroutine.done()) {
            if (ImGui::Button(_("Scan gaps for hidden files"))) {
                auto iso = m_cachedIso.lock();
                if (iso) {
                    m_gapScanProgress = 0.0f;
                    m_gapScanCoroutine = scanAllGaps(iso);
                }
            }
            ImGuiHelpers::ShowHelpMarker(_(R"(Reads sector headers in gap regions to detect
hidden files that were removed from the ISO9660
directory but still have intact Mode 1/2 sector
headers and subheader file boundary markers.)"));
        } else {
            ImGui::ProgressBar(m_gapScanProgress);
            m_gapScanCoroutine.resume();
        }
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
                            m_selectedIsGap == (entry.isGap() || entry.isHidden());
            auto id = fmt::format("{}##{}", entry.path, i);
            if (ImGui::Selectable(id.c_str(), selected,
                                  ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap)) {
                m_selectedPath = entry.path;
                m_selectedLBA = entry.lba;
                m_selectedSize = entry.size;
                m_selectedEntry = entry.dirEntry;
                switch (entry.type) {
                    case FlatEntry::Gap:
                    case FlatEntry::System: m_selectedMode = IEC60908b::SectorMode::RAW; break;
                    case FlatEntry::HiddenM1: m_selectedMode = IEC60908b::SectorMode::M1; break;
                    case FlatEntry::HiddenM2F1: m_selectedMode = IEC60908b::SectorMode::M2_FORM1; break;
                    case FlatEntry::HiddenM2F2: m_selectedMode = IEC60908b::SectorMode::M2_FORM2; break;
                    default: m_selectedMode = IEC60908b::SectorMode::GUESS; break;
                }
                m_hasSelection = true;
                m_selectedIsDir = entry.isDir();
                m_selectedIsGap = entry.isGap() || entry.isHidden();
            }
            if (!entry.isDir() && ImGui::BeginPopupContextItem()) {
                IEC60908b::SectorMode entryMode = IEC60908b::SectorMode::GUESS;
                switch (entry.type) {
                    case FlatEntry::Gap:
                    case FlatEntry::System: entryMode = IEC60908b::SectorMode::RAW; break;
                    case FlatEntry::HiddenM1: entryMode = IEC60908b::SectorMode::M1; break;
                    case FlatEntry::HiddenM2F1: entryMode = IEC60908b::SectorMode::M2_FORM1; break;
                    case FlatEntry::HiddenM2F2: entryMode = IEC60908b::SectorMode::M2_FORM2; break;
                    default: break;
                }
                if (ImGui::MenuItem(_("Extract"))) {
                    m_selectedPath = entry.path;
                    m_selectedLBA = entry.lba;
                    m_selectedSize = entry.size;
                    m_selectedMode = entryMode;
                    m_hasSelection = true;
                    m_saveFileDialog.openDialog();
                }
                if (ImGui::MenuItem(_("Replace"))) {
                    m_selectedPath = entry.path;
                    m_selectedLBA = entry.lba;
                    m_selectedSize = entry.size;
                    m_selectedMode = entryMode;
                    m_hasSelection = true;
                    m_openReplaceFileDialog.openDialog();
                }
                if (ImGui::MenuItem(_("Hex Edit"))) {
                    auto isoPtr = m_cachedIso.lock();
                    if (isoPtr) {
                        openHexEditor(entry.path,
                                      IO<File>(new CDRIsoFile(isoPtr, entry.lba, entry.size, entryMode)));
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
        m_gapScanCoroutine = {};
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
                IEC60908b::SectorMode mode = m_selectedMode;
                auto isoPtr = m_cachedIso.lock();
                if (isoPtr) {
                    m_extractionProgress = 0.0f;
                    m_extractionCoroutine = [](IsoBrowser* self, std::shared_ptr<CDRIso> iso, uint32_t lba,
                                               uint32_t size, IEC60908b::SectorMode mode,
                                               std::string dest) -> Coroutine<> {
                        auto time = std::chrono::steady_clock::now();
                        IO<File> src(new CDRIsoFile(iso, lba, size, mode));
                        if (src->failed()) {
                            g_system->printf(_("ISO extract: failed to open source region.\n"));
                            co_return;
                        }
                        IO<File> out(new UvFile(dest, FileOps::TRUNCATE));
                        if (out->failed()) {
                            g_system->printf(_("ISO extract: failed to open destination file.\n"));
                            co_return;
                        }
                        uint8_t buffer[2048];
                        uint32_t remaining = size;
                        uint32_t written = 0;
                        while (remaining > 0) {
                            uint32_t chunk = std::min(remaining, (uint32_t)sizeof(buffer));
                            auto read = src->read(buffer, chunk);
                            if (read <= 0) {
                                g_system->printf(_("ISO extract: failed while reading ISO data.\n"));
                                co_return;
                            }
                            auto wrote = out->write(buffer, read);
                            if (wrote != read) {
                                g_system->printf(_("ISO extract: failed while writing destination file.\n"));
                                co_return;
                            }
                            remaining -= static_cast<uint32_t>(read);
                            written += static_cast<uint32_t>(read);
                            if (std::chrono::steady_clock::now() - time > std::chrono::milliseconds(50)) {
                                self->m_extractionProgress = (float)written / (float)size;
                                co_yield self->m_extractionCoroutine.awaiter();
                                time = std::chrono::steady_clock::now();
                            }
                        }
                        self->m_extractionProgress = 1.0f;
                    }(this, isoPtr, lba, size, mode, destPath);
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
                IEC60908b::SectorMode mode = m_selectedMode;
                auto isoPtr = m_cachedIso.lock();
                if (isoPtr) {
                    m_extractionProgress = 0.0f;
                    m_extractionCoroutine = [](IsoBrowser* self, std::shared_ptr<CDRIso> iso, uint32_t lba,
                                               uint32_t originalSize, IEC60908b::SectorMode mode,
                                               std::string src) -> Coroutine<> {
                        auto time = std::chrono::steady_clock::now();
                        IO<File> replacement(new UvFile(src));
                        if (replacement->failed()) {
                            g_system->printf(_("ISO replace: failed to open replacement file.\n"));
                            co_return;
                        }
                        IO<File> isoFile(new CDRIsoFile(iso, lba, originalSize, mode));
                        size_t replacementSize = replacement->size();
                        uint32_t replaceSize = replacementSize > originalSize
                                                   ? originalSize
                                                   : static_cast<uint32_t>(replacementSize);
                        if (replacementSize > originalSize) {
                            g_system->printf(
                                _("ISO replace: replacement file is larger than target (%zu > %u). Truncating.\n"),
                                replacementSize, originalSize);
                        }
                        uint8_t buffer[2048];
                        uint32_t remaining = replaceSize;
                        uint32_t written = 0;
                        while (remaining > 0) {
                            uint32_t chunk = std::min(remaining, (uint32_t)sizeof(buffer));
                            auto read = replacement->read(buffer, chunk);
                            if (read <= 0) {
                                g_system->printf(_("ISO replace: failed while reading replacement file.\n"));
                                co_return;
                            }
                            auto wrote = isoFile->write(buffer, read);
                            if (wrote != read) {
                                g_system->printf(_("ISO replace: failed while writing to ISO.\n"));
                                co_return;
                            }
                            remaining -= static_cast<uint32_t>(read);
                            written += static_cast<uint32_t>(read);
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
                                auto wrote = isoFile->write(zeros, chunk);
                                if (wrote != static_cast<ssize_t>(chunk)) {
                                    g_system->printf(_("ISO replace: failed while zero-padding ISO.\n"));
                                    co_return;
                                }
                                padRemaining -= static_cast<uint32_t>(wrote);
                                written += static_cast<uint32_t>(wrote);
                                if (std::chrono::steady_clock::now() - time > std::chrono::milliseconds(50)) {
                                    self->m_extractionProgress = (float)written / (float)originalSize;
                                    co_yield self->m_extractionCoroutine.awaiter();
                                    time = std::chrono::steady_clock::now();
                                }
                            }
                        }
                        self->m_extractionProgress = 1.0f;
                    }(this, isoPtr, lba, originalSize, mode, srcPath);
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
                std::unordered_set<uint32_t> visitedDirs;
                visitedDirs.insert(m_reader->getRootDirEntry().get<ISO9660LowLevel::DirEntry_LBA>());
                drawFilesystemTree(m_reader->getRootDirEntry(), "", visitedDirs);
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
            ImU8 b = 0;
            auto r = inst.m_file->readAt(&b, 1, off);
            if (r != 1) b = 0;
            return b;
        };
        inst.m_editor.WriteFn = [&inst](size_t off, ImU8 d) { inst.m_file->writeAt(&d, 1, off); };
        inst.m_editor.Cache.BulkReadFn = [&inst](void* dest, size_t off, size_t len) {
            auto r = inst.m_file->readAt(dest, len, off);
            // Zero-fill anything we didn't read so stale buffer contents
            // never leak into the hex view on short reads or errors.
            if (r < 0) r = 0;
            if (static_cast<size_t>(r) < len) {
                std::memset(static_cast<uint8_t*>(dest) + r, 0, len - static_cast<size_t>(r));
            }
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
