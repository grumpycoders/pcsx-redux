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

#include <chrono>

#include "core/cdrom.h"
#include "fmt/format.h"
#include "imgui/imgui.h"
#include "support/uvfile.h"

static void ShowHelpMarker(const char* desc) {
    ImGui::SameLine();
    ImGui::TextDisabled("(?)");
    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::PushTextWrapPos(ImGui::GetFontSize() * 35.0f);
        ImGui::TextUnformatted(desc);
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
}

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
                g_emulator->m_cdrom->setIso(new CDRIso());
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
        ImGui::TextWrapped(_("No iso or invalid iso loaded."));
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

        ShowHelpMarker(_(R"(Computes the CRC32 of each track, and of
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

    ImGui::End();
}
