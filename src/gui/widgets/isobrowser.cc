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

#include "core/cdrom.h"
#include "fmt/format.h"
#include "imgui/imgui.h"
#include "support/uvfile.h"

void PCSX::Widgets::IsoBrowser::draw(CDRom* cdrom, const char* title) {
    if (!ImGui::Begin(title, &m_show)) {
        ImGui::End();
        return;
    }

    auto iso = cdrom->m_iso.get();

    if (iso->failed()) {
        ImGui::TextWrapped(_("No iso or invalid iso loaded."));
        ImGui::End();
        return;
    }

    auto str = fmt::format(f_("Disc size: {} ({}) - CRC32: {:08x}"), iso->getTD(0), iso->getTD(0).toLBA(), m_fullCRC);
    ImGui::TextUnformatted(str.c_str());
    ImGui::SameLine();
    bool startCaching = ImGui::Button(_("Cache files"));
    bool allCached = true;
    UvThreadOp::iterateOverAllOps([startCaching, &allCached](UvThreadOp* f) {
        if (startCaching && !f->caching() && f->canCache()) f->startCaching();
        if (!f->caching()) {
            allCached = false;
        } else if (f->cacheProgress() != 1.0f) {
            allCached = false;
        }
    });
    ImGui::SameLine();
    if (!allCached) ImGui::BeginDisabled();
    if (ImGui::Button(_("Compute CRCs"))) {
        m_fullCRC = crc32(0L, Z_NULL, 0);
        uint32_t lba = 0;
        for (unsigned t = 1; t <= iso->getTN(); t++) {
            uint32_t len = iso->getLength(t).toLBA();
            m_crcs[t] = crc32(0L, Z_NULL, 0);
            uint8_t buffer[2352];
            for (unsigned s = 0; s < len; s++) {
                iso->readSectors(lba++, buffer, 1);
                m_fullCRC = crc32(m_fullCRC, buffer, 2352);
                m_crcs[t] = crc32(m_crcs[t], buffer, 2352);
            }
        }
    }
    if (!allCached) ImGui::EndDisabled();
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
