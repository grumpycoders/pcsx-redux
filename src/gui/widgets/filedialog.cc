/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <malloc.h>
#include <stdio.h>
#include <windows.h>
#endif

#include <algorithm>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "core/system.h"
#include "gui/widgets/filedialog.h"
#include "imgui.h"

struct InputTextCallback_UserData {
    PCSX::u8string* Str;
    ImGuiInputTextCallback ChainCallback;
    void* ChainCallbackUserData;
};

static int InputTextCallback(ImGuiInputTextCallbackData* data) {
    InputTextCallback_UserData* user_data = (InputTextCallback_UserData*)data->UserData;
    if (data->EventFlag == ImGuiInputTextFlags_CallbackResize) {
        // Resize string callback
        // If for some reason we refuse the new length (BufTextLen) and/or capacity (BufSize) we need to set them back
        // to what we want.
        PCSX::u8string* str = user_data->Str;
        IM_ASSERT(data->Buf == reinterpret_cast<const char*>(str->c_str()));
        str->resize(data->BufTextLen);
        data->Buf = (char*)str->c_str();
    } else if (user_data->ChainCallback) {
        // Forward to user callback, if any
        data->UserData = user_data->ChainCallbackUserData;
        return user_data->ChainCallback(data);
    }
    return 0;
}

static bool InputText(const char* label, PCSX::u8string* str, ImGuiInputTextFlags flags = 0,
                      ImGuiInputTextCallback callback = NULL, void* user_data = NULL) {
    IM_ASSERT((flags & ImGuiInputTextFlags_CallbackResize) == 0);
    flags |= ImGuiInputTextFlags_CallbackResize;

    InputTextCallback_UserData cb_user_data;
    cb_user_data.Str = str;
    cb_user_data.ChainCallback = callback;
    cb_user_data.ChainCallbackUserData = user_data;
    return ImGui::InputText(label, const_cast<char*>(reinterpret_cast<const char*>(str->c_str())), str->capacity() + 1,
                            flags, InputTextCallback, &cb_user_data);
}

#ifdef _WIN32
void PCSX::Widgets::FileDialog::fillRoots() {
    DWORD drivesMask = GetLogicalDrives();
    for (TCHAR drive = 'A'; drive <= 'Z'; drive++, drivesMask >>= 1) {
        if (!(drivesMask & 1)) continue;
        BOOL success = FALSE;
        TCHAR rootPath[4];
        TCHAR volumeName[MAX_PATH + 1];
        rootPath[0] = drive;
        rootPath[1] = ':';
        rootPath[2] = '\\';
        rootPath[3] = '\0';
        success = GetVolumeInformation(rootPath, volumeName, MAX_PATH + 1, NULL, NULL, NULL, NULL, 0);
        if (!success) continue;
#ifdef UNICODE
        int needed;
        char8_t* str;

        needed = WideCharToMultiByte(CP_UTF8, 0, rootPath, -1, NULL, 0, NULL, NULL);
        if (needed <= 0) continue;
        str = (char8_t*)_malloca(needed);
        WideCharToMultiByte(CP_UTF8, 0, rootPath, -1, reinterpret_cast<LPSTR>(str), needed, NULL, NULL);
        PCSX::u8string root = str;
        _freea(str);

        needed = WideCharToMultiByte(CP_UTF8, 0, volumeName, -1, NULL, 0, NULL, NULL);
        if (needed <= 0) continue;
        str = (char8_t*)_malloca(needed);
        WideCharToMultiByte(CP_UTF8, 0, volumeName, -1, reinterpret_cast<LPSTR>(str), needed, NULL, NULL);
        PCSX::u8string label = root + MAKEU8(" (") + str + MAKEU8(")");
        _freea(str);
#else
        PCSX::u8string root = rootName;
        std::string label = root + " (" + volumeName + ")";
#endif
        Root addingRoot{root, label};
        m_roots.push_back({root, label});
    }
}
#else
void PCSX::Widgets::FileDialog::fillRoots() { m_roots.push_back({MAKEU8(u8"/"), MAKEU8(u8"(root)")}); }
#endif

void PCSX::Widgets::FileDialog::openDialog() {
    ImGui::OpenPopup(m_title());
    m_selected.clear();
    m_sorter.name = SORT_DOWN;
    m_sorter.size = UNSORTED;
    m_sorter.date = UNSORTED;
    m_newFile = MAKEU8(u8"");
}

bool PCSX::Widgets::FileDialog::draw() {
    bool done = false;
    if (ImGui::BeginPopupModal(m_title(), NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
        if (m_cacheDirty) {
            fillRoots();
            try {
                if (!std::filesystem::exists(m_currentPath)) setToCurrentPath();
                if (!std::filesystem::is_directory(m_currentPath)) setToCurrentPath();
            } catch (...) {
                setToCurrentPath();
            }
            m_spaceInfo = std::filesystem::space(m_currentPath);
            for (auto& p : std::filesystem::directory_iterator(m_currentPath)) {
                if (p.is_directory()) {
                    m_directories.push_back(p.path().filename().u8string());
                } else {
                    try {
                        auto status = p.status();
                        auto lastWrite = std::filesystem::last_write_time(p);
                        auto timeSinceEpoch = lastWrite.time_since_epoch();
                        auto count = timeSinceEpoch.count();
                        std::time_t dateTime = count / 100000000;
                        const std::tm* converted = std::localtime(&dateTime);
                        std::ostringstream formatted;
                        formatted << std::put_time(converted, "%c");
                        m_files.push_back(
                            {p.path().filename().u8string(), std::filesystem::file_size(p), formatted.str(), dateTime});
                    } catch (...) {
                    }
                }
            }
            if (m_sorter.name != UNSORTED || m_sorter.size != UNSORTED || m_sorter.date != UNSORTED) {
                std::sort(m_files.begin(), m_files.end(), m_sorter);
            }
            std::sort(m_directories.begin(), m_directories.end());
            m_cacheDirty = false;
        }

        bool goHome = false;
        bool goUp = false;
        PCSX::u8string goDown = MAKEU8(u8"");
        File* selected = nullptr;

        if (ImGui::Button(_("Home"))) goHome = true;
        ImGui::SameLine();
        ImGui::TextUnformatted(reinterpret_cast<const char*>(m_currentPath.u8string().c_str()));
        {
            ImGui::BeginChild("Directories", ImVec2(250, 350), true, ImGuiWindowFlags_HorizontalScrollbar);
            if (ImGui::TreeNode(_("Roots"))) {
                for (auto& p : m_roots) {
                    if (ImGui::Selectable(reinterpret_cast<const char*>(p.label.c_str()), false, 0,
                                          ImVec2(ImGui::GetWindowContentRegionWidth(), 0))) {
                        goDown = p.root;
                    }
                }
                ImGui::TreePop();
            }
            if (ImGui::TreeNodeEx(_("Directories"), ImGuiTreeNodeFlags_DefaultOpen)) {
                if (ImGui::Selectable("..", false, 0, ImVec2(ImGui::GetWindowContentRegionWidth(), 0))) {
                    goUp = true;
                }
                for (auto& p : m_directories) {
                    if (ImGui::Selectable(reinterpret_cast<const char*>(p.c_str()), false, 0,
                                          ImVec2(ImGui::GetWindowContentRegionWidth(), 0))) {
                        goDown = p;
                    }
                }
                ImGui::TreePop();
            }
            ImGui::EndChild();
        }
        ImGui::SameLine();
        {
            std::string header;
            ImGui::BeginChild(_("Files"), ImVec2(500, 350), true, ImGuiWindowFlags_HorizontalScrollbar);
            ImGui::Columns(3);
            switch (m_sorter.name) {
                case UNSORTED:
                    header = _("  File");
                    break;
                case SORT_DOWN:
                    header = _("v File");
                    break;
                case SORT_UP:
                    header = _("^ File");
                    break;
            }
            if (ImGui::Selectable(header.c_str())) {
                switch (m_sorter.name) {
                    case UNSORTED:
                        m_sorter.name = SORT_DOWN;
                        break;
                    case SORT_DOWN:
                        m_sorter.name = SORT_UP;
                        break;
                    case SORT_UP:
                        m_sorter.name = UNSORTED;
                        break;
                }
                m_sorter.size = UNSORTED;
                m_sorter.date = UNSORTED;
                nukeCache();
            }
            ImGui::NextColumn();
            switch (m_sorter.size) {
                case UNSORTED:
                    header = _("  Size");
                    break;
                case SORT_DOWN:
                    header = _("v Size");
                    break;
                case SORT_UP:
                    header = _("^ Size");
                    break;
            }
            if (ImGui::Selectable(header.c_str())) {
                switch (m_sorter.size) {
                    case UNSORTED:
                        m_sorter.size = SORT_DOWN;
                        break;
                    case SORT_DOWN:
                        m_sorter.size = SORT_UP;
                        break;
                    case SORT_UP:
                        m_sorter.size = UNSORTED;
                        break;
                }
                m_sorter.name = UNSORTED;
                m_sorter.date = UNSORTED;
                nukeCache();
            }
            ImGui::NextColumn();
            switch (m_sorter.date) {
                case UNSORTED:
                    header = _("  Date & Time");
                    break;
                case SORT_DOWN:
                    header = _("v Date & Time");
                    break;
                case SORT_UP:
                    header = _("^ Date & Time");
                    break;
            }
            if (ImGui::Selectable(header.c_str())) {
                switch (m_sorter.date) {
                    case UNSORTED:
                        m_sorter.date = SORT_DOWN;
                        break;
                    case SORT_DOWN:
                        m_sorter.date = SORT_UP;
                        break;
                    case SORT_UP:
                        m_sorter.date = UNSORTED;
                        break;
                }
                m_sorter.name = UNSORTED;
                m_sorter.size = UNSORTED;
                nukeCache();
            }
            ImGui::NextColumn();
            ImGui::Separator();

            for (auto& p : m_files) {
                PCSX::u8string label = MAKEU8(u8"##") + p.filename;
                if (ImGui::Selectable(reinterpret_cast<const char*>(label.c_str()), p.selected,
                                      ImGuiSelectableFlags_SpanAllColumns)) {
                    for (auto& f : m_files) f.selected = false;
                    p.selected = true;
                    if (m_flags & NewFile) {
                        m_newFile = std::filesystem::path(p.filename).filename().u8string();
                    }
                }
                ImGui::SameLine();
                ImGui::TextUnformatted(reinterpret_cast<const char*>(p.filename.c_str()));
                ImGui::NextColumn();
                ImGui::TextUnformatted(std::to_string(p.size).c_str());
                ImGui::NextColumn();
                ImGui::TextUnformatted(p.dateTime.c_str());
                ImGui::NextColumn();

                if (p.selected) selected = &p;
            }

            ImGui::EndChild();
        }
        PCSX::u8string selectedStr;
        bool gotSelected = selected;
        if (m_flags & NewFile) {
            ImGui::TextUnformatted(reinterpret_cast<const char*>(m_currentPath.u8string().c_str()));
            ImGui::SameLine();
            std::string label = std::string("##") + m_title() + "Filename";
            InputText(label.c_str(), &m_newFile);
            selectedStr = m_newFile;
            gotSelected = !m_newFile.empty();
        } else {
            selectedStr =
                (m_currentPath / std::filesystem::path(selected ? selected->filename : MAKEU8(u8"..."))).u8string();
            ImGui::TextUnformatted(reinterpret_cast<const char*>(selectedStr.c_str()));
        }
        if (!gotSelected) {
            const ImVec4 lolight = ImGui::GetStyle().Colors[ImGuiCol_TextDisabled];
            ImGui::PushStyleColor(ImGuiCol_Button, lolight);
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, lolight);
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, lolight);
        }
        if (ImGui::Button(_("OK"), ImVec2(120, 30)) && gotSelected) {
            m_selected.clear();
            m_selected.push_back(selectedStr);
            ImGui::CloseCurrentPopup();
            done = true;
        }
        if (!gotSelected) ImGui::PopStyleColor(3);
        ImGui::SetItemDefaultFocus();
        ImGui::SameLine();
        if (ImGui::Button(_("Cancel"), ImVec2(120, 30))) {
            ImGui::CloseCurrentPopup();
            done = true;
        }
        ImGui::EndPopup();

        if (goUp) {
            m_currentPath = m_currentPath.parent_path();
            nukeCache();
        } else if (!goDown.empty()) {
            m_currentPath = m_currentPath / goDown;
            nukeCache();
        } else if (goHome) {
            setToCurrentPath();
            nukeCache();
        }
    }

    return done;
}
