/***************************************************************************
 *   Copyright (C) 2023 PCSX-Redux authors                                 *
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

#include <filesystem>
#include <string>
#include <vector>

#include "imgui.h"

namespace PCSX {

class GUI;
namespace Widgets {

class NamedSaveStates {
  public:
    NamedSaveStates(bool& show) : m_show(show) {}
    void draw(GUI* gui, const char* title);
    bool& m_show;

    static constexpr int NAMED_SAVE_STATE_LENGTH_MAX = 128;

    static std::filesystem::path createSaveStatePath(GUI* gui, std::string saveStateName);

    std::vector<std::pair<std::filesystem::path, std::string>> getNamedSaveStates(GUI* gui);

    struct TextFilters {
        static int filterNonPathCharacters(ImGuiInputTextCallbackData* data) { return testChar(data->EventChar); }
        static int testChar(char c) { return testChar((ImWchar)c); }
        static int testChar(ImWchar c);
        static bool isValid(char c) { return testChar((ImWchar)c) == 0; }
        static bool isValid(ImWchar c) { return testChar(c) == 0; }
    };

  private:
    bool saveSaveState(GUI* gui, std::filesystem::path saveStatePath);
    bool loadSaveState(GUI* gui, std::filesystem::path saveStatePath);
    bool deleteSaveState(GUI* gui, std::filesystem::path saveStatePath);

    char m_namedSaveNameString[NAMED_SAVE_STATE_LENGTH_MAX] = "";
};

}  // namespace Widgets

}  // namespace PCSX
